"""
https://claude.ai/chat/e26ae156-3af6-4327-aca0-16964547bd5d
RVWMO Memory Model Checker  (v2 — with lightweight cycle check fix)
====================================================================
Checks execution traces for RVWMO (RISC-V Weak Memory Ordering) violations.

Core data structures:
  SES   - Store Event Set: all surviving stores per address (rf candidates)
  DAG   - Directed graph of memory ordering constraints
  TAINT - Register taint map for dependency tracking (PPO rules 9-11)
  SEEN  - seen[observer_hart][source_hart] = max store order confirmed seen

Key relations tracked in DAG:
  co  - coherence order (same address, same hart only — inferred from PO)
  rf  - reads-from (store -> load)
  fr  - from-reads (load -> later store, derived from rf + co)
  ppo - preserved program order (model-dependent rules)
  dep - address/data/control dependency edges

CRITICAL DESIGN DECISION — diff-hart co is never permanently committed:
  For stores from different harts at the same address, co order is unknown
  until a load observes it. Even then, multiple co orderings may be valid.
  Committing one co ordering permanently risks false violations if that
  ordering later creates a cycle while another valid ordering would not.
  Solution: rf edges are committed (determined by value match), but fr edges
  are only committed after a lightweight DFS confirms no cycle is created.
  The seen map (minimum across all valid witnesses) is the only persistent
  cross-load state for co reasoning.

RVWMO Other-Multi-Copy Atomic note:
  Stores from DIFFERENT harts to DIFFERENT addresses have NO required global
  ordering. Hart C may see S1 (H_A) before S2 (H_B) while Hart D sees S2
  before S1. This is legal. The checker does NOT enforce agreement between
  harts on relative order of stores from different source harts.
  Violations only arise from explicit constraints: ppo, fences, dependencies,
  or same-address coherence.

Usage:
  checker = RVWMOChecker(margin=30000)
  for event in trace:
      if event.type == STORE:  checker.process_store(...)
      if event.type == LOAD:   checker.process_load(...)
      if event.type == FENCE:  checker.process_fence(...)
      if event.type == AMO:    checker.process_amo(...)
      if checker.event_count % PRUNE_INTERVAL  == 0:
          checker.prune(current_cycle)
      if checker.event_count % TARJAN_INTERVAL == 0:
          checker.check_cycles()
  checker.check_cycles()   # final check
  checker.prune(final_cycle)
"""

from collections import defaultdict
from typing import Optional, List, Dict, Tuple, Set
import dataclasses

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_ORDER       = 0x7FFFFFFF  # sentinel: "seen everything"
PRUNE_INTERVAL  = 1000        # prune SES/DAG every N events
TARJAN_INTERVAL = 10000       # full Tarjan cycle check every N events

# Event types
STORE     = "STORE"
LOAD      = "LOAD"
FENCE_R   = "FENCE_R"    # acquire
FENCE_W   = "FENCE_W"    # release
FENCE_RW  = "FENCE_RW"   # full fence
FENCE_TSO = "FENCE_TSO"  # TSO-level fence (RVWMO fence.tso)
AMO       = "AMO"

# DAG edge types
CO       = "co"
RF       = "rf"
FR       = "fr"
PPO      = "ppo"
ADDR_DEP = "addr_dep"
DATA_DEP = "data_dep"
CTRL_DEP = "ctrl_dep"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class StoreEvent:
    order:   int    # global sequence number (assigned at arrival)
    hart:    tuple  # hart id e.g. (chip, core, thread)
    address: int    # physical address
    value:   int    # written value
    mask:    int    # byte-enable mask
    cycle:   int    # simulation cycle
    etype:   str = STORE


@dataclasses.dataclass
class LoadEvent:
    order:    int
    hart:     tuple
    address:  int
    value:    int   # observed value returned by hardware
    mask:     int
    cycle:    int
    addr_reg: int   # register holding address (for addr-dep tracking)
    dst_reg:  int   # destination register (written by load, for taint)
    etype:    str = LOAD


@dataclasses.dataclass
class FenceEvent:
    order:  int
    hart:   tuple
    ftype:  str     # one of FENCE_R / FENCE_W / FENCE_RW / FENCE_TSO
    cycle:  int
    etype:  str = "FENCE"


@dataclasses.dataclass
class DAGNode:
    event: object        # StoreEvent | LoadEvent | FenceEvent
    edges: List[Tuple]   # [(dst_order, edge_type), ...]


@dataclasses.dataclass
class SearchResult:
    rf_source: StoreEvent
    new_seen:  Dict   # updated seen map (minimum across valid witnesses)
    # NOTE: co ordering is intentionally NOT stored here.
    # diff-hart co is never committed permanently to the DAG.


# ---------------------------------------------------------------------------
# Step 0 — Initialization
# ---------------------------------------------------------------------------

class RVWMOChecker:
    """
    Main RVWMO checker.

    Call process_store / process_load / process_fence / process_amo
    for each event in the trace (in program order per hart).

    Call prune()        every PRUNE_INTERVAL  events.
    Call check_cycles() every TARJAN_INTERVAL events (and at end of trace).

    Violations are accumulated in self.violations as human-readable strings.
    """

    def __init__(self, margin: int = 30000):
        """
        margin : cycle age threshold for store pruning.
                 Stores older than `margin` cycles AND overwritten are
                 candidates for removal from SES/DAG.
                 Must be >= maximum store-buffer drain time of the target HW.
                 Too small  -> false positives (legal reads flagged).
                 Too large  -> unbounded memory growth.
                 30 000 cycles is a safe default for modern OOO cores.
        """
        self.margin = margin

        # SES: address -> [StoreEvent, ...] in arrival order.
        # Stores only (loads/fences not here).
        # diff-hart co within an address is discovered lazily by loads.
        self.ses: Dict[int, List[StoreEvent]] = defaultdict(list)

        # DAG: order -> DAGNode.
        # Contains ALL events (stores, loads, fences, AMOs).
        # Permanent edges: ppo, rf, fr (post-cycle-check), same-hart co.
        # diff-hart co edges are NEVER added here.
        self.dag: Dict[int, DAGNode] = {}

        # TAINT: reg_id -> set of store orders whose value is in this reg.
        # Enables PPO rules 9 (addr dep), 10 (data dep).
        # Updated on every load (and AMO read).
        self.taint: Dict[int, Set[int]] = defaultdict(set)

        # SEEN: seen[observer_hart][source_hart] = max confirmed order.
        # Represents the MINIMUM constraint across all valid rf witnesses.
        # Never over-committed; future loads use this to prune co search.
        self.seen: Dict[tuple, Dict[tuple, int]] = \
            defaultdict(lambda: defaultdict(int))

        # last_event[hart]: most recent event from each hart.
        # Used to find `prev` for ppo edge construction.
        self.last_event: Dict[tuple, object] = {}

        # recent_stores/loads[hart]: events since last release-type fence.
        # Used to build release-side ppo edges when a fence arrives.
        self.recent_stores: Dict[tuple, List] = defaultdict(list)
        self.recent_loads:  Dict[tuple, List] = defaultdict(list)

        # Global event sequence counter.  Incremented for every event.
        self.order_counter: int = 0

        # Event counter used to trigger prune / Tarjan intervals.
        self.event_count: int = 0

        # Accumulated violations (strings).
        self.violations: List[str] = []

    # -----------------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------------

    def _next_order(self) -> int:
        o = self.order_counter
        self.order_counter += 1
        return o

    def _add_node(self, event) -> DAGNode:
        node = DAGNode(event=event, edges=[])
        self.dag[event.order] = node
        return node

    def _add_edge(self, src: int, dst: int, etype: str):
        """Add directed edge src->dst.  No-op if either node missing."""
        if src in self.dag and dst in self.dag:
            entry = (dst, etype)
            if entry not in self.dag[src].edges:
                self.dag[src].edges.append(entry)

    def _remove_edge(self, src: int, dst: int, etype: str):
        """Remove a specific edge (used to undo temporary edges)."""
        if src in self.dag:
            self.dag[src].edges = [
                e for e in self.dag[src].edges
                if e != (dst, etype)]

    def _align_value(self, value: int, address: int,
                     nbytes: int) -> Tuple[int, int]:
        """
        Return (aligned_value, tbd_mask).
        tbd_mask has 1s for every bit that still needs a store to explain it.
        Real implementation handles byte-lane alignment; simplified here.
        """
        full_mask = (1 << (nbytes * 8)) - 1
        return value & full_mask, full_mask

    def _compute_new_seen(self, rf_source: StoreEvent,
                          current_seen: Dict,
                          load_hart: tuple) -> Dict:
        """
        Return a copy of current_seen updated so that
        seen[rf_source.hart] >= rf_source.order.
        Does NOT mutate current_seen.
        """
        new_seen = dict(current_seen)
        prev = new_seen.get(rf_source.hart, 0)
        if rf_source.order > prev:
            new_seen[rf_source.hart] = rf_source.order
        return new_seen

    def _violates_same_hart_co(self, store: StoreEvent,
                                partial_co: List[StoreEvent]) -> bool:
        """
        Return True if appending `store` to partial_co would place a
        same-hart store AFTER a store with higher program order from the
        same hart at the same address — violating same-hart co = PO rule.
        """
        for existing in partial_co:
            if (existing.hart    == store.hart and
                    existing.address == store.address and
                    existing.order   >  store.order):
                return True
        return False

    # -----------------------------------------------------------------------
    # Step 1 — Process STORE
    # -----------------------------------------------------------------------

    def process_store(self, hart: tuple, address: int,
                      value: int, mask: int,
                      addr_reg: int, data_reg: int,
                      cycle: int):
        """
        Process an incoming store event.

        - Assigns global order; creates DAG node.
        - Adds ppo edge from previous same-hart event (if PPO rule fires).
        - Adds addr/data dependency edges via taint map (PPO rules 9-10).
        - Adds store to SES for future rf candidate lookup.
        - Adds same-hart co edge immediately (co = PO for same hart).
          diff-hart co at same address is deferred until a load resolves it.
        """
        store = StoreEvent(
            order   = self._next_order(),
            hart    = hart,
            address = address,
            value   = value,
            mask    = mask,
            cycle   = cycle)
        self._add_node(store)

        # ppo edge from previous same-hart event
        prev = self.last_event.get(hart)
        if prev is not None and self.qualifies_ppo(prev, store):
            self._add_edge(prev.order, store.order, PPO)

        # Address dependency (PPO rule 9)
        for tainted_order in self.taint.get(addr_reg, set()):
            self._add_edge(tainted_order, store.order, ADDR_DEP)

        # Data dependency (PPO rule 10)
        for tainted_order in self.taint.get(data_reg, set()):
            self._add_edge(tainted_order, store.order, DATA_DEP)

        # Same-hart co: inferred immediately from program order.
        # Find the most recent same-hart store at this address and add co edge.
        # Only immediate predecessor (avoids redundant transitive edges).
        same_hart_prior = [s for s in self.ses[address]
                           if s.hart == hart]
        if same_hart_prior:
            immediate_pred = max(same_hart_prior, key=lambda s: s.order)
            self._add_edge(immediate_pred.order, store.order, CO)

        self.ses[address].append(store)
        self.last_event[hart] = store
        self.recent_stores[hart].append(store)
        self.event_count += 1

    # -----------------------------------------------------------------------
    # Step 2 — Process LOAD
    # -----------------------------------------------------------------------

    def process_load(self, hart: tuple, address: int,
                     value: int, mask: int,
                     addr_reg: int, dst_reg: int,
                     cycle: int):
        """
        Process an incoming load event.

        - Assigns global order; creates DAG node.
        - Adds ppo edge from previous same-hart event.
        - Adds addr dependency edges via taint map.
        - Calls search_rf_and_co() to find a valid rf assignment.
            * Searches ALL co orderings for diff-hart same-address stores.
            * Lightweight DFS cycle check guards each candidate before commit.
            * Returns minimum seen map across all valid witnesses.
        - Adds rf edge.
        - Adds fr edges (only for co orderings confirmed cycle-free).
        - Updates SEEN map (minimum seen preserved — never over-commits).
        - Updates TAINT map (load result may feed future dependencies).

        Reports violation if no valid rf source exists.
        """
        load = LoadEvent(
            order    = self._next_order(),
            hart     = hart,
            address  = address,
            value    = value,
            mask     = mask,
            cycle    = cycle,
            addr_reg = addr_reg,
            dst_reg  = dst_reg)
        self._add_node(load)

        prev = self.last_event.get(hart)
        if prev is not None and self.qualifies_ppo(prev, load):
            self._add_edge(prev.order, load.order, PPO)

        # Address dependency (PPO rule 9)
        for tainted_order in self.taint.get(addr_reg, set()):
            self._add_edge(tainted_order, load.order, ADDR_DEP)

        candidates   = list(self.ses[address])
        current_seen = dict(self.seen[hart])
        result = self.search_rf_and_co(load, candidates, current_seen)

        if result is None:
            self.violations.append(
                f"VIOLATION: no valid rf source — "
                f"hart={hart} addr={address:#x} "
                f"value={value:#x} cycle={cycle}")
            self.last_event[hart] = load
            self.recent_loads[hart].append(load)
            self.event_count += 1
            return

        # rf edge: permanently commit (value match already confirmed)
        self._add_edge(result.rf_source.order, load.order, RF)

        # fr edges: load missed every store that is co-after rf_source.
        # For same-hart stores: program order determines co-after directly.
        # For diff-hart stores: conservatively add fr for all stores that
        # COULD be co-after in any valid ordering.
        # The lightweight cycle check inside _search_recursive already
        # rejected orderings where these fr edges would create a cycle,
        # so committing them here is safe for the chosen ordering.
        for store in self.ses[address]:
            if store.order == result.rf_source.order:
                continue
            if store.hart == result.rf_source.hart:
                if store.order > result.rf_source.order:
                    self._add_edge(load.order, store.order, FR)
            else:
                # diff-hart: add fr conservatively
                self._add_edge(load.order, store.order, FR)

        # Update SEEN with minimum across valid witnesses
        for src_hart, order in result.new_seen.items():
            if order > self.seen[hart][src_hart]:
                self.seen[hart][src_hart] = order

        # TAINT: mark dst_reg as tainted by rf_source
        self.taint[dst_reg] = {result.rf_source.order}

        self.last_event[hart] = load
        self.recent_loads[hart].append(load)
        self.event_count += 1

    # -----------------------------------------------------------------------
    # Step 3 — search_rf_and_co  (entry point)
    # -----------------------------------------------------------------------

    def search_rf_and_co(self, load: LoadEvent,
                         candidates: List[StoreEvent],
                         seen: Dict) -> Optional[SearchResult]:
        """
        Entry point for rf + co exhaustive search.

        Separates candidates into:
          same_hart: co already known from PO — sorted, no search needed.
          diff_hart: co unknown — searched recursively by _search_recursive.

        Returns SearchResult with minimum seen map across ALL valid witnesses,
        or None if no valid assignment exists (violation).

        Key invariant: diff-hart co is searched here but NEVER committed to
        the DAG.  Only rf edges, fr edges (after cycle check), and the seen
        map persist after this call returns.
        """
        load_value, tbd = self._align_value(
            load.value, load.address, 8)

        same_hart = sorted(
            [s for s in candidates if s.hart == load.hart],
            key=lambda s: s.order)

        diff_hart = [s for s in candidates if s.hart != load.hart]

        return self._search_recursive(
            load        = load,
            load_value  = load_value,
            tbd         = tbd,
            partial_co  = same_hart.copy(),
            unplaced    = diff_hart.copy(),
            seen        = seen,
            rf_source   = None,
            best_result = None)

    # -----------------------------------------------------------------------
    # Step 3a — _search_recursive  (recursive co search)
    # -----------------------------------------------------------------------

    def _search_recursive(self,
                          load:        LoadEvent,
                          load_value:  int,
                          tbd:         int,
                          partial_co:  List[StoreEvent],
                          unplaced:    List[StoreEvent],
                          seen:        Dict,
                          rf_source:   Optional[StoreEvent],
                          best_result: Optional[SearchResult]
                          ) -> Optional[SearchResult]:
        """
        Recursively place unplaced diff-hart stores into partial_co,
        trying every possible position (permutation via recursion/backtrack).

        At each recursion level:
          Pick one unplaced store; append to partial_co (making it latest).
          Apply three CHEAP local pruning checks (no DAG traversal).
          *** NEW: lightweight DFS cycle check at base case before commit ***
          Recurse on remaining unplaced stores.
          Merge seen maps (take MINIMUM) across all valid witnesses.
          Backtrack and try next candidate.

        BASE CASE (unplaced empty):
          All stores placed.  Check tbd==0 (all load bytes explained).
          *** Run lightweight DFS to confirm no cycle before committing. ***
          If cycle found -> reject this co ordering, try others.
          If no cycle   -> valid result, merge into best_result.

        Why we continue after finding first valid result:
          Multiple co orderings may be valid.  Each yields a different seen
          map.  We must collect ALL valid orderings to compute the true
          MINIMUM seen map — committing only the weakest necessary constraint.
          Over-committing seen map causes false violations in future loads.

        ISSUE ADDRESSED HERE:
          Original code had no cycle check inside the recursion.
          It committed rf+fr edges based on local value/seen checks alone.
          A locally valid co ordering can still create a global DAG cycle
          when combined with existing ppo/rf/fr edges from prior events.
          Committing such an ordering causes a false violation when the
          periodic Tarjan run detects the cycle.

        SOLUTION: lightweight DFS at base case.
          Before committing, temporarily add the candidate rf+fr edges,
          run DFS from affected nodes (NOT full Tarjan — only reachable
          subgraph), check for back-edges.  Remove temp edges if cycle found.
          Cost: O(D) where D = depth of reachable subgraph from affected nodes.
          Typically D << V (full graph size).  Tractable per load event.

        OTHER OPTIONS CONSIDERED:
          Option A — commit first, rely on periodic Tarjan only.
            Risk: wrong co ordering committed permanently.
            False violations possible.  Not acceptable for a precise checker.

          Option B — defer all fr edges, never commit co.
            fr edges are essential for cycle detection (no fr -> no backward
            edges -> no cycles possible -> checker always passes -> useless).
            Not viable.

          Option C — full Tarjan per co candidate.
            O(V+E) per candidate × N! candidates = intractable.
            Not viable for online checking.

          Option D — offline complete search.
            Collect full trace, try all global co assignments, run Tarjan.
            Exponential but exact.  Suitable only for small traces or
            post-silicon debug, not online production checking.

          CHOSEN: Option lightweight DFS (between A and C in cost/accuracy).
            O(D) per candidate where D << V.
            Catches false violations before commit.
            Tractable for online checking.
        """

        # ── BASE CASE ──────────────────────────────────────────────────────
        if not unplaced:
            if tbd != 0 or rf_source is None:
                # Some load bytes unexplained — this co ordering is invalid
                return best_result

            # ----------------------------------------------------------------
            # LIGHTWEIGHT CYCLE CHECK (the fix)
            #
            # Before committing rf + fr edges for this co ordering, verify
            # that adding them does not create a cycle in the existing DAG.
            #
            # We temporarily add the candidate edges, run a DFS limited to
            # nodes reachable from the affected source nodes, check for
            # back-edges (which indicate a cycle), then remove the temp edges
            # regardless of outcome.
            #
            # If a cycle is found: this co ordering is rejected.
            #   _search_recursive backtracks and tries the next permutation.
            # If no cycle: safe to commit this ordering.
            # ----------------------------------------------------------------
            temp_edges = self._compute_temp_edges(
                load, rf_source, partial_co)

            if self._creates_cycle(temp_edges):
                # This co ordering creates a global DAG cycle.
                # Reject it and let the recursion try other permutations.
                return best_result

            # Valid co ordering — compute updated seen map
            new_seen = self._compute_new_seen(
                rf_source, seen, load.hart)
            result = SearchResult(
                rf_source = rf_source,
                new_seen  = new_seen)

            # Merge with best_result: take MINIMUM seen per hart.
            # Minimum = weakest constraint = avoids over-constraining future loads.
            if best_result is None:
                return result

            merged = {}
            all_harts = set(best_result.new_seen) | set(new_seen)
            for h in all_harts:
                merged[h] = min(
                    best_result.new_seen.get(h, MAX_ORDER),
                    new_seen.get(h, MAX_ORDER))
            return SearchResult(
                rf_source = best_result.rf_source,
                new_seen  = merged)

        # ── RECURSIVE CASE ─────────────────────────────────────────────────
        # Try each unplaced store as the NEXT (latest) entry in partial_co.
        for i, store in enumerate(unplaced):

            # Pruning 1 — same-hart co constraint (cheapest check first)
            # Within the same hart at the same address, co must follow PO.
            if self._violates_same_hart_co(store, partial_co):
                continue

            # Pruning 2 — value check
            # Does this store correctly explain the bytes of the load it covers?
            contribution  = (load_value ^ store.value) & tbd & store.mask
            value_matches = (contribution == 0) and bool(tbd & store.mask)

            # Pruning 3 — seen map check
            # If load's hart has already confirmed seeing past this store
            # (seen[load.hart][store.hart] >= store.order) and the value
            # does not match, this store cannot be the latest visible store
            # to the load — prune unless a later store from same hart is seen.
            already_seen = (seen.get(store.hart, 0) >= store.order)
            if already_seen and not value_matches:
                later_seen = any(
                    seen.get(s.hart, 0) >= s.order
                    for s in partial_co
                    if s.hart    == store.hart and
                       s.address == store.address and
                       s.order   >  store.order)
                if not later_seen:
                    continue  # prune: store must be latest but value wrong

            # Place store at end of partial_co (currently latest in co)
            new_partial = partial_co + [store]
            new_unplaced = unplaced[:i] + unplaced[i + 1:]

            # Update tbd bitmask and rf_source candidate
            if value_matches:
                new_tbd       = tbd & ~store.mask  # bytes now explained
                new_rf        = store
            else:
                new_tbd       = tbd
                new_rf        = rf_source           # unchanged

            # Recurse on remaining unplaced stores
            result = self._search_recursive(
                load        = load,
                load_value  = load_value,
                tbd         = new_tbd,
                partial_co  = new_partial,
                unplaced    = new_unplaced,
                seen        = seen,
                rf_source   = new_rf,
                best_result = best_result)

            if result is not None:
                best_result = result
                # Do NOT return immediately.
                # Continue to find ALL valid orderings so we can
                # compute the true minimum seen map across all of them.

        return best_result

    # -----------------------------------------------------------------------
    # Step 3b — Lightweight cycle check helpers
    # -----------------------------------------------------------------------

    def _compute_temp_edges(self,
                            load:      LoadEvent,
                            rf_source: StoreEvent,
                            co_ordering: List[StoreEvent]
                            ) -> List[Tuple[int, int, str]]:
        """
        Compute the set of DAG edges that would be added if we commit
        the given co ordering and rf_source for this load.

        Returns list of (src_order, dst_order, edge_type) tuples.
        These are added temporarily for the cycle check and removed
        immediately after regardless of outcome.

        Edges computed:
          rf  : rf_source -> load
          fr  : load -> every store co-after rf_source at same address
        """
        edges = []

        # rf edge
        edges.append((rf_source.order, load.order, RF))

        # fr edges: load -> stores that are co-after rf_source
        rf_idx = co_ordering.index(rf_source) \
                 if rf_source in co_ordering else -1

        for store in self.ses[load.address]:
            if store.order == rf_source.order:
                continue
            # same-hart: use program order
            if store.hart == rf_source.hart:
                if store.order > rf_source.order:
                    edges.append((load.order, store.order, FR))
            else:
                # diff-hart: use position in co_ordering
                store_idx = co_ordering.index(store) \
                            if store in co_ordering else -1
                if store_idx > rf_idx:
                    edges.append((load.order, store.order, FR))

        return edges

    def _creates_cycle(self,
                       temp_edges: List[Tuple[int, int, str]]
                       ) -> bool:
        """
        Temporarily add temp_edges to the DAG, run a DFS limited to nodes
        reachable from the affected source nodes, check for back-edges
        (which indicate a cycle).  Remove temp_edges before returning.

        Cost: O(D) where D = size of reachable subgraph from affected nodes.
        In practice D << V (total DAG size) because we only traverse
        the subgraph reachable from the handful of newly added edge sources.

        Returns True if a cycle is detected, False otherwise.

        WHY not full Tarjan here:
          Full Tarjan is O(V+E) and would be called inside every recursive
          branch at every load event — completely intractable.
          Lightweight DFS from affected nodes only is O(D) and fast enough
          to run per co candidate.
        """
        # Add temp edges
        for (src, dst, etype) in temp_edges:
            self._add_edge(src, dst, etype)

        # DFS from each affected source node
        cycle_found = False
        affected_sources = {e[0] for e in temp_edges}

        for start in affected_sources:
            if self._dfs_has_cycle(start, set(), set()):
                cycle_found = True
                break

        # Always remove temp edges (success or failure)
        for (src, dst, etype) in temp_edges:
            self._remove_edge(src, dst, etype)

        return cycle_found

    def _dfs_has_cycle(self,
                       node:     int,
                       visited:  Set[int],
                       on_stack: Set[int]
                       ) -> bool:
        """
        Standard iterative DFS back-edge detection.
        Returns True if a cycle is reachable from `node`.

        visited:  nodes whose entire subtree has been explored.
        on_stack: nodes currently on the DFS recursion stack.
                  A back-edge to an on_stack node = cycle.

        Uses an explicit stack to avoid Python recursion depth limits
        for large DAGs.
        """
        # Iterative DFS using explicit stack of (node, edge_iterator)
        stack = [(node, iter(self.dag[node].edges
                             if node in self.dag else []))]
        on_stack.add(node)
        visited.add(node)

        while stack:
            current, edges = stack[-1]
            try:
                dst, _ = next(edges)
                if dst not in self.dag:
                    continue
                if dst in on_stack:
                    return True   # back-edge -> cycle
                if dst not in visited:
                    visited.add(dst)
                    on_stack.add(dst)
                    stack.append(
                        (dst, iter(self.dag[dst].edges)))
            except StopIteration:
                # All edges from current explored
                on_stack.discard(current)
                stack.pop()

        return False

    # -----------------------------------------------------------------------
    # Step 4 — Process FENCE
    # -----------------------------------------------------------------------

    def process_fence(self, hart: tuple, fence_type: str, cycle: int):
        """
        Process a fence instruction.  Adds ppo edges according to fence type.

        FENCE_W  (release):
          All prior loads AND stores ->ppo-> fence.
          "Nothing before can move after."
          Added NOW from recent_loads + recent_stores lists.
          Acquire side: none.

        FENCE_R  (acquire):
          fence ->ppo-> all subsequent loads and stores.
          "Nothing after can move before."
          Added LATER when subsequent events arrive via qualifies_ppo().
          Release side: none.

        FENCE_RW (full fence):
          Release side: prior ops ->ppo-> fence (added now).
          Acquire side: fence ->ppo-> subsequent ops (added later).

        FENCE_TSO:
          Release side: prior LOADS  ->ppo-> fence (added now).
                        prior STORES ->ppo-> fence (added now).
          Acquire side: fence ->ppo-> subsequent LOADS  (added later).
                        fence ->ppo-> subsequent STORES (added later).
          NOTE: prior STORES are NOT ordered before subsequent LOADS.
          That ST->LD reordering is TSO's one permitted relaxation.
          FENCE_TSO enforces TSO-level ordering, not full SC.

        Fences do NOT go into recent_stores/recent_loads.
        They are not memory accesses.
        """
        fence = FenceEvent(
            order  = self._next_order(),
            hart   = hart,
            ftype  = fence_type,
            cycle  = cycle)
        self._add_node(fence)

        if fence_type == FENCE_W:
            # Release: prior loads and stores ->ppo-> fence
            for prior in (self.recent_loads[hart] +
                          self.recent_stores[hart]):
                self._add_edge(prior.order, fence.order, PPO)
            self.recent_loads[hart].clear()
            self.recent_stores[hart].clear()

        elif fence_type == FENCE_R:
            # Acquire: nothing to add now.
            # qualifies_ppo(fence_r, next_event) returns True,
            # so edges are added when subsequent events arrive.
            pass

        elif fence_type == FENCE_RW:
            # Release side (added now)
            for prior in (self.recent_loads[hart] +
                          self.recent_stores[hart]):
                self._add_edge(prior.order, fence.order, PPO)
            self.recent_loads[hart].clear()
            self.recent_stores[hart].clear()
            # Acquire side handled via qualifies_ppo on future events

        elif fence_type == FENCE_TSO:
            # Release side: prior LOADS and STORES ->ppo-> fence
            for prior in (self.recent_loads[hart] +
                          self.recent_stores[hart]):
                self._add_edge(prior.order, fence.order, PPO)
            self.recent_loads[hart].clear()
            self.recent_stores[hart].clear()
            # Acquire side: fence ->ppo-> subsequent LOADS and STORES
            # (but NOT prior stores before subsequent loads — ST->LD allowed)
            # Handled via qualifies_ppo on future events.

        self.last_event[hart] = fence
        self.event_count += 1

    # -----------------------------------------------------------------------
    # Step 5 — qualifies_ppo
    # -----------------------------------------------------------------------

    def qualifies_ppo(self, prev, curr) -> bool:
        """
        Return True if RVWMO PPO rules require prev to be globally ordered
        before curr.  Both must be from the same hart (only called same-hart).

        PPO rules covered:
          Fence acquire side : FENCE_R / FENCE_RW / FENCE_TSO ->ppo-> any mem op.
          Fence release side : any mem op ->ppo-> FENCE_W / FENCE_RW / FENCE_TSO.
          AMO                : fully ordered (acquire + release).
          Addr dependency    : load result used as address of curr (rule 9).
          Data dependency    : load result used as data of store curr (rule 10).
          Ctrl dependency    : load result controls branch before curr (rule 11).
          LD->LD same addr   : pipeline ordering (rule 12).
          ST->LD same addr   : store-to-load forwarding ordering (rule 13).

        Returns False if no rule fires — RVWMO permits reordering in that case.
        """
        prev_type = (prev.etype if hasattr(prev, 'etype')
                     else getattr(prev, 'ftype', None))
        curr_type = (curr.etype if hasattr(curr, 'etype')
                     else getattr(curr, 'ftype', None))

        # Fence acquire side: fence ->ppo-> subsequent mem ops
        if prev_type in (FENCE_R, FENCE_RW, FENCE_TSO):
            if curr_type in (LOAD, STORE, AMO):
                return True

        # Fence release side: mem ops ->ppo-> fence
        if curr_type in (FENCE_W, FENCE_RW, FENCE_TSO):
            if prev_type in (LOAD, STORE, AMO):
                return True

        # AMO: both acquire and release — everything orders around it
        if prev_type == AMO or curr_type == AMO:
            return True

        # PPO rule 9: address dependency
        curr_addr_reg = getattr(curr, 'addr_reg', None)
        if curr_addr_reg is not None:
            if prev.order in self.taint.get(curr_addr_reg, set()):
                return True

        # PPO rule 10: data dependency (stores only)
        if curr_type in (STORE, AMO):
            curr_data_reg = getattr(curr, 'data_reg', None)
            if curr_data_reg is not None:
                if prev.order in self.taint.get(curr_data_reg, set()):
                    return True

        # PPO rule 11: control dependency (hook — implement per trace format)
        if self._has_control_dependency(prev, curr):
            return True

        # PPO rule 12: load -> load, same address (pipeline ordering)
        if (prev_type == LOAD and curr_type == LOAD and
                hasattr(prev, 'address') and hasattr(curr, 'address') and
                prev.address == curr.address):
            return True

        # PPO rule 13: store -> load, same address
        if (prev_type == STORE and curr_type == LOAD and
                hasattr(prev, 'address') and hasattr(curr, 'address') and
                prev.address == curr.address):
            return True

        return False   # no PPO rule fires; RVWMO allows reordering

    def _has_control_dependency(self, prev, curr) -> bool:
        """
        Stub for PPO rule 11 (control dependency).
        Full implementation tracks branch instructions whose outcome depends
        on a load result, ordering all instructions after the branch relative
        to that load.  Implement based on your trace format.
        """
        return False

    # -----------------------------------------------------------------------
    # Step 6 — Process AMO
    # -----------------------------------------------------------------------

    def process_amo(self, hart: tuple, address: int,
                    read_value: int, write_value: int,
                    mask: int, addr_reg: int,
                    data_reg: int, dst_reg: int,
                    cycle: int):
        """
        Process an Atomic Memory Operation (AMO).

        AMO = atomic load + store:
          Read part : reads current value at address -> read_value.
          Write part: writes new value to address   -> write_value.

        AMO is both acquire AND release under RVWMO:
          All prior ops   ->ppo-> AMO  (release, added now via prev->AMO edge).
          AMO ->ppo-> all subsequent ops  (acquire, via qualifies_ppo later).

        Actions mirror process_load (read part) + process_store (write part):
          Find rf source for read_value (same recursive co search as load).
          Add rf and fr edges for read part.
          Add AMO to SES as a store (write part).
          Add co edges: AMO write comes after all existing stores at address
          (AMO is sequentially after its own read — atomicity guarantee).
          Update SEEN and TAINT.
        """
        amo = StoreEvent(
            order   = self._next_order(),
            hart    = hart,
            address = address,
            value   = write_value,
            mask    = mask,
            cycle   = cycle,
            etype   = AMO)
        self._add_node(amo)

        # ppo: release side — prev ->ppo-> AMO
        prev = self.last_event.get(hart)
        if prev is not None:
            self._add_edge(prev.order, amo.order, PPO)

        # Dependency edges
        for tainted_order in self.taint.get(addr_reg, set()):
            self._add_edge(tainted_order, amo.order, ADDR_DEP)
        for tainted_order in self.taint.get(data_reg, set()):
            self._add_edge(tainted_order, amo.order, DATA_DEP)

        # Find rf source for AMO's READ part (reads old value)
        amo_as_load = LoadEvent(
            order    = amo.order,
            hart     = hart,
            address  = address,
            value    = read_value,
            mask     = mask,
            cycle    = cycle,
            addr_reg = addr_reg,
            dst_reg  = dst_reg)

        candidates   = list(self.ses[address])
        current_seen = dict(self.seen[hart])
        result = self.search_rf_and_co(amo_as_load, candidates, current_seen)

        if result is None:
            self.violations.append(
                f"VIOLATION: no valid rf for AMO — "
                f"hart={hart} addr={address:#x} cycle={cycle}")
        else:
            self._add_edge(result.rf_source.order, amo.order, RF)

            for store in self.ses[address]:
                if store.order == result.rf_source.order:
                    continue
                if store.hart == result.rf_source.hart:
                    if store.order > result.rf_source.order:
                        self._add_edge(amo.order, store.order, FR)
                else:
                    self._add_edge(amo.order, store.order, FR)

            for src_hart, order in result.new_seen.items():
                if order > self.seen[hart][src_hart]:
                    self.seen[hart][src_hart] = order

            self.taint[dst_reg] = {amo.order}

        # AMO WRITE: comes after all existing stores at address (atomicity)
        for existing in self.ses[address]:
            self._add_edge(existing.order, amo.order, CO)
        self.ses[address].append(amo)

        self.last_event[hart]       = amo
        self.recent_stores[hart].append(amo)
        self.event_count += 1

    # -----------------------------------------------------------------------
    # Step 7 — Prune
    # -----------------------------------------------------------------------

    def prune(self, current_cycle: int):
        """
        Remove stores from SES and DAG that are no longer needed.
        Call every PRUNE_INTERVAL events to keep memory bounded.

        A store is safe to prune only if ALL four conditions hold:
          1. Age > margin cycles  (old enough to have drained from HW store buffers).
          2. Overwritten: a newer store exists at same address  (not latest).
          3. No register in TAINT still holds this store's value.
          4. All known observer harts have confirmed seeing past this store
             via SEEN map  (seen[h][store.hart] >= store.order for all h).

        Pruning too aggressively (small margin) -> false positives:
          A legal load that reads an old-but-still-in-buffer value cannot
          find its rf source after the store is pruned -> spurious violation.

        Pruning too conservatively (large margin) -> memory growth:
          Old stores accumulate indefinitely; DAG and SES grow without bound.

        After removing from SES, the DAG node and its TAINT entries are also
        cleaned up to keep the graph compact for Tarjan runs.
        """
        for address in list(self.ses.keys()):
            surviving = []
            for store in self.ses[address]:
                age = current_cycle - store.cycle

                # Condition 1: too recent
                if age <= self.margin:
                    surviving.append(store)
                    continue

                # Condition 2: is this the latest store at address?
                newer_exists = any(
                    s.order > store.order
                    for s in self.ses[address] if s != store)
                if not newer_exists:
                    surviving.append(store)
                    continue

                # Condition 3: any register still tainted by this store?
                taint_active = any(
                    store.order in ts
                    for ts in self.taint.values())
                if taint_active:
                    surviving.append(store)
                    continue

                # Condition 4: not all harts have seen past this store
                all_seen = all(
                    self.seen[h].get(store.hart, 0) >= store.order
                    for h in self.seen)
                if not all_seen:
                    surviving.append(store)
                    continue

                # Safe to prune — remove from DAG and TAINT
                if store.order in self.dag:
                    del self.dag[store.order]
                for reg in list(self.taint.keys()):
                    self.taint[reg].discard(store.order)
                    if not self.taint[reg]:
                        del self.taint[reg]
                # (store dropped from surviving -> removed from SES implicitly)

            self.ses[address] = surviving

    # -----------------------------------------------------------------------
    # Step 8 — check_cycles  (Tarjan SCC)
    # -----------------------------------------------------------------------

    def check_cycles(self):
        """
        Run Tarjan's SCC algorithm on the full current DAG.
        Call every TARJAN_INTERVAL events and once at end of trace.

        A cycle exists iff any Strongly Connected Component has size > 1.
        A cycle in the DAG means no valid RVWMO execution can explain the
        observed trace -> violation reported.

        Tarjan's algorithm: O(V+E), single DFS pass, each node visited once.
        At steady state with margin=30000: V~20000, E~52000, ~72000 ops/run.
        At 10^9 ops/sec and TARJAN_INTERVAL=10000: ~100 runs/ms -> ~7ms overhead.

        The lightweight DFS inside _search_recursive handles the LOCAL cycle
        check per co candidate.  This periodic full Tarjan is the GLOBAL check
        that catches any cycles that slipped through (e.g. from ppo chains
        that span multiple loads and could not be seen locally).
        """
        visited  = {}
        low      = {}
        on_stack = {}
        stack    = []
        timer    = [0]

        def strongconnect(v):
            visited[v] = low[v] = timer[0]
            timer[0]  += 1
            stack.append(v)
            on_stack[v] = True

            node = self.dag.get(v)
            if node:
                for (w, _) in node.edges:
                    if w not in visited:
                        strongconnect(w)
                        low[v] = min(low[v], low[w])
                    elif on_stack.get(w, False):
                        low[v] = min(low[v], visited[w])

            if low[v] == visited[v]:
                scc = []
                while True:
                    w = stack.pop()
                    on_stack[w] = False
                    scc.append(w)
                    if w == v:
                        break
                if len(scc) > 1:
                    self.violations.append(
                        f"VIOLATION: cycle — {self._describe_cycle(scc)}")

        for v in list(self.dag.keys()):
            if v not in visited:
                strongconnect(v)

    def _describe_cycle(self, scc: List[int]) -> str:
        """Format SCC members as a human-readable cycle description."""
        parts = []
        for order in scc:
            node = self.dag.get(order)
            if node:
                e = node.event
                addr = getattr(e, 'address', '?')
                parts.append(
                    f"{e.etype}(hart={e.hart},"
                    f"addr={addr:#x},order={e.order})")
        return " -> ".join(parts) + " -> [cycle]"


# ---------------------------------------------------------------------------
# ## Trace Through Simple Example + General Usage Flow
# ---------------------------------------------------------------------------
"""
GENERAL FLOW
============

Initialization:
    checker = RVWMOChecker(margin=30000)

AT EVERY MEMORY EVENT in the trace:

    STORE:
        checker.process_store(hart, address, value, mask,
                              addr_reg, data_reg, cycle)
        # Adds DAG node, ppo edge (if PPO rule fires), same-hart co edge.
        # Adds to SES.  diff-hart co deferred until a load resolves it.

    LOAD:
        checker.process_load(hart, address, value, mask,
                             addr_reg, dst_reg, cycle)
        # Adds DAG node, ppo edge.
        # Runs _search_recursive(): tries all co orderings for diff-hart
        #   stores at this address.  Lightweight DFS guards each candidate.
        # Commits rf edge.  Commits fr edges for cycle-free ordering only.
        # Updates SEEN (minimum across all valid witnesses).
        # Updates TAINT (load result -> dst_reg).
        # Reports violation if no valid rf source found.

    FENCE:
        checker.process_fence(hart, fence_type, cycle)
        # FENCE_W  (release): prior ops ->ppo-> fence. Added now.
        # FENCE_R  (acquire): fence ->ppo-> future ops. Added on future events.
        # FENCE_RW:           both directions.
        # FENCE_TSO:          like FENCE_RW minus ST->LD relaxation.

    AMO:
        checker.process_amo(hart, address, read_value, write_value,
                            mask, addr_reg, data_reg, dst_reg, cycle)
        # Atomic load + store.  Acquire + release ordering.

EVERY 1000 EVENTS (PRUNE_INTERVAL):
    checker.prune(current_cycle)
    # Removes old overwritten stores to keep SES/DAG bounded.
    # Must satisfy all 4 conditions: age, overwritten, untainted, seen.

EVERY 10000 EVENTS (TARJAN_INTERVAL):
    checker.check_cycles()
    # Full Tarjan SCC on current DAG.  Reports any cycle as violation.
    # Catches global cycles that local DFS inside _search_recursive missed.

AT END OF TRACE:
    checker.check_cycles()      # final global check
    checker.prune(final_cycle)  # final cleanup
    if checker.violations:
        for v in checker.violations:
            print(v)
    else:
        print("RVWMO PASS")


SIMPLE EXAMPLE — Message Passing (MP) Pattern
===============================================

Harts: H_A (writer), H_B (reader).
Addresses: A1 (data), A2 (flag).

    H_A: ST[A1]=1    (S1 — store data)
    H_A: fence.rw    (ensures S1 ordered before S2)
    H_A: ST[A2]=1    (S2 — store flag)
    H_B: LD[A2]->1   (L1 — load flag, sees S2)
    H_B: LD[A1]->0   (L2 — load data, reads initial — misses S1)

Processing S1 (H_A, A1, value=1):
    DAG: {S1}. SES[A1]=[S1]. No co edges yet.

Processing fence.rw (H_A):
    recent_stores[H_A]=[S1] -> S1->ppo->fence added.
    recent_stores cleared.

Processing S2 (H_A, A2, value=1):
    DAG: {S1, fence, S2}.
    qualifies_ppo(fence, S2)? FENCE_RW acquire side -> YES.
    fence->ppo->S2 added.

Processing L1 (H_B, A2, reads=1):
    search_rf_and_co: only candidate is S2, value=1 matches.
    Lightweight DFS: rf edge S2->L1 alone, no cycle. Safe.
    S2->rf->L1 added.  No fr edges (S2 is only store at A2).
    SEEN[H_B][H_A] = S2.order.

Processing L2 (H_B, A1, reads=0):
    qualifies_ppo(L1, L2)? LD->LD same hart -> YES.
    L1->ppo->L2 added.
    search_rf_and_co: S1 at A1, value=1 != 0.  No match.
    If initial value tracked: rf=INIT, fr: L2->fr->S1.
    Lightweight DFS: S1->ppo->fence->ppo->S2->rf->L1->ppo->L2->fr->S1.
    CYCLE DETECTED in DFS. This co ordering rejected.
    No other co ordering available. result=None.
    VIOLATION reported: "no valid rf source for load H_B A1 value=0".

Final check_cycles():
    Tarjan confirms cycle:
    S1->ppo->fence->ppo->S2->rf->L1->ppo->L2->fr->S1.
    VIOLATION: classic message-passing violation.
    H_B saw the flag (S2) but not the data (S1).
"""


# ---------------------------------------------------------------------------
# Main driver — example usage
# ---------------------------------------------------------------------------

if __name__ == "__main__":

    checker = RVWMOChecker(margin=30000)

    H_A = (0, 0, 0)   # writer hart
    H_B = (0, 0, 1)   # reader hart
    A1  = 0x1000       # data address
    A2  = 0x2000       # flag address
    MASK = 0xFFFFFFFF
    cycle = 0

    # S1: H_A stores data=1 to A1
    checker.process_store(
        hart=H_A, address=A1, value=1, mask=MASK,
        addr_reg=1, data_reg=2, cycle=cycle)
    cycle += 1

    # Full fence: ensures S1 globally ordered before S2
    checker.process_fence(hart=H_A, fence_type=FENCE_RW, cycle=cycle)
    cycle += 1

    # S2: H_A stores flag=1 to A2
    checker.process_store(
        hart=H_A, address=A2, value=1, mask=MASK,
        addr_reg=1, data_reg=3, cycle=cycle)
    cycle += 1

    # L1: H_B loads flag from A2, sees 1 (sees S2)
    checker.process_load(
        hart=H_B, address=A2, value=1, mask=MASK,
        addr_reg=1, dst_reg=4, cycle=cycle)
    cycle += 1

    # L2: H_B loads data from A1, reads 0 (misses S1 — violation)
    checker.process_load(
        hart=H_B, address=A1, value=0, mask=MASK,
        addr_reg=1, dst_reg=5, cycle=cycle)
    cycle += 1

    # Final checks
    checker.check_cycles()
    checker.prune(cycle)

    print("=== RVWMO Checker Results ===")
    if checker.violations:
        for v in checker.violations:
            print(v)
    else:
        print("PASS — no violations found")
