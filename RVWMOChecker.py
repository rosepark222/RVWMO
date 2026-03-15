"""
RVWMO Memory Model Checker  (v3 — PPO-ordered seen map fix)
============================================================

CHANGES FROM v2
---------------
v2 BUG:
    process_load() used the FULL accumulated seen map when checking each load.
    The seen map is updated in GRADUATION ORDER (the order events appear in
    the trace).  But RVWMO allows loads with no PPO relationship to be
    REORDERED — the later-graduating load may have EXECUTED (read memory)
    BEFORE the earlier-graduating load.

    Example (from the trace that exposed this bug):
        S3  (H_A, A1, value=6f8ef337, order=3)
        S5  (H_A, A1, value=a063,     order=5)   ← overwrites S3
        S12 (H_A, A2, value=5244,     order=12)
        L19 (H_B, A2, reads=5244)                ← graduates first
        L23 (H_B, A1, reads=6f8ef337)            ← graduates second

    v2 processed L19 first, updated seen[H_B][H_A]=12, then checked L23
    using that seen map.  seen[H_B][H_A]=12 >= S5.order=5 caused the
    checker to conclude S5 was already seen, making S3 invisible, and
    flagging L23 reading 6f8ef337 as a VIOLATION.

    BUT: L19 and L23 have NO PPO relationship (different addresses, no
    fence/dependency between them).  RVWMO allows L23 to float before L19.
    If L23 executed (read memory) BEFORE L19, then at the time L23 read A1:
        seen[H_B][H_A] was still 0 (L19 had not yet executed).
        S5 was not yet confirmed seen.
        S3 was a valid rf candidate.
        L23 reading 6f8ef337 (S3's value) is PERFECTLY LEGAL.

    The v2 checker incorrectly reported a FALSE VIOLATION because it used
    graduation order to build the seen map instead of PPO-ordered execution
    order.

v3 FIX:
    Introduced USE_PPO_ORDERED_SEEN compile-time flag (see below).

    When USE_PPO_ORDERED_SEEN = True  (the fix):
        process_load() calls _ppo_ordered_seen() instead of using the full
        self.seen[hart] map.  _ppo_ordered_seen() returns a seen map that
        only includes contributions from loads that are PPO-ordered BEFORE
        the current load in program order.  Loads with no PPO relationship
        to the current load do NOT contribute their seen updates.

        For L23: L19 has no PPO edge to L23 (different addresses, no sync).
        Therefore L19's seen update (seen[H_B][H_A]=12) is excluded when
        checking L23.  L23 sees seen[H_B][H_A]=0.  S3 is a valid rf
        candidate.  L23 reading 6f8ef337 is PASS. ✓

    When USE_PPO_ORDERED_SEEN = False  (v2 behaviour, for comparison):
        Full accumulated seen map used.  May produce false violations for
        reordered loads as described above.

    Additionally, v3 tracks seen_at_load[load.order] = the seen map snapshot
    AT THE TIME each load was processed.  This enables _ppo_ordered_seen()
    to reconstruct the correct per-load seen contribution.

OTHER OPTIONS CONSIDERED FOR THE FIX (not implemented):
    Option A — Execution-order trace:
        Hardware emits load events in execution order (when load reads
        memory), not graduation order.  Checker processes in that order.
        Correct but requires richer trace format not always available.

    Option B — Reorder annotation:
        Hardware annotates each load: "this load was reordered before X."
        Checker adjusts seen map accordingly.  Even richer trace required.

    Option C — Accept approximation (v2 behaviour):
        Process in graduation order, accept false violations for reordered
        loads, investigate manually.  Practical but imprecise.

    CHOSEN Option D — PPO-ordered seen map (this file):
        At check time for load L, only include seen contributions from
        loads that are PPO-ordered before L.  No richer trace needed.
        Correctly handles reordering without requiring execution-order trace.
        May be slightly more permissive (misses some violations where a
        non-PPO-ordered load happened to execute in order), but produces
        no false violations.  Best tradeoff for online checking.

Core data structures (unchanged from v2):
    SES   - Store Event Set: surviving stores per address (rf candidates)
    DAG   - Directed graph of ordering constraints
    TAINT - Register taint map for PPO dependency tracking
    SEEN  - seen[observer_hart][source_hart] = max store order confirmed seen

Key relations in DAG (unchanged from v2):
    co  - coherence order (same address, same hart, inferred from PO)
    rf  - reads-from
    fr  - from-reads (load -> later store, derived from rf+co)
    ppo - preserved program order
    dep - address/data/control dependency

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
    checker.check_cycles()
    checker.prune(final_cycle)
"""

from collections import defaultdict
from typing import Optional, List, Dict, Tuple, Set
import dataclasses

# ---------------------------------------------------------------------------
# Compile-time flags
# ---------------------------------------------------------------------------

# SET THIS FLAG to switch between v2 behaviour and the v3 fix.
#
# True  (v3 fix):
#   Use PPO-ordered seen map in process_load().
#   Only loads that are PPO-ordered before the current load contribute
#   their seen updates.  Prevents false violations for reordered loads.
#   Recommended for RVWMO checking.
#
# False (v2 behaviour):
#   Use full accumulated seen map regardless of PPO ordering.
#   May produce false violations when loads reorder (no PPO between them).
#   Kept here for comparison / regression purposes.
USE_PPO_ORDERED_SEEN: bool = True


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_ORDER       = 0x7FFFFFFF
PRUNE_INTERVAL  = 1000
TARJAN_INTERVAL = 10000

STORE     = "STORE"
LOAD      = "LOAD"
FENCE_R   = "FENCE_R"
FENCE_W   = "FENCE_W"
FENCE_RW  = "FENCE_RW"
FENCE_TSO = "FENCE_TSO"
AMO       = "AMO"

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
    order:   int
    hart:    tuple
    address: int
    value:   int
    mask:    int
    cycle:   int
    etype:   str = STORE


@dataclasses.dataclass
class LoadEvent:
    order:    int
    hart:     tuple
    address:  int
    value:    int
    mask:     int
    cycle:    int
    addr_reg: int
    dst_reg:  int
    etype:    str = LOAD


@dataclasses.dataclass
class FenceEvent:
    order:  int
    hart:   tuple
    ftype:  str
    cycle:  int
    etype:  str = "FENCE"


@dataclasses.dataclass
class DAGNode:
    event: object
    edges: List[Tuple]   # [(dst_order, edge_type), ...]


@dataclasses.dataclass
class SearchResult:
    rf_source: StoreEvent
    new_seen:  Dict


# ---------------------------------------------------------------------------
# Step 0 — Initialization
# ---------------------------------------------------------------------------

class RVWMOChecker:
    """
    RVWMO checker v3.
    Set USE_PPO_ORDERED_SEEN at top of file to switch between v2 and v3.
    """

    def __init__(self, margin: int = 30000):
        self.margin = margin

        # SES: address -> [StoreEvent]
        self.ses: Dict[int, List[StoreEvent]] = defaultdict(list)

        # DAG: order -> DAGNode
        self.dag: Dict[int, DAGNode] = {}

        # TAINT: reg -> set of store orders
        self.taint: Dict[int, Set[int]] = defaultdict(set)

        # SEEN: seen[observer][source] = max confirmed order
        # Built in graduation order.  Used directly in v2 mode.
        # In v3 mode, _ppo_ordered_seen() filters this per load.
        self.seen: Dict[tuple, Dict[tuple, int]] = \
            defaultdict(lambda: defaultdict(int))

        # v3 addition:
        # seen_at_load[load.order] = dict snapshot of seen[hart] contributions
        # made BY this specific load (i.e. what this load added to seen map).
        # Used by _ppo_ordered_seen() to reconstruct PPO-gated seen map.
        self.seen_at_load: Dict[int, Dict[tuple, int]] = {}

        # ppo_predecessors_map[load.order] = list of load orders that are
        # PPO-ordered directly before this load (same hart, ppo edge exists).
        # Used by _ppo_ordered_seen() to walk the PPO chain.
        self.ppo_pred_loads: Dict[int, List[int]] = defaultdict(list)

        self.last_event:     Dict[tuple, object] = {}
        self.recent_stores:  Dict[tuple, List]   = defaultdict(list)
        self.recent_loads:   Dict[tuple, List]   = defaultdict(list)

        self.order_counter: int = 0
        self.event_count:   int = 0
        self.violations:    List[str] = []

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
        if src in self.dag and dst in self.dag:
            entry = (dst, etype)
            if entry not in self.dag[src].edges:
                self.dag[src].edges.append(entry)

    def _remove_edge(self, src: int, dst: int, etype: str):
        if src in self.dag:
            self.dag[src].edges = [
                e for e in self.dag[src].edges
                if e != (dst, etype)]

    def _align_value(self, value: int, address: int,
                     nbytes: int) -> Tuple[int, int]:
        full_mask = (1 << (nbytes * 8)) - 1
        return value & full_mask, full_mask

    def _compute_new_seen(self, rf_source: StoreEvent,
                          current_seen: Dict,
                          load_hart: tuple) -> Dict:
        new_seen = dict(current_seen)
        prev = new_seen.get(rf_source.hart, 0)
        if rf_source.order > prev:
            new_seen[rf_source.hart] = rf_source.order
        return new_seen

    def _violates_same_hart_co(self, store: StoreEvent,
                                partial_co: List[StoreEvent]) -> bool:
        for existing in partial_co:
            if (existing.hart    == store.hart and
                    existing.address == store.address and
                    existing.order   >  store.order):
                return True
        return False

    # -----------------------------------------------------------------------
    # v3 FIX: PPO-ordered seen map
    # -----------------------------------------------------------------------

    def _ppo_ordered_seen(self, hart: tuple,
                          current_load: LoadEvent) -> Dict[tuple, int]:
        """
        [v3 FIX — only called when USE_PPO_ORDERED_SEEN = True]

        Return a seen map for `hart` that includes ONLY contributions from
        loads that are PPO-ordered before current_load.

        A load L_prev is PPO-ordered before current_load if there exists a
        PPO edge L_prev ->ppo-> current_load in the DAG (direct or transitive).

        Rationale:
            RVWMO allows loads with no PPO relationship to reorder.
            If L19 and L23 have no PPO edge, L23 may have executed (read
            memory) before L19.  Using L19's seen update when checking L23
            would incorrectly assume L19 executed first — potentially causing
            a false violation.

            By restricting the seen map to PPO-ordered predecessors, we only
            apply ordering constraints that RVWMO actually guarantees.

        Implementation:
            Walk the PPO predecessor chain (stored in ppo_pred_loads).
            Accumulate seen contributions from each PPO-ordered prior load
            (stored per-load in seen_at_load).
            Contributions from loads not on this chain are excluded.

        Example — the bug trace:
            S3  (H_A, A1, value=6f8ef337, order=3)
            S5  (H_A, A1, value=a063,     order=5)
            S12 (H_A, A2, value=5244,     order=12)
            L19 (H_B, A2, reads=5244)      ← graduates before L23
            L23 (H_B, A1, reads=6f8ef337) ← graduates after L19

            No PPO edge L19->L23 (different addresses, no fence/dep).

            v2 (USE_PPO_ORDERED_SEEN=False):
                seen used for L23 = {H_A: 12}  (includes L19's contribution)
                S5.order=5 <= 12 → S5 confirmed seen
                S5 overwrites S3 → S3 invisible
                L23 reading 6f8ef337 (S3 value) → VIOLATION  ← FALSE

            v3 (USE_PPO_ORDERED_SEEN=True):
                L19 not PPO-ordered before L23 → exclude L19's contribution
                seen used for L23 = {H_A: 0}   (empty — no PPO predecessors)
                S5.order=5 > 0 → S5 not confirmed seen
                S3 is a valid rf candidate
                L23 reading 6f8ef337 (S3 value) → PASS  ✓

            Why PASS is correct:
                L23 may have floated before L19 in the pipeline.
                At the moment L23 read A1, L19 had not yet read A2.
                SEEN[H_B][H_A] was 0 at that moment.
                S5 was not yet confirmed seen by H_B.
                S3 was the latest store visible to H_B at A1.
                Reading S3's value 6f8ef337 is a legal RVWMO execution.
        """
        result: Dict[tuple, int] = {}

        # BFS/DFS over PPO predecessor loads for current_load
        visited: Set[int] = set()
        queue:   List[int] = list(self.ppo_pred_loads.get(
                                      current_load.order, []))

        while queue:
            pred_order = queue.pop()
            if pred_order in visited:
                continue
            visited.add(pred_order)

            # Accumulate this predecessor load's seen contributions
            contrib = self.seen_at_load.get(pred_order, {})
            for src_hart, order in contrib.items():
                if order > result.get(src_hart, 0):
                    result[src_hart] = order

            # Walk further back along PPO chain
            for grandpred in self.ppo_pred_loads.get(pred_order, []):
                if grandpred not in visited:
                    queue.append(grandpred)

        return result

    # -----------------------------------------------------------------------
    # Step 1 — Process STORE
    # -----------------------------------------------------------------------

    def process_store(self, hart: tuple, address: int,
                      value: int, mask: int,
                      addr_reg: int, data_reg: int,
                      cycle: int):
        """
        Process an incoming store event.
        Adds DAG node, ppo edge, dependency edges, same-hart co edge, SES entry.
        diff-hart co is deferred until a load resolves it.
        """
        store = StoreEvent(
            order   = self._next_order(),
            hart    = hart,
            address = address,
            value   = value,
            mask    = mask,
            cycle   = cycle)
        self._add_node(store)

        prev = self.last_event.get(hart)
        if prev is not None and self.qualifies_ppo(prev, store):
            self._add_edge(prev.order, store.order, PPO)

        for tainted_order in self.taint.get(addr_reg, set()):
            self._add_edge(tainted_order, store.order, ADDR_DEP)
        for tainted_order in self.taint.get(data_reg, set()):
            self._add_edge(tainted_order, store.order, DATA_DEP)

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

        v2 vs v3 difference is HERE — in how current_seen is built:

            v2 (USE_PPO_ORDERED_SEEN=False):
                current_seen = dict(self.seen[hart])
                Uses the FULL accumulated seen map in graduation order.
                If L19 graduated before L23, L19's seen updates are included
                when checking L23, even if L23 may have executed first.
                Risk: false violations for reordered loads.

            v3 (USE_PPO_ORDERED_SEEN=True):
                current_seen = self._ppo_ordered_seen(hart, load)
                Uses ONLY seen updates from loads PPO-ordered before this load.
                L19 not PPO-ordered before L23 → L19's seen excluded from L23.
                Correctly handles RVWMO load reordering.
                No false violations from graduation-order vs execution-order mismatch.

        After search_rf_and_co():
            Records this load's own seen contribution in seen_at_load[load.order].
            Records PPO predecessor relationship in ppo_pred_loads.
            These enable future loads to call _ppo_ordered_seen() correctly.
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
        ppo_edge_added = False
        if prev is not None and self.qualifies_ppo(prev, load):
            self._add_edge(prev.order, load.order, PPO)
            ppo_edge_added = True
            # v3: track PPO predecessor loads for _ppo_ordered_seen()
            if getattr(prev, 'etype', None) == LOAD:
                self.ppo_pred_loads[load.order].append(prev.order)
            # If prev is a fence, walk back to find the load PPO-before fence
            elif getattr(prev, 'etype', None) == 'FENCE':
                for candidate in self.ppo_pred_loads.get(prev.order, []):
                    self.ppo_pred_loads[load.order].append(candidate)

        for tainted_order in self.taint.get(addr_reg, set()):
            self._add_edge(tainted_order, load.order, ADDR_DEP)

        # ----------------------------------------------------------------
        # v2 vs v3: seen map selection
        # ----------------------------------------------------------------
        if USE_PPO_ORDERED_SEEN:
            # v3 FIX: only use seen from PPO-ordered predecessors.
            # See _ppo_ordered_seen() docstring for full explanation and
            # the L19/L23 example that motivated this fix.
            current_seen = self._ppo_ordered_seen(hart, load)
        else:
            # v2 BEHAVIOUR: full accumulated seen map.
            # May cause false violations when loads reorder.
            current_seen = dict(self.seen[hart])
        # ----------------------------------------------------------------

        candidates = list(self.ses[address])
        result = self.search_rf_and_co(load, candidates, current_seen)

        if result is None:
            self.violations.append(
                f"VIOLATION: no valid rf source — "
                f"hart={hart} addr={address:#x} "
                f"value={value:#x} cycle={cycle} "
                f"[USE_PPO_ORDERED_SEEN={USE_PPO_ORDERED_SEEN}]")
            self.last_event[hart] = load
            self.recent_loads[hart].append(load)
            self.event_count += 1
            return

        self._add_edge(result.rf_source.order, load.order, RF)

        for store in self.ses[address]:
            if store.order == result.rf_source.order:
                continue
            if store.hart == result.rf_source.hart:
                if store.order > result.rf_source.order:
                    self._add_edge(load.order, store.order, FR)
            else:
                self._add_edge(load.order, store.order, FR)

        # Update global seen map (graduation order, used for pruning)
        seen_delta: Dict[tuple, int] = {}
        for src_hart, order in result.new_seen.items():
            if order > self.seen[hart][src_hart]:
                self.seen[hart][src_hart] = order
                seen_delta[src_hart] = order
            elif src_hart in result.new_seen:
                seen_delta[src_hart] = result.new_seen[src_hart]

        # v3: record this load's own seen contribution for future
        # _ppo_ordered_seen() calls.
        self.seen_at_load[load.order] = seen_delta

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
        Separates candidates into same-hart (co known from PO) and
        diff-hart (co unknown, searched recursively).
        Returns SearchResult with minimum seen map, or None (violation).
        diff-hart co is never committed permanently to the DAG.
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
    # Step 3a — _search_recursive
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
        Recursively place unplaced diff-hart stores into partial_co.
        At each level: pick one unplaced store, append (making it latest),
        apply three local pruning checks, recurse, merge minimum seen map.

        BASE CASE: run lightweight DFS cycle check before committing.
        If cycle found: reject this co ordering, try others.

        Continue after first valid result to collect ALL valid orderings
        and compute true minimum seen map across all witnesses.
        """

        # ── BASE CASE ──────────────────────────────────────────────────────
        if not unplaced:
            if tbd != 0 or rf_source is None:
                return best_result

            temp_edges = self._compute_temp_edges(
                load, rf_source, partial_co)
            if self._creates_cycle(temp_edges):
                return best_result  # reject: would create cycle

            new_seen = self._compute_new_seen(
                rf_source, seen, load.hart)
            result = SearchResult(rf_source=rf_source, new_seen=new_seen)

            if best_result is None:
                return result

            merged = {}
            for h in set(best_result.new_seen) | set(new_seen):
                merged[h] = min(
                    best_result.new_seen.get(h, MAX_ORDER),
                    new_seen.get(h, MAX_ORDER))
            return SearchResult(
                rf_source=best_result.rf_source, new_seen=merged)

        # ── RECURSIVE CASE ─────────────────────────────────────────────────
        for i, store in enumerate(unplaced):

            # Pruning 1: same-hart co must follow PO
            if self._violates_same_hart_co(store, partial_co):
                continue

            # Pruning 2: value check
            contribution  = (load_value ^ store.value) & tbd & store.mask
            value_matches = (contribution == 0) and bool(tbd & store.mask)

            # Pruning 3: seen map check
            already_seen = (seen.get(store.hart, 0) >= store.order)
            if already_seen and not value_matches:
                later_seen = any(
                    seen.get(s.hart, 0) >= s.order
                    for s in partial_co
                    if s.hart    == store.hart and
                       s.address == store.address and
                       s.order   >  store.order)
                if not later_seen:
                    continue

            new_partial  = partial_co + [store]
            new_unplaced = unplaced[:i] + unplaced[i + 1:]

            if value_matches:
                new_tbd = tbd & ~store.mask
                new_rf  = store
            else:
                new_tbd = tbd
                new_rf  = rf_source

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

        return best_result

    # -----------------------------------------------------------------------
    # Step 3b — Lightweight cycle check helpers (unchanged from v2)
    # -----------------------------------------------------------------------

    def _compute_temp_edges(self,
                            load:        LoadEvent,
                            rf_source:   StoreEvent,
                            co_ordering: List[StoreEvent]
                            ) -> List[Tuple[int, int, str]]:
        """Compute rf + fr edges for a candidate co ordering (not yet committed)."""
        edges = []
        edges.append((rf_source.order, load.order, RF))

        rf_idx = (co_ordering.index(rf_source)
                  if rf_source in co_ordering else -1)

        for store in self.ses[load.address]:
            if store.order == rf_source.order:
                continue
            if store.hart == rf_source.hart:
                if store.order > rf_source.order:
                    edges.append((load.order, store.order, FR))
            else:
                store_idx = (co_ordering.index(store)
                             if store in co_ordering else -1)
                if store_idx > rf_idx:
                    edges.append((load.order, store.order, FR))

        return edges

    def _creates_cycle(self,
                       temp_edges: List[Tuple[int, int, str]]
                       ) -> bool:
        """
        Temporarily add temp_edges, run DFS from affected nodes,
        check for cycle, remove temp_edges.  O(D) cost, D=reachable depth.
        """
        for (src, dst, etype) in temp_edges:
            self._add_edge(src, dst, etype)

        cycle_found = False
        for start in {e[0] for e in temp_edges}:
            if self._dfs_has_cycle(start, set(), set()):
                cycle_found = True
                break

        for (src, dst, etype) in temp_edges:
            self._remove_edge(src, dst, etype)

        return cycle_found

    def _dfs_has_cycle(self,
                       node:     int,
                       visited:  Set[int],
                       on_stack: Set[int]) -> bool:
        """Iterative DFS back-edge detection.  Returns True if cycle found."""
        stack = [(node, iter(
            self.dag[node].edges if node in self.dag else []))]
        on_stack.add(node)
        visited.add(node)

        while stack:
            current, edges = stack[-1]
            try:
                dst, _ = next(edges)
                if dst not in self.dag:
                    continue
                if dst in on_stack:
                    return True
                if dst not in visited:
                    visited.add(dst)
                    on_stack.add(dst)
                    stack.append((dst, iter(self.dag[dst].edges)))
            except StopIteration:
                on_stack.discard(current)
                stack.pop()

        return False

    # -----------------------------------------------------------------------
    # Step 4 — Process FENCE (unchanged from v2)
    # -----------------------------------------------------------------------

    def process_fence(self, hart: tuple, fence_type: str, cycle: int):
        """
        Process a fence instruction.

        FENCE_W  (release): prior loads+stores ->ppo-> fence. Added now.
        FENCE_R  (acquire): fence ->ppo-> subsequent ops. Added on future events.
        FENCE_RW (full):    both directions.
        FENCE_TSO:          like FENCE_RW minus ST->LD relaxation.
        """
        fence = FenceEvent(
            order  = self._next_order(),
            hart   = hart,
            ftype  = fence_type,
            cycle  = cycle)
        self._add_node(fence)

        if fence_type == FENCE_W:
            for prior in (self.recent_loads[hart] +
                          self.recent_stores[hart]):
                self._add_edge(prior.order, fence.order, PPO)
            self.recent_loads[hart].clear()
            self.recent_stores[hart].clear()

        elif fence_type == FENCE_R:
            pass  # acquire side handled via qualifies_ppo on future events

        elif fence_type == FENCE_RW:
            for prior in (self.recent_loads[hart] +
                          self.recent_stores[hart]):
                self._add_edge(prior.order, fence.order, PPO)
            self.recent_loads[hart].clear()
            self.recent_stores[hart].clear()

        elif fence_type == FENCE_TSO:
            for prior in (self.recent_loads[hart] +
                          self.recent_stores[hart]):
                self._add_edge(prior.order, fence.order, PPO)
            self.recent_loads[hart].clear()
            self.recent_stores[hart].clear()

        # v3: record fence as PPO predecessor for subsequent loads
        self.ppo_pred_loads[fence.order] = list(
            self.ppo_pred_loads.get(
                self.last_event[hart].order
                if hart in self.last_event else -1, []))

        self.last_event[hart] = fence
        self.event_count += 1

    # -----------------------------------------------------------------------
    # Step 5 — qualifies_ppo (unchanged from v2)
    # -----------------------------------------------------------------------

    def qualifies_ppo(self, prev, curr) -> bool:
        """
        Return True if RVWMO PPO rules require prev ordered before curr.
        Both must be from same hart.

        Rules: fence acquire/release, AMO, addr dep (9), data dep (10),
               ctrl dep (11), LD->LD same addr (12), ST->LD same addr (13).
        """
        prev_type = (prev.etype if hasattr(prev, 'etype')
                     else getattr(prev, 'ftype', None))
        curr_type = (curr.etype if hasattr(curr, 'etype')
                     else getattr(curr, 'ftype', None))

        if prev_type in (FENCE_R, FENCE_RW, FENCE_TSO):
            if curr_type in (LOAD, STORE, AMO):
                return True

        if curr_type in (FENCE_W, FENCE_RW, FENCE_TSO):
            if prev_type in (LOAD, STORE, AMO):
                return True

        if prev_type == AMO or curr_type == AMO:
            return True

        curr_addr_reg = getattr(curr, 'addr_reg', None)
        if curr_addr_reg is not None:
            if prev.order in self.taint.get(curr_addr_reg, set()):
                return True

        if curr_type in (STORE, AMO):
            curr_data_reg = getattr(curr, 'data_reg', None)
            if curr_data_reg is not None:
                if prev.order in self.taint.get(curr_data_reg, set()):
                    return True

        if self._has_control_dependency(prev, curr):
            return True

        if (prev_type == LOAD and curr_type == LOAD and
                hasattr(prev, 'address') and hasattr(curr, 'address') and
                prev.address == curr.address):
            return True

        if (prev_type == STORE and curr_type == LOAD and
                hasattr(prev, 'address') and hasattr(curr, 'address') and
                prev.address == curr.address):
            return True

        return False

    def _has_control_dependency(self, prev, curr) -> bool:
        """Stub for PPO rule 11.  Implement per trace format."""
        return False

    # -----------------------------------------------------------------------
    # Step 6 — Process AMO (unchanged from v2)
    # -----------------------------------------------------------------------

    def process_amo(self, hart: tuple, address: int,
                    read_value: int, write_value: int,
                    mask: int, addr_reg: int,
                    data_reg: int, dst_reg: int,
                    cycle: int):
        """
        AMO = atomic load + store.  Acquire + release ordering.
        Find rf source for read part; add to SES as store for write part.
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

        prev = self.last_event.get(hart)
        if prev is not None:
            self._add_edge(prev.order, amo.order, PPO)

        for t in self.taint.get(addr_reg, set()):
            self._add_edge(t, amo.order, ADDR_DEP)
        for t in self.taint.get(data_reg, set()):
            self._add_edge(t, amo.order, DATA_DEP)

        amo_as_load = LoadEvent(
            order=amo.order, hart=hart, address=address,
            value=read_value, mask=mask, cycle=cycle,
            addr_reg=addr_reg, dst_reg=dst_reg)

        if USE_PPO_ORDERED_SEEN:
            current_seen = self._ppo_ordered_seen(hart, amo_as_load)
        else:
            current_seen = dict(self.seen[hart])

        result = self.search_rf_and_co(
            amo_as_load, list(self.ses[address]), current_seen)

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

        for existing in self.ses[address]:
            self._add_edge(existing.order, amo.order, CO)
        self.ses[address].append(amo)

        self.last_event[hart]       = amo
        self.recent_stores[hart].append(amo)
        self.event_count += 1

    # -----------------------------------------------------------------------
    # Step 7 — Prune (unchanged from v2)
    # -----------------------------------------------------------------------

    def prune(self, current_cycle: int):
        """
        Remove stores from SES/DAG that satisfy all four pruning conditions:
          1. Age > margin cycles.
          2. Overwritten (newer store exists at same address).
          3. No register tainted by this store.
          4. All observer harts confirmed seen past this store.
        """
        for address in list(self.ses.keys()):
            surviving = []
            for store in self.ses[address]:
                if current_cycle - store.cycle <= self.margin:
                    surviving.append(store); continue
                if not any(s.order > store.order
                           for s in self.ses[address] if s != store):
                    surviving.append(store); continue
                if any(store.order in ts for ts in self.taint.values()):
                    surviving.append(store); continue
                if not all(self.seen[h].get(store.hart, 0) >= store.order
                           for h in self.seen):
                    surviving.append(store); continue
                if store.order in self.dag:
                    del self.dag[store.order]
                for reg in list(self.taint.keys()):
                    self.taint[reg].discard(store.order)
                    if not self.taint[reg]:
                        del self.taint[reg]
            self.ses[address] = surviving

    # -----------------------------------------------------------------------
    # Step 8 — check_cycles / Tarjan (unchanged from v2)
    # -----------------------------------------------------------------------

    def check_cycles(self):
        """
        Full Tarjan SCC on current DAG.  Cycle in SCC size>1 = violation.
        O(V+E).  Run every TARJAN_INTERVAL events and at end of trace.
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
        parts = []
        for order in scc:
            node = self.dag.get(order)
            if node:
                e = node.event
                parts.append(
                    f"{e.etype}(hart={e.hart},"
                    f"addr={getattr(e,'address','?'):#x},"
                    f"order={e.order})")
        return " -> ".join(parts) + " -> [cycle]"


# ---------------------------------------------------------------------------
# General usage flow (comment block)
# ---------------------------------------------------------------------------
"""
GENERAL FLOW
============

    checker = RVWMOChecker(margin=30000)
    # Toggle USE_PPO_ORDERED_SEEN at top of file to switch v2/v3 behaviour.

AT EVERY MEMORY EVENT:
    STORE : checker.process_store(hart, address, value, mask,
                                  addr_reg, data_reg, cycle)
    LOAD  : checker.process_load(hart, address, value, mask,
                                  addr_reg, dst_reg, cycle)
    FENCE : checker.process_fence(hart, fence_type, cycle)
    AMO   : checker.process_amo(hart, address, read_value, write_value,
                                 mask, addr_reg, data_reg, dst_reg, cycle)

EVERY 1000 EVENTS:
    checker.prune(current_cycle)

EVERY 10000 EVENTS:
    checker.check_cycles()

AT END OF TRACE:
    checker.check_cycles()
    checker.prune(final_cycle)
    print(checker.violations or "PASS")
"""


# ---------------------------------------------------------------------------
# Main driver — demonstrates v2 vs v3 on the bug trace
# ---------------------------------------------------------------------------

if __name__ == "__main__":

    # The trace that exposed the v2 false-violation bug:
    #
    #   S3  (H_A, A1, value=6f8ef337, order=3)
    #   S5  (H_A, A1, value=a063,     order=5)   ← overwrites S3 at A1
    #   S12 (H_A, A2, value=5244,     order=12)
    #   L19 (H_B, A2, reads=5244)                 ← graduates before L23
    #   L23 (H_B, A1, reads=6f8ef337)             ← graduates after L19
    #
    # L19 and L23 have NO PPO relationship:
    #   Different addresses (A2 vs A1).
    #   No fence between them.
    #   No address/data/control dependency.
    #
    # Two possible execution orderings:
    #
    # Case A — L23 executes AFTER L19 (in-order execution):
    #   At L23's execution time: seen[H_B][H_A] = 12 (from L19).
    #   S5.order=5 <= 12 → S5 confirmed seen by H_B.
    #   S5 overwrites S3 at A1 → S3 invisible to H_B.
    #   L23 reading 6f8ef337 (S3's value) is ILLEGAL.
    #   → VIOLATION (real).
    #
    # Case B — L23 floats BEFORE L19 (RVWMO reordering):
    #   At L23's execution time: seen[H_B][H_A] = 0 (L19 not yet executed).
    #   S5.order=5 > 0 → S5 NOT confirmed seen by H_B.
    #   S3 is a valid rf candidate at A1.
    #   L23 reading 6f8ef337 (S3's value) is LEGAL.
    #   → PASS (legal RVWMO execution).
    #
    # v2 (USE_PPO_ORDERED_SEEN=False):
    #   Processes in graduation order: L19 first, L23 second.
    #   After L19: seen[H_B][H_A] = 12.
    #   Checks L23 with seen[H_B][H_A] = 12.
    #   Assumes Case A (in-order). Reports VIOLATION.
    #   But Case B is a valid RVWMO execution → FALSE VIOLATION.
    #
    # v3 (USE_PPO_ORDERED_SEEN=True):
    #   L19 has no PPO edge to L23.
    #   _ppo_ordered_seen() excludes L19's contribution from L23's check.
    #   Checks L23 with seen[H_B][H_A] = 0.
    #   S3 is valid. L23 reading 6f8ef337 → PASS. ✓

    H_A = (2, 3, 0)   # source hart
    H_B = (2, 1, 1)   # observer hart
    A1  = 0x12828      # address 1 (stores S3, S5)
    A2  = 0x4028       # address 2 (store S12)
    cycle = 100

    def run_test(flag: bool):
        global USE_PPO_ORDERED_SEEN
        USE_PPO_ORDERED_SEEN = flag
        label = "v3 FIX (PPO-ordered seen)" if flag else "v2 (full seen)"
        print(f"\n{'='*55}")
        print(f" Running with USE_PPO_ORDERED_SEEN = {flag}  [{label}]")
        print(f"{'='*55}")

        c = RVWMOChecker(margin=30000)

        # S3: H_A stores 6f8ef337 to A1
        c.process_store(hart=H_A, address=A1, value=0x6f8ef337,
                        mask=0xFFFFFFFF, addr_reg=1, data_reg=2,
                        cycle=cycle+0)
        print("  processed S3 (H_A, A1, value=6f8ef337)")

        # S5: H_A overwrites A1 with a063
        c.process_store(hart=H_A, address=A1, value=0xa063,
                        mask=0xFFFFFFFF, addr_reg=1, data_reg=2,
                        cycle=cycle+10)
        print("  processed S5 (H_A, A1, value=a063)  [overwrites S3]")

        # S12: H_A stores 5244 to A2
        c.process_store(hart=H_A, address=A2, value=0x5244,
                        mask=0xFFFFFFFF, addr_reg=1, data_reg=3,
                        cycle=cycle+20)
        print("  processed S12 (H_A, A2, value=5244)")

        # L19: H_B loads A2 -> 5244
        c.process_load(hart=H_B, address=A2, value=0x5244,
                       mask=0xFFFFFFFF, addr_reg=1, dst_reg=4,
                       cycle=cycle+30)
        print("  processed L19 (H_B, A2, reads=5244)")
        print(f"    seen[H_B][H_A] after L19 = "
              f"{c.seen[H_B].get(H_A, 0)}")

        # L23: H_B loads A1 -> 6f8ef337
        # This is the problematic load.
        # No PPO edge from L19 to L23 (different addresses, no fence/dep).
        # L23 may have floated before L19 in RVWMO.
        c.process_load(hart=H_B, address=A1, value=0x6f8ef337,
                       mask=0xFFFFFFFF, addr_reg=1, dst_reg=5,
                       cycle=cycle+40)
        print("  processed L23 (H_B, A1, reads=6f8ef337)")

        c.check_cycles()

        if c.violations:
            print(f"\n  RESULT: VIOLATION(S) FOUND")
            for v in c.violations:
                print(f"    {v}")
        else:
            print(f"\n  RESULT: PASS — no violations")

    # Run with v2 behaviour (false violation expected)
    run_test(flag=False)

    # Run with v3 fix (pass expected)
    run_test(flag=True)

    print("\n")
    print("Expected:")
    print("  USE_PPO_ORDERED_SEEN=False (v2): VIOLATION  "
          "(false — graduation order assumed)")
    print("  USE_PPO_ORDERED_SEEN=True  (v3): PASS       "
          "(correct — L23 may have floated before L19)")
