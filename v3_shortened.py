from collections import defaultdict
from typing import Optional, List, Dict, Tuple, Set
import dataclasses
USE_PPO_ORDERED_SEEN: bool = True
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
 class RVWMOChecker:

    def __init__(self, margin: int = 30000):
        self.margin = margin
        self.ses: Dict[int, List[StoreEvent]] = defaultdict(list)
        self.dag: Dict[int, DAGNode] = {}
        self.taint: Dict[int, Set[int]] = defaultdict(set)
        self.seen: Dict[tuple, Dict[tuple, int]] = \
            defaultdict(lambda: defaultdict(int))
        self.seen_at_load: Dict[int, Dict[tuple, int]] = {}
        self.ppo_pred_loads: Dict[int, List[int]] = defaultdict(list)
        self.last_event:     Dict[tuple, object] = {}
        self.recent_stores:  Dict[tuple, List]   = defaultdict(list)
        self.recent_loads:   Dict[tuple, List]   = defaultdict(list)
        self.order_counter: int = 0
        self.event_count:   int = 0
        self.violations:    List[str] = []
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
    def _ppo_ordered_seen(self, hart: tuple,
                          current_load: LoadEvent) -> Dict[tuple, int]:

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
    def process_store(self, hart: tuple, address: int,
                      value: int, mask: int,
                      addr_reg: int, data_reg: int,
                      cycle: int):
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
    def process_load(self, hart: tuple, address: int,
                     value: int, mask: int,
                     addr_reg: int, dst_reg: int,
                     cycle: int):

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
        if USE_PPO_ORDERED_SEEN:
            current_seen = self._ppo_ordered_seen(hart, load)
        else:
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
    def search_rf_and_co(self, load: LoadEvent,
                         candidates: List[StoreEvent],
                         seen: Dict) -> Optional[SearchResult]:

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
    def _compute_temp_edges(self,
                            load:        LoadEvent,
                            rf_source:   StoreEvent,
                            co_ordering: List[StoreEvent]
                            ) -> List[Tuple[int, int, str]]:
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
    def process_fence(self, hart: tuple, fence_type: str, cycle: int):
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
    def qualifies_ppo(self, prev, curr) -> bool:
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
    def process_amo(self, hart: tuple, address: int,
                    read_value: int, write_value: int,
                    mask: int, addr_reg: int,
                    data_reg: int, dst_reg: int,
                    cycle: int):
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
    def prune(self, current_cycle: int):
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
    def check_cycles(self):
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
