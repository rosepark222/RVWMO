------------------------------------------------------------------------------------------

https://lucid.app/lucidspark/eb41369c-1c54-4c7c-9c79-e20132c4a38d/edit?invitationId=inv_2230bfad-7aea-4d5e-85d6-a617e3b790b3&page=0_0#

------------------------------------------------------------------------------------------
------------------------------------------------------------------------------------------
------------------------------------------------------------------------------------------
How single RF source limitation affects in real chip design -- 4 cores having L1 cache of 64byte line. I am sure  multiple stores should be merged to explain load in general. However, what is the likelihood of that happening ? And also, would it trigger a false failure because not finding rf ?  
Copilot said:
Copilot

Reasoning completed in 3 steps
Great question. Let’s separate architecture-level rules from microarchitecture reality, and then talk about how a single‑RF‑source checker can impact your verification and how likely it is to miss “real” behaviors on a 4‑core chip with 64‑byte L1 lines.

1) Architecture vs. implementation
RVWMO (the RISC‑V memory model) defines what values a load is allowed to return. Critically, the Load‑Value rule is byte‑granular: each byte of a load must be the value written by the latest store to that byte (in the chosen execution). At the model level, this means a load may legally return a value whose bytes came from different stores, if those stores wrote different bytes.

Real hardware doesn’t move bytes around one‑by‑one during a load. In a coherent cache hierarchy, a load returns data from one cache line state (a 64‑byte line in your setup). That line state is the result of the protocol’s serialization of stores (from all cores) into the line: by the time the line resides in the load’s L1 (or is filled from L2/LLC), the line already embodies the latest per‑byte values. In other words, the line you read may already be a merge of multiple prior stores at different byte offsets—but the load itself still reads one line snapshot.

Implication: At the memory‑model level, a load that returns a “merged” value is normal and legal. At the microarchitectural level, that merged value typically arises because the line was updated by multiple stores (possibly at different times) and coherence presented a single, latest snapshot when the load executed.

2) How often would a single load need “multi‑store merging”?
Two distinct contexts:

A) Same core (store buffer + forwarding)
If your own core just performed multiple stores (possibly partial/byte stores) to disjoint bytes and then does a load, the load usually forwards from the store buffer (or sees the line that already reflects those writes). The forwarding/merge happens inside the core; the load still logically reads one source (the forward/buffer or the line).
This scenario is common, but it generally doesn’t challenge the “single RF source” in a checker if your checker treats store‑buffer forwarding as “the latest single store” (or as a synthetic combined write before the load).
B) Different cores writing different bytes of the same word
This is the “multi‑store merge” that worries you: Core 0 writes byte 0; Core 1 writes byte 1; a later load reads two bytes that were produced by two different cores.
In correctly synchronized programs, this is rare. Multi‑core code almost always protects such updates with locks, atomics (AMO/LR/SC), or ensures alignment/full‑word stores. Two cores independently writing sub‑word slices of the same word without synchronization is typically a data race and outside language‑level guarantees, so production code avoids it.
In OS/device/driver code, byte/half‑word flags exist, but loads are usually of the same size (byte load for a byte flag). Full‑width loads of words assembled from multiple unrelated byte stores are uncommon on the hot path.
Bottom line on likelihood: In real workloads, a single load that requires a logical merge of different cores’ separate sub‑word stores to “explain” its observed value is uncommon, and when it happens it’s usually a racy pattern that higher‑level software rules discourage. In microbenchmarks/litmus tests, however, we deliberately craft such patterns—so you’ll see them there.

3. How often does this happen in real workloads?
✅ In normal production code:
EXTREMELY RARE.
Why?
Because programmers almost always use:

full‑word loads/stores,
atomic instructions (AMOs, LR/SC),
aligned accesses,
language‑level synchronization,
proper mutual exclusion.

It is practically unheard‑of in well‑written kernel/user code to have:

core 0 writing byte 0 of a word,
core 1 writing byte 1,
core 2 writing byte 2,
core 3 reading the entire 64‑bit word…

except in litmus tests and stress tests.
✅ Where it does happen:

Racy test kernels
Microbenchmarks
Coherence validation tests
Randomized stress generators
Edge cases in drivers manipulating flags/bitfields

✅ In real production workloads:
The chance is close to zero because it's typically a data race.


------------------------------------------------------------------------------------------
can you describe how search_rf_and_co works in detail? Does it search for rf and then co one by one or search the entire combination of rf and co ? 

Absolutely. I’ll walk you through how search_rf_and_co works in your checker, in plain terms and then in precise, code-level steps—so it’s clear what it searches, when it picks an RF (reads‑from) source, how it builds a CO (coherence order) consistent with that RF choice, and where cycle checks and ‘seen’ pruning apply.

Short answer:
search_rf_and_co does not first fix RF and then compute CO in a separate pass.
Instead, it jointly explores RF choices and CO placements in a single backtracking search. The recursion tries candidate stores, incrementally builds a partial CO for “diff‑hart” stores at the same address, and only accepts an RF choice if there exists some CO placement that avoids cycles and matches the load’s value/mask constraints.

Big-picture mental model
Think of the problem it must solve for one load L at address A:

There are several stores to A from possibly multiple harts (same hart and different harts).
The checker doesn’t know the final global memory order (GMO) of those different-hart stores yet (stores from one hart have program order constraints, but inter‑hart order is not predetermined).
To decide which store S L can legally read from, it must find a consistent CO order among those stores such that:
Value matches what L observed under the mask,
No RF/FR/PPO/CO cycle is created, and
Any active seen/strict_seen pruning isn’t violated.
Hence the search must consider RF and CO together.

Where the search starts — process_load()
When a load arrives:

It collects candidates = all stores to the same address from the SES (store event set).
It computes seen for the load’s hart (either PPO-ordered seen or global seen depending on your configuration).
It calls:



Python
result = self.search_rf_and_co(load, candidates, seen, strict_seen=...)
where strict_seen is True only if you decided to model “fence-before-load” as a visibility guard (note: you concluded you don’t want that for MP tests).
If result is not None, process_load() then commits:

the chosen RF edge(s),
the corresponding FR edges from the load to later stores for the same address,
and updates seen, taint, etc.
What search_rf_and_co does
At a high level, it:

Normalizes the load value to 64 bits (load_value, tbd = _align_value(...)).
Splits stores into:
same-hart (already ordered by program order → some CO edges already exist),
diff-hart (order unknown; must be searched).
Applies a cheap pre-filter on diff-hart candidates by mask/value compatibility (so the recursive search won’t explode on obviously incompatible stores).
Sorts diff‑hart candidates by a most-constraining-first heuristic (e.g., wider mask first) to prune early.
Calls the recursive engine:



Python
return self._search_recursive(
    load=load,
    load_value=load_value,
    tbd=tbd,                       # “to be determined” bits of the load still unresolved
    partial_co=same_hart.copy(),   # initial CO chain seeded by same-hart order
    unplaced=diff_hart.copy(),     # diff-hart stores to place into CO
    seen=seen,
    rf_source=None,                # (single-store mode) becomes the chosen RF store
    strict_seen=strict_seen
)
This is where RF and CO are explored together.
The recursive engine — _search_recursive(...)
This is the heart of the joint search:

State it maintains
partial_co: an ordered list of stores (all same‑hart stores + any diff‑hart stores already placed in this path of the search). This is an in-progress CO proposal for the address.
unplaced: remaining diff‑hart stores that have yet to be placed into partial_co (they’ll be tried in various positions implicitly by the recursion).
tbd: a 64-bit mask of bits in the load value that are still not proven to come from the chosen RF store (in single‑store mode: tbd must become 0 when the RF store is selected).
rf_source: the current chosen single store that provides all bits (under its mask) for the load (in single‑store mode).
In single‑store mode, once you pick a store whose (load_value ^ store.value) & store.mask == 0, you can set rf_source = store and clear those bits from tbd (i.e., tbd &= ~store.mask). For a fully masked load your tbd goes to 0 immediately.

The control flow
Base case: if there are no unplaced diff‑hart stores left:

Check tbd == 0 (single‑store mode) → the chosen RF completely matches the load value.
If strict_seen is enabled and you model it, verify the RF is not “newer than seen”.
Build temporary edges for cycle detection:
One RF edge from the rf_store to the load.
All needed FR edges from the load to any later stores to this address (later according to the in-progress CO).
Call _creates_cycle(temp_edges):
Temporarily inserts those RF/FR edges into the DAG, runs DFS/Tarjan from affected nodes; if a cycle is found, reject this RF/CO arrangement; else accept.
If accepted, compute the new seen map (_compute_new_seen(...)):
seen[load_hart][rf_source.hart] = max(previous, rf_source.order).
Return a SearchResult with that single rf_source and the updated new_seen.
Recursive case: still have unplaced diff‑hart stores:

Iterate each candidate store in unplaced (order often chosen by heuristics).
Same-hart PO check: If placing this store would break same-hart program order relative to any already-placed same-hart stores in partial_co, skip it.
Value/mask test:



Python
contribution = (load_value ^ store.value) & tbd & store.mask
value_matches = (contribution == 0) and bool(tbd & store.mask)
In single‑store mode, you only “set” rf_source = store when value_matches and the store’s mask covers the load’s relevant bits (for a fully-masked 64-bit load, that’s the whole word).
Seen-based pruning (optional): If you kept strict_seen, you may reject stores that are “newer than seen” (you now decided to disable this for MP).
Form the next state:
new_partial_co = partial_co + [store]
new_unplaced = unplaced minus store
new_rf_source = store if value_matches and you haven’t chosen RF yet; otherwise keep the current one.
Also: new_tbd = tbd & ~store.mask if you just chose this store as the RF source; otherwise unchanged.
Recurse into _search_recursive with the next state.
If any recursion returns a valid SearchResult, bubble it up immediately (the search is existential: it just needs one consistent CO ordering for the chosen RF).
Key point: by placing diff‑hart stores into partial_co while you try potential RF candidates, you are implicitly searching CO at the same time as you search for an RF that makes the load value legal. That’s why this algorithm is a joint RF+CO search, not a sequential one.

Where cycles are ruled out
Cycle detection happens only in the base case, when the branch has fully placed (or skipped) all diff‑hart stores and you have a candidate RF and a complete proposed CO for the address.

The search constructs temporary RF+FR edges, inserts them into the DAG, runs DFS/Tarjan starting from the edge sources, and then rolls back the temporary edges.
If a cycle is detected (e.g., your classic S0 → FR → S2 → … → L → … → back to L pattern), that RF/CO path is rejected, and the recursion backtracks to try alternate placements/RF choices.
This is precisely how your MP example rejects RF = S0 and accepts RF = S5 when you disabled the strict_seen pruning.

What “seen” and “strict_seen” do (and don’t)
seen is a per‑hart dictionary capturing the latest store order the load’s hart has “already observed” from each source hart due to earlier loads. It’s used for two things:

Pruning: drop candidate placements that can’t possibly be made consistent with previously observed ordering info.
Updating: once you choose an RF store from hart H0, your seen[H1][H0] may advance to that store’s order.
strict_seen (if you keep it) is a local checker policy that says:

“If the previous event on this hart is a fence that we treat as acquire-like, do not allow the next load to read a store that is newer than what we’ve already seen from that other hart.”

You already determined you do not want this in your MP tests; set it to False so it won’t reject S5.

RVWMO point: Standard RISC‑V fences (FENCE.R/FENCE.RW) do not impose cross‑hart visibility; they only constrain intra‑hart ordering. Your cycle detector already enforces the real global consistency; you don’t need strict_seen to “protect” loads.

Putting it all together on your example
For the final MP case you posted:

Hart 0: S2(x=100) → F3 → S4(y=1) → S5(x=2)
Hart 1: L6(y=1) → F7 → L8(x=?)
The search tries RF = S0: CO placement + RF/FR edges → cycle → reject.
It tries RF = S2: value mismatch (L8 wants 2, S2 wrote 100) → reject.
It tries RF = S5: value matches; temp RF/FR edges + proposed CO produce no cycle → accept.
new_seen[(1,)][(0,)] advances to order(S5).
This is exactly what your current algorithm is supposed to do once you set strict_seen=False for this load.

Practical debugging checklist
Before search: print candidates, seen, and whether strict_seen is on.
During recursion:
Log each store tried, whether value_matches, and the new tbd.
Log partial_co contents on each recursive level.
At base case:
Print chosen RF store, tbd, and the set of temp edges (RF/FR).
If a cycle is detected, dump the discovered SCC path.
This makes it immediate to see why a candidate is rejected: value mismatch, seen pruning, or cycle.

TL;DR
Does search_rf_and_co search RF first and then CO?
No. It jointly explores both.
It builds a partial CO while considering potential RF candidates.
At the base case, it performs cycle detection on the hypothetical RF/FR edges with that CO.
If no cycle and value matches → success. Otherwise → backtrack.
strict_seen is optional pruning; for MP tests, it should be off (or ignored).
If you want, I can instrument your current file with a verbose trace (one toggle) that prints the exact partial CO chain and the temporary RF/FR edges each time a base case is hit—that makes following the search crystal clear.

-------------------------------------------------------------------------------------------------------------

-------------------------------------------------------------------------------------------------------------

v3 fix:

question:
In the below trace, L23 and L19 does not have a dependency thus, they can be reordered in RVWMO. How does process_load function handles the case L23 floats before L19 ? 

# 79217:  H(2:3:0)  S3: ST   [PA=...12828] = ...6f8ef337      o3
# 79227:  H(2:3:0)  S5:  ST  [PA=...12828]  = ...a063            o5
# 79293:  H(2:3:0)  S12: ST  [PA=...4028]   = ...5244            o12
# 79347:  H(2:1:1)  L19: LD  [PA=...4028]   -> ...5244   
# 79395:  H(2:1:1)  L23: LD  [PA=...12828]  -> ...6f8ef337

answer:
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

solution:
Here is a summary of everything in v3:
The switch is the single line at the top:
pythonUSE_PPO_ORDERED_SEEN: bool = True   # v3 fix
USE_PPO_ORDERED_SEEN: bool = False  # v2 behaviour
The fix lives in two places. First, process_load() selects the seen map based on the flag — either _ppo_ordered_seen() (v3) or dict(self.seen[hart]) (v2). Second, _ppo_ordered_seen() is the new function that walks ppo_pred_loads backwards from the current load, accumulates only seen contributions from PPO-ordered predecessors, and excludes everything else.
Two new bookkeeping structures were added to support the fix: seen_at_load[load.order] records what each individual load contributed to the seen map, and ppo_pred_loads[load.order] records which prior loads have a PPO edge into each load — enabling the backward walk in _ppo_ordered_seen().
The __main__ block runs the exact bug trace twice — once with False (produces the false violation) and once with True (correctly passes) — and prints the expected outcome for each.
  
-------------------------------------------------------------------------------------------------------------

v2 has the answer to this question:

def _search_recursive(self, load: LoadEvent,
                          load_value: int,
                          tbd: int,
                          partial_co: List[StoreEvent],
                          unplaced: List[StoreEvent],
                          seen: Dict,
                          rf_source: Optional[StoreEvent],
                          best_result: Optional[SearchResult]
                          ) -> Optional[SearchResult]:
        """
        Recursively place unplaced diff-hart stores into partial_co,
        trying every possible position (permutation via recursion).
        At each level:
          Pick one unplaced store and append it to partial_co
          (making it the current latest store in co ordering).
          Apply three pruning checks before recursing.
          Recurse on remaining unplaced stores.
          If valid result found, merge seen map (take minimum).

In the above _search_recursive , how do we know if the DAG having candidate co is valid without running entire tarjan search ?

answer:

The problem:
_search_recursive() tries co orderings.
Each co ordering produces different fr edges.
Different fr edges may or may not create cycles.

To know if a co ordering is valid:
  We need to know if it creates a cycle.
  To know if it creates a cycle:
  We need to run Tarjan on the full DAG
  with those co+fr edges included.

But running Tarjan inside every recursive
branch is extremely expensive:
  O(V+E) per Tarjan run.
  N! co orderings to try.
  Total: N! × O(V+E) per load event.
  Completely intractable.

So what does _search_recursive() actually check?

The solutions:
Option 1: Current approach (commit first, check later).
  Accept risk of false violations from wrong co choice.
  Mitigate by: choosing co ordering that minimizes
  seen map (minimum seen = most conservative choice).
  In practice: most loads have only 1-2 candidates.
  K=1: no co ambiguity. No false violation risk.
  K=2: two orderings. May pick wrong one rarely.

Option 2: Defer fr edge commitment.
  Do not add fr edges from _search_recursive().
  Only add rf edge (determined by value match).
  Let Tarjan infer violations from rf+ppo alone.
  Problem: fr edges are essential for cycle detection.
  Without fr: many violations undetectable.

Option 3: Run lightweight cycle check per co candidate.
  Before committing co ordering:
    Temporarily add co+fr edges to DAG.
    Run DFS from affected nodes only (not full Tarjan).
    Check if any cycle forms locally.
    If cycle: try next co ordering.
    If no cycle: commit.
  Cost: O(depth × K!) per load.
        Depth = max path length from affected nodes.
        Tractable if depth is small.
  This is the most correct practical approach.

Option 4: Full offline checking.
  Collect complete trace.
  Try ALL global co assignments.
  Run Tarjan on each.
  Exponential but exact.
  Only for small traces or verification.


The complete v2 file is ready. Here is a summary of what changed from v1 and where each piece lives:
New functions added:
_compute_temp_edges() — computes the rf + fr edges that would be committed for a given co ordering, without touching the DAG yet.
_creates_cycle() — temporarily adds those edges, runs lightweight DFS from the affected source nodes only, removes them regardless of result.
_dfs_has_cycle() — iterative DFS back-edge detection, avoids Python recursion limits, O(D) where D is the reachable subgraph depth.
Where the fix lands in _search_recursive() — at the base case only (when unplaced is empty), before merging into best_result. If the DFS finds a cycle, that co ordering is silently rejected and backtracking continues to try the next permutation.
The issue/solution/options commentary is inside _search_recursive()'s docstring under the labels ISSUE ADDRESSED HERE, SOLUTION, and OTHER OPTIONS CONSIDERED, so it is co-located with the code it describes.





------------------------------------------------------------------------------------------
Sorts diff‑hart candidates by a most-constraining-first heuristic (e.g., wider mask first) to prune early.

explain this with examples.
Copilot said:
Copilot
Absolutely — this is an important part of why your checker’s CO‑search doesn’t blow up combinatorially.
Let me explain the “most‑constraining‑first heuristic” precisely, and show why masks matter and why the ordering matters, with simple examples.

store value       mask                     meaning
S1    0x000000AA  0xFF                     writes only low byte
S2    0xBB000000  0xFF000000               writes only byte[3]
S3    0x44556677  0xFFFFFFFFFFFFFFFF       writes full 64 bits


Load wants:
L → 0x1122334455667788

If you try S1 first:

S1 matches only 1 byte (0xAA vs 0x88 mismatch → immediate fail).
But the recursive search continues:
you now try S2, S3, etc.
tbd mostly unchanged → still lots of unresolved bits.
Long search path.

If you try S3 first (wide mask):

(load_value ^ S3.value) & S3.mask almost certainly ≠ 0
→ immediate mismatch
→ branch pruned.

This skips many recursive paths.

✅ Example 2 — Tiny masks cause search explosion if not ordered last
Imagine 5 diff‑hart stores:
S1 writes only byte 0
S2 writes only byte 1
S3 writes only byte 2
S4 writes only byte 3
S5 writes only byte 4

If you try them in arbitrary order:

For each store, tbd reduces only 8 bits.
The recursion depth goes up, because each store still leaves many unresolved bits.
The search size grows factorially (O(k!)).

If you have even 6–8 such stores, search explodes.
But if mask sizes differ (or if some have more bytes), trying the larger‑mask ones first reduces the number of unresolved bits quickly and prunes dead branches early.
------------------------------------------------------------------------------------------

    full_mask = 0xFFFFFFFFFFFFFFFF
    load_value = 0x000000000000BBAA
 
    c.process_load((1,), 0x100, load_value, full_mask, addr_reg=0, dst_reg=1, cycle=4)

for this load, ordered stores should explain 0x000000000000BBAA or 0xBBAA ? 

Q: Do stores need to explain 0x000000000000BBAA or just 0xBBAA?
✅ They must explain the full 64‑bit value 0x000000000000BBAA
because your checker always aligns the load to 8 bytes and full_mask is 64 bits.
Q: Why is merging relevant?
Because only S1 explains byte 0, only S3 explains byte 1, and no store writes bytes 2–7 (so fallback uses the initial value).
Q: Is this correct for real hardware?
Yes — the core reads one 64‑byte cache line, which may contain bytes written by different stores. Architecturally, the load returns the merged 64‑bit word.
------------------------------------------------------------------------------------------

Absolutely—here’s a self‑contained pytest-style test that demonstrates how the taint map drives address-dependency edges in your checker.
What this test shows

Hart 0 writes a pointer/base (value 0x200) into memory at 0x300.
Hart 1 loads that pointer from 0x300 into register 10 (dst_reg=10).
Your checker taints reg 10 with the RF source store that supplied the pointer.
Hart 1 then executes a store to address 0x200 with addr_reg=10.
The checker recognizes the register is tainted → it adds an ADDR_DEP edge from the RF source store (that defined the pointer) to this new store.
The test asserts that the ADDR_DEP edge is present and inspects the taint map and DAG.


This isolates and proves the intended behavior of:
Pythonfor t in self.taint.get(addr_reg, set()):    self._add_edge(t, store.order, ADDR_DEP)Show more lines

 
What to look for in the debug / DAG


Taint:
Python{ 10: { 0 } }Show more lines
Meaning reg 10 is tainted by order 0 (S_base), the RF source of L_ptr.


Key DAG edges:

S0 -rf-> L2  (S_base to L_ptr)
S0 -addr_dep-> S3  (address dependency from pointer‑defining store to the address‑using store)
Standard PPO edges from same‑hart sequencing as applicable.




Why this proves the address dependency via taint


When process_load completes, your checker sets:
Pythonself.taint[dst_reg] = {rf_source.order}Show more lines
So the RF source that fed the load becomes the taint origin for that destination register.


Later, when a store (or load) uses addr_reg=<that register>, the checker links:
Pythonfor t in self.taint.get(addr_reg, set()):    self._add_edge(t, store.order, ADDR_DEP)Show more lines
Thus, the address dependency is captured through the taint map, yielding:
S_base →addr_dep→ S_use



If you’d like, I can add a second half to the test that demonstrates address dependency into a load (i.e., tainted register driving process_load(..., addr_reg=10, ...)), which would add an ADDR_DEP edge from the taint origin to the later load as well.

------------------------------------------------------------------------------------------

4/2/2026
1, Refactor load processing logic to clarify strict seen conditions and improve handling of RF and FR edges. 
2, Implement fallback merge-aware logic for load value explanation when single-store RF search fails.this fallback is needed because the load value may be the result of merge of multiple smaller stores. How likely that would be is debatable. 
3, However, how robust this fallback logic or how this fallback work is not studied or verified.
4, For unit test, Adjust assertion in test for expected violations and add new test for address dependency via taint map.

------------------------------------------------------------------------------------------
------------------------------------------------------------------------------------------
------------------------------------------------------------------------------------------
------------------------------------------------------------------------------------------
------------------------------------------------------------------------------------------
------------------------------------------------------------------------------------------
------------------------------------------------------------------------------------------
------------------------------------------------------------------------------------------
------------------------------------------------------------------------------------------
------------------------------------------------------------------------------------------
------------------------------------------------------------------------------------------
------------------------------------------------------------------------------------------
------------------------------------------------------------------------------------------
------------------------------------------------------------------------------------------
------------------------------------------------------------------------------------------
------------------------------------------------------------------------------------------
------------------------------------------------------------------------------------------