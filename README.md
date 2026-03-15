


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





