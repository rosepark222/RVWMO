
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
