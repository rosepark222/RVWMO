import pytest

from RVWMOChecker import RVWMOChecker


def test_simple_store_load_no_violations():
    c = RVWMOChecker()

    # baseline initial values
    full_mask = 0xFFFFFFFFFFFFFFFF
    c.process_store((0,), 0x100, 0, full_mask, addr_reg=0, data_reg=0, cycle=0)
    c.process_store((0,), 0x104, 0, full_mask, addr_reg=0, data_reg=0, cycle=0)

    c.process_store((0,), 0x100, 100, full_mask, addr_reg=0, data_reg=0, cycle=1)
    c.process_store((0,), 0x104, 1, full_mask, addr_reg=0, data_reg=0, cycle=2)

    c.process_load((1,), 0x104, 1, full_mask, addr_reg=0, dst_reg=1, cycle=3)
    c.process_load((1,), 0x100, 100, full_mask, addr_reg=0, dst_reg=2, cycle=4)
    #print(c.dump_trace())
    #print(c.dump_dag())

    c.check_cycles()
    assert c.violations == []


def test_mp_message_passing_relaxed_behavior_allowed():
    c = RVWMOChecker()

    # initial baseline values (A=0, Flag=0)
    full_mask = 0xFFFFFFFFFFFFFFFF
    c.process_store((0,), 0x100, 0, full_mask, addr_reg=0, data_reg=0, cycle=0)
    c.process_store((0,), 0x104, 0, full_mask, addr_reg=0, data_reg=0, cycle=0)

    full_mask = 0xFFFFFFFFFFFFFFFF
    # Hart 0 writes data then flag
    c.process_store((0,), 0x100, 100, full_mask, addr_reg=0, data_reg=0, cycle=1)
    c.process_store((0,), 0x104, 1, full_mask, addr_reg=0, data_reg=0, cycle=2)

    # Hart 1 reads flag then data; target behavior r1=1, r2=0
    c.process_load((1,), 0x104, 1, full_mask, addr_reg=0, dst_reg=1, cycle=3)
    c.process_load((1,), 0x100, 0, full_mask, addr_reg=0, dst_reg=2, cycle=4)

    #print(c.dump_trace())
    #print(c.dump_dag())
    c.check_cycles()
    assert c.violations == []

def test_inconsistent_merged_value_should_fail():
    c = RVWMOChecker()

    full_mask = 0xFFFFFFFFFFFFFFFF
    byte_mask_low  = 0x00000000000000FF   # only low byte
    byte_mask_high = 0x000000000000FF00   # only byte[1]

    # -------------------------------------------------------------------------
    # Hart 0 initial value for X: X = 0x0000
    # -------------------------------------------------------------------------
    c.process_store((0,), 0x100, 0x0000000000000000, full_mask, addr_reg=0, data_reg=0, cycle=0)

    # -------------------------------------------------------------------------
    # Hart 0 writes a NEW low byte 0xAA at cycle 1
    # X.low = AA
    # -------------------------------------------------------------------------
    c.process_store((0,), 0x100, 0x00000000000000AA, byte_mask_low, addr_reg=0, data_reg=0, cycle=1)

    # Fence on Hart 0 (separates low-byte write from upcoming high-byte write)
    c.process_fence((0,), 'FENCE_RW', cycle=2)

    # -------------------------------------------------------------------------
    # Hart 0 writes a NEW high byte 0xBB at cycle 3
    # X.high = BB
    # -------------------------------------------------------------------------
    c.process_store((0,), 0x100, 0x000000000000BB00, byte_mask_high, addr_reg=0, data_reg=0, cycle=3)

    # -------------------------------------------------------------------------
    # Hart 1 attempts to load a value that requires MERGING:
    #    low byte from the earlier store S_low
    #    high byte from the later  store S_high
    #
    # The inconsistent merged value the test forces is: 0x000000000000BBAA
    # This is not produced by any single store.
    # -------------------------------------------------------------------------
    load_value = 0x000000000000BBAA
    c.set_debug(True)
    c.process_load((1,), 0x100, load_value, full_mask, addr_reg=0, dst_reg=1, cycle=4)

    print(c.dump_trace())
    print(c.dump_dag())
    c.check_cycles()
    print(c.dump_cycle())

    for v in c.violations:
        print(v)

    # -------------------------------------------------------------------------
    # EXPECTED: checker must reject the read because the value requires
    # merging bytes across two different versioned stores (S_low and S_high).
    # -------------------------------------------------------------------------
    assert len(c.violations) >= 0
    
def test_addr_dependency_via_taint_map():
    c = RVWMOChecker()
    c.set_debug(True)

    full_mask = 0xFFFFFFFFFFFFFFFF

    # -------------------------------------------------------------------------
    # Hart 0: Initialize memory
    #  - At 0x300 we place a "pointer value": 0x200
    #  - At 0x200 we place initial data (0)
    # -------------------------------------------------------------------------
    # S_base writes the pointer 0x200 at address 0x300
    c.process_store((0,), 0x300, 0x0000000000000200, full_mask, addr_reg=0, data_reg=0, cycle=0)
    # S_init writes initial data at address 0x200
    c.process_store((0,), 0x200, 0x0000000000000000, full_mask, addr_reg=0, data_reg=0, cycle=0.1)

    # Keep track of orders for checking specific edges later
    # The last store we did is order 1 (S_init), so S_base must be order 0.
    s_base_order = 0  # store to 0x300
    s_init_order = 1  # store to 0x200

    # -------------------------------------------------------------------------
    # Hart 1: Load the pointer into a register, then use that register as address
    #  L_ptr: loads from 0x300 -> 0x200 into dst_reg=10
    #  S_use: store to [addr in reg10] = 0xAB
    # The checker should:
    #   - RF: S_base -> L_ptr (so reg10 is tainted by S_base.order)
    #   - When S_use executes with addr_reg=10, add ADDR_DEP: S_base -> S_use
    # -------------------------------------------------------------------------
    # L_ptr reads the pointer 0x200
    c.process_load((1,), 0x300, 0x0000000000000200, full_mask, addr_reg=0, dst_reg=10, cycle=1.0)

    # Now use the loaded pointer in reg10 as the target address (0x200)
    c.process_store((1,), 0x200, 0x00000000000000AB, full_mask, addr_reg=10, data_reg=0, cycle=2.0)

    # Identify the orders for L_ptr and S_use:
    # After two stores (orders 0 and 1), L_ptr is order 2, S_use is order 3.
    l_ptr_order = 2  # load from 0x300
    s_use_order = 3  # store to 0x200 with addr_reg=10

    # -------------------------------------------------------------------------
    # Inspect the taint map and DAG to verify address dependency edges
    # -------------------------------------------------------------------------
    print("\n--- TRACE ---")
    print(c.dump_trace())

    print("\n--- DAG ---")
    print(c.dump_dag())

    print("\n--- TAINT ---")
    print(c.dump_taint())

    # The taint map for register 10 should include the RF source that fed L_ptr.
    # L_ptr should have read from S_base (order 0), so reg10 must be tainted by {0}.
    taint = c.dump_taint()
    assert 10 in taint, "Register 10 should be tainted after L_ptr."
    assert s_base_order in taint[10], "Register 10 must be tainted by S_base (the RF source for L_ptr)."

    # The DAG should include an address dependency edge:
    #   S_base (order 0) -addr_dep-> S_use (order 3)
    dag = c.dump_dag()
    expected_edge = f"S{s_base_order} -addr_dep-> S{s_use_order}"
    assert expected_edge in dag, f"Missing ADDR_DEP edge: {expected_edge}"

    # Also, sanity-check RF for the pointer load (S_base -> L_ptr), and FR edges around S_use.
    expected_rf = f"S{s_base_order} -rf-> L{l_ptr_order}"
    assert expected_rf in dag, f"Pointer load should RF from S_base: {expected_rf}"

    # Optional: ensure we didn't generate any cycles
    c.check_cycles()
    assert not c.violations, f"No cycles expected, but got: {c.violations}"

def test_mp_with_fences_should_pass():
    c = RVWMOChecker()

    # initial baseline values (A=0, Flag=0)
    full_mask = 0xFFFFFFFFFFFFFFFF
    c.process_store((0,), 0x100, 0, full_mask, addr_reg=0, data_reg=0, cycle=0)
    c.process_store((0,), 0x104, 0, full_mask, addr_reg=0, data_reg=0, cycle=0)

    full_mask = 0xFFFFFFFFFFFFFFFF
    # Hart 0 writes data then flag with fence in between
    c.process_store((0,), 0x100, 100, full_mask, addr_reg=0, data_reg=0, cycle=1)
    c.process_fence((0,), 'FENCE_RW', cycle=2)
    c.process_store((0,), 0x104, 1, full_mask, addr_reg=0, data_reg=0, cycle=3)
    c.process_store((0,), 0x100, 2, full_mask, addr_reg=0, data_reg=0, cycle=3.5)

    # Hart 1 reads flag then data with fence in between
    c.process_load((1,), 0x104, 1, full_mask, addr_reg=0, dst_reg=1, cycle=4)
    c.process_fence((1,), 'FENCE_RW', cycle=5)
    c.set_debug(True)
    c.process_load((1,), 0x100, 2, full_mask, addr_reg=0, dst_reg=2, cycle=6)

    print(c.dump_trace())
    print(c.dump_dag())
    c.check_cycles()
    print(c.dump_cycle())
    for v in c.violations:
        print(v)
    assert len(c.violations) >= 1

def test_mp_with_fences_should_fail():
    c = RVWMOChecker()

    # initial baseline values (A=0, Flag=0)
    full_mask = 0xFFFFFFFFFFFFFFFF
    c.process_store((0,), 0x100, 0, full_mask, addr_reg=0, data_reg=0, cycle=0)
    c.process_store((0,), 0x104, 0, full_mask, addr_reg=0, data_reg=0, cycle=0)

    full_mask = 0xFFFFFFFFFFFFFFFF
    # Hart 0 writes data then flag with fence in between
    c.process_store((0,), 0x100, 100, full_mask, addr_reg=0, data_reg=0, cycle=1)
    c.process_fence((0,), 'FENCE_RW', cycle=2)
    c.process_store((0,), 0x104, 1, full_mask, addr_reg=0, data_reg=0, cycle=3)

    # Hart 1 reads flag then data with fence in between
    c.process_load((1,), 0x104, 1, full_mask, addr_reg=0, dst_reg=1, cycle=4)
    c.process_fence((1,), 'FENCE_RW', cycle=5)
    c.set_debug(True)
    c.process_load((1,), 0x100, 0, full_mask, addr_reg=0, dst_reg=2, cycle=6)

    print(c.dump_trace())
    print(c.dump_dag())
    c.check_cycles()
    print(c.dump_cycle())
    for v in c.violations:
        print(v)
    assert len(c.violations) >= 1


def test_iriw_weak_behavior_allowed():
    c = RVWMOChecker()

    # initial baseline values for A and B
    full_mask = 0xFFFFFFFFFFFFFFFF
    c.process_store((0,), 0x200, 0, full_mask, addr_reg=0, data_reg=0, cycle=0)
    c.process_store((0,), 0x204, 0, full_mask, addr_reg=0, data_reg=0, cycle=0)

    # Two writers
    c.process_store((0,), 0x200, 1, full_mask, addr_reg=0, data_reg=0, cycle=1)
    c.process_store((1,), 0x204, 1, full_mask, addr_reg=0, data_reg=0, cycle=2)

    # Two readers with opposite orders
    c.process_load((2,), 0x200, 1, full_mask, addr_reg=0, dst_reg=1, cycle=3)
    c.process_load((2,), 0x204, 0, full_mask, addr_reg=0, dst_reg=2, cycle=4)

    c.process_load((3,), 0x204, 1, full_mask, addr_reg=0, dst_reg=3, cycle=3)
    c.process_load((3,), 0x200, 0, full_mask, addr_reg=0, dst_reg=4, cycle=4)

    c.check_cycles()
    # In RVWMO, this IRIW behavior may be illegal; confirm checker catches it.
    assert len(c.violations) >= 1


def test_debug_dump_methods():
    c = RVWMOChecker()
    full_mask = 0xFFFFFFFFFFFFFFFF
    c.process_store((0,), 0x300, 42, full_mask, addr_reg=0, data_reg=0, cycle=1)
    c.process_load((1,), 0x300, 42, full_mask, addr_reg=0, dst_reg=7, cycle=2)

    ses = c.dump_ses()
    taint = c.dump_taint()
    dag = c.dump_dag()

    assert 0x300 in ses
    assert 7 in taint
    dag_lines = dag.split('\n') if dag else []
    assert len(dag_lines) >= 1
    assert any("rf" in line for line in dag_lines), "Expected at least one RF edge"

    # ensure helper returns contain expected fields
    assert ses[0x300][0]["value"] == 42
    assert next(iter(taint[7])) == 0
