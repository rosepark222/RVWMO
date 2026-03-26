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
