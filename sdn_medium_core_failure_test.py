#!/usr/bin/env python3
# sdn_medium_core_failure_test.py - CT/2020/087 R.M.K.K.Siriwardhana
# SDN medium topology, whole core switch failure. Measures how long host to
# server traffic takes to re route onto the surviving core.


import threading
import time

from mininet.log import info

import measure_lib as ml
from sdn_campus_topo_v6 import (
    build_network, stop_network, WEBSRV_IP,
)

# Config
NUM_RUNS     = 3          # 3 runs per area (was 5) -- saves ~40% wall time
TCP_DURATION = 600
UDP_DURATION = 600
UDP_BW       = "0"
PING_COUNT   = 1000

RESTORE_SETTLE   = 12     # lowered; the health gate below does the real check
RESTORE_STEP_GAP = 3      # gap (s) between per-link restores -> no flush storm
HEAL_ROUNDS      = 6      # health-gate attempts before declaring the net broken
HEAL_PING_COUNT  = 4

WARMUP_COUNT    = 8
WARMUP_INTERVAL = 0.3
WARMUP_SETTLE   = 1.0

POLL_INTERVAL = ml.PING_INTERVAL
PRE_SECS      = 3
CONV_TIMEOUT  = 15
FAILOVER_WINDOW = PRE_SECS + CONV_TIMEOUT

OUTPUT_CSV = "sdn_medium_core_failure_results.csv"

# Every link core-sw1 owns (from sdn_campus_topo_v6.build_topology()).
CORE1_LINKS = [
    ("core-sw1", "core-sw2"),
    ("core-sw1", "area1-sw-A"), ("core-sw1", "area1-sw-B"),
    ("core-sw1", "area2-sw-A"), ("core-sw1", "area2-sw-B"),
    ("core-sw1", "area3-sw-A"), ("core-sw1", "area3-sw-B"),
    ("core-sw1", "acc-sw100"),
]

# One scenario per area; all fail the SAME whole-core set, only the source moves.
SCENARIOS = [
    {"name": "Core1-Down-Area1-to-Server", "src": "h10_1"},
    {"name": "Core1-Down-Area2-to-Server", "src": "h40_1"},
    {"name": "Core1-Down-Area3-to-Server", "src": "h70_1"},
]

METRIC_COLS = [
    "Convergence_Time_s", "Recovered", "Packets_Lost", "Resolution_s",
    "Cut_Verified",
    "NetHealthy_PreCut", "NetHealthy_PostRestore",   # controller-fault diagnostics
    "Latency_ms", "Jitter_ms", "Throughput_Mbps", "PacketLoss_pct",
    "ControlPlane_CPU_pct", "ControlPlane_Mem_MB",
]
FIELDNAMES = ["Scenario", "Run"] + METRIC_COLS


def set_link(net, a, b, status):
    """Bring every link between nodes a and b up/down, at BOTH ends."""
    node_a, node_b = net.get(a), net.get(b)
    intfs = []
    for link in net.linksBetween(node_a, node_b):
        i1, i2 = link.intf1, link.intf2
        if getattr(i1.node, "name", "").startswith("core"):
            intfs.append(i2)
            intfs.append(i1)
        else:
            intfs.append(i1)
            intfs.append(i2)
    for intf in intfs:
        intf.ifconfig("down" if status == "down" else "up")


def cut_core1(net):
    """Fail core-sw1 entirely: drop every link it owns, back-to-back."""
    for a, b in CORE1_LINKS:
        set_link(net, a, b, "down")


def restore_core1(net, gap=RESTORE_STEP_GAP):
    """GENTLE restore:"""
    for a, b in CORE1_LINKS:
        set_link(net, a, b, "up")
        time.sleep(gap)


def _ping_ok(host, dst_ip, count=HEAL_PING_COUNT):
    out = host.cmd(f"ping -c {count} -W 1 {dst_ip}")
    return "0% packet loss" in out


def heal_gate(src, dst_host, dst_ip, rounds=HEAL_ROUNDS):
    """Verify src<->dst is fully reachable, re-warming BOTH directions each round to trigger any reinstall the controller still owes."""
    src_ip = src.IP()
    for _ in range(rounds):
        if _ping_ok(src, dst_ip):
            return True
        src.cmd(f"ping -c 2 -W 1 {dst_ip} > /dev/null 2>&1")
        if dst_host is not None and src_ip and src_ip.startswith("10.10."):
            dst_host.cmd(f"ping -c 2 -W 1 {src_ip} > /dev/null 2>&1")
        time.sleep(2)
    return _ping_ok(src, dst_ip)


def _rekey(row):
    row["Scenario"] = row.pop("Pair")
    return row


def run_once(net, pids, sc, dst_host, dst_ip):
    src = net.get(sc["src"])

    # 0. Ensure a HEALTHY starting state. If the previous run's restore left the
    #    net broken, try one full restore as a rescue, then re-check.
    pre_ok = heal_gate(src, dst_host, dst_ip)
    if not pre_ok:
        info("*** PRE-CUT net unhealthy -- full restore rescue attempt\n")
        restore_core1(net)
        time.sleep(RESTORE_SETTLE)
        pre_ok = heal_gate(src, dst_host, dst_ip)
        if not pre_ok:
            info("*** WARNING: net still unhealthy before cut -- controller did "
                 "NOT recover from the previous run (see NetHealthy_PreCut=0)\n")

    # 1. Warm the reverse path before the timed cut.
    src.cmd(f"ping -c {WARMUP_COUNT} -i {WARMUP_INTERVAL} -W 1 "
            f"{dst_ip} > /dev/null 2>&1")
    time.sleep(WARMUP_SETTLE)

    # 2. Timed whole-core failure + Phase-1 control-plane sample.
    cut_ok = {"ok": 0}
    fo = {}

    def _sample_failover():
        fo["cpu"], fo["mem"], fo["peak"] = \
            ml.sample_pids_usage(pids, FAILOVER_WINDOW)

    def fail_fn():
        cut_core1(net)
        ok, detail = ml.verify_links_down(net, CORE1_LINKS)
        cut_ok["ok"] = 1 if ok else 0
        if not ok:
            info(f"*** WARNING: core-sw1 cut NOT fully verified ({detail})\n")

    fo_thread = threading.Thread(target=_sample_failover)
    fo_thread.start()
    conv, recovered, lost = ml.measure_convergence(
        src, dst_ip, fail_fn,
        pre_secs=PRE_SECS, timeout=CONV_TIMEOUT, poll_interval=POLL_INTERVAL,
    )
    fo_thread.join()

    # 3. GENTLE restore + settle.
    restore_core1(net)
    time.sleep(RESTORE_SETTLE)

    # 4. HEALTH GATE after restore (diagnostic + heals before steady state).
    post_ok = heal_gate(src, dst_host, dst_ip)
    if not post_ok:
        info("*** WARNING: net unhealthy AFTER restore -- controller failed to "
             "reinstall the path (NetHealthy_PostRestore=0)\n")

    # 4b. Warm before steady-state measurement.
    src.cmd(f"ping -c {WARMUP_COUNT} -i {WARMUP_INTERVAL} -W 1 "
            f"{dst_ip} > /dev/null 2>&1")
    time.sleep(WARMUP_SETTLE)

    # 5. Steady-state metrics + Phase-2 control-plane sample.
    latency = ml.run_ping(src, dst_ip, PING_COUNT)
    window  = TCP_DURATION + UDP_DURATION + 6
    ss = {}

    def _sample_steady():
        ss["cpu"], ss["mem"], ss["peak"] = ml.sample_pids_usage(pids, window)

    t = threading.Thread(target=_sample_steady)
    t.start()
    time.sleep(1)
    throughput   = ml.run_iperf_tcp(src, dst_host, dst_ip, TCP_DURATION)
    jitter, loss = ml.run_iperf_udp(src, dst_host, dst_ip, UDP_BW, UDP_DURATION)
    t.join()

    def r(x):
        return round(x, 3) if isinstance(x, (int, float)) else "ERR"

    return {
        "Convergence_Time_s":   conv if conv is not None else "ERR",
        "Recovered":            1 if recovered else 0,
        "Packets_Lost":         lost if lost is not None else "ERR",
        "Resolution_s":         POLL_INTERVAL,
        "Cut_Verified":         cut_ok["ok"],
        "NetHealthy_PreCut":      1 if pre_ok else 0,
        "NetHealthy_PostRestore": 1 if post_ok else 0,
        "Failover_CPU_pct":     fo.get("cpu", 0.0),
        "Failover_Mem_MB":      fo.get("mem", 0.0),
        "Failover_MemPeak_MB":  fo.get("peak", 0.0),
        "Latency_ms":           r(latency),
        "Jitter_ms":            r(jitter),
        "Throughput_Mbps":      r(throughput),
        "PacketLoss_pct":       r(loss),
        "ControlPlane_CPU_pct": ss.get("cpu", 0.0),
        "ControlPlane_Mem_MB":  ss.get("mem", 0.0),
        "ControlPlane_MemPeak_MB": ss.get("peak", 0.0),
    }


def test_runs(net):
    pids = [ml.get_ryu_pid()]
    dst_host, dst_ip = net.get("websrv"), WEBSRV_IP

    all_rows = []
    for sc in SCENARIOS:
        info(f"\n*** === {sc['name']} (src {sc['src']} -> websrv @ {dst_ip}) ===\n")
        rows = []
        for run in range(1, NUM_RUNS + 1):
            info(f"*** {sc['name']} run {run}/{NUM_RUNS}\n")
            rows.append({"Scenario": sc["name"], "Run": run,
                         **run_once(net, pids, sc, dst_host, dst_ip)})
            info(f"*** {rows[-1]}\n")
            time.sleep(2)

        ok = sum(1 for r_ in rows if r_["Recovered"] == 1)
        info(f"*** {sc['name']}: {ok}/{NUM_RUNS} runs recovered\n")

        avg, std = ml.summarize_pair(sc["name"], rows, METRIC_COLS)
        all_rows.extend(rows + [_rekey(avg), _rekey(std)])
        ml.write_results_csv_incremental(OUTPUT_CSV, FIELDNAMES, all_rows)

    data_rows = [r_ for r_ in all_rows if isinstance(r_["Run"], int)]
    ga, gs = ml.grand_summary(data_rows, METRIC_COLS)
    all_rows.extend([_rekey(ga), _rekey(gs)])
    ml.write_results_csv(OUTPUT_CSV, FIELDNAMES, all_rows)

    total_ok = sum(1 for r_ in data_rows if r_["Recovered"] == 1)
    post_bad = sum(1 for r_ in data_rows if r_["NetHealthy_PostRestore"] == 0)
    info(f"\n*** OVERALL: {total_ok}/{len(data_rows)} runs recovered\n")
    info(f"*** CONTROLLER-FAULT CHECK: {post_bad}/{len(data_rows)} runs left the "
         f"net broken after restore (NetHealthy_PostRestore=0). "
         f"{'>0 => controller restore handling is the fault.' if post_bad else '0 => controller recovered every time.'}\n")


def main():
    net, _ctx = build_network(hosts_per_subnet=1)
    try:
        test_runs(net)
    except KeyboardInterrupt:
        info("\n*** Interrupted\n")
    finally:
        stop_network(net)


if __name__ == "__main__":
    main()
