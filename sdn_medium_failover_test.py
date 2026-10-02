#!/usr/bin/env python3
# sdn_medium_failover_test.py - CT/2020/087 R.M.K.K.Siriwardhana
# SDN medium topology, failover scenario. Fast failover groups on the area
# switches reroute in the datapath. Mirrors the traditional failover test.


import threading
import time

from mininet.log import info

import measure_lib as ml
from sdn_campus_topo_v6 import (
    build_network, stop_network, WEBSRV_IP,
)

# Config  (identical to traditional_medium_failover_test.py)
NUM_RUNS     = 5
TCP_DURATION = 600
UDP_DURATION = 600
UDP_BW       = "0"
PING_COUNT   = 1000

# RESTORE_SETTLE exists for the TRADITIONAL side: after a link is restored, OSPF
# must re-form its adjacency before traffic reverts to the primary core, and at
# FRR's slower timers that takes tens of seconds. The SDN side reconverges far
# faster, but the value is kept IDENTICAL purely so the two harnesses are
# symmetric. (If the traditional OSPF timers are the fast 2 s/8 s set, this may
# be lowered on BOTH sides together -- never on one side only.)
RESTORE_SETTLE = 45

WARMUP_COUNT    = 8
WARMUP_INTERVAL = 0.3
WARMUP_SETTLE   = 1.0

POLL_INTERVAL = ml.PING_INTERVAL   # convergence-measurement resolution
PRE_SECS      = 3      # baseline traffic before the cut
CONV_TIMEOUT  = 15     # measurement window after the cut

# The control plane is sampled across the convergence window. Kept a touch
# shorter than measure_convergence's own blocking time (PRE_SECS + CONV_TIMEOUT
# + grace) so the sampler thread finishes around the same time and join() is
# cheap; the interesting activity (cut + reroute) happens right after the cut,
# well inside this window.
FAILOVER_WINDOW = PRE_SECS + CONV_TIMEOUT

OUTPUT_CSV = "sdn_medium_failover_results.csv"

# BOTH of an area's AREA switches must lose their core-sw1 link (see docstring).
# NOTE: rebuilt topology -> the FF-bearing tier is the AREA switches
# (areaN-sw-A/-B), NOT the old dist-swN-A/-B.
SCENARIOS = [
    {"name": "Area1-Reroute-viaCore2", "src": "h10_1",
     "fail": [("core-sw1", "area1-sw-A"), ("core-sw1", "area1-sw-B")]},
    {"name": "Area2-Reroute-viaCore2", "src": "h40_1",
     "fail": [("core-sw1", "area2-sw-A"), ("core-sw1", "area2-sw-B")]},
    {"name": "Area3-Reroute-viaCore2", "src": "h70_1",
     "fail": [("core-sw1", "area3-sw-A"), ("core-sw1", "area3-sw-B")]},
]

METRIC_COLS = [
    "Convergence_Time_s", "Recovered", "Packets_Lost", "Resolution_s",
    "Cut_Verified",
    # Steady-state data-plane metrics on the recovered + re-warmed network.
    "Latency_ms", "Jitter_ms", "Throughput_Mbps", "PacketLoss_pct",
    # Phase 2: control plane in steady state after recovery.
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
            intfs.append(i2)   # non-core (area-switch) side first
            intfs.append(i1)
        else:
            intfs.append(i1)
            intfs.append(i2)

    if status == "down":
        for intf in intfs:
            intf.ifconfig("down")
    else:
        for intf in intfs:   # order irrelevant on restore
            intf.ifconfig("up")


def _rekey(row):
    """summarize_pair()/grand_summary() emit 'Pair'; this test uses 'Scenario'."""
    row["Scenario"] = row.pop("Pair")
    return row


def run_once(net, pids, sc, dst_ip):
    src = net.get(sc["src"])
    dst = net.get("websrv")

    # 1. Known-good starting state (all cut links restored).
    for a, b in sc["fail"]:
        set_link(net, a, b, "up")
    time.sleep(RESTORE_SETTLE)

    # 2. Warm up so the reverse path is fully installed before the timed cut.
    src.cmd(f"ping -c {WARMUP_COUNT} -i {WARMUP_INTERVAL} -W 1 "
            f"{dst_ip} > /dev/null 2>&1")
    time.sleep(WARMUP_SETTLE)

    # 3. Timed failover, WITH the control plane sampled across the whole window.
    cut_ok = {"ok": 0, "detail": ""}
    fo = {}

    def _sample_failover():
        # Same sampler, same PID set, same code path as the traditional side.
        fo["cpu"], fo["mem"], fo["peak"] = \
            ml.sample_pids_usage(pids, FAILOVER_WINDOW)

    def fail_fn():
        for a, b in sc["fail"]:
            set_link(net, a, b, "down")
        # Confirm the cut really happened: a zero-loss run is otherwise
        # ambiguous between "recovered below resolution" and "link never cut".
        ok, detail = ml.verify_links_down(net, sc["fail"])
        cut_ok["ok"] = 1 if ok else 0
        cut_ok["detail"] = detail
        if not ok:
            info(f"*** WARNING: link cut NOT verified ({detail}) -- "
                 f"this run's convergence figure is invalid\n")

    fo_thread = threading.Thread(target=_sample_failover)
    fo_thread.start()
    conv, recovered, lost = ml.measure_convergence(
        src, dst_ip, fail_fn,
        pre_secs=PRE_SECS,
        timeout=CONV_TIMEOUT,
        poll_interval=POLL_INTERVAL,
    )
    fo_thread.join()

    # 4. Restore and settle.
    for a, b in sc["fail"]:
        set_link(net, a, b, "up")
    time.sleep(RESTORE_SETTLE)

    # 4b. RE-WARM BEFORE MEASURING STEADY STATE.
    #     Restoring the link makes the SDN controller flush every installed pair
    #     so paths can revert to the primary core; the traditional FIB survives
    #     the restore untouched. Without this re-warm, step 5 would measure SDN
    #     on a COLD flow table and traditional on a WARM FIB -- the first ICMP
    #     packet then pays a one-off install round-trip that inflates SDN's
    #     "steady-state" latency. The warm-up is identical to step 2 and applied
    #     to BOTH paradigms (it costs the traditional side nothing). The install
    #     cost itself is a real SDN property, characterised elsewhere -- it does
    #     not belong in a steady-state figure.
    src.cmd(f"ping -c {WARMUP_COUNT} -i {WARMUP_INTERVAL} -W 1 "
            f"{dst_ip} > /dev/null 2>&1")
    time.sleep(WARMUP_SETTLE)

    # 5. Steady-state metrics on the recovered AND warmed network, with the
    #    control plane sampled across the load window (Phase 2).
    latency = ml.run_ping(src, dst_ip, PING_COUNT)
    window  = TCP_DURATION + UDP_DURATION + 6
    ss = {}

    def _sample_steady():
        ss["cpu"], ss["mem"], ss["peak"] = ml.sample_pids_usage(pids, window)

    t = threading.Thread(target=_sample_steady)
    t.start()
    time.sleep(1)
    throughput   = ml.run_iperf_tcp(src, dst, dst_ip, TCP_DURATION)
    jitter, loss = ml.run_iperf_udp(src, dst, dst_ip, UDP_BW, UDP_DURATION)
    t.join()

    def r(x):
        return round(x, 3) if isinstance(x, (int, float)) else "ERR"

    return {
        "Convergence_Time_s":   conv if conv is not None else "ERR",
        "Recovered":            1 if recovered else 0,
        "Packets_Lost":         lost if lost is not None else "ERR",
        "Resolution_s":         POLL_INTERVAL,
        "Cut_Verified":         cut_ok["ok"],
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
    # A single Ryu process IS the entire SDN control plane -- the direct
    # counterpart to the traditional side's aggregated FRR daemon PIDs.
    pids   = [ml.get_ryu_pid()]
    dst_ip = WEBSRV_IP

    all_rows = []
    for sc in SCENARIOS:
        info(f"\n*** === {sc['name']} (src {sc['src']} -> websrv) ===\n")
        rows = []
        for run in range(1, NUM_RUNS + 1):
            info(f"*** {sc['name']} run {run}/{NUM_RUNS}\n")
            rows.append({"Scenario": sc["name"], "Run": run,
                         **run_once(net, pids, sc, dst_ip)})
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
    info(f"\n*** OVERALL: {total_ok}/{len(data_rows)} runs recovered\n")


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
