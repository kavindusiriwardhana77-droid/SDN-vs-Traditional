#!/usr/bin/env python3
# traditional_medium_core_failure_test.py - CT/2020/087 R.M.K.K.Siriwardhana
# Traditional medium topology, whole core router failure. OSPF plus VRRP
# re election move traffic onto the surviving core.


import threading
import time

from mininet.log import info

import measure_lib as ml
from traditional_campus_topo_v4 import (
    build_network, stop_network, get_all_router_pids,
    WEB_SERVER_IP,
)

# Config  (aligned with sdn_medium_core_failure_test.py, for a fair comparison)
NUM_RUNS     = 3          # 3 areas x 3 runs = 9, matching the SDN core test
TCP_DURATION = 600
UDP_DURATION = 600
UDP_BW       = "0"
PING_COUNT   = 1000

RESTORE_SETTLE   = 45     # default OSPF timers -> adjacency re-forms in 10-40 s
RESTORE_STEP_GAP = 3      # gentle restore: one core-r1 link at a time

WARMUP_COUNT    = 8
WARMUP_INTERVAL = 0.3
WARMUP_SETTLE   = 1.0

POLL_INTERVAL = ml.PING_INTERVAL   # 2 ms convergence resolution
PRE_SECS      = 3        # baseline traffic before the cut
CONV_TIMEOUT  = 15       # measurement window after the cut

HEAL_ATTEMPTS = 20       # health-gate: up to 20 probe passes
HEAL_GAP      = 1.0

OUTPUT_CSV = "traditional_medium_core_failure_results.csv"

# The 8 links core-r1 owns. Cutting ALL of them = the whole core offline.
CORE1_LINKS = [
    ("core-r1", "core-r2"),                                   # backbone
    ("core-r1", "dsw-srv"),                                   # server-farm uplink
    ("core-r1", "area1-r-A"), ("core-r1", "area1-r-B"),       # area 1 ABRs
    ("core-r1", "area2-r-A"), ("core-r1", "area2-r-B"),       # area 2 ABRs
    ("core-r1", "area3-r-A"), ("core-r1", "area3-r-B"),       # area 3 ABRs
]

# One scenario per area: measure how each area's host->server path recovers when
# the whole primary core dies. All three cut the SAME 8 links (core-r1 offline);
# only the measured source differs.
SCENARIOS = [
    {"name": "CoreR1-Down-Area1", "src": "h10_1"},
    {"name": "CoreR1-Down-Area2", "src": "h40_1"},
    {"name": "CoreR1-Down-Area3", "src": "h70_1"},
]

METRIC_COLS = [
    "Convergence_Time_s", "Recovered", "Packets_Lost", "Resolution_s",
    "Cut_Verified", "NetHealthy_PreCut", "NetHealthy_PostRestore",
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
            intfs.append(i2)   # non-core side first
            intfs.append(i1)
        else:
            intfs.append(i1)
            intfs.append(i2)

    if status == "down":
        for intf in intfs:
            intf.ifconfig("down")
    else:
        for intf in intfs:
            intf.ifconfig("up")


def cut_core1(net):
    """Down all 8 of core-r1's links (both ends) -- the whole core offline."""
    for a, b in CORE1_LINKS:
        set_link(net, a, b, "down")


def gentle_restore(net, gap=RESTORE_STEP_GAP):
    """Bring core-r1's 8 links back up ONE AT A TIME (see docstring)."""
    for a, b in CORE1_LINKS:
        set_link(net, a, b, "up")
        time.sleep(gap)


def heal_gate(src, dst, dst_ip, src_ip, attempts=HEAL_ATTEMPTS, gap=HEAL_GAP):
    """Ping src->websrv until a clean (0%-loss) pass, warming BOTH directions."""
    for _ in range(attempts):
        out = src.cmd(f"ping -c 3 -i 0.3 -W 1 {dst_ip} 2>/dev/null")
        if src_ip:
            dst.cmd(f"ping -c 3 -i 0.3 -W 1 {src_ip} > /dev/null 2>&1")
        if "0% packet loss" in out:
            return True
        time.sleep(gap)
    return False


def _rekey(row):
    """summarize_pair()/grand_summary() emit 'Pair'; this test uses 'Scenario'."""
    row["Scenario"] = row.pop("Pair")
    return row


def run_once(net, pids, sc):
    src    = net.get(sc["src"])
    dst    = net.get("websrv")
    dst_ip = WEB_SERVER_IP
    src_ip = src.IP()

    # 1. Verify a healthy starting state. The previous run ends with restore +
    #    heal, and the fresh build is healthy, so this normally passes at once.
    #    If it does not (a transient), force a clean restore so one bad recovery
    #    cannot cascade into every later run.
    healthy_pre = heal_gate(src, dst, dst_ip, src_ip)
    if not healthy_pre:
        info("*** pre-cut heal FAILED -- forcing gentle restore + settle\n")
        gentle_restore(net)
        time.sleep(RESTORE_SETTLE)
        healthy_pre = heal_gate(src, dst, dst_ip, src_ip)

    # 2. Warm up (identical to the SDN core test, so neither side is advantaged).
    src.cmd(f"ping -c {WARMUP_COUNT} -i {WARMUP_INTERVAL} -W 1 "
            f"{dst_ip} > /dev/null 2>&1")
    time.sleep(WARMUP_SETTLE)

    # 3. Timed whole-core failure: all 8 of core-r1's links down together.
    cut_ok = {"ok": 0, "detail": ""}

    def fail_fn():
        cut_core1(net)
        # Confirm all 16 interfaces are actually down. A run that lost zero
        # packets is otherwise ambiguous ("recovered below resolution" vs "the
        # cut never happened"); Cut_Verified separates the two.
        ok, detail = ml.verify_links_down(net, CORE1_LINKS)
        cut_ok["ok"] = 1 if ok else 0
        cut_ok["detail"] = detail
        if not ok:
            info(f"*** WARNING: core cut NOT fully verified ({detail}) -- "
                 f"this run's convergence figure is invalid\n")

    conv, recovered, lost = ml.measure_convergence(
        src, dst_ip, fail_fn,
        pre_secs=PRE_SECS,
        timeout=CONV_TIMEOUT,
        poll_interval=POLL_INTERVAL,
    )

    # 4. Restore core-r1 gently, then settle for OSPF adjacency re-formation.
    gentle_restore(net)
    time.sleep(RESTORE_SETTLE)

    # 5. Confirm the network came fully back before measuring steady state.
    healthy_post = heal_gate(src, dst, dst_ip, src_ip)

    # 6. Re-warm (removes the one-off cache/adjacency-refresh cost from the
    #    steady-state figure), then measure steady state on the recovered net.
    src.cmd(f"ping -c {WARMUP_COUNT} -i {WARMUP_INTERVAL} -W 1 "
            f"{dst_ip} > /dev/null 2>&1")
    time.sleep(WARMUP_SETTLE)

    latency = ml.run_ping(src, dst_ip, PING_COUNT)
    window  = TCP_DURATION + UDP_DURATION + 6
    holder  = {}

    def _sample():
        holder["cpu"], holder["mem"], holder["peak"] = \
            ml.sample_pids_usage(pids, window)

    t = threading.Thread(target=_sample)
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
        "NetHealthy_PreCut":    1 if healthy_pre else 0,
        "NetHealthy_PostRestore": 1 if healthy_post else 0,
        "Latency_ms":           r(latency),
        "Jitter_ms":            r(jitter),
        "Throughput_Mbps":      r(throughput),
        "PacketLoss_pct":       r(loss),
        "ControlPlane_CPU_pct": holder.get("cpu", 0.0),
        "ControlPlane_Mem_MB":  holder.get("mem", 0.0),
        "ControlPlane_MemPeak_MB": holder.get("peak", 0.0),
    }


def test_runs(ctx):
    net = ctx["net"]
    # WHOLE-DEVICE control plane: every process in all 8 routers' network
    # namespaces, the fair counterpart to the SDN side's single Ryu process.
    pids = get_all_router_pids(ctx["all_routers"])

    all_rows = []
    for sc in SCENARIOS:
        info(f"\n*** === {sc['name']} "
             f"(src {sc['src']} -> websrv, core-r1 OFFLINE) ===\n")
        rows = []
        for run in range(1, NUM_RUNS + 1):
            info(f"*** {sc['name']} run {run}/{NUM_RUNS}\n")
            rows.append({"Scenario": sc["name"], "Run": run,
                         **run_once(net, pids, sc)})
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
    broken   = sum(1 for r_ in data_rows if r_["NetHealthy_PostRestore"] == 0)
    info(f"\n*** OVERALL: {total_ok}/{len(data_rows)} runs recovered\n")
    # POST-RESTORE HEALTH CHECK. If any run failed to return to full health
    # after restore, the NEXT run's numbers are suspect. On the traditional
    # side this should be 0: FRR was never killed, and there is no shared
    # controller state to corrupt, so a whole-core restore is clean.
    info(f"*** POST-RESTORE HEALTH CHECK: {broken}/{len(data_rows)} runs did "
         f"NOT return to full health after restore "
         f"({'clean' if broken == 0 else 'INVESTIGATE'})\n")


def main():
    ctx = build_network(hosts_per_vlan=1)
    try:
        test_runs(ctx)
    except KeyboardInterrupt:
        info("\n*** Interrupted\n")
    finally:
        stop_network(ctx)


if __name__ == "__main__":
    main()
