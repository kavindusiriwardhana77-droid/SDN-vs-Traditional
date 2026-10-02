#!/usr/bin/env python3
# traditional_medium_failover_test.py - CT/2020/087 R.M.K.K.Siriwardhana
# Traditional medium topology, failover scenario. OSPF reconverges onto the
# backup core. Mirrors the SDN failover test.


import threading
import time

from mininet.log import info

import measure_lib as ml
from traditional_campus_topo_v4 import (
    build_network, stop_network, get_all_router_pids,
    WEB_SERVER_IP, DHCP_DNS_IP,
)

# Config  (identical to sdn_medium_failover_test.py, for a fair comparison)
NUM_RUNS     = 5
TCP_DURATION = 600
UDP_DURATION = 600
UDP_BW       = "0"
PING_COUNT   = 1000

# Medium settles more slowly than small: 8 routers, more OSPF adjacencies, plus
# VRRP advertisements. Give the control plane extra room (small uses 6).
# 45 s, NOT 6-8 s. OSPF now runs at FRR's DEFAULT timers (hello 10 s,
# dead 40 s), so re-forming an adjacency after the link is restored takes
# 10-40 s. Settling for only 8 s would start the next run before the primary
# path was back, so the "cut" would sever a path that traffic had already
# abandoned and the run would measure nothing. Applied IDENTICALLY to the SDN
# side (which does not need it) purely to keep the two harnesses symmetric.
RESTORE_SETTLE = 45

WARMUP_COUNT    = 8
WARMUP_INTERVAL = 0.3
WARMUP_SETTLE   = 1.0

# 10 ms => 100 pps. This is the RESOLUTION of the convergence measurement.
# The previous 50 ms interval could not resolve any outage shorter than 50 ms,
# yet the old metric still reported values like 0.2 ms -- those were not
# recovery times, they were the phase offset between the cut and the next
# scheduled ping. See measure_lib.measure_convergence().
POLL_INTERVAL = ml.PING_INTERVAL
PRE_SECS      = 3      # baseline traffic before the cut
CONV_TIMEOUT  = 15     # measurement window after the cut

OUTPUT_CSV = "traditional_medium_failover_results.csv"

# BOTH of an area's ABRs must lose their core-r1 link (see docstring).
SCENARIOS = [
    {"name": "Area1-Reroute-viaCore2", "src": "h10_1",
     "fail": [("core-r1", "area1-r-A"), ("core-r1", "area1-r-B")]},
    {"name": "Area2-Reroute-viaCore2", "src": "h40_1",
     "fail": [("core-r1", "area2-r-A"), ("core-r1", "area2-r-B")]},
    {"name": "Area3-Reroute-viaCore2", "src": "h70_1",
     "fail": [("core-r1", "area3-r-A"), ("core-r1", "area3-r-B")]},
]

METRIC_COLS = [
    "Convergence_Time_s", "Recovered", "Packets_Lost", "Resolution_s",
    "Cut_Verified",
    "Latency_ms", "Jitter_ms", "Throughput_Mbps", "PacketLoss_pct",
    "ControlPlane_CPU_pct", "ControlPlane_Mem_MB",
]
FIELDNAMES = ["Scenario", "Run"] + METRIC_COLS


def set_link(net, a, b, status):
    """Bring every link between nodes a and b up/down, at BOTH ends."""
    node_a, node_b = net.get(a), net.get(b)
    intfs = []
    for link in net.linksBetween(node_a, node_b):
        # Order each link's two interfaces so the NON-core side (which carries
        # the Fast Failover group and watches its own port) is dropped first.
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
        # On restore, order does not matter for correctness.
        for intf in intfs:
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

    # 2. Warm up (identical to the SDN test, so neither side is advantaged).
    src.cmd(f"ping -c {WARMUP_COUNT} -i {WARMUP_INTERVAL} -W 1 "
            f"{dst_ip} > /dev/null 2>&1")
    time.sleep(WARMUP_SETTLE)

    # 3. Timed failover: cut BOTH of the area's links to core-r1 together.
    cut_ok = {"ok": 0, "detail": ""}

    def fail_fn():
        for a, b in sc["fail"]:
            set_link(net, a, b, "down")
        # Confirm the cut really happened. Without this, a run that lost zero
        # packets is ambiguous: it could mean "recovered faster than we can
        # measure" OR "the link never went down". Cut_Verified separates them.
        ok, detail = ml.verify_links_down(net, sc["fail"])
        cut_ok["ok"] = 1 if ok else 0
        cut_ok["detail"] = detail
        if not ok:
            info(f"*** WARNING: link cut NOT verified ({detail}) -- "
                 f"this run's convergence figure is invalid\n")

    conv, recovered, lost = ml.measure_convergence(
        src, dst_ip, fail_fn,
        pre_secs=PRE_SECS,
        timeout=CONV_TIMEOUT,
        poll_interval=POLL_INTERVAL,
    )

    # 4. Restore and settle.
    for a, b in sc["fail"]:
        set_link(net, a, b, "up")
    time.sleep(RESTORE_SETTLE)

    # 4b. RE-WARM BEFORE MEASURING STEADY STATE -- and this is load-bearing.
    #
    # Restoring the link makes the SDN controller flush every installed pair
    # so paths can revert to the primary core. The traditional side has no
    # equivalent step: OSPF routes live in the kernel FIB and survive the
    # restore untouched.
    #
    # So without this re-warm, step 5 measures SDN on a COLD flow table and
    # traditional on a WARM FIB. The first ICMP packet then pays a full
    # controller round-trip (reactive flow install), which -- averaged over a
    # 10-packet ping -- inflated SDN's "steady-state" latency by ~1.4 ms at
    # small scale and ~3.2 ms at medium (i.e. ~14 ms and ~32 ms of one-off
    # install cost, spread across ten packets). That is a measurement
    # artefact of the harness, NOT a property of SDN steady-state latency.
    #
    # The warm-up is identical to the one in step 2 and is applied to BOTH
    # paradigms, so neither is advantaged: it costs the traditional side
    # nothing (its FIB is already populated) and simply removes the one-off
    # install cost from a metric that is supposed to describe steady state.
    #
    # NOTE: the install cost itself is a real and reportable SDN property --
    # it should be characterised deliberately as first-packet flow-install
    # latency, not smuggled into the steady-state latency figure.
    src.cmd(f"ping -c {WARMUP_COUNT} -i {WARMUP_INTERVAL} -W 1 "
            f"{dst_ip} > /dev/null 2>&1")
    time.sleep(WARMUP_SETTLE)

    # 5. Steady-state metrics, measured on the recovered AND warmed network.
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
        # Packets_Lost and Resolution_s make the convergence figure auditable:
        # an outage of 0.0 with 0 packets lost means "recovered faster than the
        # 10 ms instrument can resolve", which is an honest statement, whereas
        # the old harness would have invented a sub-millisecond number.
        "Packets_Lost":         lost if lost is not None else "ERR",
        "Resolution_s":         POLL_INTERVAL,
        "Cut_Verified":         cut_ok["ok"],
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
    # namespaces (zebra + ospfd + vrrpd + staticd + watchfrr + dhcrelay + the
    # shell), not just the three FRR daemons. This is the fair counterpart to
    # the SDN side's single Ryu process, and is why medium's control-plane
    # CPU/memory is much higher.
    pids     = get_all_router_pids(ctx["all_routers"])
    dst_ip   = WEB_SERVER_IP


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
    ctx = build_network(hosts_per_vlan=1)
    try:
        test_runs(ctx)
    except KeyboardInterrupt:
        info("\n*** Interrupted\n")
    finally:
        stop_network(ctx)


if __name__ == "__main__":
    main()
