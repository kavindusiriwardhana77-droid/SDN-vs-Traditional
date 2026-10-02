#!/usr/bin/env python3
# sdn_medium_5host_test.py - CT/2020/087 R.M.K.K.Siriwardhana
# SDN medium campus, 5 hosts per VLAN scalability scenario. Mirrors
# traditional_medium_5host_test.py; only the paradigm differs.


import threading
import time

from mininet.log import info

import measure_lib as ml
from sdn_campus_topo_v6 import (
    build_network, stop_network, resolve_host_ip,
    WEBSRV_IP, DHCPDNS_IP,
)

HOSTS_PER_SUBNET = 5
NUM_RUNS         = 5
TCP_DURATION     = 600
UDP_DURATION     = 600
UDP_BW           = "0"
PING_COUNT       = 1000
OUTPUT_CSV       = "sdn_medium_5host_results.csv"

# Background load (global requirement: traffic must keep running DURING
# measurements). Same noise placement as the normal test -- these VLANs are
# never measured here, so the noise loads the fabric without colliding with any
# measured host. The 5 concurrent measured flows already load the network; this
# keeps the extra load modest so it cannot saturate them. Applied IDENTICALLY to
# both paradigms.
ENABLE_BACKGROUND = True
NOISE_SPECS = [("h20_1", "h50_1"), ("h80_1", "h120_1")]

PAIRS = [
    {"name": "VLAN10-VLAN30", "src_vlan": 10, "dst_vlan": 30},
    {"name": "VLAN40-VLAN60", "src_vlan": 40, "dst_vlan": 60},
    {"name": "VLAN70-VLAN90", "src_vlan": 70, "dst_vlan": 90},
    {"name": "Area1-Area2",   "src_vlan": 10, "dst_vlan": 40},
    {"name": "Area1-Area3",   "src_vlan": 10, "dst_vlan": 70},
    {"name": "Area2-Area3",   "src_vlan": 40, "dst_vlan": 70},
    {"name": "Host-ServerFarm", "src_vlan": 10, "dst": "websrv"},
]

METRIC_COLS = [
    "NumHostPairs", "Latency_ms", "Jitter_ms", "Throughput_Mbps",
    "PacketLoss_pct", "ControlPlane_CPU_pct", "ControlPlane_Mem_MB",
]
FIELDNAMES = ["Pair", "Run"] + METRIC_COLS


def build_host_pairs(net, pair):
    hp = []
    for i in range(1, HOSTS_PER_SUBNET + 1):
        src = net.get(f"h{pair['src_vlan']}_{i}")
        if pair.get("dst") == "websrv":
            dst, dst_ip = net.get("websrv"), WEBSRV_IP
        else:
            dst = net.get(f"h{pair['dst_vlan']}_{i}")
            dst_ip = resolve_host_ip(net, dst.name)
        if dst_ip and dst_ip.startswith("10.10."):
            hp.append((src, dst, dst_ip))
    return hp


def prewarm_pairs(host_pairs):
    """Warm BOTH directions of every concurrent pair before the timed runs."""
    for src, dst, dst_ip in host_pairs:
        src.cmd(f"ping -c 1 -W 1 {dst_ip} > /dev/null 2>&1")
        src_ip = src.IP()
        if src_ip and src_ip.startswith("10.10."):
            dst.cmd(f"ping -c 1 -W 1 {src_ip} > /dev/null 2>&1")


def ping_multi(host_pairs):
    res = {}

    def _one(i, src, dst_ip):
        res[i] = ml.run_ping(src, dst_ip, PING_COUNT)

    threads = []
    for i, (src, _dst, dst_ip) in enumerate(host_pairs):
        t = threading.Thread(target=_one, args=(i, src, dst_ip))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    vals = [v for v in res.values() if v is not None]
    return round(sum(vals) / len(vals), 3) if vals else None


def run_single(net, pids, host_pairs):
    window = TCP_DURATION + UDP_DURATION + 8
    holder = {}

    def _sample():
        holder["cpu"], holder["mem"], holder["peak"] = \
            ml.sample_pids_usage(pids, window)

    latency = ping_multi(host_pairs)

    t = threading.Thread(target=_sample)
    t.start()
    time.sleep(1)
    throughput   = ml.run_iperf_tcp_multi(host_pairs, TCP_DURATION)
    jitter, loss = ml.run_iperf_udp_multi(host_pairs, UDP_BW, UDP_DURATION)
    t.join()

    def r(x):
        return round(x, 3) if isinstance(x, (int, float)) else "ERR"

    return {
        "NumHostPairs": len(host_pairs),
        "Latency_ms": r(latency), "Jitter_ms": r(jitter),
        "Throughput_Mbps": r(throughput), "PacketLoss_pct": r(loss),
        "ControlPlane_CPU_pct": holder.get("cpu", 0.0),
        "ControlPlane_Mem_MB": holder.get("mem", 0.0),
        "ControlPlane_MemPeak_MB": holder.get("peak", 0.0),
    }


def test_runs(net):
    ctrl_pid = ml.get_ryu_pid()
    info(f"*** Controller PID: {ctrl_pid}\n")
    pids = [ctrl_pid]

    bg = None
    if ENABLE_BACKGROUND:
        noise = [(net.get(s), net.get(d), resolve_host_ip(net, d))
                 for s, d in NOISE_SPECS]
        dns_noise = [(net.get("h110_1"), "srv1.campus.lk", DHCPDNS_IP)]
        bg = ml.BackgroundTraffic(noise, dns_pairs=dns_noise)
        try:
            bg.start()
        except Exception as e:
            info(f"*** background start failed ({e!r}); continuing\n")
            bg = None

    all_rows = []
    try:
        for pair in PAIRS:
            host_pairs = build_host_pairs(net, pair)
            info(f"\n*** === {pair['name']} "
                 f"({len(host_pairs)} concurrent pairs) ===\n")
            info(f"*** Pre-warming flows for {pair['name']} "
                 f"(untimed, both directions)\n")
            prewarm_pairs(host_pairs)
            rows = []
            for run in range(1, NUM_RUNS + 1):
                info(f"*** {pair['name']} run {run}/{NUM_RUNS}\n")
                m = run_single(net, pids, host_pairs)
                rows.append({"Pair": pair["name"], "Run": run, **m})
                info(f"*** {rows[-1]}\n")
                time.sleep(2)
            avg, std = ml.summarize_pair(pair["name"], rows, METRIC_COLS)
            all_rows.extend(rows + [avg, std])
            ml.write_results_csv_incremental(OUTPUT_CSV, FIELDNAMES, all_rows)
    finally:
        if bg:
            bg.stop()

    data_rows = [r for r in all_rows if isinstance(r["Run"], int)]
    ga, gs = ml.grand_summary(data_rows, METRIC_COLS)
    all_rows.extend([ga, gs])
    ml.write_results_csv(OUTPUT_CSV, FIELDNAMES, all_rows)


def main():
    net, ctx = build_network(hosts_per_subnet=HOSTS_PER_SUBNET)
    try:
        test_runs(net)
    except KeyboardInterrupt:
        info("\n*** Interrupted\n")
    finally:
        stop_network(net)


if __name__ == "__main__":
    main()
