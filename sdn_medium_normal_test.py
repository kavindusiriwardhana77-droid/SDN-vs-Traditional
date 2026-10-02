#!/usr/bin/env python3
# sdn_medium_normal_test.py - CT/2020/087 R.M.K.K.Siriwardhana
# SDN medium campus, normal scenario. Same topology and measurement library
# as the traditional normal test, so only the paradigm differs.


import threading
import time

from mininet.log import info

import measure_lib as ml
from sdn_campus_topo_v6 import (
    build_network, stop_network, resolve_host_ip,
    WEBSRV_IP, DHCPDNS_IP,
)

# -- Test parameters (identical to the traditional normal harness) --
NUM_RUNS      = 5
TCP_DURATION  = 600
UDP_DURATION  = 600
UDP_BW        = "0"
PING_COUNT    = 1000
ENABLE_BACKGROUND = True    # Proposal 5.3: measure under load, not on an idle
                            # network. Applied IDENTICALLY to both paradigms,
                            # so it cannot bias the comparison.
OUTPUT_CSV    = "sdn_medium_normal_results.csv"

PAIRS = [
    {"name": "VLAN10-VLAN30",   "src": "h10_1", "dst": "h30_1", "http": False},
    {"name": "VLAN40-VLAN60",   "src": "h40_1", "dst": "h60_1", "http": False},
    {"name": "VLAN70-VLAN90",   "src": "h70_1", "dst": "h90_1", "http": False},
    {"name": "Area1-Area2",     "src": "h10_1", "dst": "h40_1", "http": False},
    {"name": "Area1-Area3",     "src": "h10_1", "dst": "h70_1", "http": False},
    {"name": "Area2-Area3",     "src": "h40_1", "dst": "h70_1", "http": False},
    {"name": "Host-ServerFarm", "src": "h10_1", "dst": "websrv", "http": True},
]

# Noise VLANs are NEVER a measured src/dst -> loading them cannot collide with
# any measured host.
NOISE_SPECS = [("h20_1", "h50_1"), ("h80_1", "h120_1")]

# Control-plane cost = the single Ryu controller process (the centralized
# replacement for the traditional side's distributed FRR daemons).
METRIC_COLS = [
    "Latency_ms", "Jitter_ms", "Throughput_Mbps", "PacketLoss_pct",
    "HTTP_ResponseTime_ms", "HTTP_Success_pct",
    "DNS_ResponseTime_ms", "DNS_Success_pct",
    "ControlPlane_CPU_pct", "ControlPlane_Mem_MB",
]
FIELDNAMES = ["Pair", "Run"] + METRIC_COLS


def host_ip(net, name):
    if name == "websrv":
        return WEBSRV_IP
    ip = resolve_host_ip(net, name)
    if not ip:
        raise RuntimeError(
            f"Cannot resolve IP for {name} (the controller itself is the DHCP "
            f"server -- check the ryu-manager log)")
    return ip


def run_single(net, pids, pair, dst_ip):
    src = net.get(pair["src"])
    dst = net.get(pair["dst"])

    latency = ml.run_ping(src, dst_ip, PING_COUNT)

    # Sample the control plane ACROSS the whole load window, in a thread on a
    # DIFFERENT namespace (root) than the host cmds -- never two cmd()s on one
    # host at once.
    window = TCP_DURATION + UDP_DURATION + 6
    holder = {}

    def _sample():
        holder["cpu"], holder["mem"], holder["peak"] = \
            ml.sample_pids_usage(pids, window)

    t = threading.Thread(target=_sample)
    t.start()
    time.sleep(1)

    throughput      = ml.run_iperf_tcp(src, dst, dst_ip, TCP_DURATION)
    jitter, loss    = ml.run_iperf_udp(src, dst, dst_ip, UDP_BW, UDP_DURATION)
    dns_ms, dns_ok  = ml.run_dns(src, "web.campus.lk", DHCPDNS_IP)
    if pair["http"]:
        http_ms, http_ok = ml.run_http(src, f"http://{dst_ip}/")
    else:
        http_ms, http_ok = "N/A", "N/A"

    t.join()

    def r(x):
        return round(x, 3) if isinstance(x, (int, float)) else "ERR"

    return {
        "Latency_ms": r(latency), "Jitter_ms": r(jitter),
        "Throughput_Mbps": r(throughput), "PacketLoss_pct": r(loss),
        "HTTP_ResponseTime_ms": http_ms if http_ms is not None else "ERR",
        "HTTP_Success_pct": http_ok if http_ok is not None else "ERR",
        "DNS_ResponseTime_ms": dns_ms if dns_ms is not None else "ERR",
        "DNS_Success_pct": dns_ok,
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
        # 3-tuples: BackgroundTraffic needs the dst HOST too, so it can
        # pre-start the iperf3 servers the UDP noise clients connect to.
        noise = [(net.get(s), net.get(d), host_ip(net, d))
                 for s, d in NOISE_SPECS]
        # h110_1 is not a measured src/dst anywhere -> safe as a dedicated
        # background-DNS source (no host.cmd() collision with a measured flow).
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
            dst_ip = host_ip(net, pair["dst"])
            info(f"\n*** === {pair['name']} ({pair['src']}->{pair['dst']} "
                 f"@ {dst_ip}) ===\n")
            # Untimed per-pair warm-up (see module docstring): kept for
            # methodological symmetry with the traditional harness.
            net.get(pair["src"]).cmd(
                f"ping -c 3 -W 1 {dst_ip} > /dev/null 2>&1")
            if pair.get("http"):
                net.get(pair["src"]).cmd(
                    f"curl -o /dev/null -s --max-time 5 "
                    f"http://{dst_ip}/ 2>/dev/null")
            pair_rows = []
            for run in range(1, NUM_RUNS + 1):
                info(f"*** {pair['name']} run {run}/{NUM_RUNS}\n")
                metrics = run_single(net, pids, pair, dst_ip)
                pair_rows.append({"Pair": pair["name"], "Run": run, **metrics})
                info(f"*** {pair_rows[-1]}\n")
                time.sleep(2)
            avg, std = ml.summarize_pair(pair["name"], pair_rows, METRIC_COLS)
            all_rows.extend(pair_rows + [avg, std])
            ml.write_results_csv_incremental(OUTPUT_CSV, FIELDNAMES, all_rows)
    finally:
        if bg:
            bg.stop()

    data_rows = [r for r in all_rows if isinstance(r["Run"], int)]
    ga, gs = ml.grand_summary(data_rows, METRIC_COLS)
    all_rows.extend([ga, gs])
    ml.write_results_csv(OUTPUT_CSV, FIELDNAMES, all_rows)


def main():
    net, ctx = build_network(hosts_per_subnet=1)
    try:
        test_runs(net)
    except KeyboardInterrupt:
        info("\n*** Interrupted\n")
    finally:
        stop_network(net)


if __name__ == "__main__":
    main()
