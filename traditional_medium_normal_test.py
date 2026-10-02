#!/usr/bin/env python3
# traditional_medium_normal_test.py - CT/2020/087 R.M.K.K.Siriwardhana
# Traditional medium campus, normal scenario. Same topology and measurement
# library as the SDN normal test, so only the paradigm differs.


import threading
import time

from mininet.log import info

import measure_lib as ml
from traditional_campus_topo_v4 import (
    build_network, stop_network, get_all_router_pids,
    WEB_SERVER_IP, DHCP_DNS_IP,
)

# -- Test parameters (identical to the SDN normal harness) --
NUM_RUNS      = 5
TCP_DURATION  = 600
UDP_DURATION  = 600
UDP_BW        = "0"
PING_COUNT    = 1000
ENABLE_BACKGROUND = True    # Proposal 5.3: measure under load, not on an
                            # idle network. Applied IDENTICALLY to both
                            # paradigms, so it cannot bias the comparison.
OUTPUT_CSV    = "traditional_medium_normal_results.csv"

# 7 test pairs -- same VLAN/area structure as the SDN side.
PAIRS = [
    {"name": "VLAN10-VLAN30",   "src": "h10_1", "dst": "h30_1", "http": False},
    {"name": "VLAN40-VLAN60",   "src": "h40_1", "dst": "h60_1", "http": False},
    {"name": "VLAN70-VLAN90",   "src": "h70_1", "dst": "h90_1", "http": False},
    {"name": "Area1-Area2",     "src": "h10_1", "dst": "h40_1", "http": False},
    {"name": "Area1-Area3",     "src": "h10_1", "dst": "h70_1", "http": False},
    {"name": "Area2-Area3",     "src": "h40_1", "dst": "h70_1", "http": False},
    {"name": "Host-ServerFarm", "src": "h10_1", "dst": "websrv", "http": True},
]

# Noise pairs that generate background load DURING measurement (hosts NOT
# used as measured src/dst, so they load the fabric without colliding).
NOISE_SPECS = [("h20_1", "h50_1"), ("h80_1", "h120_1")]

METRIC_COLS = [
    "Latency_ms", "Jitter_ms", "Throughput_Mbps", "PacketLoss_pct",
    "HTTP_ResponseTime_ms", "HTTP_Success_pct",
    "DNS_ResponseTime_ms", "DNS_Success_pct",
    "ControlPlane_CPU_pct", "ControlPlane_Mem_MB",
]
FIELDNAMES = ["Pair", "Run"] + METRIC_COLS


def host_ip(net, name):
    """Real (DHCP-leased or static) IP; build_network already resolved these."""
    if name == "websrv":
        return WEB_SERVER_IP
    return net.get(name).IP()


def run_single(net, pids, pair, dst_ip):
    src = net.get(pair["src"])
    dst = net.get(pair["dst"])

    latency = ml.run_ping(src, dst_ip, PING_COUNT)

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
    dns_ms, dns_ok  = ml.run_dns(src, "web.campus.lk", DHCP_DNS_IP)
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


def test_runs(ctx):
    net = ctx["net"]
    pids = get_all_router_pids(ctx["all_routers"])
    info(f"*** Whole-device control-plane usage across {len(pids)} PIDs "
         f"(all processes in the 8 router namespaces)\n")

    # Background load
    bg = None
    if ENABLE_BACKGROUND:
        # 3-tuples: BackgroundTraffic needs the dst HOST too, so it can
        # pre-start the iperf3 servers the UDP noise clients connect to.
        noise = [(net.get(s), net.get(d), host_ip(net, d))
                 for s, d in NOISE_SPECS]
        # h110_1 is not used as a measured src/dst anywhere -> safe as a
        # dedicated background-DNS source (no host.cmd() collision).
        dns_noise = [(net.get("h110_1"), "srv1.campus.lk", DHCP_DNS_IP)]
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
            # UNTIMED WARM-UP -- run once per pair, before the 5 timed runs.
            #
            # Without it, run 1 of every pair is a systematic outlier: the ARP
            # cache is cold (and on the SDN side the flow is not yet installed),
            # so run 1 measured ~0.95 ms against ~0.25 ms for runs 2-5, and the
            # first HTTP request took 13.9 ms against ~5 ms. That is a one-off
            # cache-population cost, not steady-state latency, and averaging it
            # into the mean inflates both the mean and the standard deviation.
            #
            # Applied IDENTICALLY to both paradigms, so neither is advantaged.
            # The cost it removes is real and is characterised separately; it
            # simply does not belong in a steady-state figure.
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
    ctx = build_network(hosts_per_vlan=1)
    try:
        test_runs(ctx)
    except KeyboardInterrupt:
        info("\n*** Interrupted\n")
    finally:
        stop_network(ctx)


if __name__ == "__main__":
    main()
