


import csv
import os
import re
import statistics
import subprocess
import time

from mininet.log import info


PING_INTERVAL = 0.002

# Process / control-plane sampling

def get_ryu_pid():
    """PID of the running ryu-manager process (the entire SDN control plane)."""
    try:
        out = subprocess.check_output(
            ["pgrep", "-f", "ryu-manager"], stderr=subprocess.DEVNULL
        ).decode().split()
        if out:
            return int(out[0])
    except Exception:
        pass
    raise RuntimeError(
        "ryu-manager is not running. Start the controller in another terminal "
        "before launching this test."
    )


def pids_in_netns(node):
    """Every PID running inside `node`'s NETWORK namespace (whole device)."""
    try:
        target = os.readlink(f"/proc/{node.pid}/ns/net")
    except OSError:
        return []
    found = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            if os.readlink(f"/proc/{entry}/ns/net") == target:
                found.append(entry)
        except OSError:
            continue          # process exited mid-scan, or not readable -- skip
    return found


def collect_netns_pids(nodes):
    """Union of every PID in each node's network namespace (whole-device set)."""
    seen, out = set(), []
    for node in nodes:
        npids = pids_in_netns(node)
        if not npids:
            info(f"*** WARNING: no PIDs found in {node.name}'s netns\n")
        for p in npids:
            if p not in seen:
                seen.add(p)
                out.append(p)
    if not out:
        raise RuntimeError(
            "No namespace PIDs found -- did the routers/controller start?")
    return out


def _rss_mb(pid):
    """Resident set size of one PID, in MB, read straight from /proc."""
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) / 1024.0
    except Exception:
        pass
    return 0.0


def _cpu_jiffies(pid):
    """utime + stime of one PID, in clock ticks."""
    try:
        with open(f"/proc/{pid}/stat") as f:
            parts = f.read().split()
        return int(parts[13]) + int(parts[14])
    except Exception:
        return None


def sample_pids_usage(pids, window, interval=1.0):
    """Sample CPU% and memory of a set of PIDs across `window` seconds."""
    pids = [p for p in pids if p]
    if not pids:
        return 0.0, 0.0, 0.0

    hz = os.sysconf("SC_CLK_TCK")
    t0 = time.time()
    start = {p: _cpu_jiffies(p) for p in pids}

    mem_samples = []
    n = max(1, int(window / interval))
    for _ in range(n):
        mem_samples.append(sum(_rss_mb(p) for p in pids))
        time.sleep(interval)

    elapsed = time.time() - t0
    end = {p: _cpu_jiffies(p) for p in pids}

    jiffies = 0
    for p in pids:
        if start.get(p) is not None and end.get(p) is not None:
            jiffies += max(0, end[p] - start[p])

    cpu_pct = 100.0 * (jiffies / hz) / elapsed if elapsed > 0 else 0.0
    mem_mean = statistics.mean(mem_samples) if mem_samples else 0.0
    mem_peak = max(mem_samples) if mem_samples else 0.0
    return round(cpu_pct, 3), round(mem_mean, 3), round(mem_peak, 3)


# Data-plane measurements

def run_ping(host, dst_ip, count=10, size=None):
    """Mean ICMP RTT in ms, or None. `size` sets the ICMP payload in bytes."""
    s = f"-s {size} " if size else ""
    out = host.cmd(f"ping -c {count} -i 0.2 -W 1 {s}{dst_ip} 2>/dev/null")
    m = re.search(r"= [\d.]+/([\d.]+)/", out)
    return float(m.group(1)) if m else None


def _iperf_server(dst, port):
    """Start a detached iperf3 server; return its PID file path."""
    pidf = f"/tmp/iperf_srv_{dst.name}_{port}.pid"
    dst.cmd(f"set +m; setsid iperf3 -s -p {port} -1 < /dev/null "
            f"> /dev/null 2>&1 & echo $! > {pidf}; set -m")
    return pidf


def _kill_pidfile(host, pidf):
    host.cmd(f"set +m; kill $(cat {pidf} 2>/dev/null) 2>/dev/null; "
             f"rm -f {pidf}; set -m")


def run_iperf_tcp(src, dst, dst_ip, duration=10, port=5201):
    """TCP throughput in Mbps, or None."""
    pidf = _iperf_server(dst, port)
    time.sleep(0.5)
    out = src.cmd(f"iperf3 -c {dst_ip} -p {port} -t {duration} -f m 2>/dev/null")
    _kill_pidfile(dst, pidf)
    vals = re.findall(r"([\d.]+) Mbits/sec.*receiver", out)
    if not vals:
        vals = re.findall(r"([\d.]+) Mbits/sec", out)
    return float(vals[-1]) if vals else None


UDP_SUMMARY_RE = re.compile(r"([\d.]+) ms\s+(\d+)/(\d+)\s+\(([\d.]+)%\)")


def _parse_udp(out):
    """(jitter_ms, loss_pct) from iperf3 UDP output -- FROM THE RECEIVER LINE."""
    for line in out.splitlines():
        if "receiver" in line:
            m = UDP_SUMMARY_RE.search(line)
            if m:
                return float(m.group(1)), float(m.group(4))
    matches = UDP_SUMMARY_RE.findall(out)
    if matches:
        last = matches[-1]
        return float(last[0]), float(last[3])
    return None, None


def run_iperf_udp(src, dst, dst_ip, bw="0", duration=10, port=5202):
    """(jitter_ms, loss_pct) from a UDP run, or (None, None)."""
    pidf = _iperf_server(dst, port)
    time.sleep(0.5)
    out = src.cmd(f"iperf3 -c {dst_ip} -u -b {bw} -p {port} "
                  f"-t {duration} -f m 2>/dev/null")
    _kill_pidfile(dst, pidf)
    return _parse_udp(out)


def run_iperf_tcp_multi(host_pairs, duration=10, base_port=5301):
    """Aggregate TCP throughput (Mbps) across concurrent flows."""
    if not host_pairs:
        return None
    srv = []
    for i, (_s, dst, _ip) in enumerate(host_pairs):
        srv.append((dst, _iperf_server(dst, base_port + i)))
    time.sleep(0.8)

    logs = []
    for i, (src, _dst, dst_ip) in enumerate(host_pairs):
        log = f"/tmp/iperf_tcp_{src.name}_{i}.log"
        src.cmd(f"set +m; setsid iperf3 -c {dst_ip} -p {base_port + i} "
                f"-t {duration} -f m < /dev/null > {log} 2>&1 & set -m")
        logs.append((src, log))

    time.sleep(duration + 3)

    total = 0.0
    got = 0
    for src, log in logs:
        out = src.cmd(f"cat {log} 2>/dev/null; rm -f {log}")
        vals = re.findall(r"([\d.]+) Mbits/sec.*receiver", out)
        if not vals:
            vals = re.findall(r"([\d.]+) Mbits/sec", out)
        if vals:
            total += float(vals[-1])
            got += 1
    for dst, pidf in srv:
        _kill_pidfile(dst, pidf)
    return round(total, 3) if got else None


def run_iperf_udp_multi(host_pairs, bw="0", duration=10, base_port=5401):
    """(mean_jitter_ms, mean_loss_pct) across concurrent UDP flows."""
    if not host_pairs:
        return None, None
    srv = []
    for i, (_s, dst, _ip) in enumerate(host_pairs):
        srv.append((dst, _iperf_server(dst, base_port + i)))
    time.sleep(0.8)

    logs = []
    for i, (src, _dst, dst_ip) in enumerate(host_pairs):
        log = f"/tmp/iperf_udp_{src.name}_{i}.log"
        src.cmd(f"set +m; setsid iperf3 -c {dst_ip} -u -b {bw} "
                f"-p {base_port + i} -t {duration} -f m "
                f"< /dev/null > {log} 2>&1 & set -m")
        logs.append((src, log))

    time.sleep(duration + 3)

    jit, loss = [], []
    for src, log in logs:
        out = src.cmd(f"cat {log} 2>/dev/null; rm -f {log}")
        j, l = _parse_udp(out)      # receiver line -- see _parse_udp()
        if j is not None:
            jit.append(j)
            loss.append(l)
    for dst, pidf in srv:
        _kill_pidfile(dst, pidf)
    if not jit:
        return None, None
    return round(statistics.mean(jit), 3), round(statistics.mean(loss), 3)


DNS_QUERIES = 5


def run_dns(host, name, dns_ip, queries=DNS_QUERIES):
    """(mean_query_time_ms, success_pct) using dig."""
    times, ok_count = [], 0
    for _ in range(queries):
        out = host.cmd(f"dig +tries=1 +time=2 @{dns_ip} {name} 2>/dev/null")
        m = re.search(r"Query time: (\d+) msec", out)
        if m:
            times.append(float(m.group(1)))
        if "ANSWER SECTION" in out:
            ok_count += 1
    if not times:
        return None, 0.0
    return round(statistics.mean(times), 3), round(100.0 * ok_count / queries, 1)


def run_http(host, url):
    """(response_time_ms, success_pct) using curl."""
    out = host.cmd(
        f"curl -o /dev/null -s -w '%{{time_total}} %{{http_code}}' "
        f"--max-time 5 {url} 2>/dev/null"
    )
    parts = out.split()
    if len(parts) >= 2:
        try:
            t = float(parts[0]) * 1000.0
            ok = 100.0 if parts[1].startswith("2") else 0.0
            return round(t, 3), ok
        except ValueError:
            pass
    return None, 0.0


# Failover convergence

def measure_convergence(src, dst_ip, fail_fn, pre_secs=3, timeout=15,
                        poll_interval=PING_INTERVAL):
    """Measure the traffic OUTAGE caused by a link failure."""
    log = f"/tmp/conv_{src.name}_{int(time.time() * 1000)}.log"
    count = int((pre_secs + timeout) / poll_interval)

    src.cmd(f"set +m; setsid ping -D -i {poll_interval} -W 1 -c {count} "
            f"{dst_ip} < /dev/null > {log} 2>&1 & set -m")

    time.sleep(pre_secs)
    cut_ts = time.time()
    fail_fn()

    # Let the ping run to completion on its own, plus a small grace period.
    time.sleep(timeout + 2)

    out = src.cmd(f"cat {log} 2>/dev/null; rm -f {log}")

    # ping -D prints "[1699999999.123456] 64 bytes from ..." for each REPLY.
    stamps = [float(t) for t in
              re.findall(r"^\[(\d+\.\d+)\].*bytes from", out, re.M)]
    if len(stamps) < 2:
        return None, False, None

    if not [t for t in stamps if t <= cut_ts]:
        # No baseline was established -- the run is invalid, not a "0 ms".
        return None, False, None
    if not [t for t in stamps if t > cut_ts]:
        # Traffic never resumed within the measurement window.
        return None, False, None

    
    gap = 0.0
    for i in range(1, len(stamps)):
        prev, cur = stamps[i - 1], stamps[i]
        if cur > cut_ts:                 # this gap could contain the outage
            gap = max(gap, cur - prev)

    if gap <= 0.0:
        return None, False, None

    packets_lost = max(0, int(round(gap / poll_interval)) - 1)

    if packets_lost == 0:
        
        outage = 0.0
    else:
        outage = max(0.0, gap - poll_interval)

    return round(outage, 4), True, packets_lost


def verify_links_down(net, fail_list):
    """Confirm every cut interface is ACTUALLY down."""
    down = 0
    total = 0
    for a, b in fail_list:
        na, nb = net.get(a), net.get(b)
        for link in net.linksBetween(na, nb):
            for intf in (link.intf1, link.intf2):
                total += 1
                out = intf.node.cmd(f"ip link show {intf.name} 2>/dev/null")
                # "state DOWN" or the absence of "UP" in the flags
                if "state DOWN" in out or ",UP" not in out.split(">")[0]:
                    down += 1
    return (down == total and total > 0), f"{down}/{total} interfaces down"


# Background load

class BackgroundTraffic:
    """Continuous mixed background load, running DURING the measurements."""

    BASE_PORT = 7201   # measured flows use 5201+, so these can never collide

    def __init__(self, noise_pairs, dns_pairs=None, udp_bw="10M",
                 duration=86400, icmp_size=1200):
        self.noise_pairs = noise_pairs
        self.dns_pairs = dns_pairs or []
        self.udp_bw = udp_bw
        self.duration = duration       # long enough to outlast the whole test
        self.icmp_size = icmp_size
        self._started = []

    @staticmethod
    def _spawn(host, command, pidfile):
        """Launch `command` on `host` FULLY DETACHED from the host's shell."""
        host.cmd(f"set +m; setsid {command} < /dev/null > /dev/null 2>&1 & "
                 f"echo $! > {pidfile}; set -m")

    def start(self):
        info(f"*** [background] starting load on {len(self.noise_pairs)} "
             f"noise pair(s) + {len(self.dns_pairs)} DNS source(s)\n")

        # Servers FIRST -- without these the UDP clients below cannot connect
        # and the background load silently degrades to ICMP only.
        for i, (_src, dst, _ip) in enumerate(self.noise_pairs):
            self._spawn(dst, f"iperf3 -s -p {self.BASE_PORT + i}",
                        f"/tmp/bgsrv_{dst.name}_{i}.pid")
            self._started.append((dst, f"/tmp/bgsrv_{dst.name}_{i}.pid"))
        time.sleep(1.0)   # let the servers bind before any client connects

        for i, (src, _dst, dst_ip) in enumerate(self.noise_pairs):
            self._spawn(src,
                        f"ping -i 0.5 -s {self.icmp_size} "
                        f"-w {self.duration} {dst_ip}",
                        f"/tmp/bgping_{src.name}_{i}.pid")
            self._started.append((src, f"/tmp/bgping_{src.name}_{i}.pid"))

            self._spawn(src,
                        f"iperf3 -c {dst_ip} -u -b {self.udp_bw} "
                        f"-t {self.duration} -p {self.BASE_PORT + i}",
                        f"/tmp/bgudp_{src.name}_{i}.pid")
            self._started.append((src, f"/tmp/bgudp_{src.name}_{i}.pid"))

        for j, (src, name, dns_ip) in enumerate(self.dns_pairs):
            self._spawn(src,
                        f"sh -c 'while :; do dig +tries=1 +time=1 "
                        f"@{dns_ip} {name} > /dev/null 2>&1; sleep 1; done'",
                        f"/tmp/bgdns_{src.name}_{j}.pid")
            self._started.append((src, f"/tmp/bgdns_{src.name}_{j}.pid"))

    def stop(self):
        # Kill by recorded PID, never with a pattern: hosts share a PID
        # namespace, so `pkill -f iperf3` would reach every host and take out
        # the measurement's own traffic.
        for host, pidf in self._started:
            host.cmd(f"set +m; kill $(cat {pidf} 2>/dev/null) 2>/dev/null; "
                     f"rm -f {pidf}; set -m")
        self._started = []
        info("*** [background] stopped\n")


# Statistics and CSV output

def _numeric(rows, col):
    out = []
    for r in rows:
        v = r.get(col)
        if isinstance(v, (int, float)):
            out.append(float(v))
    return out


def summarize_pair(name, rows, metric_cols):
    """Return (mean_row, std_row) for one group of runs."""
    avg = {"Pair": name, "Run": "AVG"}
    std = {"Pair": name, "Run": "STDEV"}
    for c in metric_cols:
        vals = _numeric(rows, c)
        avg[c] = round(statistics.mean(vals), 3) if vals else "N/A"
        std[c] = round(statistics.stdev(vals), 3) if len(vals) > 1 else 0.0
    return avg, std


def grand_summary(rows, metric_cols):
    """Return (grand_mean_row, grand_std_row) across every run in the file."""
    avg = {"Pair": "ALL", "Run": "GRAND_AVG"}
    std = {"Pair": "ALL", "Run": "GRAND_STDEV"}
    for c in metric_cols:
        vals = _numeric(rows, c)
        avg[c] = round(statistics.mean(vals), 3) if vals else "N/A"
        std[c] = round(statistics.stdev(vals), 3) if len(vals) > 1 else 0.0
    return avg, std


def write_results_csv(path, fieldnames, rows):
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)
    info(f"\n*** Results written to {path} ({len(rows)} rows)\n")


def write_results_csv_incremental(path, fieldnames, rows):
    """Rewrite the CSV after every group, so an interrupted run still yields"""
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)
    info(f"*** [checkpoint] {path} updated ({len(rows)} rows so far)\n")
