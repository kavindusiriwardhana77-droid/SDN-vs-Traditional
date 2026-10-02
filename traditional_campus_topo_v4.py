#!/usr/bin/env python3
# traditional_campus_topo_v4.py - CT/2020/087 R.M.K.K.Siriwardhana
# Reusable traditional medium campus topology (FRRouting OSPF + VRRP).
# Structural mirror of sdn_campus_topo_v6.py; only the paradigm differs.


import os
import re
import shutil
import subprocess
import time
from collections import defaultdict
from statistics import mean

from mininet.net import Mininet
from mininet.node import Node, OVSSwitch
from mininet.link import TCLink
from mininet.log import setLogLevel, info
from mininet.cli import CLI

import measure_lib as ml   # shared, so BOTH paradigms use the SAME collectors

# Link bandwidth caps (Mbps) -- IDENTICAL scheme to sdn_campus_topo_v6.py so
# both paradigms are shaped the same way. Plain Mininet Link has NO limit at
# all (veth pairs move tens of Gbps in software), which produced meaningless
# throughput numbers. TCLink + bw= enforces real shaping via Linux tc.
BW_CORE_CORE  = 1000    # 1 Gbps core-core backbone (Mininet TCLink caps at 1000 Mbit)
BW_CORE_DIST  = 1000    # 1 Gbps core <-> ABR uplinks
BW_DIST_ACC   = 1000    # 1 Gbps ABR/dist-switch <-> access uplinks
BW_ACC_HOST   = 100     # 100 Mbps access switch <-> end host (wired desktop)
BW_ACC_SERVER = 1000    # 1 Gbps server-farm access switch <-> server hosts
BW_CORE_SRVSW = 1000    # 1 Gbps core <-> server-farm switch

# Topology configuration  (mirror of sdn_campus_topo_v6.py)
# vlan_id : (human name, third octet, area)
VLANS = {
    10:  ("Admin-Management",     10, 1),
    20:  ("Admin-Staff",          20, 1),
    30:  ("Admin-IT",             30, 1),
    110: ("WiFi-Staff",          110, 1),
    40:  ("Academic-Lecturer",    40, 2),
    50:  ("Academic-UG-Student",  50, 2),
    60:  ("Academic-PG-Student",  60, 2),
    120: ("WiFi-Student",        120, 2),
    70:  ("Lab-Research",         70, 3),
    80:  ("Lab-Computer",         80, 3),
    90:  ("Lab-IoT",              90, 3),
}
SERVER_VLAN    = 100
DHCP_DNS_IP    = "10.10.100.2"
WEB_SERVER_IP  = "10.10.100.11"
SRV1_IP        = "10.10.100.12"
SERVER_GW_VIP  = "10.10.100.1"

# DHCP pool -- identical to the SDN side so both paradigms hand out
# addresses from the same range.
DHCP_POOL_START = 50
DHCP_POOL_END   = 99

FRR_RUN_ROOT = "/tmp/frr-campus-v4"

# VRRP priorities: A router is Master, B router is Backup.
VRRP_PRI = {"A": 110, "B": 90}


def subnet(third):
    return f"10.10.{third}.0/24"

def vrrp_vip(third):
    return f"10.10.{third}.1"

def real_ip(third, which):
    return f"10.10.{third}.{2 if which == 'A' else 3}/24"

def vrrp_v4_mac(vrid):
    return f"00:00:5e:00:01:{vrid & 0xff:02x}"


# FRR router node

class FRRRouter(Node):
    """A Mininet host that runs FRR zebra/ospfd/vrrpd as an L3 router."""

    def config(self, **params):
        super().config(**params)
        self.cmd("sysctl -w net.ipv4.ip_forward=1")
        self.run_dir = os.path.join(FRR_RUN_ROOT, self.name)
        if os.path.isdir(self.run_dir):
            shutil.rmtree(self.run_dir)
        os.makedirs(self.run_dir, exist_ok=True)
        os.chmod(self.run_dir, 0o777)

    def write_frr_configs(self, router_id, ospf_interfaces, networks_by_area,
                          vrrp_interfaces=None):
        vrrp_interfaces = vrrp_interfaces or []
        rd = self.run_dir

        daemons = ("zebra=yes\nospfd=yes\nstaticd=yes\nvrrpd=yes\n"
                   "bgpd=no\nripd=no\nospf6d=no\nisisd=no\neigrpd=no\nripngd=no\n"
                   "vtysh_enable=yes\n")
        zebra = f"hostname {self.name}\nlog file {rd}/zebra.log\n!\n"

        ospf = [f"hostname {self.name}", "router ospf",
                f" ospf router-id {router_id}"]
        for net_, area in networks_by_area:
            ospf.append(f" network {net_} area {area}")
        ospf.append("!")
        for entry in ospf_interfaces:
            ifname, area = entry[0], entry[1]
            cost = entry[2] if len(entry) > 2 else None
            # TIMERS ARE LEFT AT FRR'S DEFAULTS (hello 10 s, dead 40 s).
            #
            # No explicit hello-interval / dead-interval is written here, so
            # every interface -- on the ABRs AND on the cores -- falls back to
            # the same FRR default. Symmetry is what matters: if only one side
            # of an adjacency carried explicit timers, the two ends would
            # disagree (2 s/8 s against 10 s/40 s) and OSPF would refuse to
            # form the neighbour relationship at all. Saying nothing on both
            # sides is therefore SAFER than tuning one side.
            #
            # WHY THIS DOES NOT SLOW FAILURE DETECTION: the failure injected by
            # the failover tests is a hard interface-down. zebra learns of it
            # immediately from a kernel netlink event and tells ospfd at once,
            # so SPF re-runs in milliseconds. The dead-interval is only the
            # fallback for a neighbour that goes silent WITHOUT the local link
            # dropping (e.g. a peer crash behind a switch), which is not the
            # failure mode under test. This is why OSPF still converges in
            # ~100 ms even though its dead interval is 40 s.
            #
            # WHAT IT DOES SLOW IS RECOVERY: re-forming the adjacency after the
            # link is restored takes 10-40 s at default timers. RESTORE_SETTLE
            # in the failover tests is sized accordingly (45 s).
            ospf += [f"interface {ifname}",
                     f" ip ospf area {area}"]
            if cost is not None:
                # The cost asymmetry (10 towards core-r1, 20 towards core-r2)
                # is retained: it is what makes core-r1 the deterministic
                # primary path and the direct counterpart of the SDN side's
                # Fast Failover primary bucket. It is a metric, not a timer.
                ospf.append(f" ip ospf cost {cost}")
            ospf.append("!")
        ospf.append(f"log file {rd}/ospfd.log")

        vrrp = [f"hostname {self.name}"]
        for v in vrrp_interfaces:
            vrrp += [f"interface {v['ifname']}",
                     f" vrrp {v['vrid']} version 2",
                     f" vrrp {v['vrid']} priority {v['priority']}",
                     f" vrrp {v['vrid']} advertisement-interval 100",
                     f" vrrp {v['vrid']} ip {v['vip']}", "!"]
        vrrp.append(f"log file {rd}/vrrpd.log")

        for fname, content in [("daemons", daemons), ("zebra.conf", zebra),
                               ("ospfd.conf", "\n".join(ospf) + "\n"),
                               ("vrrpd.conf", "\n".join(vrrp) + "\n")]:
            with open(os.path.join(rd, fname), "w") as f:
                f.write(content)

    def start_frr(self):
        rd = self.run_dir
        sock = f"{rd}/zebra.sock"
        for path, conf, pid in [
            ("/usr/lib/frr/zebra", "zebra.conf", "zebra.pid"),
            ("/usr/lib/frr/ospfd", "ospfd.conf", "ospfd.pid"),
        ]:
            out = self.cmd(f"{path} -f {rd}/{conf} -d -u root -g root "
                           f"-i {rd}/{pid} -z {sock} --vty_socket {rd} 2>&1")
            if out and out.strip():
                info(f"*** [{self.name}] {path}: {out.strip()}\n")
            time.sleep(1)

    def start_vrrpd(self):
        rd = self.run_dir
        sock = f"{rd}/zebra.sock"
        out = self.cmd(f"/usr/lib/frr/vrrpd -f {rd}/vrrpd.conf -d -u root -g root "
                       f"-i {rd}/vrrpd.pid -z {sock} --vty_socket {rd} 2>&1")
        if out and out.strip():
            info(f"*** [{self.name}] vrrpd: {out.strip()}\n")
        time.sleep(1)
        self.cmd(f"vtysh --vty_socket {rd} -c 'conf t' "
                 f"-c 'no router vrrp' -c 'exit' 2>/dev/null || true")
        time.sleep(0.5)

    def stop_frr(self):
        for pid in ("zebra.pid", "ospfd.pid", "vrrpd.pid"):
            p = os.path.join(self.run_dir, pid)
            if os.path.exists(p):
                self.cmd(f"kill $(cat {p}) 2>/dev/null")


class P2PAllocator:
    """Hands out successive /30 blocks from 10.0.0.0/8 for router links."""

    def __init__(self):
        self._n = 0

    def next_pair(self):
        b = self._n
        self._n += 4
        return f"10.0.0.{b}/30", f"10.0.0.{b+1}/30", f"10.0.0.{b+2}/30"


def assign_p2p(link, ip_a, ip_b):
    link.intf1.setIP(ip_a)
    link.intf2.setIP(ip_b)
    link.intf1.ifconfig("up")
    link.intf2.ifconfig("up")


def add_access_layer(net, dist_sw_name, vlan_ids, hosts_per_vlan):
    dist_sw = net.get(dist_sw_name)
    records = {}
    for vlan in vlan_ids:
        name, third, area = VLANS[vlan]
        acc_sw = net.addSwitch(f"acc-sw{vlan}", cls=OVSSwitch,
                               failMode="standalone")
        uplink = net.addLink(dist_sw, acc_sw, cls=TCLink, bw=BW_DIST_ACC)
        host_intfs, hosts = [], []
        for n in range(1, hosts_per_vlan + 1):
            h = net.addHost(f"h{vlan}_{n}")
            hl = net.addLink(h, acc_sw, cls=TCLink, bw=BW_ACC_HOST)
            host_intfs.append(hl.intf2.name)
            hosts.append(h)
        records[vlan] = {"switch": acc_sw, "uplink_intf": uplink.intf2.name,
                         "host_intfs": host_intfs, "hosts": hosts,
                         "third_octet": third}
    return records


def configure_host_dhcp(rec):
    for h in rec["hosts"]:
        intf = h.intfList()[0].name
        h.cmd(f"ip link set {intf} up")
        h.cmd(f"dhclient -nw -pf /tmp/dhclient-{h.name}.pid "
              f"-lf /tmp/dhclient-{h.name}.lease {intf} "
              f"> /tmp/dhclient-{h.name}.log 2>&1 &")


def start_dhcrelay(abr, subifs):
    phys_ifaces = [intf.name for intf in abr.intfList() if intf.name != "lo"]
    all_ifaces = phys_ifaces + list(subifs)
    ifaces = " ".join(f"-i {s}" for s in all_ifaces)
    abr.cmd(f"dhcrelay -d {ifaces} {DHCP_DNS_IP} "
            f"> /tmp/dhcrelay-{abr.name}.log 2>&1 &")


def write_dnsmasq_conf(path, vlans):
    lines = [
        "# Auto-generated by traditional_campus_topo_v4.py",
        "port=53", "domain=campus.lk", "expand-hosts",
        "dhcp-authoritative", "log-dhcp", "log-queries",
    ]
    for vlan, (name, third, area) in vlans.items():
        gw  = vrrp_vip(third)
        tag = f"vlan{vlan}"
        lines += [
            f"# VLAN {vlan} ({name})",
            f"dhcp-range=set:{tag},10.10.{third}.{DHCP_POOL_START},"
            f"10.10.{third}.{DHCP_POOL_END},255.255.255.0,12h",
            f"dhcp-option=tag:{tag},3,{gw}",
            f"dhcp-option=tag:{tag},6,{DHCP_DNS_IP}",
        ]
    lines += [
        f"address=/dhcp-dns.campus.lk/{DHCP_DNS_IP}",
        f"address=/web.campus.lk/{WEB_SERVER_IP}",
        f"address=/srv1.campus.lk/{SRV1_IP}",
    ]
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")


def wait_for_real_ip(host, timeout=20, interval=1):
    """Poll until the host has a real 10.10.x.x lease; patch intf.ip cache."""
    intf = host.intfList()[0]
    waited = 0
    while waited <= timeout:
        out = host.cmd(f"ip -4 addr show {intf.name}")
        m = re.search(r"inet (10\.10\.\d+\.\d+)", out)
        if m:
            intf.ip = m.group(1)
            return intf.ip
        time.sleep(interval)
        waited += interval
    return None


# Control-plane usage helpers (shared by all traditional medium tests)

def get_all_router_pids(all_routers):
    """WHOLE-DEVICE control-plane PIDs:"""
    pids = ml.collect_netns_pids(all_routers)
    info(f"*** Whole-device control-plane sampling: {len(pids)} PIDs across "
         f"{len(all_routers)} router namespaces\n")
    return pids


def sample_routers_usage_combined(pids, duration):
    """Total control-plane CPU% and RSS across all FRR daemons, summed per timestamp then averaged over the window (fair 'whole-network control plane cost')."""
    env = dict(os.environ, LC_ALL="C", LANG="C")
    pid_arg = ",".join(pids)
    try:
        out = subprocess.run(
            ["pidstat", "-u", "-r", "-p", pid_arg, "1", str(duration)],
            capture_output=True, text=True, timeout=duration + 20, env=env
        ).stdout
    except FileNotFoundError:
        raise RuntimeError("pidstat not found -- sudo apt install sysstat")

    cpu_by_time = defaultdict(float)
    mem_by_time_kb = defaultdict(float)
    mode = None
    for raw_line in out.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("Linux") or line.startswith("Average:"):
            continue
        if "UID" in line and "PID" in line:
            if "%CPU" in line:
                mode = "cpu"
            elif "RSS" in line:
                mode = "mem"
            continue
        parts = line.split()
        if mode == "cpu" and len(parts) >= 9:
            try:
                cpu_by_time[parts[0]] += float(parts[7])
            except (ValueError, IndexError):
                pass
        elif mode == "mem" and len(parts) >= 8:
            try:
                mem_by_time_kb[parts[0]] += float(parts[6])
            except (ValueError, IndexError):
                pass

    if not cpu_by_time or not mem_by_time_kb:
        info(f"*** WARNING: pidstat parse incomplete "
             f"(cpu_ts={len(cpu_by_time)}, mem_ts={len(mem_by_time_kb)})\n")
    avg_cpu = mean(cpu_by_time.values()) if cpu_by_time else 0.0
    avg_mem_mb = (mean(mem_by_time_kb.values()) / 1024.0) if mem_by_time_kb else 0.0
    return avg_cpu, avg_mem_mb


# Build network

def build_network(hosts_per_vlan=1, converge_wait=18, lease_wait=8):
    """Full bring-up:"""
    setLogLevel("info")
    if os.path.isdir(FRR_RUN_ROOT):
        shutil.rmtree(FRR_RUN_ROOT)
    os.makedirs(FRR_RUN_ROOT, exist_ok=True)

    net = Mininet(topo=None, build=False, link=TCLink, switch=OVSSwitch,
                  controller=None)
    p2p = P2PAllocator()

    info("*** Adding core routers\n")
    core_r1 = net.addHost("core-r1", cls=FRRRouter)
    core_r2 = net.addHost("core-r2", cls=FRRRouter)

    info("*** Adding dual ABRs per area\n")
    abr_pairs = {}
    for area in (1, 2, 3):
        abr_pairs[area] = {
            "A": net.addHost(f"area{area}-r-A", cls=FRRRouter),
            "B": net.addHost(f"area{area}-r-B", cls=FRRRouter),
        }

    info("*** Adding distribution switches\n")
    dist_sws = {
        1: net.addSwitch("dist-sw1", cls=OVSSwitch, failMode="standalone"),
        2: net.addSwitch("dist-sw2", cls=OVSSwitch, failMode="standalone"),
        3: net.addSwitch("dist-sw3", cls=OVSSwitch, failMode="standalone"),
    }

    info("*** Adding server-farm distribution switch\n")
    dist_sw_server = net.addSwitch("dsw-srv", cls=OVSSwitch,
                                   failMode="standalone",
                                   dpid="0000000000000099")

    info("*** Adding backbone links\n")
    backbone_link = net.addLink(core_r1, core_r2, cls=TCLink, bw=BW_CORE_CORE)
    backbone_net, backbone_ip1, backbone_ip2 = p2p.next_pair()
    backbone_subnets = [backbone_net]

    dsrv_r1_link = net.addLink(core_r1, dist_sw_server, cls=TCLink, bw=BW_CORE_SRVSW)
    dsrv_r2_link = net.addLink(core_r2, dist_sw_server, cls=TCLink, bw=BW_CORE_SRVSW)

    abr_core_links = {}
    for area, pair in abr_pairs.items():
        for which, abr in pair.items():
            l1 = net.addLink(abr, core_r1, cls=TCLink, bw=BW_CORE_DIST)
            n1, ip1a, ip1b = p2p.next_pair()
            l2 = net.addLink(abr, core_r2, cls=TCLink, bw=BW_CORE_DIST)
            n2, ip2a, ip2b = p2p.next_pair()
            abr_core_links[(area, which)] = {
                "to_r1": l1, "net1": n1, "ip1_abr": ip1a, "ip1_core": ip1b,
                "to_r2": l2, "net2": n2, "ip2_abr": ip2a, "ip2_core": ip2b,
            }
            backbone_subnets += [n1, n2]

    info("*** Adding server farm hosts\n")
    acc_sw100 = net.addSwitch("acc-sw100", cls=OVSSwitch, failMode="standalone")
    net.addLink(acc_sw100, dist_sw_server, cls=TCLink, bw=BW_CORE_SRVSW)

    dhcp_dns = net.addHost("dhcpdns", ip=f"{DHCP_DNS_IP}/24",
                           defaultRoute=f"via {SERVER_GW_VIP}")
    net.addLink(dhcp_dns, acc_sw100, cls=TCLink, bw=BW_ACC_SERVER)
    websrv = net.addHost("websrv", ip=f"{WEB_SERVER_IP}/24",
                         defaultRoute=f"via {SERVER_GW_VIP}")
    net.addLink(websrv, acc_sw100, cls=TCLink, bw=BW_ACC_SERVER)
    srv1 = net.addHost("srv1", ip=f"{SRV1_IP}/24",
                       defaultRoute=f"via {SERVER_GW_VIP}")
    net.addLink(srv1, acc_sw100, cls=TCLink, bw=BW_ACC_SERVER)
    mon = net.addHost("mon")
    mon_link = net.addLink(mon, acc_sw100, cls=TCLink, bw=BW_ACC_SERVER)

    info("*** Adding ABR <-> dist-sw trunk links\n")
    abr_dist_links = {}
    for area, pair in abr_pairs.items():
        for which, abr in pair.items():
            abr_dist_links[(area, which)] = net.addLink(
                abr, dist_sws[area], cls=TCLink, bw=BW_DIST_ACC)

    info("*** Adding access layer\n")
    access_layer_records = {}
    for area in (1, 2, 3):
        vlan_ids = [v for v, (_, _, a) in VLANS.items() if a == area]
        access_layer_records[area] = add_access_layer(
            net, dist_sws[area].name, vlan_ids, hosts_per_vlan)

    info("*** Building network\n")
    net.build()

    all_acc_sws = [net.get(f"acc-sw{v}") for v in VLANS]
    for sw in list(dist_sws.values()) + [dist_sw_server, acc_sw100] + all_acc_sws:
        sw.start([])

    info("*** Setting OVS port modes (VLAN tags/trunks)\n")
    vlan_records = {}
    for ar in access_layer_records.values():
        vlan_records.update(ar)

    for vlan, rec in vlan_records.items():
        sw = rec["switch"]
        sw.cmd(f"ovs-vsctl set port {rec['uplink_intf']} trunks={vlan}")
        for hi in rec["host_intfs"]:
            sw.cmd(f"ovs-vsctl set port {hi} tag={vlan}")

    acc_sw100_uplink = net.linksBetween(acc_sw100, dist_sw_server)[0].intf1.name
    acc_sw100.cmd(f"ovs-vsctl set port {acc_sw100_uplink} trunks={SERVER_VLAN}")
    for intf in acc_sw100.intfList():
        if intf.name in ("lo", acc_sw100_uplink, mon_link.intf2.name):
            continue
        acc_sw100.cmd(f"ovs-vsctl set port {intf.name} tag={SERVER_VLAN}")

    for intf in dist_sw_server.intfList():
        if intf.name != "lo":
            dist_sw_server.cmd(f"ovs-vsctl set port {intf.name} trunks={SERVER_VLAN}")

    info("*** Creating VLAN sub-interfaces on ABRs\n")
    abr_vlan_subifs = {}
    for area, pair in abr_pairs.items():
        vlan_ids = [v for v, (_, _, a) in VLANS.items() if a == area]
        for which, abr in pair.items():
            phys = abr_dist_links[(area, which)].intf1.name
            subifs = []
            for vlan in vlan_ids:
                _, third, _ = VLANS[vlan]
                sub = f"v{vlan}{which.lower()}"
                abr.cmd(f"ip link add link {phys} name {sub} type vlan id {vlan}")
                abr.cmd(f"ip addr add {real_ip(third, which)} dev {sub}")
                abr.cmd(f"ip link set {sub} up")
                subifs.append(sub)
            abr.cmd(f"ip link set {phys} up")
            abr_vlan_subifs[(area, which)] = subifs

    info("*** Creating VLAN 100 sub-interfaces on core routers (VRRP)\n")
    cr1_phys = dsrv_r1_link.intf1.name
    cr1_sub  = "vlan100a"
    core_r1.cmd(f"ip link add link {cr1_phys} name {cr1_sub} type vlan id {SERVER_VLAN}")
    core_r1.cmd(f"ip addr add 10.10.100.4/24 dev {cr1_sub}")
    core_r1.cmd(f"ip link set {cr1_sub} up")
    core_r1.cmd(f"ip link set {cr1_phys} up")

    cr2_phys = dsrv_r2_link.intf1.name
    cr2_sub  = "vlan100b"
    core_r2.cmd(f"ip link add link {cr2_phys} name {cr2_sub} type vlan id {SERVER_VLAN}")
    core_r2.cmd(f"ip addr add 10.10.100.5/24 dev {cr2_sub}")
    core_r2.cmd(f"ip link set {cr2_sub} up")
    core_r2.cmd(f"ip link set {cr2_phys} up")

    info("*** Pre-creating VRRP macvlan devices for ABRs\n")
    for area, pair in abr_pairs.items():
        vlan_ids = [v for v, (_, _, a) in VLANS.items() if a == area]
        for which, abr in pair.items():
            subifs = abr_vlan_subifs[(area, which)]
            for i, vlan in enumerate(vlan_ids):
                mac  = vrrp_v4_mac(vlan)
                macv = f"{subifs[i]}-vr"
                abr.cmd(f"ip link add link {subifs[i]} name {macv} "
                        f"address {mac} type macvlan mode bridge")
                abr.cmd(f"ip link set {macv} up")

    info("*** Pre-creating VRRP macvlan devices for core routers (VLAN 100)\n")
    vrid100  = 100
    mac100   = vrrp_v4_mac(vrid100)
    cr1_macv = "vlan100a-vr"
    cr2_macv = "vlan100b-vr"
    core_r1.cmd(f"ip link add link {cr1_sub} name {cr1_macv} "
                f"address {mac100} type macvlan mode bridge")
    core_r1.cmd(f"ip link set {cr1_macv} up")
    core_r2.cmd(f"ip link add link {cr2_sub} name {cr2_macv} "
                f"address {mac100} type macvlan mode bridge")
    core_r2.cmd(f"ip link set {cr2_macv} up")

    info("*** Assigning backbone /30 addresses\n")
    assign_p2p(backbone_link, backbone_ip1, backbone_ip2)
    for (area, which), d in abr_core_links.items():
        assign_p2p(d["to_r1"], d["ip1_abr"], d["ip1_core"])
        assign_p2p(d["to_r2"], d["ip2_abr"], d["ip2_core"])

    info("*** Writing FRR configs\n")
    # Core routers' P2P links to every ABR must ALSO be listed here, with the
    # SAME hello/dead timers the ABR side gets. If only the ABR side has
    # explicit timers, the ABR expects hello=2s/dead=8s while the core side
    # silently falls back to FRR's defaults (hello=10s/dead=40s), and OSPF
    # refuses to form a neighbour at all (RouterDeadInterval mismatch) --
    # breaking connectivity completely, not just failover. (This exact bug was
    # diagnosed and fixed in traditional_small_topo.py.)
    core_r1_p2p = [(d["to_r1"].intf2.name, 0)
                   for d in abr_core_links.values()]
    core_r2_p2p = [(d["to_r2"].intf2.name, 0)
                   for d in abr_core_links.values()]

    core_r1.write_frr_configs(
        router_id="10.0.0.1",
        ospf_interfaces=[(cr1_sub, 0)] + core_r1_p2p,
        networks_by_area=([(subnet(SERVER_VLAN), 0)] + [(s, 0) for s in backbone_subnets]),
        vrrp_interfaces=[{"ifname": cr1_sub, "vrid": vrid100,
                          "vip": SERVER_GW_VIP, "priority": 110}],
    )
    core_r2.write_frr_configs(
        router_id="10.0.0.2",
        ospf_interfaces=[(cr2_sub, 0)] + core_r2_p2p,
        networks_by_area=([(subnet(SERVER_VLAN), 0)] + [(s, 0) for s in backbone_subnets]),
        vrrp_interfaces=[{"ifname": cr2_sub, "vrid": vrid100,
                          "vip": SERVER_GW_VIP, "priority": 90}],
    )

    for area, pair in abr_pairs.items():
        vlan_ids = [v for v, (_, _, a) in VLANS.items() if a == area]
        for which, abr in pair.items():
            subifs = abr_vlan_subifs[(area, which)]
            ospf_ifaces = [(s, area) for s in subifs]
            # Cost bias on the two core-facing P2P links: core-r1 is the
            # preferred (lower-cost) path, core-r2 the secondary. Without this
            # both links are equal-cost, traffic is hashed unpredictably across
            # them (ECMP), and a failover test cannot know which link actually
            # carries the flow. With the cost set, OSPF's normal SPF
            # recalculation also reverts to core-r1 automatically once it is
            # restored. (Same fix as traditional_small_topo.py.)
            d = abr_core_links[(area, which)]
            ospf_ifaces += [(d["to_r1"].intf1.name, 0, 10),
                            (d["to_r2"].intf1.name, 0, 20)]
            nets = [(subnet(VLANS[v][1]), area) for v in vlan_ids]
            nets += [(s, 0) for s in backbone_subnets]
            vrrp_ifaces = [
                {"ifname": subifs[i], "vrid": vlan_ids[i],
                 "vip": vrrp_vip(VLANS[vlan_ids[i]][1]), "priority": VRRP_PRI[which]}
                for i in range(len(vlan_ids))
            ]
            abr.write_frr_configs(
                router_id=f"10.{area}.1.{1 if which == 'A' else 2}",
                ospf_interfaces=ospf_ifaces,
                networks_by_area=nets,
                vrrp_interfaces=vrrp_ifaces,
            )

    info("*** Starting FRR (zebra + ospfd) on all routers\n")
    all_routers = [core_r1, core_r2]
    for pair in abr_pairs.values():
        all_routers += [pair["A"], pair["B"]]
    for r in all_routers:
        r.start_frr()

    info("*** Waiting 8s for zebra to register interface IPs before vrrpd\n")
    time.sleep(8)

    info("*** Starting vrrpd on all routers\n")
    for r in all_routers:
        r.start_vrrpd()

    info("*** Applying VRRP virtual IPs to macvlan devices\n")
    time.sleep(3)
    for area, pair in abr_pairs.items():
        vlan_ids = [v for v, (_, _, a) in VLANS.items() if a == area]
        for which in ("A", "B"):
            subifs = abr_vlan_subifs[(area, which)]
            for i, vlan in enumerate(vlan_ids):
                _, third, _ = VLANS[vlan]
                macv = f"{subifs[i]}-vr"
                if which == "A":
                    vip = vrrp_vip(third)
                    pair["A"].cmd(f"ip addr add {vip}/32 dev {macv} 2>/dev/null")
                    # setsid + `set +m`: a bare "&" would leave this arping as
                    # a JOB of the router's persistent bash shell, and when it
                    # exits bash prints "[1]+ Done ..." into that shell. That
                    # notice lands in the output of the NEXT cmd() on the router
                    # and desyncs Mininet's prompt parser, after which node.cmd()
                    # silently stops taking effect. Detach it properly.
                    pair["A"].cmd(
                        f"set +m; setsid arping -U -I {macv} -c 2 {vip} "
                        f"< /dev/null > /dev/null 2>&1 & set -m")
                else:
                    real = f"10.10.{third}.3"
                    pair["B"].cmd(f"ip addr add {real}/32 dev {macv} 2>/dev/null")
    core_r1.cmd(f"ip addr add {SERVER_GW_VIP}/32 dev {cr1_macv} 2>/dev/null")
    core_r1.cmd(f"set +m; setsid arping -U -I {cr1_macv} -c 2 {SERVER_GW_VIP} "
                f"< /dev/null > /dev/null 2>&1 & set -m")
    core_r2.cmd(f"ip addr add 10.10.100.5/32 dev {cr2_macv} 2>/dev/null")

    info("*** Starting dnsmasq (DHCP + DNS)\n")
    conf_path = os.path.join(FRR_RUN_ROOT, "dnsmasq-campus.conf")
    write_dnsmasq_conf(conf_path, VLANS)
    dhcp_dns.cmd(f"ip link set {dhcp_dns.intfList()[0].name} up")
    dhcp_dns.cmd(f"dnsmasq -C {conf_path} --no-daemon "
                 f"--pid-file=/tmp/dnsmasq-campus.pid "
                 f"> /tmp/dnsmasq-campus.log 2>&1 &")

    info("*** Starting nginx web server (websrv)\n")
    websrv.cmd(f"ip link set {websrv.intfList()[0].name} up")
    websrv.cmd("mkdir -p /tmp/www")
    websrv.cmd("echo '<html><body><h1>Campus LK Web Server</h1></body></html>' "
               "> /tmp/www/index.html")
    if "nginx" in websrv.cmd("which nginx 2>/dev/null"):
        websrv.cmd("nginx -g 'daemon off; error_log /tmp/nginx-err.log;' "
                   "-c /dev/stdin <<'EOF'\n"
                   "events{} http{server{listen 80; root /tmp/www;}}\nEOF\n"
                   "> /tmp/nginx.log 2>&1 &")
    else:
        websrv.cmd("cd /tmp/www && python3 -m http.server 80 "
                   "> /tmp/httpserver.log 2>&1 &")

    info("*** Starting dhcrelay on all ABRs\n")
    for (area, which), subifs in abr_vlan_subifs.items():
        start_dhcrelay(abr_pairs[area][which], subifs)

    info(f"*** Waiting {converge_wait}s for OSPF/VRRP to converge\n")
    time.sleep(converge_wait)

    info("*** Starting DHCP clients on access hosts\n")
    for rec in vlan_records.values():
        configure_host_dhcp(rec)

    info(f"*** Cleaning up Mininet auto-IPs ({lease_wait}s wait for leases)\n")
    time.sleep(lease_wait)
    for rec in vlan_records.values():
        for h in rec["hosts"]:
            intf = h.intfList()[0].name
            h.cmd(f"ip -4 addr show {intf} | grep 'inet 10\\.0\\.' | "
                  f"awk '{{print $2}}' | xargs -r -I{{}} ip addr del {{}} dev {intf} 2>/dev/null")
            h.cmd(f"ip route del 10.0.0.0/8 dev {intf} 2>/dev/null")

    info("*** Refreshing Mininet's cached host IPs to match DHCP leases\n")
    for rec in vlan_records.values():
        for h in rec["hosts"]:
            if not wait_for_real_ip(h):
                info(f"*** WARNING: {h.name} never got a DHCP lease\n")

    info("*** Setting up OVS mirror on acc-sw100 -> mon\n")
    acc_sw100.cmd(
        f"ovs-vsctl -- set Bridge acc-sw100 mirrors=@m "
        f"-- --id=@m create Mirror name=mon-mirror "
        f"select-all=true output-port=@out "
        f"-- --id=@out get Port {mon_link.intf2.name}"
    )

    info("*** Traditional medium network ready.\n")

    return {
        "net": net,
        "all_routers": all_routers,
        "core_r1": core_r1,
        "core_r2": core_r2,
        "abr_pairs": abr_pairs,
        "dist_sws": dist_sws,
        "dist_sw_server": dist_sw_server,
        "acc_sw100": acc_sw100,
        "abr_core_links": abr_core_links,
        "abr_dist_links": abr_dist_links,
        "vlan_records": vlan_records,
        "dhcp_dns": dhcp_dns,
        "websrv": websrv,
        "srv1": srv1,
    }


def stop_network(ctx):
    """Best-effort teardown: stop FRR + services, then the network."""
    info("*** Stopping services\n")
    for r in ctx.get("all_routers", []):
        r.stop_frr()
    if ctx.get("dhcp_dns"):
        ctx["dhcp_dns"].cmd("pkill dnsmasq 2>/dev/null")
    if ctx.get("websrv"):
        ctx["websrv"].cmd("pkill nginx 2>/dev/null; pkill python3 2>/dev/null")
    info("*** Stopping network\n")
    try:
        ctx["net"].stop()
    except Exception as e:
        info(f"*** net.stop(): {e!r} (safe to ignore after 'sudo mn -c')\n")


# Standalone sanity check

def main():
    ctx = build_network()
    net = ctx["net"]
    try:
        info("\n*** === Leased IPs ===\n")
        for rec in ctx["vlan_records"].values():
            for h in rec["hosts"]:
                info(f"***   {h.name}: {h.IP()}\n")

        src = net.get("h10_1")
        dst = net.get("h30_1")
        dst_ip = dst.IP()
        if dst_ip and dst_ip.startswith("10.10."):
            info(f"\n*** Sample ping h10_1 -> h30_1 ({dst_ip})\n")
            info(src.cmd(f"ping -c 3 {dst_ip}"))

        info("\n*** Dropping to Mininet CLI (Ctrl-D to exit + clean up)\n")
        CLI(net)
    finally:
        stop_network(ctx)


if __name__ == "__main__":
    main()
