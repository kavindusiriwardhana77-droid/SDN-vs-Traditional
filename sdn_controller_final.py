#!/usr/bin/env python3
# sdn_controller_final.py - CT/2020/087 R.M.K.K.Siriwardhana
# Single Ryu controller for the SDN medium campus. Handles learning, DHCP,
# central path computation and OpenFlow fast failover groups.


from __future__ import annotations

import struct
import time as _time
import heapq
from collections import defaultdict, deque

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (
    CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls,
)
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub, addrconv
from ryu.lib.packet import (
    packet, ethernet, arp, ipv4, udp, dhcp, ether_types,
)
from ryu.topology import event as topo_event
from ryu.topology.api import get_switch, get_link

# Network configuration  (must match sdn_campus_topo_v6.py exactly)

GATEWAY_MAC = "aa:bb:cc:00:00:01"
GATEWAY_IPS = {"10.10.{}.1".format(s) for s in
               [10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120]}

# Access-switch DPID -> subnet third octet. UNCHANGED from before: the access
# tier did not move, only the dist/area tier did.
ACC_DPID_TO_THIRD = {
    0x30:  100,
    0x110: 10,  0x120: 20,  0x130: 30,  0x140: 110,
    0x210: 40,  0x220: 50,  0x230: 60,  0x240: 120,
    0x310: 70,  0x320: 80,  0x330: 90,
}
THIRD_TO_ACC_DPID = {v: k for k, v in ACC_DPID_TO_THIRD.items()}

# Cores + path preference (mirror of OSPF cost 10/20)
CORE1_DPID = 0x1     # preferred / primary
CORE2_DPID = 0x2     # backup
EDGE_COST_DEFAULT   = 1
EDGE_COST_VIA_CORE2 = 5   # any hop touching core-sw2 is penalised

# Area ("ABR-position") switches  -- the tier that now carries the FF groups.
# DPIDs must match sdn_campus_topo_v6.py:
#   area1-sw-A/B = 0x1a/0x1b, area2 = 0x2a/0x2b, area3 = 0x3a/0x3b
AREA_SW_DPIDS = {0x1a, 0x1b, 0x2a, 0x2b, 0x3a, 0x3b}

# One downlink group id per AREA switch, installed on each core.
# (core -> that area switch; primary = direct link, backup = core-core backbone)
AREA_GID = {
    0x1a: 201, 0x1b: 202,   # area 1: A, B
    0x2a: 203, 0x2b: 204,   # area 2: A, B
    0x3a: 205, 0x3b: 206,   # area 3: A, B
}
GID_UPLINK = 100   # uplink FF group id on each area switch

DHCPDNS_IP       = "10.10.100.2"
LEASE_SECONDS    = 3600
DHCP_SERVER_PORT = 67
DHCP_CLIENT_PORT = 68

# Host n (1-indexed) -> 10.10.<third>.<DHCP_BASE + n>  (host1 -> .11 ...)
DHCP_BASE = 10

RATE_LIMIT_PPS = 2000
RECONCILE_SECS = 4

# Proactive settle: after this long with no new LLDP wiring, pre-install the
# switch fabric. Kept modest; the topo's build_network() also waits for LLDP.
PROACTIVE_SETTLE_SECS = 8

# OpenFlow priorities
PRI_MISS      = 0
PRI_DHCP_DROP = 50    # core/dist/area: drop stray DHCP broadcasts in hardware
PRI_L3        = 100
PRI_FLOOD     = 150
PRI_ARP       = 200   # ARP + access-switch DHCP punt share this tier


def ip_third(ip):
    p = ip.split(".")
    return int(p[2]) if len(p) == 4 and p[0] == "10" and p[1] == "10" else None


class SDNCampusControllerFinal(app_manager.RyuApp):
    """Proactive SDN controller for CT/2020/087 (medium topology)."""
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SDNCampusControllerFinal, self).__init__(*args, **kwargs)
        self.dps = {}

        # Topology: additive wiring + port-status liveness -> live graph
        self.wire       = defaultdict(dict)   # wire[dpid][nbr] = local_port
        self.adj        = defaultdict(dict)   # adj[dpid][port] = nbr
        self.down_ports = defaultdict(set)
        self.graph      = defaultdict(dict)

        self.hosts       = {}   # ip -> {mac, dpid, port}
        self.tree_edges  = set()
        self.pair_paths  = {}   # pair -> set(frozenset({dpid_a, dpid_b}))
        self.installed   = set()
        self.uplink_ff_installed   = set()   # area dpids with uplink group
        self.core_ff_installed     = set()   # (core_dpid, gid) tuples

        # DHCP
        self.dhcp_leases    = {}                     # mac -> assigned_ip
        self.subnet_counter = defaultdict(lambda: 1)

        self._rate = defaultdict(lambda: [0.0, 0])

        self._in_failover     = False
        self._deferred_pending = False

        # Proactive bookkeeping
        self._fabric_installed = False
        self._last_wire_change = _time.time()

        self._reconcile_thread = hub.spawn(self._reconcile_loop)
        self._proactive_thread = hub.spawn(self._proactive_loop)

        self.logger.info(
            "[FINAL] PROACTIVE controller ready. Built-in DHCP (installs host "
            "flows at lease time), area-switch Fast Failover groups, "
            "startup fabric pre-install, packet-in only for unknown traffic."
        )

    # Switch connect

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def sw_features(self, ev):
        dp = ev.msg.datapath
        self.dps[dp.id] = dp
        is_acc = dp.id in ACC_DPID_TO_THIRD
        self.logger.info(
            "[SW] {:#x} connected ({}) total={}".format(
                dp.id, "access" if is_acc else "core/dist/area", len(self.dps))
        )
        ofp, par = dp.ofproto, dp.ofproto_parser

        # Table-miss -> controller (fallback only; proactive flows sit above it)
        self._add_flow(dp, PRI_MISS, par.OFPMatch(),
                       [par.OFPActionOutput(ofp.OFPP_CONTROLLER,
                                            ofp.OFPCML_NO_BUFFER)])
        # ARP -> controller everywhere (controller proxies the gateway)
        self._add_flow(dp, PRI_ARP,
                       par.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP),
                       [par.OFPActionOutput(ofp.OFPP_CONTROLLER,
                                            ofp.OFPCML_NO_BUFFER)])
        if is_acc:
            # Access switches punt DHCP to the controller (it answers directly)
            self._add_flow(dp, PRI_ARP,
                           par.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                        ip_proto=17,
                                        udp_dst=DHCP_SERVER_PORT),
                           [par.OFPActionOutput(ofp.OFPP_CONTROLLER,
                                                ofp.OFPCML_NO_BUFFER)])
        else:
            # Core/dist/area: drop stray DHCP broadcasts in hardware
            self._add_flow(dp, PRI_DHCP_DROP,
                           par.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                        ip_proto=17,
                                        udp_dst=DHCP_SERVER_PORT),
                           [])

    # Topology WIRING from LLDP  (additive only)

    @set_ev_cls(topo_event.EventLinkAdd)
    def link_add(self, ev):
        s, d = ev.link.src, ev.link.dst
        self.wire[s.dpid][d.dpid] = s.port_no
        self.wire[d.dpid][s.dpid] = d.port_no
        self.adj[s.dpid][s.port_no] = d.dpid
        self.adj[d.dpid][d.port_no] = s.dpid
        self.down_ports[s.dpid].discard(s.port_no)
        self.down_ports[d.dpid].discard(d.port_no)
        self._last_wire_change = _time.time()
        self.logger.info(
            "[TOPO] WIRE {:#x}:{} <-> {:#x}:{}".format(
                s.dpid, s.port_no, d.dpid, d.port_no)
        )
        self._rebuild_graph()
        self._rebuild_tree()
        self._push_flood_rules()

    @set_ev_cls(topo_event.EventLinkDelete)
    def link_del(self, ev):
        # LOG-ONLY. Real liveness comes from EventOFPPortStatus.
        s, d = ev.link.src, ev.link.dst
        self.logger.debug(
            "[TOPO] LLDP-delete {:#x}<->{:#x} (ignored -- port-status driven)"
            .format(s.dpid, d.dpid)
        )

    # Topology LIVENESS from port-status  (authoritative)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status(self, ev):
        msg     = ev.msg
        dp      = msg.datapath
        ofp     = dp.ofproto
        port    = msg.desc
        port_no = port.port_no
        reason  = msg.reason

        link_down = (reason == ofp.OFPPR_DELETE) or \
                    bool(port.state & ofp.OFPPS_LINK_DOWN)

        if link_down:
            self._handle_port_down(dp.id, port_no)
        else:
            self._handle_port_up(dp.id, port_no)

    def _ff_covered_edge(self, dpid, nbr):
        """True if this edge's failure is fully self-healed in the datapath by a Fast Failover group -- i.e."""
        return (
            (dpid in AREA_SW_DPIDS and nbr in (CORE1_DPID, CORE2_DPID)) or
            (nbr in AREA_SW_DPIDS and dpid in (CORE1_DPID, CORE2_DPID))
        )

    def _handle_port_down(self, dpid, port_no):
        if port_no in self.down_ports[dpid]:
            return
        nbr = self.adj.get(dpid, {}).get(port_no)
        self.down_ports[dpid].add(port_no)
        if nbr is None:
            return   # host-facing port, nothing to reroute
        self.logger.warning(
            "[LINK-DOWN] {:#x}:{} <-> {:#x}  (port-status)".format(
                dpid, port_no, nbr)
        )

        ff_covered = self._ff_covered_edge(dpid, nbr)

        if ff_covered:
            self._in_failover = True
        self._rebuild_graph()

        if ff_covered:
            # CRITICAL PATH -- do NOT touch the switches here. A core-down event
            # drops many AREA<->CORE ports at once; rewriting flood rules on
            # every switch now would queue control traffic AHEAD of the
            # datapath bucket swap and stall it. The FF group needs nothing from
            # us: buckets are installed and the sibling core is pre-programmed.
            self.logger.info(
                "[FAILOVER] {:#x}<->{:#x} is FF-group-covered -- datapath "
                "self-heals; deferring flood-rule rebuild".format(dpid, nbr)
            )
            self._schedule_deferred_rebuild()
            return

        # Not FF-covered: the controller really must reroute this.
        self._rebuild_tree()
        self._push_flood_rules()
        self._flush_affected(dpid, nbr)

    def _schedule_deferred_rebuild(self):
        if self._deferred_pending:
            return
        self._deferred_pending = True

        def _worker():
            hub.sleep(1.0)          # let the port-down burst finish
            self._deferred_pending = False
            self._in_failover = False
            self._ensure_uplink_ff_groups()
            self._ensure_downlink_ff_groups()
            self._rebuild_tree()
            self._push_flood_rules()
            self.logger.info("[FAILOVER] deferred rebuild done")

        hub.spawn(_worker)

    def _handle_port_up(self, dpid, port_no):
        if port_no not in self.down_ports[dpid]:
            return
        self.down_ports[dpid].discard(port_no)
        nbr = self.adj.get(dpid, {}).get(port_no)
        self.logger.info(
            "[LINK-UP] {:#x}:{}".format(dpid, port_no)
            + (" <-> {:#x}".format(nbr) if nbr else " (host port)")
        )
        if nbr is None:
            return
        self._in_failover = False
        self._rebuild_graph()
        self._rebuild_tree()
        self._push_flood_rules()
        # Auto-revert: reinstall fabric + host pairs so a restored core-sw1
        # path is re-preferred instead of staying pinned to the backup.
        n = len(self.installed)
        for pair in list(self.installed):
            self._delete_pair_flows(pair)
        self.installed.clear()
        self.pair_paths.clear()
        self.logger.info(
            "[RESTORE] {} pair(s) flushed; reinstalling fabric + host flows"
            .format(n)
        )
        # Proactively rebuild everything rather than waiting for traffic.
        self._install_fabric()
        self._install_all_known_host_pairs()

    def _flush_affected(self, dpid, nbr):
        """Targeted flush:"""
        if self._ff_covered_edge(dpid, nbr):
            self.logger.info(
                "[FAILOVER] {:#x}<->{:#x} is FF-group-covered "
                "(sibling core pre-programmed) -- datapath self-healed".format(
                    dpid, nbr)
            )
            return
        failed   = frozenset({dpid, nbr})
        affected = [p for p, edges in self.pair_paths.items()
                    if failed in edges]
        self.logger.info(
            "[FAILOVER] {} pair(s) flushed for reroute".format(len(affected))
        )
        for pair in affected:
            self._delete_pair_flows(pair)
            self.installed.discard(pair)
            self.pair_paths.pop(pair, None)

    def _delete_pair_flows(self, pair):
        src_ip, dst_ip = pair
        for dpid, dp in self.dps.items():
            ofp, par = dp.ofproto, dp.ofproto_parser
            for a, b in ((src_ip, dst_ip), (dst_ip, src_ip)):
                dp.send_msg(par.OFPFlowMod(
                    datapath=dp, command=ofp.OFPFC_DELETE,
                    out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
                    priority=PRI_L3,
                    match=par.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                       ipv4_src=a, ipv4_dst=b)))

    # Graph = wiring intersected with liveness

    def _rebuild_graph(self):
        g = defaultdict(dict)
        for dpid, nbrs in self.wire.items():
            for nbr, port in nbrs.items():
                if port in self.down_ports[dpid]:
                    continue
                rev = self.wire.get(nbr, {}).get(dpid)
                if rev is not None and rev in self.down_ports[nbr]:
                    continue
                g[dpid][nbr] = port
        self.graph = g
        # Skip FF refresh while a failover is in flight (see _handle_port_down).
        if not self._in_failover:
            self._ensure_uplink_ff_groups()
            self._ensure_downlink_ff_groups()

    # Fast Failover groups  (now on AREA switches / cores-to-area)

    def _ensure_uplink_ff_groups(self):
        """Uplink FF group on every AREA switch:"""
        for dpid in AREA_SW_DPIDS:
            dp = self.dps.get(dpid)
            if not dp:
                continue
            port1 = self.wire.get(dpid, {}).get(CORE1_DPID)
            port2 = self.wire.get(dpid, {}).get(CORE2_DPID)
            if port1 is None or port2 is None:
                continue
            ofp, par = dp.ofproto, dp.ofproto_parser
            buckets = [
                par.OFPBucket(watch_port=port1, watch_group=ofp.OFPG_ANY,
                              actions=[par.OFPActionOutput(port1)]),
                par.OFPBucket(watch_port=port2, watch_group=ofp.OFPG_ANY,
                              actions=[par.OFPActionOutput(port2)]),
            ]
            cmd = (ofp.OFPGC_MODIFY if dpid in self.uplink_ff_installed
                   else ofp.OFPGC_ADD)
            dp.send_msg(par.OFPGroupMod(
                datapath=dp, command=cmd, type_=ofp.OFPGT_FF,
                group_id=GID_UPLINK, buckets=buckets))
            if dpid not in self.uplink_ff_installed:
                self.uplink_ff_installed.add(dpid)
                self.logger.info(
                    "[FF-GROUP] {:#x}: uplink group {} installed "
                    "(primary=port{}->core-sw1, backup=port{}->core-sw2)"
                    .format(dpid, GID_UPLINK, port1, port2)
                )

    def _ensure_downlink_ff_groups(self):
        """Downlink FF group on each core, one per AREA switch:"""
        for core_dpid in (CORE1_DPID, CORE2_DPID):
            dp = self.dps.get(core_dpid)
            if not dp:
                continue
            other = CORE2_DPID if core_dpid == CORE1_DPID else CORE1_DPID
            backbone = self.wire.get(core_dpid, {}).get(other)
            if backbone is None:
                continue
            ofp, par = dp.ofproto, dp.ofproto_parser
            for area_dpid, gid in AREA_GID.items():
                direct = self.wire.get(core_dpid, {}).get(area_dpid)
                if direct is None:
                    continue
                buckets = [
                    par.OFPBucket(watch_port=direct, watch_group=ofp.OFPG_ANY,
                                  actions=[par.OFPActionOutput(direct)]),
                    par.OFPBucket(watch_port=backbone, watch_group=ofp.OFPG_ANY,
                                  actions=[par.OFPActionOutput(backbone)]),
                ]
                key = (core_dpid, gid)
                cmd = (ofp.OFPGC_MODIFY if key in self.core_ff_installed
                       else ofp.OFPGC_ADD)
                dp.send_msg(par.OFPGroupMod(
                    datapath=dp, command=cmd, type_=ofp.OFPGT_FF,
                    group_id=gid, buckets=buckets))
                if key not in self.core_ff_installed:
                    self.core_ff_installed.add(key)
                    self.logger.info(
                        "[FF-GROUP] {:#x}: downlink group {} for {:#x} "
                        "(primary=port{} direct, backup=port{} via backbone)"
                        .format(core_dpid, gid, area_dpid, direct, backbone)
                    )

    # PROACTIVE fabric + host-pair pre-install

    def _proactive_loop(self):
        """Once LLDP wiring has been quiet for PROACTIVE_SETTLE_SECS, install the switch fabric ONCE."""
        while True:
            hub.sleep(2.0)
            if self._fabric_installed:
                continue
            if not self.graph:
                continue
            quiet = _time.time() - self._last_wire_change
            if quiet < PROACTIVE_SETTLE_SECS:
                continue
            try:
                self._ensure_uplink_ff_groups()
                self._ensure_downlink_ff_groups()
                self._install_fabric()
                self._fabric_installed = True
                self.logger.info(
                    "[PROACTIVE] fabric pre-installed; controller now idle "
                    "(host flows install at DHCP lease time)"
                )
            except Exception as e:
                self.logger.warning("[PROACTIVE] fabric install retry: {}"
                                    .format(e))

    def _install_fabric(self):
        """Pre-install switch-to-switch reachability is implicit in the L3 host-pair flows (which are what actually forward IP traffic)."""
        self._rebuild_tree()
        self._push_flood_rules()
        self._install_all_known_host_pairs()

    def _install_all_known_host_pairs(self):
        """Install L3 flows for every pair of currently-known hosts."""
        ips = list(self.hosts.keys())
        for i, a in enumerate(ips):
            for b in ips[i + 1:]:
                self._install_pair(a, b)

    def _install_pair(self, ip_a, ip_b):
        """Proactively install both directions for one host pair."""
        if not ip_a or not ip_b or ip_a == ip_b:
            return False
        pair = (min(ip_a, ip_b), max(ip_a, ip_b))
        if pair in self.installed:
            return True
        ha = self.hosts.get(ip_a)
        hb = self.hosts.get(ip_b)
        if not ha or not hb:
            return False
        fwd = self._bfs(ha["dpid"], hb["dpid"])
        if not fwd:
            return False
        rev = list(reversed(fwd))
        ok1 = self._install_path(fwd, ip_a, ip_b,
                                 ha["mac"], hb["mac"], hb["port"])
        ok2 = self._install_path(rev, ip_b, ip_a,
                                 hb["mac"], ha["mac"], ha["port"])
        if ok1 and ok2:
            self.installed.add(pair)
            edges = {frozenset({fwd[i], fwd[i + 1]})
                     for i in range(len(fwd) - 1)}
            self.pair_paths[pair] = edges
            self.logger.info(
                "[L3-PROACTIVE] installed {} <-> {} : {}".format(
                    ip_a, ip_b, "->".join("{:#x}".format(x) for x in fwd))
            )
            return True
        self.logger.warning(
            "[L3-PROACTIVE] partial install {} <-> {} -- not marked".format(
                ip_a, ip_b)
        )
        return False

    # Self-heal reconcile

    def _reconcile_loop(self):
        while True:
            hub.sleep(RECONCILE_SECS)
            try:
                self._reconcile_now()
            except Exception as e:
                self.logger.debug("[RECONCILE] skipped: {}".format(e))

    def _reconcile_now(self):
        try:
            links = get_link(self, None)
        except Exception:
            return
        if not links:
            return
        added = 0
        for lnk in links:
            s, d = lnk.src, lnk.dst
            if self.wire.get(s.dpid, {}).get(d.dpid) != s.port_no:
                self.wire[s.dpid][d.dpid] = s.port_no
                self.adj[s.dpid][s.port_no] = d.dpid
                self.down_ports[s.dpid].discard(s.port_no)
                added += 1
        if added:
            self._last_wire_change = _time.time()
            self.logger.info("[RECONCILE] restored {} wiring entr(ies)"
                             .format(added))
            self._rebuild_graph()
            self._rebuild_tree()
            self._push_flood_rules()

    # Spanning tree + flood scope

    def _rebuild_tree(self):
        if not self.graph:
            self.tree_edges = set()
            return
        root = min(self.graph)
        seen, q, edges = {root}, deque([root]), set()
        while q:
            u = q.popleft()
            for v in self.graph.get(u, {}):
                if v not in seen:
                    seen.add(v)
                    edges.add(frozenset({u, v}))
                    q.append(v)
        self.tree_edges = edges
        self.logger.info(
            "[STP] {} tree edges / {} switches".format(len(edges), len(self.dps))
        )

    def _host_facing_ports(self, dpid):
        uplink_ports = set(self.graph.get(dpid, {}).values())
        try:
            sw = get_switch(self, dpid)
            all_ports = [p.port_no for p in sw[0].ports] if sw else []
        except Exception:
            all_ports = []
        return [p for p in all_ports if p not in uplink_ports]

    def _flood_ports(self, dpid):
        host_ports = self._host_facing_ports(dpid)
        tree_ports = [port for nbr, port in self.graph.get(dpid, {}).items()
                      if frozenset({dpid, nbr}) in self.tree_edges]
        return list(set(host_ports) | set(tree_ports))

    def _push_flood_rules(self):
        for dpid, dp in self.dps.items():
            ports = self._flood_ports(dpid)
            if not ports:
                continue
            par = dp.ofproto_parser
            self._add_flow(
                dp, PRI_FLOOD,
                par.OFPMatch(eth_dst="ff:ff:ff:ff:ff:ff"),
                [par.OFPActionOutput(p) for p in ports]
            )

    # Packet-In dispatcher  (FALLBACK ONLY in the proactive design)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def pkt_in(self, ev):
        msg     = ev.msg
        dp      = msg.datapath
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return

        # Rate limiter, bucketed per (dpid, in_port, ethertype)
        key = (dp.id, in_port, eth.ethertype)
        now = _time.time()
        ws, cnt = self._rate[key]
        if now - ws >= 1.0:
            self._rate[key] = [now, 1]
        else:
            cnt += 1
            self._rate[key][1] = cnt
            if cnt > RATE_LIMIT_PPS:
                return

        arp_p = pkt.get_protocol(arp.arp)
        if arp_p:
            self._handle_arp(dp, in_port, eth, arp_p)
            return

        ip_p = pkt.get_protocol(ipv4.ipv4)
        if ip_p:
            udp_p = pkt.get_protocol(udp.udp)
            if udp_p and udp_p.dst_port == DHCP_SERVER_PORT:
                dhcp_p = pkt.get_protocol(dhcp.dhcp)
                if dhcp_p:
                    self._handle_dhcp(dp, in_port, eth, dhcp_p)
                return
            self._handle_ip(dp, in_port, eth, ip_p, msg.data)

    # ARP proxy

    def _handle_arp(self, dp, in_port, eth, arp_p):
        if eth.src == GATEWAY_MAC:
            return
        src_ip, dst_ip = arp_p.src_ip, arp_p.dst_ip
        self._learn(src_ip, arp_p.src_mac, dp.id, in_port)
        if arp_p.opcode != arp.ARP_REQUEST:
            return
        if dst_ip in GATEWAY_IPS or dst_ip in self.hosts:
            reply_mac = (GATEWAY_MAC if dst_ip in GATEWAY_IPS
                         else self.hosts[dst_ip]["mac"])
            self._arp_reply(dp, in_port, arp_p.src_mac, src_ip,
                            reply_mac, dst_ip)
        else:
            third = ip_third(dst_ip)
            if third:
                tgt = THIRD_TO_ACC_DPID.get(third)
                if tgt and tgt in self.dps:
                    self._arp_probe(self.dps[tgt],
                                    "10.10.{}.1".format(third), dst_ip)

    def _arp_reply(self, dp, port, dst_mac, dst_ip, src_mac, src_ip):
        p = packet.Packet()
        p.add_protocol(ethernet.ethernet(
            dst=dst_mac, src=src_mac, ethertype=ether_types.ETH_TYPE_ARP))
        p.add_protocol(arp.arp(
            opcode=arp.ARP_REPLY,
            src_mac=src_mac, src_ip=src_ip,
            dst_mac=dst_mac, dst_ip=dst_ip))
        p.serialize()
        self._send(dp, port, p.data)

    def _arp_probe(self, dp, gw_ip, dst_ip):
        p = packet.Packet()
        p.add_protocol(ethernet.ethernet(
            dst="ff:ff:ff:ff:ff:ff", src=GATEWAY_MAC,
            ethertype=ether_types.ETH_TYPE_ARP))
        p.add_protocol(arp.arp(
            opcode=arp.ARP_REQUEST,
            src_mac=GATEWAY_MAC, src_ip=gw_ip,
            dst_mac="00:00:00:00:00:00", dst_ip=dst_ip))
        p.serialize()
        ofp, par = dp.ofproto, dp.ofproto_parser
        ports = self._host_facing_ports(dp.id)
        if not ports:
            ports = self._flood_ports(dp.id)
        actions = ([par.OFPActionOutput(pt) for pt in ports]
                   if ports else
                   [par.OFPActionOutput(ofp.OFPP_FLOOD)])
        dp.send_msg(par.OFPPacketOut(
            datapath=dp, buffer_id=ofp.OFP_NO_BUFFER,
            in_port=ofp.OFPP_CONTROLLER,
            actions=actions, data=p.data))

    # DHCP server (built-in) -- INSTALLS HOST FLOWS AT LEASE TIME (proactive)

    def _handle_dhcp(self, dp, in_port, eth, dhcp_p):
        third = ACC_DPID_TO_THIRD.get(dp.id)
        if third is None:
            self.logger.warning(
                "[DHCP] Unexpected packet on non-access {:#x}, ignored"
                .format(dp.id))
            return

        msg_type = None
        for opt in dhcp_p.options.option_list:
            if opt.tag == dhcp.DHCP_MESSAGE_TYPE_OPT:
                msg_type = opt.value[0]
                break
        if msg_type not in (dhcp.DHCP_DISCOVER, dhcp.DHCP_REQUEST):
            return

        gw_ip = "10.10.{}.1".format(third)
        client_mac = eth.src

        if client_mac not in self.dhcp_leases:
            idx = self.subnet_counter[third]
            self.subnet_counter[third] += 1
            assigned_ip = "10.10.{}.{}".format(third, DHCP_BASE + idx)
            self.dhcp_leases[client_mac] = assigned_ip
        else:
            assigned_ip = self.dhcp_leases[client_mac]

        reply_type = (dhcp.DHCP_OFFER if msg_type == dhcp.DHCP_DISCOVER
                      else dhcp.DHCP_ACK)
        self.logger.info(
            "[DHCP] {} {} -> {} on {:#x}:{}".format(
                "OFFER" if reply_type == dhcp.DHCP_OFFER else "ACK",
                assigned_ip, client_mac, dp.id, in_port)
        )

        # On ACK: learn the host AND proactively install its flows to every
        # other known host. This is the heart of the proactive design -- the
        # controller knows ip/mac/location because it granted the lease, so it
        # programs the datapath NOW instead of waiting for a packet-in.
        if reply_type == dhcp.DHCP_ACK:
            self._learn(assigned_ip, client_mac, dp.id, in_port)
            for other_ip in list(self.hosts.keys()):
                if other_ip != assigned_ip:
                    self._install_pair(assigned_ip, other_ip)

        options = dhcp.options(option_list=[
            dhcp.option(dhcp.DHCP_MESSAGE_TYPE_OPT, bytes([reply_type])),
            dhcp.option(dhcp.DHCP_SUBNET_MASK_OPT,
                        addrconv.ipv4.text_to_bin("255.255.255.0")),
            dhcp.option(dhcp.DHCP_GATEWAY_ADDR_OPT,
                        addrconv.ipv4.text_to_bin(gw_ip)),
            dhcp.option(dhcp.DHCP_DNS_SERVER_ADDR_OPT,
                        addrconv.ipv4.text_to_bin(DHCPDNS_IP)),
            dhcp.option(dhcp.DHCP_IP_ADDR_LEASE_TIME_OPT,
                        struct.pack("!I", LEASE_SECONDS)),
            dhcp.option(dhcp.DHCP_SERVER_IDENTIFIER_OPT,
                        addrconv.ipv4.text_to_bin(gw_ip)),
        ])

        reply_dhcp = dhcp.dhcp(
            op=2, chaddr=dhcp_p.chaddr, htype=1, hlen=6, hops=0,
            xid=dhcp_p.xid, secs=0, flags=dhcp_p.flags,
            ciaddr="0.0.0.0", yiaddr=assigned_ip,
            siaddr=gw_ip, giaddr="0.0.0.0",
            options=options)

        p = packet.Packet()
        p.add_protocol(ethernet.ethernet(
            dst="ff:ff:ff:ff:ff:ff", src=GATEWAY_MAC,
            ethertype=ether_types.ETH_TYPE_IP))
        p.add_protocol(ipv4.ipv4(
            src=gw_ip, dst="255.255.255.255", proto=17))
        p.add_protocol(udp.udp(
            src_port=DHCP_SERVER_PORT, dst_port=DHCP_CLIENT_PORT))
        p.add_protocol(reply_dhcp)
        p.serialize()
        self._send(dp, in_port, p.data)

    # IP routing (FALLBACK: only reached for a genuinely unknown packet)

    def _handle_ip(self, dp, in_port, eth, ip_p, raw):
        src_ip, dst_ip = ip_p.src, ip_p.dst
        self._learn(src_ip, eth.src, dp.id, in_port)

        if dst_ip not in self.hosts:
            third = ip_third(dst_ip)
            if third:
                tgt = THIRD_TO_ACC_DPID.get(third)
                if tgt and tgt in self.dps:
                    self._arp_probe(self.dps[tgt],
                                    "10.10.{}.1".format(third), dst_ip)
            return

        dst_h = self.hosts[dst_ip]
        src_h = self.hosts.get(src_ip)
        if not src_h:
            return

        pair = (min(src_ip, dst_ip), max(src_ip, dst_ip))
        if pair not in self.installed:
            # Proactive install should already have covered this; if we are
            # here it is a genuinely new/unknown pair -> install now.
            self._install_pair(src_ip, dst_ip)

        # Forward this specific packet so it is not lost while flows settle.
        fwd = self._bfs(src_h["dpid"], dst_h["dpid"])
        if fwd and len(fwd) >= 2:
            out = self.graph[fwd[0]].get(fwd[1])
            if out:
                self._send(dp, out, raw)
        elif fwd and len(fwd) == 1:
            self._send(dp, dst_h["port"], raw)

    # Host learning

    def _learn(self, ip, mac, dpid, port):
        if not ip or ip == "0.0.0.0":
            return
        if dpid not in ACC_DPID_TO_THIRD:
            return   # reject learning from core/dist/area switches
        expected = ACC_DPID_TO_THIRD.get(dpid)
        t = ip_third(ip)
        if expected is not None and t is not None and expected != t:
            return
        prev = self.hosts.get(ip)
        if not prev:
            self.logger.info("[HOST] NEW {}/{} on {:#x}:{}".format(
                ip, mac, dpid, port))
        elif prev["dpid"] != dpid:
            self.logger.warning(
                "[HOST] MOVE IGNORED: {} tried {:#x} -> {:#x} (keeping original)"
                .format(ip, prev["dpid"], dpid))
            return
        self.hosts[ip] = {"mac": mac, "dpid": dpid, "port": port}

    # Weighted shortest path (Dijkstra; core-sw2 penalised)

    def _edge_cost(self, u, v):
        if u == CORE2_DPID or v == CORE2_DPID:
            return EDGE_COST_VIA_CORE2
        return EDGE_COST_DEFAULT

    def _bfs(self, src, dst):
        """Priority-weighted Dijkstra:"""
        if src == dst:
            return [src]
        dist, prev, visited = {src: 0}, {}, set()
        pq = [(0, src)]
        while pq:
            d, u = heapq.heappop(pq)
            if u in visited:
                continue
            visited.add(u)
            if u == dst:
                break
            for v, _port in self.graph.get(u, {}).items():
                if v in visited:
                    continue
                nd = d + self._edge_cost(u, v)
                if nd < dist.get(v, float("inf")):
                    dist[v] = nd
                    prev[v] = u
                    heapq.heappush(pq, (nd, v))
        if dst not in prev and dst != src:
            return []
        path = [dst]
        while path[-1] != src:
            path.append(prev[path[-1]])
        path.reverse()
        return path

    # Flow installation

    def _install_path(self, path, src_ip, dst_ip,
                      src_mac, dst_mac, final_port):
        """Install the flow on every switch along `path`."""
        for i, dpid in enumerate(path):
            dp = self.dps.get(dpid)
            if not dp:
                self.logger.error(
                    "[L3] Switch {:#x} not connected -- aborting install "
                    "{}->{}".format(dpid, src_ip, dst_ip))
                return False
            par     = dp.ofproto_parser
            is_last = (i == len(path) - 1)
            if is_last:
                actions = [
                    par.OFPActionSetField(eth_src=GATEWAY_MAC),
                    par.OFPActionSetField(eth_dst=dst_mac),
                    par.OFPActionOutput(final_port),
                ]
            else:
                nxt = path[i + 1]
                out = self.graph[dpid].get(nxt)
                if out is None:
                    self.logger.error(
                        "[L3] Missing edge {:#x}->{:#x}".format(dpid, nxt))
                    return False
                if (dpid in AREA_SW_DPIDS and nxt in (CORE1_DPID, CORE2_DPID)
                        and dpid in self.uplink_ff_installed):
                    # Request direction: area switch's uplink decision.
                    actions = [par.OFPActionGroup(GID_UPLINK)]
                elif (dpid in (CORE1_DPID, CORE2_DPID) and nxt in AREA_GID
                        and (dpid, AREA_GID[nxt]) in self.core_ff_installed):
                    # Reply direction: core switch's downlink decision.
                    actions = [par.OFPActionGroup(AREA_GID[nxt])]
                else:
                    actions = [par.OFPActionOutput(out)]
            self._add_flow(
                dp, PRI_L3,
                par.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                             ipv4_src=src_ip, ipv4_dst=dst_ip),
                actions, idle_timeout=0
            )

        # Mirror onto the sibling core (see long note in previous version):
        # an FF bucket swap only changes the OUTPUT PORT; the flow entry must
        # already exist on the core the traffic swaps to.
        for i, dpid in enumerate(path):
            if dpid not in (CORE1_DPID, CORE2_DPID):
                continue
            if i == len(path) - 1:
                continue
            sibling = CORE2_DPID if dpid == CORE1_DPID else CORE1_DPID
            sdp = self.dps.get(sibling)
            if not sdp:
                continue
            nxt  = path[i + 1]
            sout = self.graph.get(sibling, {}).get(nxt)
            if sout is None:
                continue
            spar = sdp.ofproto_parser
            if (nxt in AREA_GID
                    and (sibling, AREA_GID[nxt]) in self.core_ff_installed):
                sactions = [spar.OFPActionGroup(AREA_GID[nxt])]
            else:
                sactions = [spar.OFPActionOutput(sout)]
            self._add_flow(
                sdp, PRI_L3,
                spar.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                              ipv4_src=src_ip, ipv4_dst=dst_ip),
                sactions, idle_timeout=0
            )

        return True

    # OpenFlow helpers

    def _add_flow(self, dp, priority, match, actions, idle_timeout=0):
        ofp, par = dp.ofproto, dp.ofproto_parser
        dp.send_msg(par.OFPFlowMod(
            datapath=dp, priority=priority, match=match,
            instructions=[
                par.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)
            ],
            idle_timeout=idle_timeout,
        ))

    def _send(self, dp, port, data):
        ofp, par = dp.ofproto, dp.ofproto_parser
        dp.send_msg(par.OFPPacketOut(
            datapath=dp, buffer_id=ofp.OFP_NO_BUFFER,
            in_port=ofp.OFPP_CONTROLLER,
            actions=[par.OFPActionOutput(port)],
            data=data,
        ))
