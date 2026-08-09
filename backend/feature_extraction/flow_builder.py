"""
feature_extraction/flow_builder.py — Bidirectional flow aggregation & CICIDS2017 feature calculation.

Accumulates raw network packets (Scapy Packet objects), aggregates them into
bidirectional 5-tuple network flows, detects flow termination (FIN/RST or timeout),
and computes the 76 CICIDS2017 feature vector for every completed flow.
"""
from __future__ import annotations

import math
import time
import logging
from typing import Any, Dict, List, Tuple, Optional

import numpy as np

from feature_extraction.feature_names import FEATURE_NAMES

logger = logging.getLogger(__name__)

# Constants
FLOW_TIMEOUT: float = 120.0       # Max flow duration in seconds
FLOW_IDLE_TIMEOUT: float = 15.0   # Inactivity timeout in seconds
IDLE_THRESHOLD: float = 1.0       # Gap in seconds to count as an idle period


class FlowBucket:
    """Stores packet metadata for a single bidirectional flow."""

    def __init__(self, key: Tuple[str, str, int, int, str], start_ts: float) -> None:
        self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol = key
        self.start_ts: float = start_ts
        self.last_ts: float = start_ts

        self.fwd_packets: List[Dict[str, Any]] = []
        self.bwd_packets: List[Dict[str, Any]] = []
        self.all_packets: List[Dict[str, Any]] = []

        self.fwd_last_ts: Optional[float] = None
        self.bwd_last_ts: Optional[float] = None

        self.fin_seen: bool = False
        self.rst_seen: bool = False

    def add_packet(self, pkt_meta: Dict[str, Any], direction: str) -> None:
        ts = pkt_meta["timestamp"]
        self.last_ts = ts
        self.all_packets.append(pkt_meta)

        if direction == "fwd":
            self.fwd_packets.append(pkt_meta)
            self.fwd_last_ts = ts
        else:
            self.bwd_packets.append(pkt_meta)
            self.bwd_last_ts = ts

        flags = pkt_meta.get("flags", "")
        if "F" in flags:
            self.fin_seen = True
        if "R" in flags:
            self.rst_seen = True

    def is_expired(self, current_ts: float) -> bool:
        if self.fin_seen or self.rst_seen:
            return True
        if (current_ts - self.last_ts) >= FLOW_IDLE_TIMEOUT:
            return True
        if (current_ts - self.start_ts) >= FLOW_TIMEOUT:
            return True
        return False

    def to_feature_dict(self) -> Dict[str, Any]:
        """Compute the 76 canonical CICIDS2017 features for this flow."""
        total_fwd_pkts = len(self.fwd_packets)
        total_bwd_pkts = len(self.bwd_packets)
        total_pkts = len(self.all_packets)

        duration_sec = max(0.0, self.last_ts - self.start_ts)
        duration_us = duration_sec * 1_000_000.0  # CICFlowMeter uses microseconds

        # Packet lengths
        fwd_lens = [p["length"] for p in self.fwd_packets]
        bwd_lens = [p["length"] for p in self.bwd_packets]
        all_lens = [p["length"] for p in self.all_packets]

        fwd_len_tot = sum(fwd_lens)
        bwd_len_tot = sum(bwd_lens)
        tot_len = fwd_len_tot + bwd_len_tot

        fwd_len_max = float(max(fwd_lens)) if fwd_lens else 0.0
        fwd_len_min = float(min(fwd_lens)) if fwd_lens else 0.0
        fwd_len_mean = float(np.mean(fwd_lens)) if fwd_lens else 0.0
        fwd_len_std = float(np.std(fwd_lens, ddof=1)) if len(fwd_lens) > 1 else 0.0

        bwd_len_max = float(max(bwd_lens)) if bwd_lens else 0.0
        bwd_len_min = float(min(bwd_lens)) if bwd_lens else 0.0
        bwd_len_mean = float(np.mean(bwd_lens)) if bwd_lens else 0.0
        bwd_len_std = float(np.std(bwd_lens, ddof=1)) if len(bwd_lens) > 1 else 0.0

        all_len_max = float(max(all_lens)) if all_lens else 0.0
        all_len_min = float(min(all_lens)) if all_lens else 0.0
        all_len_mean = float(np.mean(all_lens)) if all_lens else 0.0
        all_len_std = float(np.std(all_lens, ddof=1)) if len(all_lens) > 1 else 0.0
        all_len_var = float(np.var(all_lens, ddof=1)) if len(all_lens) > 1 else 0.0

        # Flow rates
        flow_bytes_s = (tot_len / duration_sec) if duration_sec > 0 else 0.0
        flow_pkts_s = (total_pkts / duration_sec) if duration_sec > 0 else 0.0
        fwd_pkts_s = (total_fwd_pkts / duration_sec) if duration_sec > 0 else 0.0
        bwd_pkts_s = (total_bwd_pkts / duration_sec) if duration_sec > 0 else 0.0

        # Inter-arrival times (IAT)
        def _calc_iat(packets: List[Dict[str, Any]]) -> Tuple[float, float, float, float, float]:
            if len(packets) < 2:
                return 0.0, 0.0, 0.0, 0.0, 0.0
            ts_list = [p["timestamp"] for p in packets]
            iats = [(ts_list[i] - ts_list[i - 1]) * 1_000_000.0 for i in range(1, len(ts_list))]
            tot = float(sum(iats))
            mean_v = float(np.mean(iats))
            std_v = float(np.std(iats, ddof=1)) if len(iats) > 1 else 0.0
            max_v = float(max(iats))
            min_v = float(min(iats))
            return tot, mean_v, std_v, max_v, min_v

        flow_iat_tot, flow_iat_mean, flow_iat_std, flow_iat_max, flow_iat_min = _calc_iat(self.all_packets)
        fwd_iat_tot, fwd_iat_mean, fwd_iat_std, fwd_iat_max, fwd_iat_min = _calc_iat(self.fwd_packets)
        bwd_iat_tot, bwd_iat_mean, bwd_iat_std, bwd_iat_max, bwd_iat_min = _calc_iat(self.bwd_packets)

        # Flags count
        fwd_psh = sum(1 for p in self.fwd_packets if "P" in p.get("flags", ""))
        bwd_psh = sum(1 for p in self.bwd_packets if "P" in p.get("flags", ""))
        fwd_urg = sum(1 for p in self.fwd_packets if "U" in p.get("flags", ""))
        bwd_urg = sum(1 for p in self.bwd_packets if "U" in p.get("flags", ""))

        fin_count = sum(1 for p in self.all_packets if "F" in p.get("flags", ""))
        syn_count = sum(1 for p in self.all_packets if "S" in p.get("flags", ""))
        rst_count = sum(1 for p in self.all_packets if "R" in p.get("flags", ""))
        psh_count = sum(1 for p in self.all_packets if "P" in p.get("flags", ""))
        ack_count = sum(1 for p in self.all_packets if "A" in p.get("flags", ""))
        urg_count = sum(1 for p in self.all_packets if "U" in p.get("flags", ""))
        cwe_count = sum(1 for p in self.all_packets if "C" in p.get("flags", ""))
        ece_count = sum(1 for p in self.all_packets if "E" in p.get("flags", ""))

        # Header lengths
        fwd_hdr_len = sum(p.get("header_len", 20) for p in self.fwd_packets)
        bwd_hdr_len = sum(p.get("header_len", 20) for p in self.bwd_packets)

        # Ratios & Sizes
        down_up_ratio = (total_bwd_pkts / total_fwd_pkts) if total_fwd_pkts > 0 else 0.0
        avg_pkt_size = (tot_len / total_pkts) if total_pkts > 0 else 0.0
        avg_fwd_seg_size = fwd_len_mean
        avg_bwd_seg_size = bwd_len_mean

        # TCP Window sizes
        fwd_win_bytes = self.fwd_packets[0].get("win_size", 0) if self.fwd_packets else 0
        bwd_win_bytes = self.bwd_packets[0].get("win_size", 0) if self.bwd_packets else 0

        # Active Data Packets (fwd packets with payload > 0)
        act_data_pkt_fwd = sum(1 for p in self.fwd_packets if p.get("payload_len", 0) > 0)

        # Minimum segment size forward (TCP header size)
        min_seg_size_fwd = min([p.get("header_len", 20) for p in self.fwd_packets]) if self.fwd_packets else 20

        # Active & Idle periods calculation
        active_times: List[float] = []
        idle_times: List[float] = []

        if len(self.all_packets) > 1:
            current_active_start = self.all_packets[0]["timestamp"]
            last_pkt_ts = self.all_packets[0]["timestamp"]

            for p in self.all_packets[1:]:
                gap = p["timestamp"] - last_pkt_ts
                if gap >= IDLE_THRESHOLD:
                    active_duration = (last_pkt_ts - current_active_start) * 1_000_000.0
                    active_times.append(max(0.0, active_duration))
                    idle_times.append(gap * 1_000_000.0)
                    current_active_start = p["timestamp"]
                last_pkt_ts = p["timestamp"]

            final_active = (last_pkt_ts - current_active_start) * 1_000_000.0
            active_times.append(max(0.0, final_active))
        else:
            active_times.append(duration_us)

        active_mean = float(np.mean(active_times)) if active_times else 0.0
        active_std = float(np.std(active_times, ddof=1)) if len(active_times) > 1 else 0.0
        active_max = float(max(active_times)) if active_times else 0.0
        active_min = float(min(active_times)) if active_times else 0.0

        idle_mean = float(np.mean(idle_times)) if idle_times else 0.0
        idle_std = float(np.std(idle_times, ddof=1)) if len(idle_times) > 1 else 0.0
        idle_max = float(max(idle_times)) if idle_times else 0.0
        idle_min = float(min(idle_times)) if idle_times else 0.0

        features: Dict[str, Any] = {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,

            "Flow Duration": duration_us,
            "Total Fwd Packets": total_fwd_pkts,
            "Total Backward Packets": total_bwd_pkts,
            "Total Length of Fwd Packets": fwd_len_tot,
            "Total Length of Bwd Packets": bwd_len_tot,
            "Fwd Packet Length Max": fwd_len_max,
            "Fwd Packet Length Min": fwd_len_min,
            "Fwd Packet Length Mean": fwd_len_mean,
            "Fwd Packet Length Std": fwd_len_std,
            "Bwd Packet Length Max": bwd_len_max,
            "Bwd Packet Length Min": bwd_len_min,
            "Bwd Packet Length Mean": bwd_len_mean,
            "Bwd Packet Length Std": bwd_len_std,
            "Flow Bytes/s": flow_bytes_s,
            "Flow Packets/s": flow_pkts_s,
            "Flow IAT Mean": flow_iat_mean,
            "Flow IAT Std": flow_iat_std,
            "Flow IAT Max": flow_iat_max,
            "Flow IAT Min": flow_iat_min,
            "Fwd IAT Total": fwd_iat_tot,
            "Fwd IAT Mean": fwd_iat_mean,
            "Fwd IAT Std": fwd_iat_std,
            "Fwd IAT Max": fwd_iat_max,
            "Fwd IAT Min": fwd_iat_min,
            "Bwd IAT Total": bwd_iat_tot,
            "Bwd IAT Mean": bwd_iat_mean,
            "Bwd IAT Std": bwd_iat_std,
            "Bwd IAT Max": bwd_iat_max,
            "Bwd IAT Min": bwd_iat_min,
            "Fwd PSH Flags": fwd_psh,
            "Bwd PSH Flags": bwd_psh,
            "Fwd URG Flags": fwd_urg,
            "Bwd URG Flags": bwd_urg,
            "Fwd Header Length": fwd_hdr_len,
            "Bwd Header Length": bwd_hdr_len,
            "Fwd Packets/s": fwd_pkts_s,
            "Bwd Packets/s": bwd_pkts_s,
            "Min Packet Length": all_len_min,
            "Max Packet Length": all_len_max,
            "Packet Length Mean": all_len_mean,
            "Packet Length Std": all_len_std,
            "Packet Length Variance": all_len_var,
            "FIN Flag Count": fin_count,
            "SYN Flag Count": syn_count,
            "RST Flag Count": rst_count,
            "PSH Flag Count": psh_count,
            "ACK Flag Count": ack_count,
            "URG Flag Count": urg_count,
            "CWE Flag Count": cwe_count,
            "ECE Flag Count": ece_count,
            "Down/Up Ratio": down_up_ratio,
            "Average Packet Size": avg_pkt_size,
            "Avg Fwd Segment Size": avg_fwd_seg_size,
            "Avg Bwd Segment Size": avg_bwd_seg_size,
            "Fwd Avg Bytes/Bulk": 0.0,
            "Fwd Avg Packets/Bulk": 0.0,
            "Fwd Avg Bulk Rate": 0.0,
            "Bwd Avg Bytes/Bulk": 0.0,
            "Bwd Avg Packets/Bulk": 0.0,
            "Bwd Avg Bulk Rate": 0.0,
            "Subflow Fwd Packets": total_fwd_pkts,
            "Subflow Fwd Bytes": fwd_len_tot,
            "Subflow Bwd Packets": total_bwd_pkts,
            "Subflow Bwd Bytes": bwd_len_tot,
            "Init_Win_bytes_forward": fwd_win_bytes,
            "Init_Win_bytes_backward": bwd_win_bytes,
            "act_data_pkt_fwd": act_data_pkt_fwd,
            "min_seg_size_forward": min_seg_size_fwd,
            "Active Mean": active_mean,
            "Active Std": active_std,
            "Active Max": active_max,
            "Active Min": active_min,
            "Idle Mean": idle_mean,
            "Idle Std": idle_std,
            "Idle Max": idle_max,
            "Idle Min": idle_min,
        }

        return features


class FlowBuilder:
    """
    Accumulates network packets and groups them into bidirectional flows.
    """

    def __init__(self) -> None:
        self._active_flows: Dict[Tuple[str, str, int, int, str], FlowBucket] = {}

    @property
    def active_flows(self) -> Dict[Tuple[str, str, int, int, str], FlowBucket]:
        return self._active_flows

    @property
    def active_flow_count(self) -> int:
        return len(self._active_flows)

    def get_active_flow_count(self) -> int:
        return len(self._active_flows)

    def add_packet(self, packet: Any) -> Optional[Dict[str, Any]]:
        """
        Extract IP/TCP/UDP/ICMP fields from a Scapy packet and insert into flow bucket.
        """
        try:

            from scapy.layers.inet import IP, TCP, UDP, ICMP
            from scapy.layers.inet6 import IPv6

            ts = float(getattr(packet, "time", time.time()))

            src_ip, dst_ip = "", ""
            proto = "IP"

            if packet.haslayer(IP):
                ip = packet[IP]
                src_ip, dst_ip = ip.src, ip.dst
            elif packet.haslayer(IPv6):
                ip6 = packet[IPv6]
                src_ip, dst_ip = ip6.src, ip6.dst
            else:
                return None  # Non-IP packet

            src_port, dst_port = 0, 0
            flags = ""
            hdr_len = 20
            payload_len = 0
            win_size = 0

            if packet.haslayer(TCP):
                tcp = packet[TCP]
                src_port, dst_port = tcp.sport, tcp.dport
                proto = "TCP"
                fval = int(tcp.flags)
                flag_chars = []
                if fval & 0x01: flag_chars.append("F")
                if fval & 0x02: flag_chars.append("S")
                if fval & 0x04: flag_chars.append("R")
                if fval & 0x08: flag_chars.append("P")
                if fval & 0x10: flag_chars.append("A")
                if fval & 0x20: flag_chars.append("U")
                if fval & 0x40: flag_chars.append("E")
                if fval & 0x80: flag_chars.append("C")
                flags = "".join(flag_chars)
                dataofs = getattr(tcp, "dataofs", None)
                hdr_len = (int(dataofs) if dataofs is not None else 5) * 4

                payload_len = len(tcp.payload) if tcp.payload else 0
                win_size = int(getattr(tcp, "window", 0))
            elif packet.haslayer(UDP):
                udp = packet[UDP]
                src_port, dst_port = udp.sport, udp.dport
                proto = "UDP"
                hdr_len = 8
                payload_len = len(udp.payload) if udp.payload else 0
            elif packet.haslayer(ICMP):
                proto = "ICMP"
                hdr_len = 8
                payload_len = len(packet[ICMP].payload) if packet[ICMP].payload else 0

            pkt_len = len(packet)

            pkt_meta = {
                "timestamp": ts,
                "length": pkt_len,
                "payload_len": payload_len,
                "header_len": hdr_len,
                "flags": flags,
                "win_size": win_size,
            }

            fwd_key = (src_ip, dst_ip, src_port, dst_port, proto)
            bwd_key = (dst_ip, src_ip, dst_port, src_port, proto)

            if fwd_key in self._active_flows:
                self._active_flows[fwd_key].add_packet(pkt_meta, "fwd")
            elif bwd_key in self._active_flows:
                self._active_flows[bwd_key].add_packet(pkt_meta, "bwd")
            else:
                bucket = FlowBucket(fwd_key, ts)
                bucket.add_packet(pkt_meta, "fwd")
                self._active_flows[fwd_key] = bucket

        except Exception as e:
            logger.debug("Failed to process packet in FlowBuilder: %s", e)

        return None

    def flush_expired_flows(self, force_all: bool = False) -> List[Dict[str, Any]]:
        """Harvest completed or timed-out flows from active flow table."""
        return self.get_completed_flows(force_all=force_all)

    def get_completed_flows(self, force_all: bool = False) -> List[Dict[str, Any]]:
        """
        Harvest completed or timed-out flows from active flow table.
        """
        current_ts = time.time()
        completed: List[Dict[str, Any]] = []
        keys_to_remove: List[Tuple[str, str, int, int, str]] = []

        for key, bucket in self._active_flows.items():
            if force_all or bucket.is_expired(current_ts):
                completed.append(bucket.to_feature_dict())
                keys_to_remove.append(key)

        for k in keys_to_remove:
            del self._active_flows[k]

        return completed
