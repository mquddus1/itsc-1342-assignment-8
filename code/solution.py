# Mohammed Abdul Quddus - Assignment 8
"""Aggregate packet metadata extracted from Wireshark captures."""

import json
from collections import Counter
from pathlib import Path


def analyze_capture_records(records):
    """Count protocols and return sorted unique destinations from packet records.

    Each record is a dictionary that may contain 'proto' and 'dst'.
    """
    protocols = Counter()
    unique_dsts = set()

    for pkt in records:
        proto = str(pkt.get('proto', 'UNKNOWN')).upper()
        protocols[proto] += 1
        if 'dst' in pkt:
            unique_dsts.add(pkt['dst'])

    return {
        'protocols_count': dict(protocols),
        'unique_destinations': sorted(unique_dsts),
    }


def aggregate_pcap_traffic(packet_list):
    """Aggregate the protocols, source IPs and TCP SYN flags in packet dictionaries."""
    protocols = Counter()
    unique_sources = set()
    total_syn_packets = 0

    for packet in packet_list:
        proto = str(packet.get('proto', 'UNKNOWN')).upper()
        protocols[proto] += 1
        if packet.get('src') is not None:
            unique_sources.add(packet['src'])
        if packet.get('syn_flag') is True:
            total_syn_packets += 1

    return {
        'protocols': dict(protocols),
        'unique_sources': sorted(unique_sources),
        'total_syn_packets': total_syn_packets,
    }


def _from_wireshark_json(packets):
    """Convert Wireshark Export Packet Dissections JSON to simple packet records."""
    records = []
    for packet in packets:
        layers = packet.get('_source', {}).get('layers', {})
        ip = layers.get('ip', {})
        ipv6 = layers.get('ipv6', {})
        src = ip.get('ip.src') or ipv6.get('ipv6.src')
        dst = ip.get('ip.dst') or ipv6.get('ipv6.dst')
        if isinstance(src, list):
            src = src[0] if src else None
        if isinstance(dst, list):
            dst = dst[0] if dst else None
        frame = layers.get('frame', {})
        proto = frame.get('frame.protocols', '')
        if isinstance(proto, list):
            proto = proto[0] if proto else ''
        protocol = str(proto).split(':')[-1].upper() if proto else 'UNKNOWN'
        tcp = layers.get('tcp', {})
        syn = tcp.get('tcp.flags.syn', '0')
        if isinstance(syn, list):
            syn = syn[0] if syn else '0'
        records.append({
            'proto': protocol,
            'src': src,
            'dst': dst,
            'syn_flag': str(syn).lower() in ('1', 'true', '0x0001'),
        })
    return records


if __name__ == '__main__':
    path = Path(__file__).with_name('capture.json')
    if path.exists():
        with path.open(encoding='utf-8') as f:
            packets = json.load(f)
        print('LIVE CAPTURE SUMMARY:')
        print(aggregate_pcap_traffic(_from_wireshark_json(packets)))
    else:
        print('No capture.json found. Export your own Wireshark capture to code/capture.json.')
