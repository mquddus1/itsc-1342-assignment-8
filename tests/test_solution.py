# Mohammed Abdul Quddus - Assignment 8 Unit Tests
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'code')))
from solution import analyze_capture_records, aggregate_pcap_traffic

# Fixed test fixture from the course starter file screenshot.
mock_records = [
    {'src': '192.168.1.15', 'dst': '8.8.8.8', 'proto': 'udp'},
    {'src': '192.168.1.15', 'dst': '142.250.190.46', 'proto': 'tcp'},
    {'src': '192.168.1.15', 'dst': '8.8.8.8', 'proto': 'udp'},
]

result = analyze_capture_records(mock_records)
assert result['protocols_count'] == {'UDP': 2, 'TCP': 1}, 'Failed Test 1: Protocol counts mismatch'
assert result['unique_destinations'] == ['142.250.190.46', '8.8.8.8'], 'Failed Test 2: Must be a sorted list'
empty_result = analyze_capture_records([])
assert empty_result['protocols_count'] == {}, 'Failed Test 3: Check dictionary keys'

# Additional tests based on the assignment's written instructions.
report = aggregate_pcap_traffic([
    {'src': '192.168.1.15', 'dst': '8.8.8.8', 'proto': 'udp', 'syn_flag': False},
    {'src': '192.168.1.10', 'dst': '8.8.8.8', 'proto': 'tcp', 'syn_flag': True},
    {'src': '192.168.1.15', 'dst': '1.1.1.1', 'proto': 'tcp', 'syn_flag': True},
])
assert report['protocols'] == {'UDP': 1, 'TCP': 2}
assert report['unique_sources'] == ['192.168.1.10', '192.168.1.15']
assert report['total_syn_packets'] == 2
assert aggregate_pcap_traffic([]) == {'protocols': {}, 'unique_sources': [], 'total_syn_packets': 0}

print('ALL UNIT TESTS PASSED - ASSIGNMENT 8')
