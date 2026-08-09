"""
tests/test_live_monitoring.py — Phase 7 Live Network Monitoring Test Suite.

Tests interface discovery, FlowBuilder 76-feature extraction,
LiveCaptureEngine lifecycle, and REST monitoring endpoints.
"""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient
from scapy.layers.inet import IP, TCP

from api.main import app
from feature_extraction.flow_builder import FlowBuilder, FlowBucket
from feature_extraction.feature_names import FEATURE_NAMES
from ingestion.capture import enumerate_interfaces, LiveCaptureEngine

client = TestClient(app)


def test_interface_enumeration():
    print("\n--- Testing Interface Enumeration ---")
    ifaces = enumerate_interfaces()
    assert isinstance(ifaces, list)
    assert len(ifaces) > 0, "Expected at least 1 network interface"

    first = ifaces[0]
    print(f"Discovered {len(ifaces)} interfaces. Sample: {first}")
    assert "name" in first
    assert "description" in first
    assert "mac_address" in first
    assert "ip_address" in first
    assert "status" in first
    assert "speed" in first


def get_auth_headers():
    resp = client.post("/auth/login", json={"username": "admin", "password": "admin123"})
    if resp.status_code == 200:
        token = resp.json()["access_token"]
        return {"Authorization": f"Bearer {token}"}
    return {}


def test_flow_builder_76_features():
    print("\n--- Testing FlowBuilder 76 CICIDS2017 Feature Extraction ---")
    builder = FlowBuilder()

    # Create dummy TCP packets using fresh timestamps right before adding
    now = time.time()

    pkt_fwd1 = IP(src="192.168.1.10", dst="10.0.0.1") / TCP(sport=12345, dport=80, flags="S", window=8192)
    pkt_fwd1.time = now

    pkt_bwd1 = IP(src="10.0.0.1", dst="192.168.1.10") / TCP(sport=80, dport=12345, flags="SA", window=16384)
    pkt_bwd1.time = now + 0.001

    pkt_fwd2 = IP(src="192.168.1.10", dst="10.0.0.1") / TCP(sport=12345, dport=80, flags="PA") / b"GET / HTTP/1.1\r\n\r\n"
    pkt_fwd2.time = now + 0.002

    pkt_bwd2 = IP(src="10.0.0.1", dst="192.168.1.10") / TCP(sport=80, dport=12345, flags="FA") / b"HTTP/1.1 200 OK\r\n\r\n"
    pkt_bwd2.time = now + 0.003

    builder.add_packet(pkt_fwd1)
    builder.add_packet(pkt_bwd1)
    builder.add_packet(pkt_fwd2)
    builder.add_packet(pkt_bwd2)

    completed = builder.get_completed_flows(force_all=True)
    assert len(completed) == 1

    flow = completed[0]
    for fname in FEATURE_NAMES:
        assert fname in flow, f"Missing feature '{fname}' in extracted flow dict"


def test_get_interfaces_endpoint():
    print("\n--- Testing GET /interfaces ---")
    response = client.get("/interfaces")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    print(f"GET /interfaces returned {len(data)} items")


def test_monitor_status_endpoint():
    print("\n--- Testing GET /monitor/status ---")
    response = client.get("/monitor/status")
    assert response.status_code == 200
    data = response.json()
    print("GET /monitor/status payload:", data)
    assert "active" in data
    assert "packets_per_sec" in data
    assert "flows_per_sec" in data
    assert "active_flows" in data
    assert "bandwidth_bps" in data
    assert "total_packets_captured" in data
    assert "total_flows_processed" in data
    assert "known_attacks_detected" in data
    assert "unknown_attacks_detected" in data


def test_monitor_start_and_stop_endpoints():
    print("\n--- Testing POST /monitor/start and POST /monitor/stop ---")
    ifaces = enumerate_interfaces()
    iface_name = ifaces[0]["name"]
    headers = get_auth_headers()

    # Start
    resp_start = client.post("/monitor/start", json={"interface": iface_name}, headers=headers)
    assert resp_start.status_code in (200, 202)
    start_data = resp_start.json()
    print("POST /monitor/start response:", start_data)
    assert start_data.get("status") in ("started", "success")

    # Verify status active
    resp_status = client.get("/monitor/status")
    assert resp_status.json()["active"] is True

    # Attempt double start -> expect 409 Conflict
    resp_start_again = client.post("/monitor/start", json={"interface": iface_name}, headers=headers)
    assert resp_start_again.status_code == 409
    print("Double start 409 check passed!")

    # Stop
    resp_stop = client.post("/monitor/stop", headers=headers)
    assert resp_stop.status_code == 200
    stop_data = resp_stop.json()
    print("POST /monitor/stop response:", stop_data)
    assert stop_data.get("status") in ("stopped", "success")

    # Verify status inactive
    resp_status2 = client.get("/monitor/status")
    assert resp_status2.json()["active"] is False


    # Verify status inactive
    resp_status2 = client.get("/monitor/status")
    assert resp_status2.json()["active"] is False



if __name__ == "__main__":
    test_interface_enumeration()
    test_flow_builder_76_features()
    test_get_interfaces_endpoint()
    test_monitor_status_endpoint()
    test_monitor_start_and_stop_endpoints()
    print("\n======================================================================")
    print("SUCCESS: Phase 7 Live Monitoring Test Suite Passed!")
    print("======================================================================")
