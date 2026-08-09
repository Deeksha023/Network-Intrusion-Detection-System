"""
tests/test_phase8_enterprise.py — Phase 8 Enterprise SOC Test Suite.

Tests:
  - JWT Auth & RBAC (/auth/login, /auth/me)
  - Threat Intelligence Enrichment & Private IP skipping (/threat-intel/lookup/{ip})
  - Automated Incident Response & OS Firewall blocking (/incident/block-ip, /incident/rules)
  - Attack Simulation Lab engine (/simulation/run)
  - Machine Learning Evaluation & Model Comparison (/evaluation/metrics, /evaluation/comparison)
  - SOC Executive Reports & Exports (/reports/generate, /reports/{id}/export)
  - Advanced Threat Analytics (/analytics/overview)
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient
from api.main import app

client = TestClient(app)


def get_auth_headers():
    resp = client.post("/auth/login", json={"username": "admin", "password": "admin123"})
    if resp.status_code == 200:
        token = resp.json()["access_token"]
        return {"Authorization": f"Bearer {token}"}
    return {}


def test_auth_login_and_me():
    print("\n--- Testing JWT Auth & Me Endpoints ---")
    resp = client.post("/auth/login", json={"username": "admin", "password": "admin123"})
    assert resp.status_code == 200, f"Login failed: {resp.status_code}"
    data = resp.json()
    assert "access_token" in data
    assert data["user"]["username"] == "admin"
    print("JWT Login successful. Token generated.")

    token = data["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    me_resp = client.get("/auth/me", headers=headers)
    assert me_resp.status_code == 200
    assert me_resp.json()["username"] == "admin"
    print("Auth /me endpoint verified!")


def test_threat_intel_enrichment():
    print("\n--- Testing Threat Intelligence Lookup ---")
    headers = get_auth_headers()
    # Test Private RFC1918 IP
    priv_resp = client.get("/threat-intel/lookup/192.168.1.100", headers=headers)
    assert priv_resp.status_code == 200
    priv_data = priv_resp.json()
    assert priv_data["is_private"] is True
    assert priv_data["country"] == "Internal Network"
    print("RFC1918 Private IP correctly identified and enriched!")

    # Test Public IP
    pub_resp = client.get("/threat-intel/lookup/185.220.101.5", headers=headers)
    assert pub_resp.status_code == 200
    pub_data = pub_resp.json()
    assert pub_data["is_private"] is False
    assert "country" in pub_data
    assert "abuse_score" in pub_data
    print("Public IP Threat Intel lookup verified!")


def test_incident_response_firewall():
    print("\n--- Testing Incident Response & Firewall Blocking ---")
    headers = get_auth_headers()
    payload = {
        "ip_address": "193.56.29.11",
        "reason": "Test Botnet C2 Firewall Rule",
        "confirmed": True,
    }
    resp = client.post("/incident/block-ip", json=payload, headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    print("OS Firewall block command generated:", data["rule"]["os_command"])

    # Check active rules
    rules_resp = client.get("/incident/rules", headers=headers)
    assert rules_resp.status_code == 200
    assert "193.56.29.11" in rules_resp.json()["blacklist"]


def test_attack_simulation_lab():
    print("\n--- Testing Security Attack Simulation Lab ---")
    headers = get_auth_headers()
    payload = {
        "attack_type": "Port Scan",
        "packet_count": 50,
        "target_ip": "172.16.0.5",
    }
    resp = client.post("/simulation/run", json=payload, headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "COMPLETED"
    assert data["flows_generated"] > 0
    print(f"Simulation {data['attack_type']} generated {data['flows_generated']} flows in {data['detection_time_ms']} ms")


def test_model_evaluation_and_comparison():
    print("\n--- Testing ML Evaluation & Model Comparison ---")
    headers = get_auth_headers()
    eval_resp = client.get("/evaluation/metrics", headers=headers)
    assert eval_resp.status_code == 200
    eval_data = eval_resp.json()
    assert "confusion_matrix" in eval_data
    assert "accuracy" in eval_data["metrics"]
    print("Confusion Matrix metrics verified!")

    comp_resp = client.get("/evaluation/comparison", headers=headers)
    assert comp_resp.status_code == 200
    comp_data = comp_resp.json()
    assert "stage1_randomforest" in comp_data
    assert "stage2_autoencoder" in comp_data
    print("Side-by-Side Model Comparison verified!")


def test_reports_generation_and_export():
    print("\n--- Testing Executive SOC Report Generation & Export ---")
    headers = get_auth_headers()
    gen_resp = client.post("/reports/generate", json={"report_type": "daily"}, headers=headers)
    assert gen_resp.status_code == 200
    gen_data = gen_resp.json()
    report_id = gen_data["report_id"]
    print(f"Report generated with ID: {report_id}")

    # Export JSON
    exp_json = client.get(f"/reports/{report_id}/export?export_format=json", headers=headers)
    assert exp_json.status_code == 200

    # Export CSV
    exp_csv = client.get(f"/reports/{report_id}/export?export_format=csv", headers=headers)
    assert exp_csv.status_code == 200

    # Export PDF
    exp_pdf = client.get(f"/reports/{report_id}/export?export_format=pdf", headers=headers)
    assert exp_pdf.status_code == 200
    print("Report PDF, CSV, and JSON exports verified!")



def test_advanced_analytics():
    print("\n--- Testing Advanced Threat Analytics ---")
    resp = client.get("/analytics/overview?window=24h")
    assert resp.status_code == 200
    data = resp.json()
    assert "top_attacks" in data
    assert "protocols" in data
    assert "top_sources" in data
    print("Analytics overview verified!")


if __name__ == "__main__":
    test_auth_login_and_me()
    test_threat_intel_enrichment()
    test_incident_response_firewall()
    test_attack_simulation_lab()
    test_model_evaluation_and_comparison()
    test_reports_generation_and_export()
    test_advanced_analytics()
    print("\n======================================================================")
    print("SUCCESS: Phase 8 Enterprise SOC Test Suite Passed!")
    print("======================================================================")
