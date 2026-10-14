import pytest
from core.auditor import analyze_policy, build_report, normalize_policy, PolicyInputError

BASE = {"principal":"service:reader", "permissions":["records:read"], "resources":["records:daily"]}

def test_minimal_policy_normalizes():
    p = normalize_policy(BASE)
    assert p["principal"] == "service:reader"
    assert p["permissions"] == ["records:read"]

def test_missing_required_field_rejected():
    with pytest.raises(PolicyInputError): normalize_policy({"principal":"x"})

def test_wrong_permissions_type_rejected():
    with pytest.raises(PolicyInputError): normalize_policy({**BASE, "permissions":"records:read"})

def test_wildcard_permission_flagged():
    assert "AP-002" in {f["rule_id"] for f in analyze_policy({**BASE,"permissions":["*"]})}

def test_production_write_flagged():
    assert "AP-003" in {f["rule_id"] for f in analyze_policy({**BASE,"permissions":["records:write"],"environment":"production"})}

def test_broad_resource_flagged():
    assert "AP-005" in {f["rule_id"] for f in analyze_policy({**BASE,"resources":["records/*"]})}

def test_explicit_network_false_flagged():
    assert "AP-006" in {f["rule_id"] for f in analyze_policy({**BASE,"conditions":{"source_network_restricted":False}})}

def test_report_has_limitations_and_score():
    r = build_report(BASE)
    assert 0 <= r["triage_score"] <= 100
    assert r["limitations"]

def test_privileged_mfa_disabled_flagged():
    fs = analyze_policy({**BASE,"permissions":["admin"],"mfa_required":False})
    assert "AP-008" in {f["rule_id"] for f in fs}
