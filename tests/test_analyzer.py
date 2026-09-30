"""
Tests for CloudLens v0.1.

Two kinds of test here on purpose:

1. Pipeline tests against the real example environments. These are the
   ones that matter most — they lock in the exact findings we verified
   by hand while building this, so a future refactor can't quietly
   change behavior without a test failing. If you change graph_builder
   or analyzer logic and one of these breaks, that's not automatically
   a bug — it might mean the expectation needs updating. Read the diff
   before assuming either direction.

2. Small unit tests for the two severity helpers, since those are pure
   functions with no graph dependency and are easy to test in
   isolation.

Run with: pytest tests/test_analyzer.py -v
(from the project root, ~/projects/cloudlens)
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "cloudlens"))

from loader import load_environment
from graph_builder import build_graph
from analyzer import find_attack_paths, _is_admin_action, _has_privilege_escalation


EXAMPLES_DIR = os.path.join(os.path.dirname(__file__), "..", "examples")


def _run(filename):
    env = load_environment(os.path.join(EXAMPLES_DIR, filename))
    graph = build_graph(env)
    findings = find_attack_paths(graph, env)
    return env, graph, findings


# ---------------------------------------------------------------------
# small-startup.json
# ---------------------------------------------------------------------

def test_small_startup_finds_exactly_one_path():
    _, _, findings = _run("small-startup.json")
    assert len(findings) == 1


def test_small_startup_path_is_critical():
    _, _, findings = _run("small-startup.json")
    assert findings[0]["severity"] == "CRITICAL"


def test_small_startup_path_ends_at_company_data():
    _, _, findings = _run("small-startup.json")
    assert findings[0]["path"][-1] == "company-data"


def test_small_startup_never_flags_dev_bucket():
    _, _, findings = _run("small-startup.json")
    for finding in findings:
        assert "dev-bucket" not in finding["path"]


# ---------------------------------------------------------------------
# bank-sim.json
# ---------------------------------------------------------------------

def test_bank_sim_finds_exactly_four_paths():
    _, _, findings = _run("bank-sim.json")
    assert len(findings) == 4


def test_bank_sim_severities_match_expected():
    _, _, findings = _run("bank-sim.json")
    severities = [f["severity"] for f in findings]
    assert severities == ["CRITICAL", "CRITICAL", "CRITICAL", "HIGH"]


def test_bank_sim_never_flags_low_sensitivity_resources():
    _, _, findings = _run("bank-sim.json")
    for finding in findings:
        assert "transaction-logs" not in finding["path"]
        assert "public-reports" not in finding["path"]


def test_bank_sim_teller_has_no_attack_paths():
    _, _, findings = _run("bank-sim.json")
    for finding in findings:
        assert "teller" not in finding["path"]


def test_bank_sim_junior_dev_reaches_both_high_resources():
    # this is the emergent finding: junior-dev inherits AdminRole's
    # transitive PassRole reach into OpsRole, not just AdminRole's own
    # direct permissions
    _, _, findings = _run("bank-sim.json")
    junior_dev_targets = {
        f["path"][-1] for f in findings if f["path"][0] == "junior-dev"
    }
    assert junior_dev_targets == {"customer-pii", "core-banking-db"}


def test_bank_sim_junior_dev_direct_path_has_no_escalation():
    # the HIGH finding (junior-dev -> AdminRole -> core-banking-db)
    # should have no PassRole hop, that's what separates it from the
    # CRITICAL findings
    _, graph, findings = _run("bank-sim.json")
    direct_path = next(
        f for f in findings
        if f["path"] == ["junior-dev", "AdminRole", "core-banking-db"]
    )
    assert _has_privilege_escalation(graph, direct_path["path"]) is False


# ---------------------------------------------------------------------
# severity helpers
# ---------------------------------------------------------------------

def test_is_admin_action_matches_wildcards():
    assert _is_admin_action("s3:*") is True
    assert _is_admin_action("iam:*") is True
    assert _is_admin_action("*") is True


def test_is_admin_action_rejects_specific_actions():
    assert _is_admin_action("s3:GetObject") is False
    assert _is_admin_action("iam:PassRole") is False


def test_has_privilege_escalation_detects_pass_role_edge():
    _, graph, _ = _run("small-startup.json")
    path_with_escalation = ["developer", "DevRole", "Lambda", "AdminRole", "company-data"]
    assert _has_privilege_escalation(graph, path_with_escalation) is True


def test_has_privilege_escalation_false_for_direct_access():
    _, graph, _ = _run("small-startup.json")
    path_without_escalation = ["developer", "DevRole", "dev-bucket"]
    assert _has_privilege_escalation(graph, path_without_escalation) is False
