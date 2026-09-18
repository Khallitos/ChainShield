"""Unit tests for ATK3: CI/CD Pipeline Injection."""
from __future__ import annotations

import pytest
from app.attacks.ci_cd_injection import (
    CICDPolicy,
    scan_workflow,
    simulate_attack,
    finding_to_siem_event,
    simulation_to_siem_event,
)


# ── Fixture workflows ──────────────────────────────────────────────────────────

VULNERABLE_WORKFLOW = {
    "name": "Vulnerable CI",
    "on": ["pull_request"],
    # No top-level permissions (over-privileged by default)
    "jobs": {
        "build": {
            "name": "Build",
            "runs-on": "ubuntu-latest",
            # No job-level permissions either
            "steps": [
                {
                    "name": "Checkout",
                    "uses": "actions/checkout@main",  # unpinned @main
                },
                {
                    "name": "Setup Node",
                    "uses": "actions/setup-node@v3",  # unpinned @v3
                },
                {
                    "name": "Run tests",
                    # Direct interpolation of untrusted PR title into shell
                    "run": "echo ${{ github.event.pull_request.title }} && npm test",
                },
                {
                    "name": "Deploy script",
                    # Dangerous run pattern
                    "run": "curl -s https://install.example.com/deploy.sh | bash",
                },
            ],
        }
    },
}

HARDENED_WORKFLOW = {
    "name": "Hardened CI",
    "on": ["pull_request"],
    "permissions": {
        "contents": "read",
        "pull-requests": "read",
    },
    "jobs": {
        "build": {
            "name": "Build",
            "runs-on": "ubuntu-latest",
            "permissions": {
                "contents": "read",
            },
            "steps": [
                {
                    "name": "Checkout",
                    # SHA-pinned
                    "uses": "actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332",
                },
                {
                    "name": "Run tests",
                    # Untrusted value placed in env var, NOT interpolated in run:
                    "env": {"PR_TITLE": "${{ github.event.pull_request.title }}"},
                    "run": 'echo "title=$PR_TITLE" && npm test',
                },
            ],
        }
    },
}

PRT_VULNERABLE_WORKFLOW = {
    "name": "PR Target Vulnerable",
    "on": {"pull_request_target": {}},
    "jobs": {
        "deploy": {
            "name": "Deploy",
            "runs-on": "ubuntu-latest",
            "steps": [
                {
                    "name": "Checkout PR head",
                    "uses": "actions/checkout@v4",
                    # No ref specified → checks out PR head by default
                },
                {
                    "name": "Build",
                    "run": "make build",
                },
            ],
        }
    },
}


# ── Test: script injection detection ──────────────────────────────────────────

def test_script_injection_detected():
    result = scan_workflow(VULNERABLE_WORKFLOW)
    rule_ids = [f.rule_id for f in result.findings]
    assert "RULE-01" in rule_ids, "Should detect script injection via untrusted PR title"


def test_script_injection_finding_is_critical():
    result = scan_workflow(VULNERABLE_WORKFLOW)
    inj = next(f for f in result.findings if f.rule_id == "RULE-01")
    assert inj.severity == "critical"
    assert "pull_request.title" in inj.evidence


def test_hardened_workflow_no_script_injection():
    result = scan_workflow(HARDENED_WORKFLOW)
    rule_ids = [f.rule_id for f in result.findings]
    assert "RULE-01" not in rule_ids, "Hardened workflow should NOT flag script injection"


# ── Test: pull_request_target + checkout ──────────────────────────────────────

def test_prt_checkout_detected():
    result = scan_workflow(PRT_VULNERABLE_WORKFLOW)
    rule_ids = [f.rule_id for f in result.findings]
    assert "RULE-02" in rule_ids, "Should detect pull_request_target + checkout"


def test_prt_not_flagged_for_normal_push_trigger():
    wf = {**VULNERABLE_WORKFLOW}  # uses pull_request, not pull_request_target
    result = scan_workflow(wf)
    rule_ids = [f.rule_id for f in result.findings]
    assert "RULE-02" not in rule_ids


# ── Test: unpinned actions ─────────────────────────────────────────────────────

def test_unpinned_action_main_detected():
    result = scan_workflow(VULNERABLE_WORKFLOW)
    rule_ids = [f.rule_id for f in result.findings]
    assert "RULE-03" in rule_ids


def test_unpinned_action_evidence_correct():
    result = scan_workflow(VULNERABLE_WORKFLOW)
    unpinned = [f for f in result.findings if f.rule_id == "RULE-03"]
    evidences = [f.evidence for f in unpinned]
    assert any("@main" in e or "@v3" in e for e in evidences)


def test_sha_pinned_action_not_flagged():
    result = scan_workflow(HARDENED_WORKFLOW)
    rule_ids = [f.rule_id for f in result.findings]
    assert "RULE-03" not in rule_ids, "SHA-pinned action should not be flagged"


# ── Test: permissions ─────────────────────────────────────────────────────────

def test_missing_permissions_flagged():
    result = scan_workflow(VULNERABLE_WORKFLOW)
    rule_ids = [f.rule_id for f in result.findings]
    assert "RULE-04" in rule_ids, "Missing permissions should be flagged"


def test_explicit_permissions_not_flagged():
    result = scan_workflow(HARDENED_WORKFLOW)
    rule_ids = [f.rule_id for f in result.findings]
    assert "RULE-04" not in rule_ids, "Explicit least-privilege permissions should pass"


# ── Test: dangerous run patterns ───────────────────────────────────────────────

def test_dangerous_run_curl_pipe_detected():
    result = scan_workflow(VULNERABLE_WORKFLOW)
    rule_ids = [f.rule_id for f in result.findings]
    assert "RULE-05" in rule_ids


def test_safe_curl_download_not_flagged():
    wf = {
        "name": "Safe CI",
        "on": ["push"],
        "permissions": {"contents": "read"},
        "jobs": {
            "build": {
                "name": "Build",
                "runs-on": "ubuntu-latest",
                "permissions": {"contents": "read"},
                "steps": [
                    {
                        "name": "Download tool",
                        # Curl downloads but does NOT pipe to shell
                        "run": "curl -fsSL https://example.com/tool -o tool && chmod +x tool && ./tool",
                        "uses": None,
                    }
                ],
            }
        },
    }
    result = scan_workflow(wf)
    rule_ids = [f.rule_id for f in result.findings]
    assert "RULE-05" not in rule_ids


# ── Test: overall severity ────────────────────────────────────────────────────

def test_vulnerable_workflow_overall_severity_critical():
    result = scan_workflow(VULNERABLE_WORKFLOW)
    assert result.overall_severity == "critical"


def test_hardened_workflow_is_clean():
    result = scan_workflow(HARDENED_WORKFLOW)
    assert result.overall_severity == "clean", (
        f"Hardened workflow should be clean but got findings: {[f.rule_id for f in result.findings]}"
    )


# ── Test: policy overrides ─────────────────────────────────────────────────────

def test_policy_can_disable_unpinned_check():
    policy = CICDPolicy(block_unpinned_actions=False)
    result = scan_workflow(VULNERABLE_WORKFLOW, policy=policy)
    rule_ids = [f.rule_id for f in result.findings]
    assert "RULE-03" not in rule_ids


def test_policy_can_disable_permissions_check():
    policy = CICDPolicy(require_explicit_permissions=False)
    result = scan_workflow(VULNERABLE_WORKFLOW, policy=policy)
    rule_ids = [f.rule_id for f in result.findings]
    assert "RULE-04" not in rule_ids


# ── Test: simulation ──────────────────────────────────────────────────────────

def test_simulate_script_injection():
    result = simulate_attack("script_injection")
    assert result.siem_severity == "critical"
    assert len(result.what_attacker_gains) > 0
    assert "GITHUB_TOKEN" in result.what_attacker_gains[0]
    assert "vulnerable" in result.baseline_outcome
    assert "blocked" in result.improved_outcome


def test_simulate_prt_checkout():
    result = simulate_attack("prt_checkout")
    assert result.siem_severity == "critical"
    assert result.attack_vector  # non-empty


def test_simulate_unpinned_action():
    result = simulate_attack("unpinned_action")
    assert result.siem_severity == "high"


def test_simulate_unknown_vector_falls_back_to_script_injection():
    result = simulate_attack("nonexistent_vector")
    assert result.siem_severity == "critical"  # falls back to script_injection


# ── Test: SIEM event serialisation ────────────────────────────────────────────

def test_finding_siem_event_keys():
    result = scan_workflow(VULNERABLE_WORKFLOW)
    inj = next(f for f in result.findings if f.rule_id == "RULE-01")
    event = finding_to_siem_event(inj, source="test")
    required_keys = {
        "event_id", "attack_type", "rule_id", "severity", "source",
        "workflow", "job", "step", "evidence", "mitigation", "timestamp",
    }
    assert required_keys.issubset(event.keys())
    assert event["attack_type"] == "ci_cd_injection"
    assert event["source"] == "test"


def test_simulation_siem_event_keys():
    sim = simulate_attack("script_injection")
    event = simulation_to_siem_event(sim, source="test")
    required_keys = {
        "event_id", "attack_type", "severity", "source", "workflow",
        "attack_vector", "what_attacker_gains", "baseline_outcome",
        "improved_outcome", "narrative", "timestamp",
    }
    assert required_keys.issubset(event.keys())
