#!/usr/bin/env bash
# Pre-install gate: run every fixture case and capture raw logs and true exit codes.
# Synthetic benign fixtures only; no lab code, hook or collector is executed, and no
# `npm install` runs in the repository tree.
#
# The gate decides (and writes its approval record) BEFORE any install; a blocked case runs
# no install at all; an approved case installs with --ignore-scripts, verifies the unpacked
# tree, and only then runs the benign hook. The gate is opt-in: calling npm, yarn, pnpm or
# bun directly bypasses it.
set -u
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
LOGDIR="${SCR_GATE_LOGDIR:-${TMPDIR:-/tmp}/scr-gate-logs}"
PY="$REPO/.venv/Scripts/python.exe"; [ -x "$PY" ] || PY="$REPO/.venv/bin/python"; [ -x "$PY" ] || PY="python"
GATE="$REPO/scripts/scr-gate/scr_gate.py"
SCRATCH_PY="$REPO/scripts/scr-gate/make_scratch_project.py"
ALLOW="$REPO/scripts/scr-gate/allowlist.json"
PROJ="$REPO/demo-site/gate-fixtures/projects"
NPM="${NPM:-npm}"
mkdir -p "$LOGDIR"

echo "### host: $(node --version 2>/dev/null) / npm $(npm --version 2>/dev/null)"

run_case() {
  name="$1"; project="$2"; shift 2
  target="$LOGDIR/target-$name"
  rm -rf "$target"
  out="$LOGDIR/$name.out.json"; err="$LOGDIR/$name.err.log"
  # raw stdout+stderr, TRUE exit code (no pipe that masks it)
  "$PY" "$GATE" install --project "$PROJ/$project" --allowlist "$ALLOW" --target "$target" "$@" \
      >"$out" 2>"$err"
  code=$?
  echo "$code" > "$LOGDIR/$name.exit"
  echo "[$name] exit=$code"
  echo "[$name] decision: $("$PY" -c "import json,sys;d=json.load(open(sys.argv[1]));print('action=',d.get('action'),'verdict=',d.get('verdict'),'resolved=',d.get('resolved_count'),'err=',d.get('fail_closed_error'))" "$out" 2>/dev/null || echo '(no json)')"
  echo "[$name] approval record:   $([ -f "$target/.chainshield-gate-approval.json" ] && echo PRESENT || echo absent)"
  echo "[$name] verification record: $([ -f "$target/.chainshield-gate-verification.json" ] && echo PRESENT || echo absent)"
  echo "[$name] markers under target:"
  find "$target" -name 'MARKER*' 2>/dev/null | sed "s#$target#<target>#"
}

echo ""
echo "=== GATE CASES (L1) ==="
run_case approved  approved
run_case blocked   blocked
run_case tampered  tampered
run_case no-lock   no-lock
run_case v1-format v1-format

echo ""
echo "=== L2 CONTROLS: bare npm on the SAME approved fixture, GATE NOT involved ==="
# These install OUTSIDE the original tree (scratch under the programme dir) and prove that
# npm alone: with or without --ignore-scripts, produces NO marker. So the marker in the
# approved gate case is attributable to the GATE's own node invocation, not to npm. npm 12's
# default script blocking is the coincidental L2 layer, never the gate's achievement.
for mode in "--ignore-scripts" ""; do
  scratch="$LOGDIR/scratch-approved-npm${mode//--/-}"
  rm -rf "$scratch"
  "$PY" "$SCRATCH_PY" "$PROJ/approved" "$scratch" >/dev/null
  log="$LOGDIR/control-npm${mode//--/-}.log"
  ( cd "$scratch" && "$NPM" ci $mode --offline --no-fund --no-audit ) >"$log" 2>&1
  c=$?
  label="npm ci ${mode:-（npm 12 default: no flag）}"
  echo "[control $label] exit=$c markers: $(find "$scratch" -name 'MARKER*' 2>/dev/null | sed "s#$scratch#<scratch>#" | tr '\n' ' ')"
  grep -i "blocked because\|install scripts blocked\|allowScripts" "$log" 2>/dev/null | head -2 | sed 's/^/    npm note: /'
  rm -rf "$scratch"
done

echo ""
echo "=== ORDERING EVIDENCE (approved case, L1): approval record BEFORE marker ==="
t="$LOGDIR/target-approved"
rec="$t/.chainshield-gate-approval.json"
marker="$(find "$t" -name 'MARKER_GOOD.txt' 2>/dev/null | head -1)"
if [ -f "$rec" ] && [ -n "$marker" ]; then
  rmt="$("$PY" -c "import os,sys;print(os.path.getmtime(sys.argv[1]))" "$rec")"
  mmt="$("$PY" -c "import os,sys;print(os.path.getmtime(sys.argv[1]))" "$marker")"
  echo "  approval record mtime <= marker mtime : $("$PY" -c "print($rmt <= $mmt)")"
  echo "  approval record (tamper-evident, NOT immutable):"
  sed 's/^/    /' "$rec"
  echo "  post-unpack verification record:"
  sed 's/^/    /' "$t/.chainshield-gate-verification.json"
else
  echo "  (approved target missing record or marker)"
fi

echo ""
echo "=================================================================="
echo "LAYER ATTRIBUTION (what each piece of evidence actually proves)"
echo "=================================================================="
cat <<'EOF'
L1 GATE DECISION (ours, attributable via ordering):
   The gate decides from the lockfile + tarball bytes + allowlist BEFORE any install.
   * BLOCKED path: the gate runs NO install at all -> no node_modules, no marker. The
     absence of the marker is attributable to the gate (not to npm blocking a script).
   * APPROVED path: approval record written first, install done with --ignore-scripts,
     unpacked tree verified, and only then the GATE invokes the benign postinstall.
     The marker's presence is attributable to the gate's own node call.
L2 npm 12 DEFAULT SCRIPT BLOCKING (NOT ours):
   npm 12 blocks dependency lifecycle scripts by default (allowScripts). The controls
   above show npm alone (which DOES install the package) still produces no marker. This
   is npm's behaviour, not this gate's achievement; it is absent on npm <= 10 and is not
   an enforcement authority this deliverable controls.
L3 WRAPPER IS OPT-IN (residual bypass):
   scr-gate is NOT wired into npm. A direct `npm ci|install|rebuild`, a developer simply
   not using the wrapper, yarn/pnpm/bun, and lockfile edits all bypass it. Lockfile EDITs
   change the composite identity (caught) and lockfile FORMAT changes are now refused
   (fail-closed), but only inside the wrapper's supported path.
EOF
echo "=== DONE ==="
