from __future__ import annotations

import ast
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
AGENT = ROOT / "agent" / "root_agent.py"
source = AGENT.read_text(encoding="utf-8")
tree = ast.parse(source)

# Privileged execution must stay argv-based, bounded and free of browser-supplied shell strings.
for node in ast.walk(tree):
    if not isinstance(node, ast.Call):
        continue
    func = node.func
    name = func.attr if isinstance(func, ast.Attribute) else (func.id if isinstance(func, ast.Name) else "")
    if name in {"run", "Popen", "check_call", "check_output"}:
        for kw in node.keywords:
            if kw.arg == "shell":
                assert not (isinstance(kw.value, ast.Constant) and kw.value.value is True), "shell=True is forbidden in privileged agent"
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) and func.value.id == "subprocess" and name == "run":
        assert any(kw.arg == "timeout" for kw in node.keywords), "direct subprocess.run must declare a timeout"

handle = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "handle")
actions: set[str] = set()
for node in ast.walk(handle):
    if isinstance(node, ast.Compare) and isinstance(node.left, ast.Name) and node.left.id == "action":
        for comparator in node.comparators:
            if isinstance(comparator, ast.Constant) and isinstance(comparator.value, str):
                actions.add(comparator.value)

expected = {
    "site-create", "site-toggle", "ssl", "db-create", "backup-site", "backup-restore",
    "file-list", "file-read", "file-write", "file-mkdir", "file-delete", "git-deploy",
    "wp-prepare", "site-logs", "service-restart", "doctor", "docker-list", "docker-control",
}
assert expected <= actions, f"privileged action contract unexpectedly lost actions: {sorted(expected - actions)}"
assert 'return {"ok": False, "error": "action not allowed"}' in source, "unknown privileged actions must fail closed"
assert 'req.get("command"' not in source and 'req.get("shell"' not in source and 'req.get("terminal"' not in source, "free-form command inputs are forbidden"
assert "ALLOWED_SERVICES" in source and 'name in ALLOWED_SERVICES' in source, "service restart must remain allowlisted"
assert 'desired not in {"start", "stop", "restart"}' in source, "container control verbs must remain allowlisted"
assert "timeout=160" in source and "timeout=140" in source and "timeout=130" in source, "long privileged operations must remain explicitly bounded"
assert "rollback_archive" in source and "pre-restore" in source and 'run(["nginx", "-t"]' in source, "restore must retain snapshot + post-validation safety"

print(f"NEXVARY privileged-agent contract gate: PASS ({len(actions)} allowlisted actions)")
