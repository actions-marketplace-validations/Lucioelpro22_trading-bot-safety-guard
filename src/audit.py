from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path


SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache"}
TEXT_SUFFIXES = {".py", ".js", ".ts", ".json", ".yaml", ".yml", ".toml", ".ini", ".env", ".txt", ".md"}
PLACEHOLDERS = ("example", "sample", "dummy", "changeme", "your_", "tu_", "test_key", "demo_key")

SECRET_PATTERNS = [
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"(?i)(?:api[_-]?key|secret[_-]?key|api[_-]?secret|token|password)\s*[:=]\s*['\"]?([^\s'\"#]{16,})"),
]
LIVE_ENDPOINTS = {
    "api.binance.com": ("testnet.binance", "demo.binance"),
    "fapi.binance.com": ("testnet.binancefuture", "demo.binance"),
    "api.bybit.com": ("api-demo.bybit.com", "api-testnet.bybit.com"),
    "open-api.bingx.com": ("open-api-vst.bingx.com",),
}
LEVERAGE_PATTERN = re.compile(r"(?i)(?:leverage|max_leverage)\s*[:=]\s*['\"]?(\d+(?:\.\d+)?)")


@dataclass(frozen=True)
class Finding:
    severity: str
    rule: str
    path: str
    line: int
    message: str


def iter_files(root: Path):
    for path in root.rglob("*"):
        if not path.is_file() or any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.name.startswith(".env") or path.suffix.lower() in TEXT_SUFFIXES:
            if path.stat().st_size <= 2_000_000:
                yield path


def is_placeholder(value: str) -> bool:
    lowered = value.lower()
    return any(marker in lowered for marker in PLACEHOLDERS)


def scan(root: Path, fail_on_secrets: bool, require_demo: bool, max_leverage: float) -> list[Finding]:
    findings: list[Finding] = []
    for path in iter_files(root):
        relative = str(path.relative_to(root)).replace("\\", "/")
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        if path.name in {".env", "env.env"}:
            findings.append(Finding("high", "tracked-env", relative, 1, "Environment file may expose credentials or account configuration."))

        for line_number, line in enumerate(content.splitlines(), 1):
            if fail_on_secrets:
                for pattern in SECRET_PATTERNS:
                    match = pattern.search(line)
                    if match and (match.lastindex is None or not is_placeholder(match.group(1))):
                        findings.append(Finding("critical", "possible-secret", relative, line_number, "Credential-like material detected; the value is redacted."))
                        break

            leverage = LEVERAGE_PATTERN.search(line)
            if leverage and float(leverage.group(1)) > max_leverage:
                findings.append(Finding("high", "excessive-leverage", relative, line_number, f"Configured leverage {leverage.group(1)}x exceeds the permitted {max_leverage:g}x."))

        if require_demo:
            lowered = content.lower()
            for endpoint, demo_markers in LIVE_ENDPOINTS.items():
                if endpoint in lowered and not any(marker in lowered for marker in demo_markers):
                    findings.append(Finding("high", "live-endpoint", relative, 1, f"Live endpoint {endpoint} appears without a demo/testnet endpoint in the same file."))

    return sorted(findings, key=lambda item: (item.severity, item.path, item.line, item.rule))


def bool_input(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def write_report(path: Path, findings: list[Finding], root: Path) -> None:
    lines = ["# Trading Bot Safety Guard", "", f"Scanned: `{root}`", "", f"Findings: **{len(findings)}**", ""]
    if findings:
        lines.extend(["| Severity | Rule | Location | Finding |", "| --- | --- | --- | --- |"])
        for item in findings:
            lines.append(f"| {item.severity.upper()} | `{item.rule}` | `{item.path}:{item.line}` | {item.message} |")
    else:
        lines.append("No policy violations were detected by this static check.")
    lines.extend(["", "> This action is a defensive configuration check, not a profitability or financial-risk assessment."])
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    root = Path(os.getenv("INPUT_SCAN_PATH", ".")).resolve()
    if not root.is_dir():
        print(f"::error::Scan path does not exist or is not a directory: {root}")
        return 2
    try:
        max_leverage = float(os.getenv("INPUT_MAX_LEVERAGE", "5"))
        if max_leverage <= 0:
            raise ValueError
    except ValueError:
        print("::error::max-leverage must be a positive number")
        return 2

    findings = scan(root, bool_input("INPUT_FAIL_ON_SECRETS", True), bool_input("INPUT_REQUIRE_DEMO", True), max_leverage)
    report = Path(os.getenv("RUNNER_TEMP", ".")) / "trading-bot-safety-report.md"
    write_report(report, findings, root)

    output_file = os.getenv("GITHUB_OUTPUT")
    if output_file:
        with open(output_file, "a", encoding="utf-8") as handle:
            handle.write(f"findings={len(findings)}\nreport={report}\n")
    summary_file = os.getenv("GITHUB_STEP_SUMMARY")
    if summary_file:
        with open(summary_file, "a", encoding="utf-8") as handle:
            handle.write(report.read_text(encoding="utf-8"))

    for item in findings:
        level = "error" if item.severity in {"critical", "high"} else "warning"
        print(f"::{level} file={item.path},line={item.line},title={item.rule}::{item.message}")
    print(json.dumps({"findings": len(findings), "report": str(report)}))
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
