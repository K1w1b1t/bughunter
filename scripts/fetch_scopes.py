#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

try:
    import yaml
except Exception:  # pragma: no cover
    yaml = None  # type: ignore


ROOT = Path(__file__).resolve().parents[1]

SOURCES = {
    "hackerone": "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/hackerone_data.json",
    "bugcrowd": "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/bugcrowd_data.json",
}

DOMAIN_RE = re.compile(r"^[a-z0-9.-]+$")
AUTOMATION_PROHIBITIVE_PATTERNS = [
    r"no automated scanning",
    r"do not use automated scanners",
    r"do not use automatic scanners",
    r"no automated tools",
    r"no automatic tools",
    r"automation is not allowed",
    r"automated scanning is prohibited",
    r"scanners are not allowed",
]
AUTOMATION_BUGCROWD_SAFE_HARBOR_ALLOWED = {"full", "partial"}
AUTOMATION_RULES_TEXT_KEYS = (
    "rules_of_engagement",
    "rules_text",
    "rules",
    "policy",
    "policies",
    "description",
)


def _fetch_json(url: str, timeout: int = 45) -> list[dict[str, Any]]:
    req = urllib.request.Request(url, headers={"User-Agent": "HunterOps-ScopeFetcher/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode("utf-8", errors="ignore"))
    return data if isinstance(data, list) else []


def _normalize_domain_pattern(raw: str) -> str:
    text = str(raw or "").strip().lower()
    if not text:
        return ""
    text = text.strip("`'\"")

    wildcard = text.startswith("*.")
    if wildcard:
        text = text[2:].strip()
    if not text:
        return ""

    if "://" in text or text.startswith("//"):
        parsed = urlparse(text if "://" in text else f"http:{text}")
        text = str(parsed.hostname or "").strip().lower()
    else:
        text = text.split()[0]
        text = text.split("/")[0]
        text = text.split("?")[0].split("#")[0]
        if ":" in text and not text.startswith("["):
            host, _, port = text.rpartition(":")
            if host and port.isdigit():
                text = host

    text = text.strip().strip(".")
    if text.startswith("*."):
        wildcard = True
        text = text[2:]

    if not text or "/" in text:
        return ""
    if text == "localhost":
        return ""
    try:
        ipaddress.ip_address(text)
        return ""
    except ValueError:
        pass

    if not DOMAIN_RE.fullmatch(text):
        return ""
    if "." not in text:
        return ""
    labels = text.split(".")
    if any(not label for label in labels):
        return ""
    if any(len(label) > 63 for label in labels):
        return ""
    if any(label.startswith("-") or label.endswith("-") for label in labels):
        return ""

    return f"*.{text}" if wildcard else text


def _pattern_covers(pattern: str, candidate: str) -> bool:
    p = str(pattern or "").strip().lower()
    c = str(candidate or "").strip().lower()
    if not p or not c:
        return False

    if p == c:
        return True

    p_is_wc = p.startswith("*.")
    c_is_wc = c.startswith("*.")
    p_base = p[2:] if p_is_wc else p
    c_base = c[2:] if c_is_wc else c

    if p_is_wc and c_is_wc:
        return c_base == p_base or c_base.endswith("." + p_base)
    if p_is_wc and not c_is_wc:
        return c.endswith("." + p_base)
    if not p_is_wc and c_is_wc:
        return c_base == p
    return False


def _env_bool(name: str, default: bool = False) -> bool:
    raw = str(os.getenv(name, "")).strip().lower()
    if not raw:
        return bool(default)
    return raw in {"1", "true", "yes", "on"}


def _rules_prohibit_automation(text: str) -> bool:
    body = str(text or "").strip().lower()
    if not body:
        return False
    for pat in AUTOMATION_PROHIBITIVE_PATTERNS:
        if re.search(pat, body, re.IGNORECASE):
            return True
    return False


def _extract_program_rules_text(program: dict[str, Any]) -> str:
    parts: list[str] = []
    for key in AUTOMATION_RULES_TEXT_KEYS:
        value = program.get(key)
        if isinstance(value, str):
            text = value.strip()
            if text:
                parts.append(text)
    return "\n".join(parts)


def _program_allows_automation(provider: str, program: dict[str, Any], *, unknown_policy: str) -> tuple[bool, str]:
    policy = str(unknown_policy or "drop").strip().lower()
    if policy not in {"allow", "drop"}:
        policy = "drop"

    if provider == "bugcrowd":
        safe_harbor = str(program.get("safe_harbor", "")).strip().lower()
        if safe_harbor:
            if safe_harbor not in AUTOMATION_BUGCROWD_SAFE_HARBOR_ALLOWED:
                return False, f"safe_harbor:{safe_harbor}"
        elif policy == "drop":
            return False, "safe_harbor:missing"

    rules_text = _extract_program_rules_text(program)
    if rules_text:
        if _rules_prohibit_automation(rules_text):
            return False, "rules_manual_only"
        return True, "rules_allow_or_unknown"

    if provider == "bugcrowd":
        return True, "safe_harbor_allowed"
    if policy == "allow":
        return True, "unknown_signal_allowed"
    return False, "unknown_signal_dropped"


def _load_manual_excludes(path: Path) -> set[str]:
    out: set[str] = set()
    if not path.exists():
        return out
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        raw = line.split("#", 1)[0].strip()
        if not raw:
            continue
        item = _normalize_domain_pattern(raw)
        if item:
            out.add(item)
    return out


def _load_program_excludes(path: Path) -> set[str]:
    out: set[str] = set()
    if not path.exists() or yaml is None:
        return out
    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception:
        return out
    programs = payload.get("programs", []) if isinstance(payload, dict) else []
    for program in programs if isinstance(programs, list) else []:
        if not isinstance(program, dict):
            continue
        for item in program.get("out_of_scope", []) if isinstance(program.get("out_of_scope", []), list) else []:
            norm = _normalize_domain_pattern(str(item))
            if norm:
                out.add(norm)
    return out


def _is_globally_excluded(candidate: str, excludes: set[str]) -> bool:
    return any(_pattern_covers(pattern, candidate) for pattern in excludes)


def _h1_targets(program: dict[str, Any]) -> tuple[set[str], set[str]]:
    if str(program.get("submission_state", "")).strip().lower() != "open":
        return set(), set()

    targets = program.get("targets", {}) if isinstance(program.get("targets"), dict) else {}
    in_scope = targets.get("in_scope", []) if isinstance(targets.get("in_scope", []), list) else []
    out_scope = targets.get("out_of_scope", []) if isinstance(targets.get("out_of_scope", []), list) else []

    allowed: set[str] = set()
    denied: set[str] = set()

    for item in in_scope:
        if not isinstance(item, dict):
            continue
        if not bool(item.get("eligible_for_submission", False)):
            continue
        asset = _normalize_domain_pattern(str(item.get("asset_identifier", "")))
        if asset:
            allowed.add(asset)

    for item in out_scope:
        if not isinstance(item, dict):
            continue
        asset = _normalize_domain_pattern(str(item.get("asset_identifier", "")))
        if asset:
            denied.add(asset)

    return allowed, denied


def _bugcrowd_targets(program: dict[str, Any], *, disclosure_only: bool) -> tuple[set[str], set[str]]:
    if disclosure_only and not bool(program.get("allows_disclosure", False)):
        return set(), set()

    targets = program.get("targets", {}) if isinstance(program.get("targets"), dict) else {}
    in_scope = targets.get("in_scope", []) if isinstance(targets.get("in_scope", []), list) else []
    out_scope = targets.get("out_of_scope", []) if isinstance(targets.get("out_of_scope", []), list) else []

    allowed: set[str] = set()
    denied: set[str] = set()

    for item in in_scope:
        if not isinstance(item, dict):
            continue
        target = _normalize_domain_pattern(str(item.get("target", "") or item.get("uri", "")))
        if target:
            allowed.add(target)

    for item in out_scope:
        if not isinstance(item, dict):
            continue
        target = _normalize_domain_pattern(str(item.get("target", "") or item.get("uri", "")))
        if target:
            denied.add(target)

    return allowed, denied


def _program_scoped_merge(allowed: set[str], denied: set[str]) -> set[str]:
    if not allowed:
        return set()
    if not denied:
        return set(allowed)
    out: set[str] = set()
    for candidate in allowed:
        if any(_pattern_covers(block, candidate) for block in denied):
            continue
        out.add(candidate)
    return out


def _split_output_domains(values: set[str]) -> tuple[list[str], list[str]]:
    wildcards = sorted([item for item in values if item.startswith("*.")])
    domains = sorted([item for item in values if not item.startswith("*.")])
    return domains, wildcards


def _atomic_write_lines(path: Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f"{path.name}.tmp")
    tmp_path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    tmp_path.replace(path)


def _resolve_max_targets(cli_value: int, env_var_name: str = "SCOPE_FETCH_MAX_TARGETS") -> tuple[int, str]:
    cli_cap = int(cli_value) if int(cli_value) > 0 else 0
    if cli_cap > 0:
        return cli_cap, "cli"

    raw = str(os.getenv(env_var_name, "")).strip()
    if not raw:
        return 0, "none"
    try:
        env_cap = int(raw)
    except ValueError:
        return 0, "invalid_env"
    if env_cap <= 0:
        return 0, "invalid_env"
    return env_cap, "env"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Fetch in-scope HackerOne/Bugcrowd targets and write data/targets/in_scope_hosts.txt"
    )
    parser.add_argument("--out", default="data/targets/in_scope_hosts.txt", help="Output file path.")
    parser.add_argument(
        "--providers",
        default="hackerone,bugcrowd",
        help="Comma-separated providers: hackerone,bugcrowd",
    )
    parser.add_argument(
        "--exclude-file",
        default="config/targets_out_of_scope.txt",
        help="Manual exclusion list (domains/wildcards).",
    )
    parser.add_argument(
        "--programs-file",
        default="config/programs.yaml",
        help="Optional local programs file for out_of_scope exclusions.",
    )
    parser.add_argument(
        "--bugcrowd-disclosure-only",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Keep only Bugcrowd programs with allows_disclosure=true (default: true).",
    )
    parser.add_argument(
        "--automation-only",
        action=argparse.BooleanOptionalAction,
        default=_env_bool("SCOPE_FETCH_AUTOMATION_ONLY", False),
        help="Keep only programs that appear to permit automation (default from SCOPE_FETCH_AUTOMATION_ONLY).",
    )
    parser.add_argument(
        "--automation-unknown-policy",
        choices=("allow", "drop"),
        default=str(os.getenv("SCOPE_FETCH_AUTOMATION_UNKNOWN_POLICY", "drop")).strip().lower() or "drop",
        help="When automation signal is missing and --automation-only is enabled: allow or drop the program.",
    )
    parser.add_argument("--timeout", type=int, default=45)
    parser.add_argument(
        "--max-targets",
        type=int,
        default=0,
        help="Optional cap after filtering (0 = unlimited). If unset/0, uses SCOPE_FETCH_MAX_TARGETS when defined.",
    )
    args = parser.parse_args()
    max_targets_cap, max_targets_source = _resolve_max_targets(args.max_targets)

    requested = {
        item.strip().lower()
        for item in str(args.providers or "").split(",")
        if item.strip()
    }
    providers = [item for item in ("hackerone", "bugcrowd") if item in requested]
    if not providers:
        raise SystemExit("No valid providers selected. Use --providers hackerone,bugcrowd")

    manual_excludes = _load_manual_excludes((ROOT / str(args.exclude_file)).resolve())
    program_excludes = _load_program_excludes((ROOT / str(args.programs_file)).resolve())
    global_excludes = set(manual_excludes) | set(program_excludes)

    merged: set[str] = set()
    stats: dict[str, dict[str, int]] = {}

    for provider in providers:
        dataset = _fetch_json(SOURCES[provider], timeout=max(5, int(args.timeout)))
        provider_targets: set[str] = set()
        programs_seen = 0
        programs_after_automation_filter = 0
        programs_filtered_automation = 0
        for program in dataset:
            if not isinstance(program, dict):
                continue
            programs_seen += 1
            if bool(args.automation_only):
                automation_allowed, _ = _program_allows_automation(
                    provider,
                    program,
                    unknown_policy=str(args.automation_unknown_policy),
                )
                if not automation_allowed:
                    programs_filtered_automation += 1
                    continue
            programs_after_automation_filter += 1
            if provider == "hackerone":
                allowed, denied = _h1_targets(program)
            else:
                allowed, denied = _bugcrowd_targets(program, disclosure_only=bool(args.bugcrowd_disclosure_only))
            provider_targets.update(_program_scoped_merge(allowed, denied))

        before_global = len(provider_targets)
        provider_targets = {item for item in provider_targets if not _is_globally_excluded(item, global_excludes)}
        stats[provider] = {
            "programs_seen": programs_seen,
            "programs_after_automation_filter": programs_after_automation_filter,
            "programs_filtered_automation": programs_filtered_automation,
            "kept_after_program_scope": before_global,
            "kept_after_global_excludes": len(provider_targets),
        }
        merged.update(provider_targets)

    if max_targets_cap > 0:
        merged = set(sorted(merged)[:max_targets_cap])

    domains, wildcards = _split_output_domains(merged)
    ordered = domains + wildcards

    out_path = (ROOT / str(args.out)).resolve()
    _atomic_write_lines(out_path, ordered)

    report = {
        "providers": providers,
        "stats": stats,
        "global_excludes": len(global_excludes),
        "automation_only": bool(args.automation_only),
        "automation_unknown_policy": str(args.automation_unknown_policy),
        "domains": len(domains),
        "wildcards": len(wildcards),
        "total_written": len(ordered),
        "max_targets_cap": max_targets_cap,
        "max_targets_source": max_targets_source,
        "output": str(out_path),
    }
    print(json.dumps(report, ensure_ascii=True))


if __name__ == "__main__":
    main()
