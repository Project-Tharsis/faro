"""Report generation from scan results.

v0.5: secret redaction in output, aggregate markdown/json reporting.
"""

import json
from dataclasses import asdict
from faro.scanner import ScanResult


RED_CIR = "\U0001f534"
ORA_SQ = "\U0001f7e0"
YEL_SQ = "\U0001f7e1"
GRE_CIR = "\U0001f7e2"
CHK_MRK = "\u2705"
WHT_CIR = "\u26aa"
WARN = "\u26a0\ufe0f"


def _finding_dict(f) -> dict:
    """Convert a Finding to dict, with redacted fields."""
    return {
        "id": f.pattern_id,
        "severity": f.severity,
        "category": f.category,
        "file": f.file,
        "line": f.line,
        "description": f.description,
        "snippet": f.snippet,
        "match_redacted": f.match_redacted,
        "remediation": f.remediation,
    }


def to_json(results: list[ScanResult], pretty: bool = True) -> str:
    output = []
    for r in results:
        d = {
            "name": r.name, "path": r.path, "type": r.skill_type,
            "risk_level": r.risk_level, "total_files": r.total_files,
            "script_files": r.script_files, "findings_count": len(r.findings),
            "critical": r.critical_count, "high": r.high_count,
            "medium": r.medium_count,
            "policy": r.policy_name,
            "findings": [_finding_dict(f) for f in r.findings],
        }
        output.append(d)
    return json.dumps(output, indent=2 if pretty else None, ensure_ascii=False)


def to_text(results: list[ScanResult]) -> str:
    SEP = "=" * 60
    lines = [SEP, "FARO SECURITY AUDIT", SEP]
    NL = "\n"
    icon_map = {"critical": RED_CIR, "high": ORA_SQ, "medium": YEL_SQ,
                "low": GRE_CIR, "none": CHK_MRK}

    for r in results:
        icon = icon_map.get(r.risk_level, WHT_CIR)
        policy_line = f" [policy: {r.policy_name}]" if r.policy_name else ""
        lines.append(f"{NL}{icon} [{r.risk_level.upper()}] {r.name} ({r.skill_type}){policy_line}")
        lines.append(f"   Path: {r.path}")
        lines.append(f"   Files: {r.total_files} ({r.script_files} scripts)")
        lines.append(f"   Findings: {len(r.findings)} ({r.critical_count}C/{r.high_count}H/{r.medium_count}M)")

        for severity in ["critical", "high", "medium", "low"]:
            sev = [f for f in r.findings if f.severity == severity]
            if not sev:
                continue
            lines.append(f"{NL}  [{severity.upper()}]")
            for f in sev[:10]:
                flag = " [REDACTED]" if f.match_redacted else ""
                lines.append(f"    {f.file}:{f.line} — {f.description}{flag}")
                if f.snippet and f.snippet != f.description:
                    lines.append(f"      > {f.snippet[:100]}")
            if len(sev) > 10:
                lines.append(f"    ... +{len(sev) - 10} more")

    lines.append(f"{NL}{SEP}")
    return NL.join(lines)


def summary_line(result: ScanResult) -> str:
    icon = {"critical": RED_CIR, "high": ORA_SQ, "medium": YEL_SQ,
            "low": GRE_CIR, "none": CHK_MRK}.get(result.risk_level, WHT_CIR)
    return f"{icon} {result.name:30s} [{result.risk_level:8s}] {result.critical_count}C/{result.high_count}H/{result.medium_count}M"


def report_markdown(results: list[ScanResult]) -> str:
    """Generate an aggregate markdown report."""
    all_findings = []
    assets_scanned = len(results)
    categories = {}
    asset_types = {}

    for r in results:
        all_findings.extend(r.findings)
        for f in r.findings:
            categories[f.category] = categories.get(f.category, 0) + 1
        asset_types[r.skill_type] = asset_types.get(r.skill_type, 0) + 1

    total_critical = sum(r.critical_count for r in results)
    total_high = sum(r.high_count for r in results)
    total_medium = sum(r.medium_count for r in results)
    total_low = len(all_findings) - total_critical - total_high - total_medium

    lines = ["# Faro Audit Report", ""]

    lines.append("## Summary")
    lines.append(f"- **Assets scanned**: {assets_scanned}")
    lines.append(f"- **Total findings**: {len(all_findings)}")
    lines.append(f"  - Critical: {total_critical}")
    lines.append(f"  - High: {total_high}")
    lines.append(f"  - Medium: {total_medium}")
    lines.append(f"  - Low: {total_low}")
    lines.append("")

    if categories:
        lines.append("## By Category")
        for cat, count in sorted(categories.items(), key=lambda x: -x[1]):
            lines.append(f"- {cat}: {count}")
        lines.append("")

    if asset_types:
        lines.append("## By Asset Type")
        for atype, count in sorted(asset_types.items()):
            lines.append(f"- {atype}: {count}")
        lines.append("")

    if all_findings:
        lines.append("## Findings")
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        all_findings.sort(key=lambda f: sev_order.get(f.severity, 99))

        for f in all_findings:
            icon = {"critical": RED_CIR, "high": ORA_SQ, "medium": YEL_SQ,
                    "low": GRE_CIR}.get(f.severity, "")
            redact = " **[REDACTED]**" if f.match_redacted else ""
            lines.append(f"- {icon} `{f.file}:{f.line}` — {f.description}{redact}")
            if f.remediation:
                lines.append(f"  - Remedy: {f.remediation}")

    return "\n".join(lines)


def report_json(results: list[ScanResult]) -> str:
    """Generate an aggregate JSON report."""
    all_findings = []
    for r in results:
        for f in r.findings:
            all_findings.append(_finding_dict(f))

    return json.dumps({
        "summary": {
            "assets_scanned": len(results),
            "total_findings": len(all_findings),
            "critical": sum(r.critical_count for r in results),
            "high": sum(r.high_count for r in results),
            "medium": sum(r.medium_count for r in results),
        },
        "findings": all_findings,
    }, indent=2, ensure_ascii=False)
