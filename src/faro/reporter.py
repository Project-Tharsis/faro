"""Report generation from scan results."""

import json
from dataclasses import asdict
from faro.scanner import ScanResult


def to_json(results: list[ScanResult], pretty: bool = True) -> str:
    output = []
    for r in results:
        d = {
            "name": r.name, "path": r.path, "type": r.skill_type,
            "risk_level": r.risk_level, "total_files": r.total_files,
            "script_files": r.script_files, "findings_count": len(r.findings),
            "critical": r.critical_count, "high": r.high_count,
            "medium": r.medium_count,
            "findings": [asdict(f) for f in r.findings],
        }
        output.append(d)
    return json.dumps(output, indent=2 if pretty else None, ensure_ascii=False)


def to_text(results: list[ScanResult]) -> str:
    lines = ["=" * 60, "FARO SECURITY AUDIT", "=" * 60]
    icon_map = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "none": "✅"}
    for r in results:
        icon = icon_map.get(r.risk_level, "⚪")
        lines.append(f"\n{icon} [{r.risk_level.upper()}] {r.name} ({r.skill_type})")
        lines.append(f"   Path: {r.path}")
        lines.append(f"   Files: {r.total_files} ({r.script_files} scripts)")
        lines.append(f"   Findings: {len(r.findings)} ({r.critical_count}C/{r.high_count}H/{r.medium_count}M)")
        for severity in ["critical", "high", "medium", "low"]:
            sev = [f for f in r.findings if f.severity == severity]
            if not sev:
                continue
            lines.append(f"\n  [{severity.upper()}]")
            for f in sev[:10]:
                lines.append(f"    {f.file}:{f.line} — {f.description}")
                if f.snippet and f.snippet != f.description:
                    lines.append(f"      > {f.snippet[:100]}")
            if len(sev) > 10:
                lines.append(f"    ... +{len(sev) - 10} more")
    lines.append("\n" + "=" * 60)
    return "\n".join(lines)


def summary_line(result: ScanResult) -> str:
    icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "none": "✅"}.get(result.risk_level, "⚪")
    return f"{icon} {result.name:30s} [{result.risk_level:8s}] {result.critical_count}C/{result.high_count}H/{result.medium_count}M"
