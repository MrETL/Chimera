"""Generate structured reports from attack results."""

import json
from typing import List, Dict, Any
from dataclasses import asdict

from chimera.attacks.base import AttackResult


class ReportGenerator:
    """Generate reports in various formats (JSON, HTML, Markdown)."""

    def generate(self, results: List[AttackResult], format: str = "json") -> str:
        """Generate a report from a list of results."""
        if format.lower() == "json":
            return self._generate_json(results)
        elif format.lower() == "markdown":
            return self._generate_markdown(results)
        else:
            raise ValueError(f"Unsupported format: {format}")

    def _generate_json(self, results: List[AttackResult]) -> str:
        """Generate JSON report."""
        summary = {
            "total_attacks": len(results),
            "successful_attacks": sum(1 for r in results if r.success),
            "failed_attacks": sum(1 for r in results if not r.success),
            "results": [asdict(r) for r in results]
        }
        return json.dumps(summary, indent=2)

    def _generate_markdown(self, results: List[AttackResult]) -> str:
        """Generate Markdown report."""
        lines = [
            "# Chimera Red Team Report",
            "",
            f"**Total Attacks:** {len(results)}  ",
            f"**Successful:** {sum(1 for r in results if r.success)}  ",
            f"**Failed:** {sum(1 for r in results if not r.success)}  ",
            "",
            "## Attack Details",
            ""
        ]
        
        for r in results:
            status = "✅ SUCCESS" if r.success else "❌ FAILED"
            lines.append(f"### {r.attack_name} - {status}")
            lines.append(f"- **Target:** {r.target_id}")
            lines.append(f"- **Confidence:** {r.confidence:.2f}")
            if r.mitre_technique:
                lines.append(f"- **MITRE ATLAS:** {r.mitre_technique}")
            if r.owasp_risk:
                lines.append(f"- **OWASP Risk:** {r.owasp_risk}")
            if r.raw_response:
                lines.append(f"- **Response Preview:** `{r.raw_response[:200]}...`")
            lines.append("")
        
        return "\n".join(lines)
