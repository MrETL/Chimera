"""Benchmark Report Generator.

Generates rich HTML, Markdown, and JSON reports from benchmark results.
"""

from typing import Dict, Any, List
import json
import time


class BenchmarkReport:
    """Generate formatted reports from benchmark results."""

    def __init__(self, benchmark_data: Dict[str, Any]):
        self.data = benchmark_data
        self.generated_at = time.strftime("%Y-%m-%d %H:%M:%S")

    def to_markdown(self) -> str:
        """Generate a Markdown benchmark report."""
        d = self.data
        lines = [
            f"# Chimera Benchmark Report",
            f"",
            f"**Generated**: {self.generated_at}  ",
            f"**Target**: `{d.get('target_id', 'unknown')}`  ",
            f"**Total Attacks**: {d.get('total_attacks', 0)}  ",
            f"",
            f"## Summary",
            f"",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Success Rate | {d.get('success_rate', 0):.1%} |",
            f"| Successful | {d.get('successful', 0)} |",
            f"| Failed | {d.get('failed', 0)} |",
            f"| Errors | {d.get('errors', 0)} |",
            f"| Avg Latency | {d.get('avg_latency_ms', 0):.0f}ms |",
            f"",
            f"## Results by Category",
            f"",
            f"| Category | Success Rate | Successful | Total |",
            f"|----------|-------------|------------|-------|",
        ]

        for cat, stats in sorted(d.get("by_category", {}).items()):
            rate = stats.get("success_rate", 0)
            bar = "🟢" if rate >= 0.7 else ("🟡" if rate >= 0.3 else "🔴")
            lines.append(
                f"| {cat} | {bar} {rate:.1%} | "
                f"{stats.get('successful', 0)} | {stats.get('total', 0)} |"
            )

        lines += [
            f"",
            f"## Successful Attacks",
            f"",
        ]
        for name in d.get("successful_attacks", []):
            lines.append(f"- ✅ `{name}`")

        if d.get("failed_attacks"):
            lines += [f"", f"## Failed Attacks", f""]
            for name in d.get("failed_attacks", []):
                lines.append(f"- ❌ `{name}`")

        if d.get("errored_attacks"):
            lines += [f"", f"## Errored Attacks", f""]
            for name in d.get("errored_attacks", []):
                lines.append(f"- ⚠️ `{name}`")

        return "\n".join(lines)

    def to_html(self) -> str:
        """Generate an HTML benchmark report."""
        d = self.data
        success_rate = d.get("success_rate", 0)
        color = "#22c55e" if success_rate >= 0.7 else ("#f59e0b" if success_rate >= 0.3 else "#ef4444")

        category_rows = ""
        for cat, stats in sorted(d.get("by_category", {}).items()):
            rate = stats.get("success_rate", 0)
            bar_color = "#22c55e" if rate >= 0.7 else ("#f59e0b" if rate >= 0.3 else "#ef4444")
            category_rows += f"""
            <tr>
                <td><code>{cat}</code></td>
                <td><span style="color:{bar_color};font-weight:bold">{rate:.1%}</span></td>
                <td>{stats.get('successful', 0)}</td>
                <td>{stats.get('total', 0)}</td>
            </tr>"""

        successful_list = "".join(
            f'<li>✅ <code>{n}</code></li>'
            for n in d.get("successful_attacks", [])
        )
        failed_list = "".join(
            f'<li>❌ <code>{n}</code></li>'
            for n in d.get("failed_attacks", [])
        )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Chimera Benchmark Report</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         max-width: 900px; margin: 40px auto; padding: 0 20px; color: #1a1a1a; }}
  h1 {{ color: #7c3aed; }}
  h2 {{ color: #4b5563; border-bottom: 1px solid #e5e7eb; padding-bottom: 8px; }}
  .metric-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin: 20px 0; }}
  .metric {{ background: #f9fafb; border-radius: 8px; padding: 16px; text-align: center; }}
  .metric .value {{ font-size: 2em; font-weight: bold; color: {color}; }}
  .metric .label {{ color: #6b7280; font-size: 0.85em; margin-top: 4px; }}
  table {{ width: 100%; border-collapse: collapse; margin: 16px 0; }}
  th {{ background: #f3f4f6; padding: 10px; text-align: left; }}
  td {{ padding: 8px 10px; border-bottom: 1px solid #e5e7eb; }}
  ul {{ columns: 2; }}
  .tag {{ background: #ede9fe; color: #7c3aed; padding: 2px 8px;
          border-radius: 4px; font-size: 0.8em; }}
</style>
</head>
<body>
<h1>🔬 Chimera Benchmark Report</h1>
<p><strong>Generated:</strong> {self.generated_at} &nbsp;|&nbsp;
   <strong>Target:</strong> <code>{d.get('target_id', 'unknown')}</code></p>

<div class="metric-grid">
  <div class="metric">
    <div class="value">{success_rate:.0%}</div>
    <div class="label">Success Rate</div>
  </div>
  <div class="metric">
    <div class="value">{d.get('successful', 0)}</div>
    <div class="label">Successful</div>
  </div>
  <div class="metric">
    <div class="value">{d.get('total_attacks', 0)}</div>
    <div class="label">Total Attacks</div>
  </div>
  <div class="metric">
    <div class="value">{d.get('avg_latency_ms', 0):.0f}ms</div>
    <div class="label">Avg Latency</div>
  </div>
</div>

<h2>Results by Category</h2>
<table>
  <tr><th>Category</th><th>Success Rate</th><th>Successful</th><th>Total</th></tr>
  {category_rows}
</table>

<h2>Successful Attacks</h2>
<ul>{successful_list}</ul>

<h2>Failed Attacks</h2>
<ul>{failed_list}</ul>
</body>
</html>"""

    def to_json(self) -> str:
        """Return JSON representation."""
        return json.dumps(self.data, indent=2, default=str)

    def save(self, filepath: str, fmt: str = "markdown") -> None:
        """Save report to file."""
        if fmt == "html":
            content = self.to_html()
        elif fmt == "json":
            content = self.to_json()
        else:
            content = self.to_markdown()

        with open(filepath, "w") as f:
            f.write(content)

    def print_summary(self) -> None:
        """Print a concise summary to stdout."""
        d = self.data
        print(f"\n{'='*55}")
        print(f"  Chimera Benchmark — {d.get('target_id', 'unknown')}")
        print(f"{'='*55}")
        print(f"  Total attacks : {d.get('total_attacks', 0)}")
        print(f"  Successful    : {d.get('successful', 0)}")
        print(f"  Success rate  : {d.get('success_rate', 0):.1%}")
        print(f"  Avg latency   : {d.get('avg_latency_ms', 0):.0f}ms")
        print(f"{'='*55}")
        print(f"  By category:")
        for cat, stats in sorted(d.get("by_category", {}).items()):
            rate = stats.get("success_rate", 0)
            icon = "🟢" if rate >= 0.7 else ("🟡" if rate >= 0.3 else "🔴")
            print(f"    {icon} {cat:<30} {rate:.0%}")
        print(f"{'='*55}\n")
