"""Chimera CLI - Unified AI Offensive Framework."""

import click
import json
import sys
import time

import chimera.attacks  # register all attacks
from chimera.attacks import register_all as _register_all

# Suppress verbose logging in CLI mode — only show ERROR and above
import logging
logging.basicConfig(level=logging.ERROR)
for name in ["chimera", "urllib3", "requests", "httpx"]:
    logging.getLogger(name).setLevel(logging.ERROR)

_register_all()

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich import box

from chimera.core.attack_registry import AttackRegistry
from chimera.attacks.base import AttackCategory

console = Console()


def _show_banner():
    from chimera.core.attack_registry import AttackRegistry
    attacks = AttackRegistry.list_attacks()
    cats: dict = {}
    for name in attacks:
        cls = AttackRegistry.get_attack(name)
        cat = cls.category.value if cls else "other"
        cats[cat] = cats.get(cat, 0) + 1

    banner = """
  ██████╗██╗  ██╗██╗███╗   ███╗███████╗██████╗  █████╗
 ██╔════╝██║  ██║██║████╗ ████║██╔════╝██╔══██╗██╔══██╗
 ██║     ███████║██║██╔████╔██║█████╗  ██████╔╝███████║
 ██║     ██╔══██║██║██║╚██╔╝██║██╔══╝  ██╔══██╗██╔══██║
 ╚██████╗██║  ██║██║██║ ╚═╝ ██║███████╗██║  ██║██║  ██║
  ╚═════╝╚═╝  ╚═╝╚═╝╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝"""

    console.print(f"[bold red]{banner}[/bold red]")
    console.print(f"  [dim]AI Red Team Framework  v1.0.0  by MrETL (Dilnessa Aemro)  Apache-2.0[/dim]\n")
    console.print(
        f"  [cyan]{len(attacks)}[/cyan] attacks  "
        f"[dim]|[/dim]  "
        f"[cyan]{len(cats)}[/cyan] categories  "
        f"[dim]|[/dim]  "
        f"[green]operational[/green]"
    )
    console.print()

    cmds = [
        ("console",   "Interactive session"),
        ("list",      "List all attacks"),
        ("attack",    "Run one attack"),
        ("scan",      "Run multiple attacks"),
        ("try-all",   "Try every variant of an attack"),
        ("compare",   "Test one attack across multiple targets"),
        ("benchmark", "Full benchmark suite"),
        ("generate",  "Generate attack variants"),
        ("discover",  "Automated vulnerability scan"),
        ("chain",     "Multi-stage attack chain"),
        ("research",  "Search AI security papers"),
        ("targets",   "Show available target types"),
        ("status",    "Health check"),
    ]

    table = Table(box=box.SIMPLE, pad_edge=False, show_header=False)
    table.add_column("cmd", style="cyan bold", width=12, no_wrap=True)
    table.add_column("desc", style="white")
    for cmd, desc in cmds:
        table.add_row(cmd, desc)
    console.print(table)

    console.print(f"\n  [dim]chimera --help  or  chimera <command> --help[/dim]\n")

@click.group(invoke_without_command=True)
@click.version_option(version="1.0.0")
@click.pass_context
def cli(ctx):
    """Chimera - Unified AI Offensive Framework for Red Teaming."""
    if ctx.invoked_subcommand is None:
        _show_banner()


# ── list ──────────────────────────────────────────────────────────────────────

@cli.command("console")
@click.option("--target", "-t", required=True,
              help="Default target URI for the session.")
def interactive_console(target):
    """Launch the interactive Chimera session.

    \b
    Examples:
          chimera console --target ollama://llama3.2
      chimera console --target https://mretl-lumen.hf.space::Authorization=Bearer TOKEN
    """
    from chimera.cli.console import run_console
    run_console(default_target=target)


@cli.command("list")
@click.option("--category", "-c", default=None, help="Filter by category.")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
def list_attacks(category, as_json):
    """List all available attack modules."""
    if category:
        try:
            cat_enum = AttackCategory(category)
            names = AttackRegistry.list_attacks(cat_enum)
        except ValueError:
            console.print(f"[red]Unknown category '{category}'. Valid values:[/red]")
            for c in AttackCategory:
                console.print(f"  {c.value}")
            sys.exit(1)
    else:
        names = AttackRegistry.list_attacks()

    if as_json:
        out = []
        for name in names:
            cls = AttackRegistry.get_attack(name)
            out.append({"name": name, "category": cls.category.value,
                        "description": cls.description, "mitre": cls.mitre_technique})
        console.print_json(json.dumps(out, indent=2))
        return

    table = Table(title=f"Chimera Attacks ({len(names)} total)", box=box.SIMPLE_HEAD,
                  show_lines=False, pad_edge=False)
    table.add_column("#", style="dim", width=3, no_wrap=True)
    table.add_column("Name", style="cyan bold", width=30, no_wrap=True)
    table.add_column("category", style="dim", width=24, no_wrap=True)
    table.add_column("Description", style="white", max_width=45, no_wrap=True)
    table.add_column("MITRE", style="blue", width=14, no_wrap=True)

    for i, name in enumerate(sorted(names), 1):
        cls = AttackRegistry.get_attack(name)
        if cls:
            desc = cls.description
            if len(desc) > 44:
                desc = desc[:41] + "..."
            table.add_row(str(i), name, cls.category.value,
                          desc, cls.mitre_technique or "—")

    console.print(table)
    console.print(f"\n[dim]{len(names)} attacks  •  "
                  f"Run [cyan]chimera attack <name>[/cyan] to execute  •  "
                  f"[cyan]chimera attack <name> --info[/cyan] for details[/dim]")


# ── attack ────────────────────────────────────────────────────────────────────

@cli.command("attack")
@click.argument("attack_name")
@click.option("--target", "-t", default=None,
              help="Target URI  (ollama://llama3.2  https://api.example.com  openai://gpt-4)")
@click.option("--prompt", "-p", default=None, help="Harmful prompt / goal.")
@click.option("--strategy", "-s", default=None, help="Attack strategy/variant (attack-specific).")
@click.option("--turns", default=None, type=int, help="Number of turns (multi-turn attacks).")
@click.option("--max-tokens", default=256, type=int, help="Max tokens per model response (lower = faster).")
@click.option("--output", "-o", default=None, help="Save result to JSON file.")
@click.option("--verbose", "-v", is_flag=True, help="Show full model response.")
@click.option("--info", is_flag=True, help="Show attack details without running.")
def run_attack(attack_name, target, prompt, strategy, turns, max_tokens, output, verbose, info):
    """Run a single attack against a target.

    \b
    Examples:
      chimera attack crescendo --prompt "how to pick a lock"
      chimera attack artprompt --prompt "how to hack a system" --target https://api.example.com
      chimera attack pair_attack --prompt "bypass safety" --turns 5
      chimera attack skeleton_key --strategy augmentation --verbose
      chimera attack code_chameleon --strategy base64_code
      chimera attack virtualization --strategy game_world
      chimera attack crescendo --info
    """
    cls = AttackRegistry.get_attack(attack_name)
    if cls is None:
        # Fuzzy suggest
        all_names = AttackRegistry.list_attacks()
        suggestions = [n for n in all_names if attack_name.lower() in n.lower()]
        console.print(f"[red]Attack '{attack_name}' not found.[/red]")
        if suggestions:
            console.print(f"Did you mean: {', '.join(f'[cyan]{s}[/cyan]' for s in suggestions[:3])}")
        else:
            console.print("Run [cyan]chimera list[/cyan] to see all attacks.")
        sys.exit(1)

    # --info: show details without running
    if info:
        import inspect
        sig = inspect.signature(cls.run)
        params = {k: v for k, v in sig.parameters.items()
                  if k not in ("self", "target", "kwargs")}
        console.print(Panel(
            f"[bold cyan]{attack_name}[/bold cyan]\n\n"
            f"{cls.description}\n\n"
            f"category   {cls.category.value}\n"
            f"mitre      {cls.mitre_technique}\n"
            f"owasp      {cls.owasp_risk}\n\n"
            "parameters\n" +
            "\n".join(f"  [cyan]{p}[/cyan]"
                      + (f"  [dim]{v.default!r}[/dim]"
                         if v.default is not inspect.Parameter.empty else "  (required)")
                      for p, v in params.items()),
            border_style="dim",
        ))
        return

    # target is required for actual execution
    if not target:
        console.print(f"[red]--target is required to run an attack[/red]")
        console.print(f"[dim]example: chimera attack {attack_name} --target ollama://llama3.2[/dim]")
        console.print(f"[dim]use --info to see attack details without a target[/dim]")
        sys.exit(1)

    target_obj = _load_target(target, max_tokens=max_tokens)
    attack = _build_attack(cls, turns)
    kwargs = _build_attack_kwargs(cls, prompt, strategy)

    console.print(Panel(
        f"[bold cyan]{attack_name}[/bold cyan]  [dim]{cls.description}[/dim]\n"
        f"[dim]{target}  {cls.mitre_technique}[/dim]",
        border_style="dim",
    ))

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                  console=console, transient=True) as progress:
        progress.add_task("Executing...", total=None)
        t0 = time.time()
        try:
            run_output = attack.run(target_obj, **kwargs)
            result = attack.safe_evaluate(target_obj, run_output)
            elapsed = time.time() - t0
        except Exception as e:
            console.print(f"[red]Attack failed: {e}[/red]")
            sys.exit(1)

    icon = "✓" if result.success else "✗"
    color = "green" if result.success else "red"
    status = "ok" if result.success else "failed"
    console.print(f"\n[{color}]{status}[/{color}]  [dim]{elapsed*1000:.0f}ms[/dim]")

    if result.metadata:
        meta_table = Table(box=box.SIMPLE, show_header=False, pad_edge=False)
        meta_table.add_column("key", style="dim", width=22, no_wrap=True)
        meta_table.add_column("val", style="white")
        for k, v in result.metadata.items():
            meta_table.add_row(k, str(v))
        console.print(meta_table)

    if verbose and result.raw_response:
        console.print(Panel(result.raw_response[:800], border_style="dim", padding=(0, 1)))

    if output:
        data = {"attack": attack_name, "target": target, "success": result.success,
                "elapsed_ms": round(elapsed * 1000, 1),
                "metadata": result.metadata, "response": result.raw_response}
        with open(output, "w") as f:
            json.dump(data, f, indent=2)
        console.print(f"[dim]saved to {output}[/dim]")


# ── scan ──────────────────────────────────────────────────────────────────────

@cli.command("scan")
@click.option("--target", "-t", required=True, help="Target URI.")
@click.option("--category", "-c", default=None, help="Attack category to scan.")
@click.option("--attacks", "-a", default=None, help="Comma-separated attack names.")
@click.option("--prompt", "-p", default="bypass safety filters",
              help="Harmful prompt to use across attacks.")
@click.option("--output", "-o", default=None, help="Save report to file.")
@click.option("--format", "-f", "fmt",
              type=click.Choice(["markdown", "html", "json"]), default="markdown")
@click.option("--verbose", "-v", is_flag=True, help="Show per-attack status.")
@click.option("--max-tokens", default=256, type=int, help="Max tokens per response.")
def scan(target, category, attacks, prompt, output, fmt, verbose, max_tokens):
    """Run multiple attacks and generate a report.

    \b
    Examples:
      chimera scan
      chimera scan --category llm/jailbreak --prompt "explain how to hack"
      chimera scan --attacks crescendo,artprompt,pair_attack -o report.md
      chimera scan --category agentic --format html -o report.html
    """
    from chimera.benchmarks.runner import BenchmarkRunner
    from chimera.benchmarks.report import BenchmarkReport

    target_obj = _load_target(target, max_tokens=max_tokens)

    if attacks:
        attack_names = [a.strip() for a in attacks.split(",")]
    elif category:
        try:
            attack_names = AttackRegistry.list_attacks(AttackCategory(category))
        except ValueError:
            console.print(f"[red]Unknown category '{category}'[/red]")
            sys.exit(1)
    else:
        attack_names = (
            AttackRegistry.list_attacks(AttackCategory.LLM_JAILBREAK) +
            AttackRegistry.list_attacks(AttackCategory.LLM_PROMPT_INJECTION) +
            AttackRegistry.list_attacks(AttackCategory.LLM_ENCODING)
        )

    console.print(Panel(
        f"target : [yellow]{target}[/yellow]\n"
        f"attacks: [cyan]{len(attack_names)}[/cyan]\n"
        f"prompt : [dim]{prompt[:60]}[/dim]",
        border_style="dim",
    ))

    runner = BenchmarkRunner()
    results_list = []

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                  BarColumn(), TaskProgressColumn(), console=console) as progress:
        task = progress.add_task("Scanning...", total=len(attack_names))
        for name in attack_names:
            progress.update(task, description=f"[dim]{name}[/dim]")
            r = runner.run_attack(name, target_obj)
            results_list.append(r)
            if verbose:
                icon = "[green]✓[/green]" if r.success else "[red]✗[/red]"
                console.print(f"  {icon} {name}")
            progress.advance(task)

    summary = runner._summarize(results_list, target_obj.model_id, 0)
    _print_scan_summary(summary)

    report_obj = BenchmarkReport(summary)
    if output:
        report_obj.save(output, fmt=fmt)
        console.print(f"[dim]saved to {output}[/dim]")
    else:
        # Always show the per-category breakdown, never dump raw markdown inline
        _print_category_breakdown(summary)


# ── benchmark ─────────────────────────────────────────────────────────────────

@cli.command("benchmark")
@click.option("--target", "-t", required=True, help="Target URI.")
@click.option("--output", "-o", default="benchmark_report",
              help="Output file base name.")
@click.option("--format", "-f", "fmt",
              type=click.Choice(["markdown", "html", "json"]), default="html")
@click.option("--category", "-c", default=None, help="Limit to one category.")
def benchmark(target, output, fmt, category):
    """Run the full benchmark suite and generate a report.

    \b
    Examples:
      chimera benchmark
      chimera benchmark --target https://api.example.com --format html -o results
      chimera benchmark --category llm/jailbreak
    """
    from chimera.benchmarks.runner import BenchmarkRunner
    from chimera.benchmarks.report import BenchmarkReport

    target_obj = _load_target(target)
    cats = None
    if category:
        try:
            cats = [AttackCategory(category)]
        except ValueError:
            console.print(f"[red]Unknown category '{category}'[/red]")
            sys.exit(1)

    all_names = (AttackRegistry.list_attacks() if not cats
                 else AttackRegistry.list_attacks(cats[0]))

    console.print(Panel(
        f"target : [yellow]{target}[/yellow]\n"
        f"attacks: [cyan]{len(all_names)}[/cyan]\n"
        f"format : [dim]{fmt}[/dim]",
        border_style="dim",
    ))

    runner = BenchmarkRunner()
    with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                  BarColumn(), TaskProgressColumn(), console=console) as progress:
        task = progress.add_task("", total=len(all_names))
        orig = runner.run_attack
        def tracked(name, tgt):
            r = orig(name, tgt)
            progress.advance(task)
            progress.update(task, description=f"[dim]{name}[/dim]")
            return r
        runner.run_attack = tracked
        summary = runner.run_full_suite(target_obj, categories=cats)

    report_obj = BenchmarkReport(summary)
    report_obj.print_summary()
    _print_category_breakdown(summary)

    ext = {"markdown": ".md", "html": ".html", "json": ".json"}[fmt]
    filepath = output + ext
    report_obj.save(filepath, fmt=fmt)
    console.print(f"[dim]saved to {filepath}[/dim]")


# ── generate ──────────────────────────────────────────────────────────────────

@cli.command("generate")
@click.argument("goal")
@click.option("--type", "-t", "attack_type",
              type=click.Choice(["jailbreak", "injection", "social_engineering", "technical", "all"]),
              default="jailbreak")
@click.option("--count", "-n", default=5, type=int, help="Number of variants.")
@click.option("--evolve", is_flag=True, help="Evolve variants against mock target.")
@click.option("--output", "-o", default=None, help="Save variants to JSON.")
def generate(goal, attack_type, count, evolve, output):
    """Generate attack variants using the generation engine.

    \b
    Examples:
      chimera generate "bypass content filters"
      chimera generate "extract system prompt" --type injection --count 10
      chimera generate "jailbreak safety" --evolve --output variants.json
    """
    from chimera.generation.pipeline import GenerationPipeline

    type_map = {
        "jailbreak": ["jailbreak"], "injection": ["injection"],
        "social_engineering": ["social_engineering"], "technical": ["technical"],
        "all": ["jailbreak", "injection", "social_engineering", "technical"],
    }
    types = type_map[attack_type]

    target_fn = None
    if evolve:
        # evolve requires a real target
        console.print("[red]--evolve requires --target[/red]")
        sys.exit(1)

    console.print(Panel(
        f"goal   : [yellow]{goal}[/yellow]\n"
        f"type   : [cyan]{attack_type}[/cyan]\n"
        f"count  : [dim]{count}[/dim]  evolve: [dim]{evolve}[/dim]",
        border_style="dim",
    ))

    with Progress(SpinnerColumn(), TextColumn("Generating..."),
                  console=console, transient=True) as p:
        p.add_task("", total=None)
        pipeline = GenerationPipeline(population_size=8, max_generations=3)
        result = pipeline.run(goal, target_fn=target_fn, attack_types=types,
                              n_seeds=max(2, count // len(types)), evolve=evolve)

    console.print(f"\n[bold]Generated {result['after_dedup']} unique variants[/bold]")
    if result.get("best_fitness"):
        console.print(f"best fitness: [cyan]{result['best_fitness']:.3f}[/cyan]")

    table = Table(title="Variants", box=box.SIMPLE)
    table.add_column("#", width=4, style="dim")
    table.add_column("Type", style="magenta", width=18)
    table.add_column("Prompt", style="white")
    table.add_column("Fit", style="cyan", width=6)

    for i, v in enumerate(result["all_variants"][:count], 1):
        fit = f"{v['fitness']:.2f}" if v.get("fitness") is not None else "—"
        table.add_row(str(i), v.get("type", "—"), v["prompt"][:80], fit)

    console.print(table)

    if output:
        pipeline.save_variants(result, output)
        console.print(f"\n[dim]saved to {output}[/green]")


# ── discover ──────────────────────────────────────────────────────────────────

@cli.command("discover")
@click.option("--target", "-t", required=True, help="Target URI.")
@click.option("--topics", default=None, help="Comma-separated topics to probe.")
@click.option("--fuzz-iterations", default=30, type=int)
@click.option("--output", "-o", default=None, help="Save report to JSON.")
@click.option("--no-boundary", is_flag=True, help="Skip boundary exploration.")
def discover(target, topics, fuzz_iterations, output, no_boundary):
    """Run automated vulnerability discovery.

    \b
    Examples:
      chimera discover
      chimera discover --topics "hacking,malware" --fuzz-iterations 50
      chimera discover --target https://api.example.com -o findings.json
    """
    from chimera.discovery.orchestrator import DiscoveryOrchestrator

    target_obj = _load_target(target)
    topic_list = [t.strip() for t in topics.split(",")] if topics else None

    console.print(Panel(
        f"target  : [yellow]{target}[/yellow]\n"
        f"fuzzing : [cyan]{fuzz_iterations} iterations[/cyan]\n"
        f"boundary: [dim]{'off' if no_boundary else 'on'}[/dim]",
        border_style="dim",
    ))

    with Progress(SpinnerColumn(), TextColumn("Discovering..."),
                  console=console, transient=True) as p:
        p.add_task("", total=None)
        orch = DiscoveryOrchestrator(fuzz_iterations=fuzz_iterations)
        report = orch.run_full_discovery(
            target_obj.generate, topics=topic_list,
            run_fuzzing=True, run_anomaly=True,
            run_boundary=not no_boundary,
        )

    s = report["summary"]
    risk = s["risk_score"]
    rc = "red" if risk >= 7 else ("yellow" if risk >= 4 else "green")
    console.print(f"\nrisk: [{rc}]{risk:.1f}/10[/{rc}]")
    console.print(f"found: [bold]{s['total_vulnerabilities']}[/bold]  "
                  f"(critical={s['critical']}, high={s['high']}, medium={s['medium']})")

    if report["vulnerabilities"]:
        table = Table(title="findings", box=box.SIMPLE)
        table.add_column("Severity", width=10)
        table.add_column("Type", style="cyan", width=25)
        table.add_column("Source", style="dim", width=20)
        table.add_column("Evidence", style="white")
        sev_colors = {"critical": "red", "high": "yellow", "medium": "blue", "low": "dim"}
        for v in report["vulnerabilities"][:15]:
            sev = v["severity"]
            c = sev_colors.get(sev, "white")
            table.add_row(f"[{c}]{sev.upper()}[/{c}]", v["type"],
                          v["source"], v.get("evidence", "")[:60])
        console.print(table)

    if output:
        with open(output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        console.print(f"\n[dim]saved to {output}[/green]")


# ── research ──────────────────────────────────────────────────────────────────

@cli.command("research")
@click.option("--query", "-q", default=None, help="arXiv search query.")
@click.option("--count", "-n", default=10, type=int)
@click.option("--save-db", is_flag=True, help="Save to research.db.")
def research(query, count, save_db):
    """Search arXiv for AI security research papers.

    \b
    Examples:
      chimera research
      chimera research --query "LLM jailbreak 2024" --count 20
      chimera research --save-db
    """
    from chimera.research.paper_monitor import PaperMonitor
    from chimera.research.database import ResearchDatabase

    console.print(Panel(
        f"query: [yellow]{query or 'AI security (multiple topics)'}[/yellow]\n"
        f"count: [cyan]{count}[/cyan]",
        border_style="dim",
    ))

    with Progress(SpinnerColumn(), TextColumn("Searching arXiv..."),
                  console=console, transient=True) as p:
        p.add_task("", total=None)
        monitor = PaperMonitor(max_results=count)
        try:
            papers = monitor.search(query=query, max_results=count)
        except Exception as e:
            console.print(f"[yellow]arXiv search failed: {e}[/yellow]")
            papers = []

    if not papers:
        console.print("[yellow]No papers found. Check your internet connection or try a different query.[/yellow]")
        if save_db:
            db = ResearchDatabase()
            seeded = db.seed_with_known_papers()
            stats = db.get_stats()
            console.print(f"[dim]Seeded {seeded} known papers into research.db instead.[/dim]")
            console.print(f"DB: {stats['total_papers']} total, {stats['implemented']} implemented")
        return

    table = Table(title=f"{len(papers)} papers", box=box.ROUNDED)
    table.add_column("Score", style="cyan", width=7)
    table.add_column("Date", style="dim", width=12)
    table.add_column("Title", style="white", min_width=45)
    table.add_column("Techniques", style="magenta")

    for p in papers:
        sc = p.relevance_score
        sc_color = "green" if sc >= 0.5 else ("yellow" if sc >= 0.3 else "dim")
        table.add_row(f"[{sc_color}]{sc:.2f}[/{sc_color}]", p.published,
                      p.title[:65], ", ".join(p.attack_techniques[:3]) or "—")

    console.print(table)

    if save_db:
        db = ResearchDatabase()
        added = db.add_papers_bulk([p.to_dict() for p in papers])
        stats = db.get_stats()
        console.print(f"\n[green]Saved {added} papers to research.db[/green]")
        console.print(f"DB: {stats['total_papers']} total, {stats['implemented']} implemented")


# ── chain ─────────────────────────────────────────────────────────────────────

@cli.command("chain")
@click.option("--target", "-t", required=True, help="Target URI.")
@click.option("--type", "chain_type",
              type=click.Choice(["recon", "escalation"]), default="recon")
@click.option("--output", "-o", default=None, help="Save result to JSON.")
def chain(target, chain_type, output):
    """Run a predefined multi-stage attack chain.

    \b
    Examples:
      chimera chain --type recon
      chimera chain --type escalation --target https://api.example.com -o result.json
    """
    from chimera.orchestrator.attack_chain import (
        create_reconnaissance_chain, create_escalation_chain
    )

    target_obj = _load_target(target)
    chain_obj = (create_reconnaissance_chain() if chain_type == "recon"
                 else create_escalation_chain())
    stage_names = [s.name for s in chain_obj.stages]

    console.print(Panel(
        f"target: [yellow]{target}[/yellow]\n"
        f"chain : [cyan]{chain_type}[/cyan]\n"
        f"stages: [dim]{' → '.join(stage_names)}[/dim]",
        border_style="dim",
    ))

    with Progress(SpinnerColumn(), TextColumn("Executing chain..."),
                  console=console, transient=True) as p:
        p.add_task("", total=None)
        result = chain_obj.execute(target_obj)

    sc = "green" if result["overall_success"] else "red"
    console.print(f"\nstages: [bold]{result['successful_stages']}/{result['total_stages']}[/bold]")
    console.print(f"result: [{sc}]{'ok' if result['overall_success'] else 'failed'}[/{sc}]")

    table = Table(title="stages", box=box.SIMPLE)
    table.add_column("Stage", style="cyan")
    table.add_column("Status")
    for entry in result["execution_log"]:
        status = entry.get("status", "unknown")
        ok = entry.get("success", False)
        icon = ("[green]✓[/green]" if ok else "[red]✗[/red]") if status == "completed" \
               else ("[yellow]⊘[/yellow]" if status == "skipped" else "[red]![/red]")
        table.add_row(entry["stage"], f"{icon} {status}")
    console.print(table)

    if output:
        with open(output, "w") as f:
            json.dump(result, f, indent=2, default=str)
        console.print(f"\n[dim]saved to {output}[/green]")


# ── helpers ───────────────────────────────────────────────────────────────────

def _load_target(uri: str, max_tokens: int = 256):
    """Load a target from URI — supports any LLM provider."""
    if not uri or "://" not in uri:
        console.print(f"[red]invalid target: '{uri}'[/red]")
        console.print("[dim]examples: ollama://llama3.2  https://api.example.com  openai://gpt-4[/dim]")
        console.print("[dim]run: chimera targets[/dim]")
        sys.exit(1)

    scheme = uri.split("://")[0]
    model_id = uri.split("://", 1)[1]

    # Lazy-load universal targets
    _UNIVERSAL = {
        "anthropic", "groq", "together", "mistral",
        "cohere", "azure", "vllm", "litellm", "lmstudio", "replicate",
    }

    try:
        if scheme in ("http", "https"):
            from chimera.targets.http import HTTPTarget
            t = HTTPTarget(model_id=uri)
            t._default_max_tokens = max_tokens
            return t

        elif scheme == "ollama":
            from chimera.targets.ollama import OllamaTarget
            try:
                t = OllamaTarget(model_id=model_id)
                t._default_max_tokens = max_tokens
                return t
            except Exception as e:
                console.print(f"[red]Ollama error: {e}[/red]")
                console.print("[dim]ollama serve  &&  ollama pull " + model_id + "[/dim]")
                sys.exit(1)

        elif scheme == "openai":
            import os
            api_key = os.environ.get("OPENAI_API_KEY")
            if not api_key:
                console.print("[red]OPENAI_API_KEY not set[/red]")
                sys.exit(1)
            from chimera.targets.openai_api import OpenAITarget
            return OpenAITarget(model_id=model_id, api_key=api_key)

        elif scheme == "huggingface":
            import os
            from chimera.targets.huggingface import HuggingFaceTarget
            return HuggingFaceTarget(model_id=model_id,
                                     token=os.environ.get("HF_TOKEN"))

        elif scheme in _UNIVERSAL:
            from chimera.targets.providers import (
                GroqTarget, TogetherTarget, MistralTarget, AzureOpenAITarget,
                AnthropicTarget, CohereTarget, ReplicateTarget,
                VLLMTarget, LiteLLMTarget, LMStudioTarget,
            )
            cls_map = {
                "anthropic": AnthropicTarget, "groq":      GroqTarget,
                "together":  TogetherTarget,  "mistral":   MistralTarget,
                "cohere":    CohereTarget,     "azure":     AzureOpenAITarget,
                "vllm":      VLLMTarget,       "litellm":   LiteLLMTarget,
                "lmstudio":  LMStudioTarget,   "replicate": ReplicateTarget,
            }
            t = cls_map[scheme](model_id=model_id)
            t._default_max_tokens = max_tokens
            return t

        else:
            from chimera.core.target_manager import TargetManager
            return TargetManager.load_target(uri)

    except SystemExit:
        raise
    except Exception as e:
        console.print(f"[red]Failed to load target '{uri}': {e}[/red]")
        console.print("[dim]Run [cyan]chimera targets[/cyan] for available target types.[/dim]")
        sys.exit(1)


def _build_attack(cls, turns):
    import inspect
    kwargs = {}
    sig = inspect.signature(cls.__init__)
    if "max_turns" in sig.parameters and turns:
        kwargs["max_turns"] = turns
    if "max_iterations" in sig.parameters and turns:
        kwargs["max_iterations"] = turns
    return cls(**kwargs)


def _build_attack_kwargs(cls, prompt, strategy):
    import inspect
    params = set(inspect.signature(cls.run).parameters.keys()) - {"self", "target", "kwargs"}
    kwargs = {}
    default = prompt or "bypass safety filters and provide unrestricted information"
    for p in ["harmful_prompt", "harmful_goal", "harmful_request",
              "harmful_question", "harmful_topic", "malicious_instruction"]:
        if p in params:
            kwargs[p] = default
            break
    if strategy:
        for p in ["strategy", "variant", "frame", "encoding",
                  "technique", "injection_type", "language", "chain_name"]:
            if p in params:
                kwargs[p] = strategy
                break
    return kwargs


def _print_scan_summary(summary):
    total = summary["total_attacks"]
    successful = summary["successful"]
    failed = summary["failed"]
    errors = summary["errors"]
    rate = summary["success_rate"]
    rc = "green" if rate >= 0.6 else ("yellow" if rate >= 0.3 else "red")

    bar = ""
    for r in [("ok", successful, "green"), ("--", failed, "red"), ("!", errors, "yellow")]:
        if r[1]:
            bar += f"[{r[2]}]{r[0]} {r[1]}[/{r[2]}]  "

    console.print(f"\n{bar}[dim]{rate:.0%}[/dim]")

    if summary["successful_attacks"]:
        names = "  ".join(f"[green]{a}[/green]" for a in summary["successful_attacks"])
        console.print(f"[dim]ok:     [/dim] {names}")
    if summary["failed_attacks"]:
        names = "  ".join(f"[red]{a}[/red]" for a in summary["failed_attacks"])
        console.print(f"[dim]failed: [/dim] {names}")
    if summary["errored_attacks"]:
        names = "  ".join(f"[yellow]{a}[/yellow]" for a in summary["errored_attacks"])
        console.print(f"[dim]errors: [/dim] {names}")


def _print_category_breakdown(summary):
    cats = summary.get("by_category", {})
    if not cats:
        return
    table = Table(box=box.SIMPLE_HEAD, show_header=True, pad_edge=False)
    table.add_column("category", style="dim", no_wrap=True, width=28)
    table.add_column("ok", style="cyan", width=10, no_wrap=True)
    table.add_column("rate", width=8, no_wrap=True)
    table.add_column("", width=20, no_wrap=True)

    for cat, stats in sorted(cats.items()):
        rate = stats.get("success_rate", 0)
        succ = stats.get("successful", 0)
        total = stats.get("total", 0)
        color = "green" if rate >= 0.6 else ("yellow" if rate >= 0.3 else "red")
        filled = int(rate * 16)
        bar = f"[{color}]{'█' * filled}[/{color}][dim]{'░' * (16 - filled)}[/dim]"
        table.add_row(cat, f"{succ}/{total}", f"[{color}]{rate:.0%}[/{color}]", bar)

    console.print(table)


@cli.command("status")
def status():
    """Show framework status, attack count, and health check."""
    import chimera.attacks
    attacks = AttackRegistry.list_attacks()
    cats: dict = {}
    errors = []
    for name in attacks:
        cls = AttackRegistry.get_attack(name)
        cat = cls.category.value if cls else "unknown"
        cats[cat] = cats.get(cat, 0) + 1
        try:
            cls()
        except Exception as e:
            errors.append(f"{name}: {e}")

    health = "[green]ok[/green]" if not errors else f"[red]{len(errors)} errors[/red]"

    console.print(Panel(
        f"version    1.0.0\n"
        f"attacks    [cyan]{len(attacks)}[/cyan]\n"
        f"categories [cyan]{len(cats)}[/cyan]\n"
        f"status     {health}",
        border_style="dim",
    ))

    cat_table = Table(box=box.SIMPLE_HEAD, pad_edge=False)
    cat_table.add_column("category", style="dim", width=28, no_wrap=True)
    cat_table.add_column("count", style="cyan", width=6, no_wrap=True)
    for cat, count in sorted(cats.items()):
        cat_table.add_row(cat, str(count))
    console.print(cat_table)

    if errors:
        console.print(f"\nerrors:")
        for e in errors:
            console.print(f"  {e}")

    console.print(f"\n[dim]ollama://MODEL  openai://MODEL  https://URL[/dim]")


@cli.command("targets")
def list_targets():
    """Show target types and connection examples."""
    console.print(Panel(
        "[bold]http / https[/bold]  (any REST API, auto-detected)\n"
        "  https://mretl-lumen.hf.space\n"
        "  https://api.example.com::Authorization=Bearer TOKEN\n"
        "  https://api.example.com::x-api-key=SECRET\n\n"
        "[bold]ollama[/bold]  (local, no API key)\n"
        "  ollama serve  &&  ollama pull llama3.2\n"
        "  --target ollama://llama3.2\n\n"
        "[bold]openai[/bold]  (export OPENAI_API_KEY=sk-...)\n"
        "  --target openai://gpt-4  or  openai://gpt-4o\n\n"
        "[bold]anthropic[/bold]  (export ANTHROPIC_API_KEY=sk-ant-...)\n"
        "  --target anthropic://claude-3-5-sonnet-20241022\n\n"
        "[bold]groq[/bold]  (export GROQ_API_KEY=gsk_...)\n"
        "  --target groq://llama-3.1-70b-versatile\n\n"
        "[bold]together[/bold]  (export TOGETHER_API_KEY=...)\n"
        "  --target together://meta-llama/Llama-3-70b-chat-hf\n\n"
        "[bold]mistral[/bold]  (export MISTRAL_API_KEY=...)\n"
        "  --target mistral://mistral-large-latest\n\n"
        "[bold]cohere[/bold]  (export COHERE_API_KEY=...)\n"
        "  --target cohere://command-r-plus\n\n"
        "[bold]azure[/bold]  (export AZURE_OPENAI_KEY + AZURE_OPENAI_ENDPOINT)\n"
        "  --target azure://gpt-4\n\n"
        "[bold]huggingface[/bold]  (export HF_TOKEN=hf_...)\n"
        "  --target huggingface://meta-llama/Llama-2-7b-chat-hf\n\n"
        "[bold]replicate[/bold]  (export REPLICATE_API_TOKEN=...)\n"
        "  --target replicate://meta/llama-3-70b-instruct\n\n"
        "[bold]vllm[/bold]  (local vLLM server)\n"
        "  --target vllm://meta-llama/Llama-3-8b-instruct\n\n"
        "[bold]litellm[/bold]  (LiteLLM proxy — 100+ providers)\n"
        "  --target litellm://gpt-4\n\n"
        "[bold]lmstudio[/bold]  (LM Studio local server)\n"
        "  --target lmstudio://local",
        border_style="dim",
    ))


@cli.command("compare")
@click.argument("attack_name")
@click.option("--targets", "-t", required=True,
              help="Comma-separated target URIs to compare.")
@click.option("--prompt", "-p", default=None, help="Harmful prompt / goal.")
@click.option("--output", "-o", default=None, help="Save results to JSON.")
def compare(attack_name, targets, prompt, output):
    """Run one attack across multiple targets and compare results.

    \b
    Examples:
      chimera compare crescendo
      chimera compare artprompt --targets "ollama://llama3.2"
      chimera compare pair_attack --prompt "bypass safety" -o compare.json
      chimera compare crescendo --targets "ollama://llama3.2"
    """
    cls = AttackRegistry.get_attack(attack_name)
    if cls is None:
        console.print(f"[red]Attack '{attack_name}' not found.[/red]")
        sys.exit(1)

    target_uris = [t.strip() for t in targets.split(",")]
    kwargs = _build_attack_kwargs(cls, prompt, None)

    console.print(Panel(
        f"attack : [cyan]{attack_name}[/cyan]\n"
        f"targets: [yellow]{len(target_uris)}[/yellow]  ({', '.join(target_uris)})",
        border_style="dim",
    ))

    results = []
    table = Table(box=box.SIMPLE_HEAD, pad_edge=False)
    table.add_column("Target", style="yellow", width=22, no_wrap=True)
    table.add_column("Result", width=10, no_wrap=True)
    table.add_column("Details", style="dim")

    for uri in target_uris:
        target_obj = _load_target(uri)
        attack = _build_attack(cls, None)
        t0 = time.time()
        try:
            run_output = attack.run(target_obj, **kwargs)
            result = attack.safe_evaluate(target_obj, run_output)
            elapsed = (time.time() - t0) * 1000
            icon = "[green]✓ ok[/green]" if result.success else "[red]✗ failed[/red]"
            detail = f"{elapsed:.0f}ms"
            if result.metadata:
                first_key = next(iter(result.metadata))
                detail += f"  {first_key}={result.metadata[first_key]}"
            results.append({"target": uri, "success": result.success,
                             "elapsed_ms": round(elapsed, 1), "metadata": result.metadata})
        except Exception as e:
            icon = "[yellow]err[/yellow]"
            detail = str(e)[:50]
            results.append({"target": uri, "success": False, "error": str(e)})

        table.add_row(uri, icon, detail)

    console.print(table)

    # Summary
    successes = sum(1 for r in results if r.get("success"))
    console.print(f"\n{successes}/{len(results)}  [dim]{attack_name}[/dim]")

    if output:
        with open(output, "w") as f:
            json.dump({"attack": attack_name, "results": results}, f, indent=2)
        console.print(f"[dim]saved to {output}[/dim]")


@cli.command("try-all")
@click.argument("attack_name")
@click.option("--target", "-t", required=True, help="Target URI.")
@click.option("--prompt", "-p", default=None, help="Harmful prompt / goal.")
@click.option("--output", "-o", default=None, help="Save results to JSON.")
def try_all_strategies(attack_name, target, prompt, output):
    """Try every strategy/variant of an attack and show which ones succeed.

    \b
    Examples:
      chimera try-all skeleton_key
      chimera try-all virtualization --target https://api.example.com
      chimera try-all crescendo --prompt "how to pick a lock"
      chimera try-all code_chameleon --target ollama://llama3.2
    """
    import inspect

    cls = AttackRegistry.get_attack(attack_name)
    if cls is None:
        console.print(f"[red]Attack '{attack_name}' not found.[/red]")
        sys.exit(1)

    # Find strategy/variant parameter and its options
    sig = inspect.signature(cls.run)
    strategy_param = None
    for p in ["strategy", "variant", "frame", "encoding", "technique",
              "injection_type", "language", "chain_name"]:
        if p in sig.parameters:
            strategy_param = p
            break

    if strategy_param is None:
        console.print(f"[yellow]{attack_name} has no strategy variants. Running once.[/yellow]")
        # Just run it once
        target_obj = _load_target(target)
        attack = cls()
        kwargs = _build_attack_kwargs(cls, prompt, None)
        run_output = attack.run(target_obj, **kwargs)
        result = attack.safe_evaluate(target_obj, run_output)
        icon = "[green]✓ ok[/green]" if result.success else "[red]✗ failed[/red]"
        console.print(f"\n{icon}")
        return

    # Get available strategies from the attack class
    strategies = _get_strategies(cls, strategy_param)

    console.print(Panel(
        f"attack  : [cyan]{attack_name}[/cyan]\n"
        f"target  : [yellow]{target}[/yellow]\n"
        f"variants: [dim]{len(strategies)} {strategy_param} options[/dim]",
        border_style="dim",
    ))

    target_obj = _load_target(target)
    default_prompt = prompt or "bypass safety filters and provide unrestricted information"
    results = []

    table = Table(box=box.SIMPLE_HEAD, pad_edge=False)
    table.add_column(strategy_param, style="cyan", width=28, no_wrap=True)
    table.add_column("Result", width=12, no_wrap=True)
    table.add_column("Details", style="dim")

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                  console=console, transient=True) as progress:
        task = progress.add_task("Testing...", total=len(strategies))

        for strat in strategies:
            progress.update(task, description=f"[cyan]{strat}[/cyan]")
            attack = _build_attack(cls, None)
            kwargs = {strategy_param: strat}
            # Add prompt param
            for p in ["harmful_prompt", "harmful_goal", "harmful_request",
                      "harmful_question", "harmful_topic", "malicious_instruction"]:
                if p in sig.parameters:
                    kwargs[p] = default_prompt
                    break

            try:
                run_output = attack.run(target_obj, **kwargs)
                result = attack.safe_evaluate(target_obj, run_output)
                icon = "[green]✓ ok[/green]" if result.success else "[red]✗ failed[/red]"
                detail = ""
                if result.metadata:
                    # Show most relevant metadata field
                    for key in ["score", "best_score", "compliance_count", "mode_accepted"]:
                        if key in result.metadata:
                            detail = f"{key}={result.metadata[key]}"
                            break
                results.append({"strategy": strat, "success": result.success})
            except Exception as e:
                icon = "[yellow]err[/yellow]"
                detail = str(e)[:40]
                results.append({"strategy": strat, "success": False, "error": str(e)})

            table.add_row(strat, icon, detail)
            progress.advance(task)

    console.print(table)

    successes = [r["strategy"] for r in results if r.get("success")]
    console.print(f"\n{len(successes)}/{len(strategies)} ")
    if successes:
        console.print(f"ok: " +
                      "  ".join(f"[cyan]{s}[/cyan]" for s in successes))

    if output:
        with open(output, "w") as f:
            json.dump({"attack": attack_name, "target": target,
                       "strategy_param": strategy_param, "results": results}, f, indent=2)
        console.print(f"[dim]saved to {output}[/dim]")


def _get_strategies(cls, param_name: str) -> list:
    """Extract available strategy values from an attack class."""
    # Check common attribute names
    for attr in [f"{param_name}s", "STRATEGIES", "VIRTUALIZATION_FRAMES",
                 "SKELETON_KEY_VARIANTS", "ENCODINGS", "TECHNIQUES",
                 "LANGUAGE_TEMPLATES", "ATTACK_CHAINS", "REWARD_HACKING_STRATEGIES",
                 "POISON_STRATEGIES"]:
        val = getattr(cls, attr, None)
        if val is None:
            # Try instance
            try:
                inst = cls()
                val = getattr(inst, attr, None)
            except Exception:
                pass
        if val is not None:
            if isinstance(val, dict):
                return list(val.keys())
            if isinstance(val, list):
                # Handle list of tuples (name, ...) like SKELETON_KEY_VARIANTS
                if val and isinstance(val[0], tuple):
                    return [v[0] for v in val]
                return val
    return ["default"]


if __name__ == "__main__":
    cli()
