"""Chimera interactive session."""

import sys, time, json, os, readline, atexit, inspect, logging, re
from typing import Optional, Dict, Any, List

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

console = Console()

BANNER = """[bold red]
  ██████╗██╗  ██╗██╗███╗   ███╗███████╗██████╗  █████╗
 ██╔════╝██║  ██║██║████╗ ████║██╔════╝██╔══██╗██╔══██╗
 ██║     ███████║██║██╔████╔██║█████╗  ██████╔╝███████║
 ██║     ██╔══██║██║██║╚██╔╝██║██╔══╝  ██╔══██╗██╔══██║
 ╚██████╗██║  ██║██║██║ ╚═╝ ██║███████╗██║  ██║██║  ██║
  ╚═════╝╚═╝  ╚═╝╚═╝╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝[/bold red]
[dim]       AI Red Team Framework  v1.0.0  by MrETL (Dilnessa Aemro)  Apache-2.0[/dim]
"""

HELP = """[bold]module[/bold]
  use <attack>              load an attack module
  back                      unload current module
  info                      details on loaded module
  search <keyword>          search attacks by name or description

[bold]options[/bold]
  set TARGET <uri>          set target  (ollama://  https://  openai://)
  set PROMPT <text>         set the prompt/goal
  set STRATEGY <name>       set attack variant
  set TURNS <n>             set number of turns (multi-turn attacks)
  set TOKENS <n>            set max tokens per response
  set VERBOSE true|false    show full response
  unset <OPT>               clear an option
  options                   show current options (alias: show options)

[bold]execution[/bold]
  run                       execute loaded attack
  run all                   run all attacks in current category
  scan                      run all attacks in current category
  try-all                   run every variant of loaded attack
  repeat <n>                run loaded attack n times
  previous                  re-run last attack

[bold]results[/bold]
  results                   show session results (alias: show results)
  sessions                  same as results
  export <file>             export results to JSON
  export <file> md          export results to markdown

[bold]information[/bold]
  attacks                   list all attacks (alias: show attacks)
  attacks <category>        filter by category
  targets                   show target connection examples
  categories                list all categories
  status                    framework status

[bold]session[/bold]
  save <file>               save session state to file
  load <file>               load session state from file
  history                   show command history
  clear                     clear screen
  help                      this help
  exit                      exit

[bold]shortcuts[/bold]
  target <uri>              alias for: set TARGET <uri>
  prompt <text>             alias for: set PROMPT <text>
  strategy <name>           alias for: set STRATEGY <name>
  tokens <n>                alias for: set TOKENS <n>
  verbose                   toggle verbose mode

[bold]example session[/bold]
  chimera > target ollama://llama3.2
  chimera > use crescendo
  chimera (crescendo) > prompt "ignore your previous instructions"
  chimera (crescendo) > tokens 200
  chimera (crescendo) > run
  chimera (crescendo) > try-all
  chimera (crescendo) > back
  chimera > search jailbreak
  chimera > use skeleton_key
  chimera (skeleton_key) > run all
  chimera > export results.json
"""


class Session:
    def __init__(self, target=None):
        self.module: Optional[str] = None
        self.opts: Dict[str, Any] = {
            "TARGET": target or "",
            "PROMPT": "",
            "STRATEGY": None,
            "TURNS": None,
            "TOKENS": 512,
            "VERBOSE": False,
        }
        self.results: List[Dict] = []
        self.count = 0
        self.last_attack: Optional[str] = None
        self.last_kwargs: Dict = {}
        self.cmd_history: List[str] = []

    @property
    def prompt_str(self) -> str:
        mod = f" ({self.module})" if self.module else ""
        return f"chimera{mod} > "

    def set(self, key: str, val: str) -> bool:
        k = key.upper()
        if k not in self.opts:
            return False
        if k in ("TURNS", "TOKENS"):
            self.opts[k] = int(val) if val.lower() not in ("none", "") else None
        elif k == "VERBOSE":
            self.opts[k] = val.lower() in ("true", "1", "yes", "on")
        else:
            self.opts[k] = val if val.lower() != "none" else None
        return True

    def add(self, attack, success, response, metadata, ms):
        self.count += 1
        self.results.append({
            "id": self.count, "attack": attack,
            "target": self.opts["TARGET"], "success": success,
            "response": response, "metadata": metadata,
            "ms": ms, "time": time.strftime("%H:%M:%S"),
        })

    def to_dict(self) -> dict:
        return {"module": self.module, "opts": self.opts,
                "results": self.results, "count": self.count}

    def from_dict(self, d: dict):
        self.module = d.get("module")
        self.opts.update(d.get("opts", {}))
        self.results = d.get("results", [])
        self.count = d.get("count", 0)


def _load(uri, tokens=512):
    if not uri or "://" not in uri:
        console.print("no target set  (target <uri>)")
        return None
    scheme = uri.split("://")[0]
    model_id = uri.split("://", 1)[1]

    _UNIVERSAL = {
        "anthropic", "groq", "together", "mistral",
        "cohere", "azure", "vllm", "litellm", "lmstudio", "replicate",
    }

    try:
        if scheme in ("http", "https"):
            from chimera.targets.http import HTTPTarget
            t = HTTPTarget(model_id=uri)
            t._default_max_tokens = tokens
            return t
        if scheme == "ollama":
            from chimera.targets.ollama import OllamaTarget
            t = OllamaTarget(model_id=model_id)
            t._default_max_tokens = tokens
            return t
        if scheme == "openai":
            import os as _os
            from chimera.targets.openai_api import OpenAITarget
            return OpenAITarget(model_id=model_id,
                                api_key=_os.environ.get("OPENAI_API_KEY", ""))
        if scheme == "huggingface":
            import os as _os
            from chimera.targets.huggingface import HuggingFaceTarget
            return HuggingFaceTarget(model_id=model_id,
                                     token=_os.environ.get("HF_TOKEN"))
        if scheme in _UNIVERSAL:
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
            t._default_max_tokens = tokens
            return t
        from chimera.core.target_manager import TargetManager
        return TargetManager.load_target(uri)
    except Exception as e:
        console.print(f"[red]target error: {e}[/red]")
        return None


def _build_kwargs(cls, prompt, strategy):
    params = set(inspect.signature(cls.run).parameters.keys()) - {"self", "target", "kwargs"}
    kw = {}
    for p in ["harmful_prompt", "harmful_goal", "harmful_request",
              "harmful_question", "harmful_topic", "malicious_instruction"]:
        if p in params:
            kw[p] = prompt or ""
            break
    if strategy:
        for p in ["strategy", "variant", "frame", "encoding",
                  "technique", "injection_type", "language"]:
            if p in params:
                kw[p] = strategy
                break
    return kw


def _get_strategies(cls) -> List[str]:
    sig = inspect.signature(cls.run)
    strat_param = None
    for p in ["strategy", "variant", "frame", "encoding", "technique",
              "injection_type", "language"]:
        if p in sig.parameters:
            strat_param = p
            break
    if not strat_param:
        return []
    for attr in [f"{strat_param}s", "STRATEGIES", "VIRTUALIZATION_FRAMES",
                 "SKELETON_KEY_VARIANTS", "ENCODINGS", "TECHNIQUES",
                 "LANGUAGE_TEMPLATES", "REWARD_HACKING_STRATEGIES"]:
        val = getattr(cls, attr, None)
        if val is None:
            try:
                val = getattr(cls(), attr, None)
            except Exception:
                pass
        if val is not None:
            if isinstance(val, dict):
                return list(val.keys())
            if isinstance(val, list):
                return [v[0] if isinstance(v, tuple) else v for v in val]
    return []


def _execute_attack(s: Session, attack_name: str, extra_kwargs: dict = None) -> Optional[dict]:
    """Core attack execution — returns result dict or None on failure."""
    from chimera.core.attack_registry import AttackRegistry
    cls = AttackRegistry.get_attack(attack_name)
    if not cls:
        console.print(f"attack '{attack_name}' not found")
        return None

    uri = s.opts["TARGET"]
    if not uri:
        console.print("no target set  (target <uri>)")
        return None

    target = _load(uri, s.opts.get("TOKENS", 512))
    if not target:
        return None

    kw = _build_kwargs(cls, s.opts.get("PROMPT"), s.opts.get("STRATEGY"))
    if extra_kwargs:
        kw.update(extra_kwargs)

    init_kw = {}
    isig = inspect.signature(cls.__init__)
    turns = s.opts.get("TURNS")
    if "max_turns" in isig.parameters and turns:
        init_kw["max_turns"] = int(turns)
    if "max_iterations" in isig.parameters and turns:
        init_kw["max_iterations"] = int(turns)

    attack = cls(**init_kw)
    t0 = time.time()
    try:
        out = attack.run(target, **kw)
        result = attack.safe_evaluate(target, out)
        ms = (time.time() - t0) * 1000
    except Exception as e:
        console.print(f"[red]error: {e}[/red]")
        return None

    resp = result.raw_response or ""
    s.add(attack_name, result.success, resp, result.metadata or {}, ms)
    s.last_attack = attack_name
    s.last_kwargs = kw

    return {
        "success": result.success,
        "ms": ms,
        "response": resp,
        "metadata": result.metadata or {},
    }


def _print_result(r: dict, verbose: bool = False):
    status = "[green]ok[/green]" if r["success"] else "[red]failed[/red]"
    console.print(f"{status}  [dim]{r['ms']:.0f}ms[/dim]")
    if r["metadata"]:
        t = Table(box=box.SIMPLE, show_header=False, pad_edge=False)
        t.add_column("k", style="dim", width=22, no_wrap=True)
        t.add_column("v", style="white")
        for k, v in r["metadata"].items():
            t.add_row(k, str(v))
        console.print(t)
    resp = r.get("response", "")
    if verbose and resp:
        console.print(Panel(resp[:1000], border_style="dim", padding=(0, 1)))
    elif resp:
        snippet = resp[:120].replace("\n", " ")
        console.print(f"  [dim]{snippet}[/dim]")
    console.print()


def cmd_use(args, s: Session):
    from chimera.core.attack_registry import AttackRegistry
    name = args.strip()
    if not name:
        console.print("usage: use <attack>"); return
    cls = AttackRegistry.get_attack(name)
    if not cls:
        all_n = AttackRegistry.list_attacks()
        sug = [n for n in all_n if name.lower() in n.lower()]
        console.print(f"'{name}' not found")
        if sug:
            console.print("  " + "  ".join(f"[cyan]{x}[/cyan]" for x in sug[:5]))
        return
    s.module = name
    strategies = _get_strategies(cls)
    strat_info = f"  {len(strategies)} variants" if strategies else ""
    console.print(f"[cyan]{name}[/cyan]  [dim]{cls.description}[/dim]{strat_info}")


def cmd_search(args, s: Session):
    from chimera.core.attack_registry import AttackRegistry
    kw = args.strip().lower()
    if not kw:
        console.print("usage: search <keyword>"); return
    names = AttackRegistry.list_attacks()
    matches = []
    for name in names:
        cls = AttackRegistry.get_attack(name)
        if cls and (kw in name.lower() or kw in cls.description.lower()
                    or kw in cls.category.value.lower()):
            matches.append((name, cls))
    if not matches:
        console.print(f"no matches for '{kw}'"); return
    t = Table(box=box.SIMPLE_HEAD, pad_edge=False)
    t.add_column("name", style="cyan", width=28, no_wrap=True)
    t.add_column("category", style="dim", width=22, no_wrap=True)
    t.add_column("description", style="white", no_wrap=True)
    for name, cls in matches:
        d = cls.description[:45] + "..." if len(cls.description) > 45 else cls.description
        t.add_row(name, cls.category.value, d)
    console.print(t)
    console.print(f"[dim]{len(matches)} matches[/dim]")


def cmd_show(args, s: Session):
    from chimera.core.attack_registry import AttackRegistry
    from chimera.attacks.base import AttackCategory
    sub = args.strip().lower()

    if sub.startswith("attacks") or sub == "":
        parts = sub.split(None, 1)
        cat_f = parts[1].strip() if len(parts) > 1 else None
        if cat_f:
            try:
                names = AttackRegistry.list_attacks(AttackCategory(cat_f))
            except ValueError:
                console.print(f"unknown category '{cat_f}'"); return
        else:
            names = AttackRegistry.list_attacks()
        t = Table(box=box.SIMPLE_HEAD, pad_edge=False)
        t.add_column("name", style="cyan", width=28, no_wrap=True)
        t.add_column("category", style="dim", width=22, no_wrap=True)
        t.add_column("description", style="white", no_wrap=True)
        for n in sorted(names):
            c = AttackRegistry.get_attack(n)
            if c:
                d = c.description[:45] + "..." if len(c.description) > 45 else c.description
                t.add_row(n, c.category.value, d)
        console.print(t)
        console.print(f"[dim]{len(names)} attacks[/dim]")

    elif sub == "options":
        cmd_options(s)

    elif sub == "results":
        cmd_results(s)

    elif sub == "targets":
        cmd_targets()

    else:
        console.print(f"unknown: show {args}  (attacks  options  results  targets)")


def cmd_options(s: Session):
    from chimera.core.attack_registry import AttackRegistry
    t = Table(box=box.SIMPLE_HEAD, pad_edge=False)
    t.add_column("option", style="cyan", width=12, no_wrap=True)
    t.add_column("value", style="yellow", width=50)
    t.add_column("description", style="dim")
    descs = {
        "TARGET":   "target URI",
        "PROMPT":   "harmful prompt or goal",
        "STRATEGY": "attack variant",
        "TURNS":    "number of turns",
        "TOKENS":   "max tokens per response",
        "VERBOSE":  "show full response",
    }
    for k, d in descs.items():
        v = s.opts.get(k)
        val = str(v) if v is not None and v != "" else "[dim]-[/dim]"
        t.add_row(k, val, d)
    console.print(t)
    if s.module:
        cls = AttackRegistry.get_attack(s.module)
        if cls:
            sig = inspect.signature(cls.run)
            params = {k: v for k, v in sig.parameters.items()
                      if k not in ("self", "target", "kwargs")}
            if params:
                console.print("\n[dim]attack parameters:[/dim]")
                for p, v in params.items():
                    dflt = f"  [dim]{v.default!r}[/dim]" if v.default is not inspect.Parameter.empty else "  (required)"
                    console.print(f"  [cyan]{p}[/cyan]{dflt}")


def cmd_info(s: Session):
    from chimera.core.attack_registry import AttackRegistry
    if not s.module:
        console.print("no module loaded"); return
    cls = AttackRegistry.get_attack(s.module)
    sig = inspect.signature(cls.run)
    params = {k: v for k, v in sig.parameters.items() if k not in ("self", "target", "kwargs")}
    strategies = _get_strategies(cls)
    strat_str = ""
    if strategies:
        strat_str = f"\n\nvariants ({len(strategies)})\n  " + "  ".join(strategies[:10])
        if len(strategies) > 10:
            strat_str += f"  ... +{len(strategies)-10} more"
    plines = "\n".join(
        f"  [cyan]{p}[/cyan]" + (f"  [dim]{v.default!r}[/dim]"
        if v.default is not inspect.Parameter.empty else "  (required)")
        for p, v in params.items()
    )
    console.print(Panel(
        f"[bold cyan]{s.module}[/bold cyan]\n\n"
        f"{cls.description}\n\n"
        f"category   {cls.category.value}\n"
        f"mitre      {cls.mitre_technique}\n"
        f"owasp      {cls.owasp_risk}\n\n"
        f"parameters\n{plines}{strat_str}",
        border_style="dim"))


def cmd_results(s: Session):
    if not s.results:
        console.print("no results yet"); return
    t = Table(box=box.SIMPLE_HEAD, pad_edge=False)
    t.add_column("#", style="dim", width=4)
    t.add_column("time", style="dim", width=10)
    t.add_column("attack", style="cyan", width=24, no_wrap=True)
    t.add_column("target", style="dim", width=30, no_wrap=True)
    t.add_column("result", width=8)
    t.add_column("ms", style="dim", width=8)
    for r in s.results:
        status = "[green]ok[/green]" if r["success"] else "[red]--[/red]"
        t.add_row(str(r["id"]), r["time"], r["attack"], r["target"][:28], status, str(int(r["ms"])))
    console.print(t)
    ok = sum(1 for r in s.results if r["success"])
    console.print(f"[dim]{ok}/{len(s.results)}[/dim]")


def cmd_targets():
    console.print(Panel(
        "[bold]http / https[/bold]  (any REST API, auto-detected)\n"
        "  https://mretl-lumen.hf.space\n"
        "  https://api.example.com::Authorization=Bearer TOKEN\n\n"
        "[bold]ollama[/bold]  (local, no API key)\n"
        "  target ollama://llama3.2\n\n"
        "[bold]openai[/bold]  (export OPENAI_API_KEY=sk-...)\n"
        "  target openai://gpt-4\n\n"
        "[bold]anthropic[/bold]  (export ANTHROPIC_API_KEY=sk-ant-...)\n"
        "  target anthropic://claude-3-5-sonnet-20241022\n\n"
        "[bold]groq[/bold]  (export GROQ_API_KEY=gsk_...)\n"
        "  target groq://llama-3.1-70b-versatile\n\n"
        "[bold]together[/bold]  (export TOGETHER_API_KEY=...)\n"
        "  target together://meta-llama/Llama-3-70b-chat-hf\n\n"
        "[bold]mistral[/bold]  (export MISTRAL_API_KEY=...)\n"
        "  target mistral://mistral-large-latest\n\n"
        "[bold]cohere[/bold]  (export COHERE_API_KEY=...)\n"
        "  target cohere://command-r-plus\n\n"
        "[bold]azure[/bold]  (export AZURE_OPENAI_KEY + AZURE_OPENAI_ENDPOINT)\n"
        "  target azure://gpt-4\n\n"
        "[bold]huggingface[/bold]  (export HF_TOKEN=hf_...)\n"
        "  target huggingface://meta-llama/Llama-2-7b-chat-hf\n\n"
        "[bold]replicate[/bold]  (export REPLICATE_API_TOKEN=...)\n"
        "  target replicate://meta/llama-3-70b-instruct\n\n"
        "[bold]vllm[/bold]  (local vLLM server)\n"
        "  target vllm://meta-llama/Llama-3-8b-instruct\n\n"
        "[bold]litellm[/bold]  (LiteLLM proxy — 100+ providers)\n"
        "  target litellm://gpt-4\n\n"
        "[bold]lmstudio[/bold]  (LM Studio local server)\n"
        "  target lmstudio://local",
        border_style="dim"))


def cmd_categories():
    from chimera.core.attack_registry import AttackRegistry
    from chimera.attacks.base import AttackCategory
    t = Table(box=box.SIMPLE_HEAD, pad_edge=False)
    t.add_column("category", style="cyan", width=28, no_wrap=True)
    t.add_column("attacks", style="dim", width=8)
    t.add_column("names", style="white")
    for cat in AttackCategory:
        names = AttackRegistry.list_attacks(cat)
        if names:
            t.add_row(cat.value, str(len(names)), "  ".join(sorted(names)))
    console.print(t)


def cmd_run(s: Session, run_all: bool = False):
    from chimera.core.attack_registry import AttackRegistry
    if not s.module:
        console.print("no module loaded  (use <attack>)"); return

    if run_all:
        cls = AttackRegistry.get_attack(s.module)
        names = AttackRegistry.list_attacks(cls.category)
        console.print(f"[cyan]{cls.category.value}[/cyan]  {len(names)} attacks  [dim]{s.opts['TARGET']}[/dim]\n")
        ok = 0
        for name in names:
            r = _execute_attack(s, name)
            if r:
                status = "[green]ok[/green]" if r["success"] else "[red]--[/red]"
                console.print(f"  {status}  {name}  [dim]{r['ms']:.0f}ms[/dim]")
                if r["success"]:
                    ok += 1
        console.print(f"\n[dim]{ok}/{len(names)}[/dim]")
        return

    console.print(f"[cyan]{s.module}[/cyan]  [dim]{s.opts['TARGET']}[/dim]")
    if s.opts.get("PROMPT"):
        console.print(f"  [dim]{s.opts['PROMPT'][:70]}[/dim]")
    console.print()
    r = _execute_attack(s, s.module)
    if r:
        _print_result(r, verbose=s.opts.get("VERBOSE", False))


def cmd_scan(s: Session):
    from chimera.core.attack_registry import AttackRegistry
    from chimera.attacks.base import AttackCategory
    uri = s.opts["TARGET"]
    if not uri:
        console.print("no target set  (target <uri>)"); return

    if s.module:
        cls = AttackRegistry.get_attack(s.module)
        names = AttackRegistry.list_attacks(cls.category)
        console.print(f"[cyan]{cls.category.value}[/cyan]  {len(names)} attacks  [dim]{uri}[/dim]\n")
    else:
        names = (AttackRegistry.list_attacks(AttackCategory.LLM_JAILBREAK) +
                 AttackRegistry.list_attacks(AttackCategory.LLM_PROMPT_INJECTION) +
                 AttackRegistry.list_attacks(AttackCategory.LLM_ENCODING))
        console.print(f"{len(names)} attacks  [dim]{uri}[/dim]\n")

    ok = 0
    for name in names:
        r = _execute_attack(s, name)
        if r:
            status = "[green]ok[/green]" if r["success"] else "[red]--[/red]"
            console.print(f"  {status}  {name}  [dim]{r['ms']:.0f}ms[/dim]")
            if r["success"]:
                ok += 1

    console.print(f"\n[dim]{ok}/{len(names)}[/dim]")
    if ok:
        succeeded = [r["attack"] for r in s.results[-len(names):] if r["success"]]
        console.print("  " + "  ".join(f"[green]{n}[/green]" for n in succeeded))


def cmd_try_all(s: Session):
    from chimera.core.attack_registry import AttackRegistry
    if not s.module:
        console.print("no module loaded"); return
    cls = AttackRegistry.get_attack(s.module)
    strategies = _get_strategies(cls)
    if not strategies:
        console.print(f"{s.module} has no variants"); return

    sig = inspect.signature(cls.run)
    strat_param = next((p for p in ["strategy", "variant", "frame", "encoding",
                                     "technique", "injection_type", "language"]
                        if p in sig.parameters), None)

    console.print(f"[cyan]{s.module}[/cyan]  {len(strategies)} variants  [dim]{s.opts['TARGET']}[/dim]\n")
    ok = 0
    for strat in strategies:
        r = _execute_attack(s, s.module, {strat_param: strat} if strat_param else {})
        if r:
            status = "[green]ok[/green]" if r["success"] else "[red]--[/red]"
            console.print(f"  {status}  [dim]{strat}[/dim]  [dim]{r['ms']:.0f}ms[/dim]")
            if r["success"]:
                ok += 1

    console.print(f"\n[dim]{ok}/{len(strategies)}[/dim]")
    if ok:
        succeeded = [r["attack"] for r in s.results[-len(strategies):] if r["success"]]
        console.print("  " + "  ".join(f"[cyan]{n}[/cyan]" for n in succeeded[:10]))


def cmd_repeat(args, s: Session):
    if not s.module:
        console.print("no module loaded"); return
    try:
        n = int(args.strip())
    except ValueError:
        console.print("usage: repeat <n>"); return
    console.print(f"[cyan]{s.module}[/cyan]  x{n}  [dim]{s.opts['TARGET']}[/dim]\n")
    ok = 0
    for i in range(n):
        r = _execute_attack(s, s.module)
        if r:
            status = "[green]ok[/green]" if r["success"] else "[red]--[/red]"
            console.print(f"  [{i+1}/{n}] {status}  [dim]{r['ms']:.0f}ms[/dim]")
            if r["success"]:
                ok += 1
    console.print(f"\n[dim]{ok}/{n}[/dim]")


def cmd_previous(s: Session):
    if not s.last_attack:
        console.print("no previous attack"); return
    console.print(f"[cyan]{s.last_attack}[/cyan]  [dim]{s.opts['TARGET']}[/dim]\n")
    r = _execute_attack(s, s.last_attack)
    if r:
        _print_result(r, verbose=s.opts.get("VERBOSE", False))


def cmd_export(args, s: Session):
    if not s.results:
        console.print("no results to export"); return
    parts = args.strip().split()
    if not parts:
        console.print("usage: export <file>  or  export <file> md"); return
    filepath = parts[0]
    fmt = parts[1].lower() if len(parts) > 1 else "json"

    if fmt == "md":
        lines = ["# chimera results\n"]
        for r in s.results:
            status = "ok" if r["success"] else "failed"
            lines.append(f"## [{r['id']}] {r['attack']}  {status}  {r['time']}")
            lines.append(f"target: {r['target']}")
            lines.append(f"response: {r['response'][:300]}\n")
        with open(filepath, "w") as f:
            f.write("\n".join(lines))
    else:
        with open(filepath, "w") as f:
            json.dump(s.results, f, indent=2)

    ok = sum(1 for r in s.results if r["success"])
    console.print(f"[dim]{len(s.results)} results ({ok} ok) → {filepath}[/dim]")


def cmd_save(args, s: Session):
    filepath = args.strip() or "chimera_session.json"
    with open(filepath, "w") as f:
        json.dump(s.to_dict(), f, indent=2)
    console.print(f"[dim]session saved → {filepath}[/dim]")


def cmd_load(args, s: Session):
    filepath = args.strip()
    if not filepath or not os.path.exists(filepath):
        console.print(f"file not found: {filepath}"); return
    with open(filepath) as f:
        s.from_dict(json.load(f))
    console.print(f"[dim]session loaded from {filepath}[/dim]")
    if s.module:
        console.print(f"module: [cyan]{s.module}[/cyan]")
    if s.opts.get("TARGET"):
        console.print(f"target: [dim]{s.opts['TARGET']}[/dim]")


def cmd_history(s: Session):
    if not s.cmd_history:
        console.print("no history"); return
    for i, cmd in enumerate(s.cmd_history[-30:], 1):
        console.print(f"  [dim]{i:3}[/dim]  {cmd}")


def cmd_status():
    from chimera.core.attack_registry import AttackRegistry
    attacks = AttackRegistry.list_attacks()
    cats: dict = {}
    for name in attacks:
        cls = AttackRegistry.get_attack(name)
        cat = cls.category.value if cls else "unknown"
        cats[cat] = cats.get(cat, 0) + 1
    console.print(Panel(
        f"version    1.0.0\n"
        f"attacks    [cyan]{len(attacks)}[/cyan]\n"
        f"categories [cyan]{len(cats)}[/cyan]\n"
        f"status     [green]ok[/green]",
        border_style="dim"))


def _setup_readline(s: Session):
    from chimera.core.attack_registry import AttackRegistry
    hist = os.path.expanduser("~/.chimera_history")
    try:
        readline.read_history_file(hist)
    except FileNotFoundError:
        pass
    readline.set_history_length(1000)
    atexit.register(readline.write_history_file, hist)

    names = AttackRegistry.list_attacks()
    from chimera.attacks.base import AttackCategory
    categories = [c.value for c in AttackCategory]

    cmds = [
        "use", "back", "info", "search", "run", "scan", "try-all",
        "repeat", "previous", "options", "attacks", "results", "targets",
        "categories", "sessions", "history", "status", "export", "save",
        "load", "clear", "help", "exit", "quit",
        "set", "unset", "target", "prompt", "strategy", "tokens", "verbose",
        "show",
    ]
    set_opts = ["TARGET", "PROMPT", "STRATEGY", "TURNS", "TOKENS", "VERBOSE"]
    show_args = ["attacks", "options", "results", "targets"]

    def completer(text, state):
        line = readline.get_line_buffer().lstrip()
        parts = line.split()
        first = parts[0].lower() if parts else ""

        if not parts or (len(parts) == 1 and not line.endswith(" ")):
            opts = [c for c in cmds if c.startswith(text)]
        elif first == "use":
            opts = [n for n in names if n.startswith(text)]
        elif first == "search":
            opts = [n for n in names if n.startswith(text)]
        elif first in ("set", "unset"):
            opts = [o for o in set_opts if o.startswith(text.upper())]
        elif first == "show":
            opts = [a for a in show_args if a.startswith(text)]
        elif first == "attacks":
            opts = [c for c in categories if c.startswith(text)]
        elif first in ("export", "save", "load"):
            # file completion
            import glob
            opts = glob.glob(text + "*")
        else:
            opts = []

        return opts[state] if state < len(opts) else None

    readline.set_completer(completer)
    readline.parse_and_bind("tab: complete")
    readline.set_completer_delims(" \t\n")


def run_console(default_target: str = None):
    from chimera.attacks import register_all
    logging.basicConfig(level=logging.ERROR)
    for n in ["chimera", "urllib3", "requests", "httpx"]:
        logging.getLogger(n).setLevel(logging.ERROR)
    register_all()

    s = Session(default_target)
    _setup_readline(s)

    console.print(BANNER)
    from chimera.core.attack_registry import AttackRegistry
    attacks = AttackRegistry.list_attacks()
    console.print(f"  [cyan]{len(attacks)}[/cyan] attacks  type [cyan]help[/cyan] for commands\n")

    if default_target:
        console.print(f"  target: [dim]{default_target}[/dim]\n")

    while True:
        try:
            sys.stdout.write(
                f"\033[1;31mchimera\033[0m"
                + (f" \033[2m(\033[0m\033[36m{s.module}\033[0m\033[2m)\033[0m" if s.module else "")
                + " > "
            )
            sys.stdout.flush()
            line = input()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[dim]use exit to quit[/dim]")
            continue

        line = line.strip()
        if not line:
            continue

        s.cmd_history.append(line)
        parts = line.split(None, 1)
        cmd = parts[0].lower()
        args = parts[1] if len(parts) > 1 else ""

        # ── exit ──────────────────────────────────────────────────────────────
        if cmd in ("exit", "quit"):
            ok = sum(1 for r in s.results if r["success"])
            console.print(f"\n[dim]{s.count} attacks  {ok} succeeded[/dim]")
            break

        # ── help ──────────────────────────────────────────────────────────────
        elif cmd == "help":
            console.print(HELP)

        # ── module ────────────────────────────────────────────────────────────
        elif cmd == "use":
            cmd_use(args, s)

        elif cmd == "back":
            if s.module:
                console.print(f"[dim]{s.module} unloaded[/dim]")
                s.module = None
            else:
                console.print("[dim]no module loaded[/dim]")

        elif cmd == "info":
            cmd_info(s)

        elif cmd == "search":
            cmd_search(args, s)

        # ── options ───────────────────────────────────────────────────────────
        elif cmd == "set":
            p = args.strip().split(None, 1)
            if len(p) < 2:
                console.print("usage: set <OPTION> <value>")
            elif s.set(p[0], p[1]):
                console.print(f"  {p[0].upper()}  [dim]{p[1]}[/dim]")
            else:
                console.print(f"unknown option '{p[0]}'")

        elif cmd == "unset":
            k = args.strip().upper()
            if k in s.opts:
                s.opts[k] = None if k not in ("TARGET", "PROMPT") else ""
                console.print(f"  {k} cleared")
            else:
                console.print(f"unknown option '{k}'")

        # shortcuts
        elif cmd == "target":
            if args:
                s.set("TARGET", args.strip())
                console.print(f"  TARGET  [dim]{args.strip()}[/dim]")
            else:
                console.print(f"  TARGET  [dim]{s.opts.get('TARGET') or '-'}[/dim]")

        elif cmd == "prompt":
            if args:
                s.set("PROMPT", args.strip())
                console.print(f"  PROMPT  [dim]{args.strip()[:60]}[/dim]")
            else:
                console.print(f"  PROMPT  [dim]{s.opts.get('PROMPT') or '-'}[/dim]")

        elif cmd == "strategy":
            if args:
                s.set("STRATEGY", args.strip())
                console.print(f"  STRATEGY  [dim]{args.strip()}[/dim]")
            else:
                console.print(f"  STRATEGY  [dim]{s.opts.get('STRATEGY') or '-'}[/dim]")

        elif cmd == "tokens":
            if args:
                s.set("TOKENS", args.strip())
                console.print(f"  TOKENS  [dim]{args.strip()}[/dim]")
            else:
                console.print(f"  TOKENS  [dim]{s.opts.get('TOKENS')}[/dim]")

        elif cmd == "verbose":
            current = s.opts.get("VERBOSE", False)
            s.opts["VERBOSE"] = not current
            console.print(f"  VERBOSE  [dim]{s.opts['VERBOSE']}[/dim]")

        elif cmd == "options":
            cmd_options(s)

        # ── execution ─────────────────────────────────────────────────────────
        elif cmd == "run":
            if args.strip().lower() == "all":
                cmd_run(s, run_all=True)
            else:
                cmd_run(s)

        elif cmd == "scan":
            cmd_scan(s)

        elif cmd == "try-all":
            cmd_try_all(s)

        elif cmd == "repeat":
            cmd_repeat(args, s)

        elif cmd == "previous":
            cmd_previous(s)

        # ── results ───────────────────────────────────────────────────────────
        elif cmd in ("results", "sessions"):
            cmd_results(s)

        elif cmd == "export":
            cmd_export(args, s)

        # ── information ───────────────────────────────────────────────────────
        elif cmd == "attacks":
            cmd_show("attacks " + args if args else "attacks", s)

        elif cmd == "show":
            cmd_show(args, s)

        elif cmd == "targets":
            cmd_targets()

        elif cmd == "categories":
            cmd_categories()

        elif cmd == "status":
            cmd_status()

        # ── session ───────────────────────────────────────────────────────────
        elif cmd == "save":
            cmd_save(args, s)

        elif cmd == "load":
            cmd_load(args, s)

        elif cmd == "history":
            cmd_history(s)

        elif cmd == "clear":
            os.system("clear")
            console.print(BANNER)

        else:
            console.print(f"unknown: {cmd}  (help)")
