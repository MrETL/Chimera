# Chimera

```
  ██████╗██╗  ██╗██╗███╗   ███╗███████╗██████╗  █████╗
 ██╔════╝██║  ██║██║████╗ ████║██╔════╝██╔══██╗██╔══██╗
 ██║     ███████║██║██╔████╔██║█████╗  ██████╔╝███████║
 ██║     ██╔══██║██║██║╚██╔╝██║██╔══╝  ██╔══██╗██╔══██║
 ╚██████╗██║  ██║██║██║ ╚═╝ ██║███████╗██║  ██║██║  ██║
  ╚═════╝╚═╝  ╚═╝╚═╝╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝
```

**v1.0.0 — by MrETL (Dilnessa Aemro)**

AI red teaming framework. Tests language models, agents, and multimodal systems for security vulnerabilities.

---

## Install

```bash
pip install chimera-ai
```

Or from source:

```bash
git clone https://github.com/MrETL/chimera
cd chimera
pip install -e .
```

---

## Usage

```bash
chimera --help
```

### Interactive session

```bash
chimera console --target ollama://llama3.2
chimera console --target openai://gpt-4
chimera console --target https://your-model-endpoint.com
```

### CLI

```bash
chimera list
chimera attack crescendo --target ollama://llama3.2 --prompt "..."
chimera scan --target https://api.example.com --category llm/jailbreak
chimera try-all skeleton_key --target openai://gpt-4
chimera benchmark --target https://api.example.com
```

---

## Targets

Works against any model — local or remote:

| Target | URI |
|--------|-----|
| Ollama (local) | `ollama://llama3.2` |
| Any REST API | `https://your-endpoint.com` |
| OpenAI | `openai://gpt-4` |
| Anthropic | `anthropic://claude-3-5-sonnet-20241022` |
| Groq | `groq://llama-3.1-70b-versatile` |
| Together AI | `together://meta-llama/Llama-3-70b-chat-hf` |
| Mistral | `mistral://mistral-large-latest` |
| Azure OpenAI | `azure://gpt-4` |
| HuggingFace | `huggingface://meta-llama/Llama-2-7b-chat-hf` |
| vLLM | `vllm://meta-llama/Llama-3-8b-instruct` |
| LiteLLM | `litellm://gpt-4` |
| LM Studio | `lmstudio://local` |

Pass API keys via environment variables or inline:

```bash
export OPENAI_API_KEY=sk-...
chimera attack artprompt --target openai://gpt-4 --prompt "..."

# Or inline
chimera attack artprompt \
  --target "https://endpoint.com::Authorization=Bearer TOKEN" \
  --prompt "..."
```

---

## License

Apache-2.0
