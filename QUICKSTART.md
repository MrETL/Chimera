# Chimera Quick Start Guide

## Installation Complete! ✅

Your Chimera v0.1.0 installation is ready. Here's how to get started.

## What You Have

- Complete core framework with modular architecture
- 3 target adapters: OpenAI, HuggingFace, PyTorch Local
- 1 attack module: DAN Jailbreak
- CLI interface with Rich formatting
- Comprehensive test suite
- Full documentation

## Quick Commands

### List Available Attacks
```bash
source venv/bin/activate
chimera list-attacks
```

### Scan a Target (Example)
```bash
# Set your OpenAI API key
export OPENAI_API_KEY="your-key-here"

# Run a scan
chimera scan openai://gpt-3.5-turbo --attack dan_jailbreak -o report.json
```

### Run Tests
```bash
source venv/bin/activate
pytest tests/ -v
```

## Project Structure

```
chimera/
├── chimera/              # Main package
│   ├── core/            # Kernel, registry, target manager
│   ├── targets/         # Target adapters (OpenAI, HF, PyTorch)
│   ├── attacks/         # Attack modules
│   ├── judges/          # Evaluation judges
│   ├── reporting/       # Report generation
│   ├── utils/           # Utilities
│   └── cli/             # Command-line interface
├── tests/               # Test suite
├── examples/            # Example scripts
└── docs/                # Documentation
```

## Next Steps

1. **Add More Attacks**: Create new attack modules in `chimera/attacks/`
2. **Add More Targets**: Create new target adapters in `chimera/targets/`
3. **Run Examples**: Check out `examples/basic_scan.py`
4. **Read Docs**: See `docs/index.md` for detailed documentation

## Development Workflow

```bash
# Activate virtual environment
source venv/bin/activate

# Make changes to code
# ...

# Run tests
pytest tests/

# Try your changes
chimera list-attacks
```

## Important Files

- `PROJECT_JOURNAL.md` - Development roadmap and progress
- `CONVERSATION_HISTORY.md` - Complete project discussions
- `README.md` - Project overview
- `pyproject.toml` - Package configuration

## Getting Help

- Check the documentation in `docs/`
- Review examples in `examples/`
- Read the project journal for context

## Safety Reminder

This tool is for authorized security testing only. Always obtain proper authorization before testing any AI systems.

---

**Status**: Core framework v0.1.0 complete and functional!
**Next**: Start adding more attack modules and target adapters.
