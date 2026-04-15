# Chimera Documentation

## Overview

Chimera is a unified AI offensive framework - "Metasploit for AI". It provides a comprehensive, cross-model platform for red teaming and adversarial testing of AI systems.

## Features

- **Cross-Model Support**: LLMs, VLMs, traditional ML models
- **Modular Architecture**: Pluggable attack modules and target adapters
- **Industry Standards**: MITRE ATLAS and OWASP LLM Top 10 mapping
- **Comprehensive Reporting**: JSON, Markdown, and HTML reports
- **Extensible**: Easy to add custom attacks and targets

## Quick Start

### Installation

```bash
pip install -e .
```

### Basic Usage

```python
from chimera import ChimeraKernel

kernel = ChimeraKernel()
results = kernel.scan_target("openai://gpt-3.5-turbo")
```

### CLI Usage

```bash
# List available attacks
chimera list-attacks

# Scan a target
chimera scan openai://gpt-3.5-turbo --attack dan_jailbreak

# Generate report
chimera scan openai://gpt-3.5-turbo -o report.json --format json
```

## Architecture

### Core Components

1. **Kernel**: Orchestrates attack execution
2. **Target Manager**: Loads and manages model targets
3. **Attack Registry**: Discovers and instantiates attacks
4. **Report Generator**: Creates structured reports

### Target Adapters

- `openai://` - OpenAI API models
- `hf://` - HuggingFace models
- `local://` - Local PyTorch models

### Attack Categories

- LLM Jailbreaks
- Prompt Injection
- Multimodal Attacks
- ML Evasion
- Model Extraction

## Creating Custom Attacks

```python
from chimera.attacks.base import BaseAttack, AttackResult, AttackCategory
from chimera.core.attack_registry import AttackRegistry

@AttackRegistry.register
class MyCustomAttack(BaseAttack):
    name = "my_custom_attack"
    description = "Description of my attack"
    category = AttackCategory.LLM_JAILBREAK
    
    def run(self, target, **kwargs):
        response = target.generate("My attack prompt")
        return response
    
    def evaluate(self, target, run_output):
        success = "indicator" in run_output.lower()
        return AttackResult(
            attack_name=self.name,
            target_id=target.model_id,
            success=success,
            confidence=0.9
        )
```

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines.

## License

MIT License - see [LICENSE](../LICENSE)
