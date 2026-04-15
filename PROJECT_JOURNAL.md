# Project Chimera - Development Journal

## Project Vision
**Goal**: Create the best real-life AI security project combining ML Engineering, ML Research, AI Red Teaming, and AI Security Engineering.

**Project Name**: Chimera - A Unified AI Offensive Framework

**Tagline**: "Metasploit for AI" - The comprehensive, cross-model adversarial attack and evaluation framework.

---

## Project Scope & Requirements

### Core Objectives
1. **Cross-Model Coverage**: Support all AI model types
   - GenAI Text (LLMs): Prompt injection, jailbreaks, role-playing, encoding attacks
   - GenAI Multimodal: Adversarial images for VLMs, malicious audio
   - Traditional ML: Evasion attacks (FGSM, PGD, C&W), model inversion, membership inference
   - Agentic Systems: Attacks on tool-using LLMs

2. **Robust Open-Source Tool**: Production-ready, widely usable
   - Clean, modular architecture
   - Comprehensive documentation
   - Easy installation and setup
   - Active community support

3. **Offensive Focus**: Primary emphasis on red teaming techniques
   - Powerful attack capabilities
   - AI-assisted orchestration
   - Automated vulnerability discovery

4. **Security Engineering**: Bridge offense to defense
   - Detailed vulnerability reports
   - Actionable remediation advice
   - OWASP LLM Top 10 & MITRE ATLAS mapping

---

## Technical Architecture

### 1. Core Framework (chimera-core)
- **Target Manager**: Unified interface for all model types
  - HuggingFaceTarget
  - OpenAIAPITarget
  - PyTorchLocalTarget
  - AnthropicAPITarget
  - OllamaTarget
  
- **Attack Registry**: Plugin system for attack modules
- **Base Attack Class**: Standard interface for all attacks
  - `run(target, **kwargs)`: Execute attack
  - `evaluate(results)`: Analyze success
  - `report()`: Generate structured output

### 2. Attack Module Categories
```
attacks/
├── llm/              # LLM-specific attacks
│   ├── jailbreak/    # Jailbreak techniques
│   ├── injection/    # Prompt injection
│   └── extraction/   # Data extraction
├── vlm/              # Vision-Language Model attacks
├── ml/               # Traditional ML attacks
│   ├── evasion/      # Evasion attacks
│   ├── poisoning/    # Data poisoning
│   └── extraction/   # Model extraction
└── agentic/          # Agent-specific attacks
```

### 3. CLI Interface Examples
```bash
# Scan for vulnerabilities
chimera scan --target "huggingface/meta-llama/Meta-Llama-3-8B" --module llm/garak

# Execute specific attack
chimera attack --target "openai/gpt-4-vision-preview" --module vlm/typographic

# Full red-team assessment
chimera redteam --target "https://your-app.com/chat" --profile "full_owasp"
```

---

## Current Landscape Analysis

### Existing Tools & Gaps

| Tool | Focus | Strengths | Limitations |
|------|-------|-----------|-------------|
| PyRIT (Microsoft) | LLM/GenAI | Model-agnostic, well-maintained | No traditional ML attacks |
| Basilisk | LLM Security | 32+ attack modules, genetic evolution | Text-only LLMs |
| Garak | LLM Scanning | Comprehensive vulnerability scanner | Static scanner, not interactive |
| ART | Traditional ML | Swiss Army knife for classic ML | No LLM/GenAI coverage |
| OpenRT | Multimodal | Vision-language model testing | Academic, not general-purpose |

**Our Advantage**: Chimera unifies all these capabilities into one modular, extensible platform.

---

## Development Roadmap

### Phase 1: Foundation (Weeks 1-2)
- [ ] Set up project structure
- [ ] Create core framework architecture
- [ ] Implement Target Manager base classes
- [ ] Build Attack Registry system
- [ ] Create BaseAttack interface

### Phase 2: Initial Attack Modules (Weeks 3-4)
- [ ] Implement 2-3 LLM jailbreak attacks
- [ ] Implement 1-2 traditional ML evasion attacks
- [ ] Create basic CLI interface
- [ ] Add simple reporting system

### Phase 3: Expansion (Weeks 5-8)
- [ ] Add multimodal attack support
- [ ] Implement AI-assisted orchestration
- [ ] Create comprehensive reporting (PDF/JSON)
- [ ] Add OWASP/MITRE ATLAS mapping

### Phase 4: Community & Polish (Weeks 9-12)
- [ ] Create "Chimera Hub" for community modules
- [ ] Write comprehensive documentation
- [ ] Add contribution guidelines
- [ ] Create example notebooks and tutorials
- [ ] Launch and promote

---

## Daily Progress Log

### Day 1 - April 15, 2026
- ✅ Defined project vision and scope
- ✅ Analyzed competitive landscape
- ✅ Designed technical architecture
- ✅ Created project journal
- 🔄 Next: Set up initial project structure

---

## Key Design Decisions

1. **Modular Plugin Architecture**: Like Metasploit, allows community contributions
2. **Unified Target Interface**: Abstract away model-specific details
3. **Offense-First, Defense-Aware**: Primary focus on attacks, but provide remediation guidance
4. **CLI + Python API**: Accessible for both automation and interactive use
5. **Standards Mapping**: Link vulnerabilities to OWASP LLM Top 10 and MITRE ATLAS

---

## Resources & References

### Key Papers & Projects
- PyRIT: https://github.com/Azure/PyRIT
- Basilisk: AI red teaming with genetic algorithms
- Garak: LLM vulnerability scanner
- ART (Adversarial Robustness Toolbox): IBM's ML security toolkit
- OWASP LLM Top 10: https://owasp.org/www-project-top-10-for-large-language-model-applications/
- MITRE ATLAS: https://atlas.mitre.org/

### Attack Techniques to Implement
- GCG (Greedy Coordinate Gradient)
- DAN (Do Anything Now) jailbreaks
- FGSM, PGD, C&W evasion attacks
- Typographic attacks for VLMs
- Model extraction and inversion
- Membership inference attacks

---

## Notes & Ideas

- Consider integration with existing tools (PyRIT, ART) rather than reimplementing everything
- Build a strong community from day one - this is key to long-term success
- Focus on documentation and examples - make it easy for others to contribute
- Consider creating a benchmark dataset for evaluating attack effectiveness
- Potential for academic papers on novel attack techniques discovered during development

---

*This journal will be updated daily as we progress through the project.*


### Day 2 - April 16, 2026
- ✅ Created complete directory structure (core, targets, attacks, reporting, cli, tests, docs)
- ✅ Implemented core kernel architecture with ChimeraKernel orchestrator
- ✅ Built attack registry system with decorator-based registration
- ✅ Created target manager with URI-based loading (openai://, hf://, local://)
- ✅ Implemented base classes for targets and attacks
- ✅ Added three target adapters: OpenAI API, HuggingFace, PyTorch Local
- ✅ Created first attack module: DAN jailbreak with MITRE/OWASP mapping
- ✅ Built reporting system with JSON and Markdown output
- ✅ Implemented CLI interface with Rich formatting
- ✅ Added comprehensive test suite with pytest
- ✅ Created pyproject.toml with modern Python packaging
- ✅ Added utilities: logging, config loading, MITRE/OWASP mappings
- ✅ Created documentation and working examples
- ✅ Updated conversation history and project journal
- 🔄 Next: Initialize git repository and test installation

**Status**: Core framework v0.1.0 is complete and ready for testing!

---

## Implementation Notes

### Architecture Decisions Made

1. **Registry Pattern for Attacks**: Using `@AttackRegistry.register` decorator allows clean plugin architecture
2. **URI-Based Target Loading**: Scheme-based URIs (openai://, hf://) provide intuitive interface
3. **Dataclass for Results**: AttackResult uses dataclass for clean, type-safe result handling
4. **Hooks System**: Pre/post attack hooks enable extensibility without modifying core
5. **Separation of Run/Evaluate**: Attacks separate execution from evaluation for flexibility

### Code Quality Features

- Type hints throughout for better IDE support
- Comprehensive docstrings for all public APIs
- Abstract base classes enforce interface contracts
- Exception hierarchy for proper error handling
- Logging integration for debugging and monitoring

### Testing Strategy

- Unit tests for core components
- Mock objects for isolated testing
- Integration tests for attack execution flow
- Test coverage for success/failure paths

---
