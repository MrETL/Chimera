"""Configuration loading and validation."""

import os
import yaml
from typing import Any, Dict, Optional
from pathlib import Path


def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """Load configuration from YAML file or environment."""
    config = {}
    
    # Default locations
    if config_path:
        paths = [Path(config_path)]
    else:
        paths = [
            Path("chimera.yaml"),
            Path("config/chimera.yaml"),
            Path.home() / ".chimera/config.yaml"
        ]
    
    for path in paths:
        if path.exists():
            with open(path, "r") as f:
                config.update(yaml.safe_load(f))
    
    # Override with environment variables
    for key, value in os.environ.items():
        if key.startswith("CHIMERA_"):
            config_key = key[8:].lower()
            config[config_key] = value
    
    return config
