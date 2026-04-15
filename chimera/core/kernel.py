"""Main Chimera kernel that orchestrates attacks."""

import logging
from typing import List, Optional, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

from tqdm import tqdm

from chimera.core.target_manager import TargetManager
from chimera.core.attack_registry import AttackRegistry
from chimera.attacks.base import BaseAttack, AttackResult
from chimera.targets.base import BaseTarget
from chimera.reporting.report_generator import ReportGenerator

logger = logging.getLogger(__name__)


class ChimeraKernel:
    """Central orchestration engine for Chimera.
    
    Responsibilities:
    - Load targets via TargetManager
    - Instantiate attacks from AttackRegistry
    - Execute single or multiple attacks against targets
    - Collect results and generate reports
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.target_manager = TargetManager()
        self.report_generator = ReportGenerator()
        self._setup_logging()

    def _setup_logging(self):
        """Configure logging based on config."""
        log_level = self.config.get("log_level", "INFO")
        logging.basicConfig(level=getattr(logging, log_level))

    def scan_target(
        self,
        target_uri: str,
        attacks: Optional[List[str]] = None,
        attack_kwargs: Optional[Dict[str, Any]] = None,
        target_kwargs: Optional[Dict[str, Any]] = None,
    ) -> List[AttackResult]:
        """Run a suite of attacks against a single target.
        
        Args:
            target_uri: URI of the target model (e.g., "openai://gpt-3.5-turbo")
            attacks: List of attack names to run. If None, runs all registered attacks.
            attack_kwargs: Additional kwargs passed to attack constructors.
            target_kwargs: Additional kwargs passed to target constructor.
            
        Returns:
            List of AttackResult objects.
        """
        target = self.target_manager.load_target(target_uri, **(target_kwargs or {}))
        attack_names = attacks or AttackRegistry.list_attacks()
        
        results = []
        for attack_name in tqdm(attack_names, desc=f"Attacking {target_uri}"):
            try:
                attack = AttackRegistry.create_instance(attack_name, **(attack_kwargs or {}))
                logger.info(f"Running attack: {attack_name}")
                
                attack.pre_attack_hook(target)
                raw_output = attack.run(target)
                result = attack.evaluate(target, raw_output)
                attack.post_attack_hook(target, result)
                
                results.append(result)
                logger.info(f"  -> Success: {result.success}, Confidence: {result.confidence:.2f}")
                
            except Exception as e:
                logger.error(f"Attack '{attack_name}' failed: {e}")
                # Create a failed result entry
                results.append(
                    AttackResult(
                        attack_name=attack_name,
                        target_id=target.model_id,
                        success=False,
                        confidence=0.0,
                        metadata={"error": str(e)}
                    )
                )
        
        return results

    def scan_targets_parallel(
        self,
        target_uris: List[str],
        attacks: Optional[List[str]] = None,
        max_workers: int = 4,
        **kwargs
    ) -> Dict[str, List[AttackResult]]:
        """Scan multiple targets in parallel."""
        results = {}
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_target = {
                executor.submit(self.scan_target, uri, attacks, **kwargs): uri
                for uri in target_uris
            }
            
            for future in as_completed(future_to_target):
                uri = future_to_target[future]
                try:
                    results[uri] = future.result()
                except Exception as e:
                    logger.error(f"Target {uri} scan failed: {e}")
                    results[uri] = []
        
        return results

    def generate_report(self, results: List[AttackResult], format: str = "json") -> str:
        """Generate a report from scan results."""
        return self.report_generator.generate(results, format=format)
