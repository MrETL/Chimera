"""Attack orchestration kernel."""

import logging
from typing import List, Optional, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

from chimera.core.target_manager import TargetManager
from chimera.core.attack_registry import AttackRegistry
from chimera.attacks.base import AttackResult

logger = logging.getLogger(__name__)


class ChimeraKernel:
    """Runs attacks against targets and collects results."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.target_manager = TargetManager()

    def scan(
        self,
        target_uri: str,
        attacks: Optional[List[str]] = None,
        attack_kwargs: Optional[Dict[str, Any]] = None,
        target_kwargs: Optional[Dict[str, Any]] = None,
    ) -> List[AttackResult]:
        """Run attacks against a target and return results."""
        target = self.target_manager.load_target(target_uri, **(target_kwargs or {}))
        names = attacks or AttackRegistry.list_attacks()
        results = []

        for name in names:
            try:
                attack = AttackRegistry.create_instance(name, **(attack_kwargs or {}))
                raw = attack.run(target)
                result = attack.safe_evaluate(target, raw)
                results.append(result)
            except Exception as e:
                logger.debug(f"{name} failed: {e}")
                results.append(AttackResult(
                    attack_name=name,
                    target_id=target.model_id,
                    success=False,
                    metadata={"error": str(e)},
                ))

        return results

    def scan_parallel(
        self,
        target_uris: List[str],
        attacks: Optional[List[str]] = None,
        max_workers: int = 4,
        **kwargs,
    ) -> Dict[str, List[AttackResult]]:
        """Scan multiple targets in parallel."""
        results: Dict[str, List[AttackResult]] = {}

        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {pool.submit(self.scan, uri, attacks, **kwargs): uri
                       for uri in target_uris}
            for future in as_completed(futures):
                uri = futures[future]
                try:
                    results[uri] = future.result()
                except Exception as e:
                    logger.error(f"{uri}: {e}")
                    results[uri] = []

        return results
