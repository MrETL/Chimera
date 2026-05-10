"""Executes attack plans with state management and error handling."""

from typing import Dict, Any, List, Optional
from chimera.orchestrator.planner import AttackPlan, AttackStep
from chimera.core.target_manager import TargetManager
from chimera.core.attack_registry import AttackRegistry
from chimera.attacks.base import AttackResult
import logging

logger = logging.getLogger(__name__)


class PlanExecutor:
    """Executes a sequence of attack steps, managing context and dependencies."""
    
    def __init__(self):
        self.target_manager = TargetManager()
        self.context: Dict[str, Any] = {}
        self.results: List[AttackResult] = []
    
    def execute_plan(self, plan: AttackPlan, target_kwargs: Optional[Dict] = None) -> List[AttackResult]:
        """Execute all steps in the plan."""
        target = self.target_manager.load_target(plan.target_uri, **(target_kwargs or {}))
        
        for step in plan.steps:
            try:
                # Resolve dependencies: if a step depends on previous output, inject it
                if step.depends_on:
                    # Find the dependent result
                    dep_result = next((r for r in self.results if r.attack_name == step.depends_on), None)
                    if dep_result:
                        step.parameters.update(dep_result.metadata)
                
                # Instantiate and run attack
                attack = AttackRegistry.create_instance(step.attack_name)
                logger.info(f"Executing step: {step.attack_name}")
                
                raw_output = attack.run(target, **step.parameters)
                result = attack.evaluate(target, raw_output)
                
                self.results.append(result)
                self.context[step.attack_name] = result
                
                logger.info(f"Step {step.attack_name} success: {result.success}")
                
                # Early termination if critical step fails
                if not result.success and step.parameters.get("critical", False):
                    logger.warning(f"Critical step {step.attack_name} failed. Halting execution.")
                    break
                    
            except Exception as e:
                logger.error(f"Step {step.attack_name} failed with exception: {e}")
                # Create a failure result
                self.results.append(AttackResult(
                    attack_name=step.attack_name,
                    target_id=plan.target_uri,
                    success=False,
                    metadata={"error": str(e)}
                ))
        
        return self.results
