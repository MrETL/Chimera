"""Coordinates multiple specialized agents for complex red teaming."""

from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from chimera.targets.base import BaseTarget
from chimera.orchestrator.planner import AutonomousPlanner, AttackPlan
from chimera.orchestrator.executor import PlanExecutor
import logging

logger = logging.getLogger(__name__)


class RedTeamOrchestrator:
    """Main orchestrator that manages the entire autonomous red teaming process."""
    
    def __init__(self, planner_model: BaseTarget):
        self.planner = AutonomousPlanner(planner_model)
        self.executor = PlanExecutor()
        self.attack_history: List[Dict] = []
    
    def run_campaign(self, target_uri: str, goal: str, max_retries: int = 3) -> Dict[str, Any]:
        """Run a full autonomous red team campaign."""
        available_attacks = AttackRegistry.list_attacks()
        
        logger.info(f"Starting campaign against {target_uri} with goal: {goal}")
        
        # Initial planning
        plan = self.planner.generate_plan(target_uri, goal, available_attacks)
        logger.info(f"Generated plan with {len(plan.steps)} steps")
        
        # Execute with retry logic
        results = []
        for attempt in range(max_retries):
            results = self.executor.execute_plan(plan)
            
            # Check if goal achieved
            if self._is_goal_achieved(goal, results):
                logger.info(f"Goal achieved on attempt {attempt+1}")
                break
            elif attempt < max_retries - 1:
                # Adapt plan based on failures
                failure_reason = self._analyze_failure(results)
                plan = self.planner.adapt_plan(plan, [r.__dict__ for r in results], failure_reason)
                logger.info(f"Plan adapted for retry {attempt+2}")
        
        # Generate final report
        report = {"results": [r.__dict__ for r in results if hasattr(r, '__dict__')]}
        
        campaign_summary = {
            "target": target_uri,
            "goal": goal,
            "success": self._is_goal_achieved(goal, results),
            "steps_executed": len(results),
            "report": report
        }
        
        self.attack_history.append(campaign_summary)
        return campaign_summary
    
    def _is_goal_achieved(self, goal: str, results: List) -> bool:
        """Heuristic to determine if campaign goal was met."""
        # TODO: use LLM judge here
        return any(r.success for r in results)
    
    def _analyze_failure(self, results: List) -> str:
        """Analyze failure patterns for plan adaptation."""
        failures = [r for r in results if not r.success]
        if not failures:
            return "No failures"
        return f"Failed steps: {', '.join([f.attack_name for f in failures])}"
