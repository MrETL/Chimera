"""Attack Generation Pipeline.

End-to-end pipeline that combines LLM generation, genetic evolution,
and mutation to produce high-quality attack variants at scale.
"""

from typing import List, Dict, Any, Optional, Callable
from chimera.generation.llm_generator import LLMAttackGenerator
from chimera.generation.genetic_engine import GeneticAttackEngine
from chimera.generation.mutator import AttackMutator
import logging
import json
import time

logger = logging.getLogger(__name__)


class GenerationPipeline:
    """Orchestrates the full attack generation workflow.
    
    Pipeline stages:
    1. Seed generation (LLM or template)
    2. Mutation expansion (create variants)
    3. Genetic evolution (optimize against target)
    4. Quality filtering (remove low-quality variants)
    5. Deduplication (remove near-duplicates)
    6. Output formatting
    """

    def __init__(
        self,
        generator_model=None,
        population_size: int = 20,
        max_generations: int = 5,
        quality_threshold: float = 0.4,
    ):
        self.generator = LLMAttackGenerator(generator_model)
        self.genetic_engine = GeneticAttackEngine(
            population_size=population_size,
            max_generations=max_generations,
        )
        self.mutator = AttackMutator()
        self.quality_threshold = quality_threshold

    def _deduplicate(self, variants: List[Dict[str, Any]],
                     similarity_threshold: float = 0.8) -> List[Dict[str, Any]]:
        """Remove near-duplicate variants using simple token overlap."""
        unique = []
        seen_tokens = []

        for variant in variants:
            prompt = variant.get("prompt", "")
            tokens = set(prompt.lower().split())

            is_duplicate = False
            for seen in seen_tokens:
                overlap = len(tokens & seen) / max(len(tokens | seen), 1)
                if overlap > similarity_threshold:
                    is_duplicate = True
                    break

            if not is_duplicate:
                unique.append(variant)
                seen_tokens.append(tokens)

        return unique

    def _quality_filter(self, variants: List[Dict[str, Any]],
                        min_length: int = 30) -> List[Dict[str, Any]]:
        """Filter out low-quality variants."""
        filtered = []
        for v in variants:
            prompt = v.get("prompt", "")
            fitness = v.get("fitness", 1.0)  # default high if not evaluated

            # Basic quality checks
            if len(prompt) < min_length:
                continue
            if fitness is not None and fitness < self.quality_threshold:
                continue
            if prompt.count("{") > 0:  # unfilled template
                continue

            filtered.append(v)
        return filtered

    def run(
        self,
        goal: str,
        target_fn: Optional[Callable[[str], str]] = None,
        attack_types: List[str] = None,
        n_seeds: int = 5,
        evolve: bool = True,
        verbose: bool = False,
    ) -> Dict[str, Any]:
        """Run the full generation pipeline.
        
        Args:
            goal: The attack goal/objective
            target_fn: Optional function to query target model (enables evolution)
            attack_types: List of attack types to generate
            n_seeds: Number of seed prompts per type
            evolve: Whether to run genetic evolution (requires target_fn)
            verbose: Print progress
            
        Returns:
            Dict with all generated variants, best prompt, stats
        """
        start_time = time.time()
        if attack_types is None:
            attack_types = ["jailbreak", "social_engineering", "technical"]

        logger.info(f"Pipeline: goal='{goal[:50]}', types={attack_types}, "
                    f"n_seeds={n_seeds}, evolve={evolve}")

        all_variants = []

        # Stage 1: Seed generation
        for attack_type in attack_types:
            seeds = self.generator.generate(goal, attack_type, n=n_seeds)
            for seed in seeds:
                all_variants.append({
                    "prompt": seed["prompt"],
                    "type": attack_type,
                    "stage": "seed",
                    "fitness": None,
                })
            if verbose:
                logger.info(f"Generated {len(seeds)} seeds for type '{attack_type}'")

        # Stage 2: Mutation expansion
        mutation_variants = []
        for variant in all_variants[:5]:  # mutate top seeds
            mutations = self.mutator.generate_variants(variant["prompt"], n=3)
            for m in mutations:
                mutation_variants.append({
                    "prompt": m["variant"],
                    "type": variant["type"],
                    "stage": "mutation",
                    "mutation_strategy": m["strategy"],
                    "fitness": None,
                })
        all_variants.extend(mutation_variants)

        if verbose:
            logger.info(f"After mutation: {len(all_variants)} total variants")

        # Stage 3: Genetic evolution (if target available)
        evolution_result = None
        if evolve and target_fn is not None:
            best_seed = all_variants[0]["prompt"] if all_variants else goal
            evolution_result = self.genetic_engine.evolve(
                seed_prompt=best_seed,
                target_fn=target_fn,
                verbose=verbose,
            )
            # Add evolved variants
            for gen_data in evolution_result.get("fitness_history", []):
                all_variants.append({
                    "prompt": gen_data.get("best_prompt_snippet", ""),
                    "type": "evolved",
                    "stage": "evolution",
                    "fitness": gen_data.get("best_fitness", 0.0),
                })

        # Stage 4: Quality filter
        filtered = self._quality_filter(all_variants)

        # Stage 5: Deduplication
        unique = self._deduplicate(filtered)

        # Find best
        evaluated = [v for v in unique if v.get("fitness") is not None]
        best = max(evaluated, key=lambda x: x["fitness"]) if evaluated else (
            unique[0] if unique else {"prompt": goal, "fitness": 0.0}
        )

        elapsed = time.time() - start_time

        return {
            "goal": goal,
            "best_prompt": best.get("prompt", goal),
            "best_fitness": best.get("fitness", 0.0),
            "total_generated": len(all_variants),
            "after_filter": len(filtered),
            "after_dedup": len(unique),
            "all_variants": unique,
            "evolution_result": evolution_result,
            "elapsed_seconds": round(elapsed, 2),
            "attack_types": attack_types,
        }

    def batch_run(self, goals: List[str], target_fn: Optional[Callable] = None,
                  **kwargs) -> List[Dict[str, Any]]:
        """Run pipeline for multiple goals."""
        results = []
        for i, goal in enumerate(goals):
            logger.info(f"Pipeline batch {i+1}/{len(goals)}: {goal[:50]}")
            result = self.run(goal, target_fn=target_fn, **kwargs)
            results.append(result)
        return results

    def save_variants(self, pipeline_result: Dict[str, Any], filepath: str) -> None:
        """Save generated variants to a JSON file."""
        output = {
            "goal": pipeline_result["goal"],
            "best_prompt": pipeline_result["best_prompt"],
            "total_variants": pipeline_result["after_dedup"],
            "variants": [
                {"prompt": v["prompt"], "type": v.get("type"), "fitness": v.get("fitness")}
                for v in pipeline_result["all_variants"]
            ],
        }
        with open(filepath, "w") as f:
            json.dump(output, f, indent=2)
        logger.info(f"Saved {len(output['variants'])} variants to {filepath}")
