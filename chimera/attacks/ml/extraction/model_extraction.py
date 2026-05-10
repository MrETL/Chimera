"""Model extraction attack."""

# torch imported lazily inside methods
# torch.nn imported lazily
from typing import List, Tuple

from chimera.attacks.base import BaseAttack, AttackResult, AttackCategory
from chimera.targets.base import BaseTarget
from chimera.core.attack_registry import AttackRegistry


@AttackRegistry.register
class ModelExtractionAttack(BaseAttack):
    """Model extraction attack to steal model functionality.
    
    Queries the target model to build a surrogate model that mimics
    its behavior.
    
    MITRE ATLAS: T0024 - Model Extraction
    OWASP ML: ML06 - Model Theft
    """

    name = "model_extraction"
    description = "Extracts model functionality through query access."
    category = AttackCategory.ML_EXTRACTION
    mitre_technique = "ATLAS.T0024"
    owasp_risk = "ML06 - Model Theft"

    def __init__(
        self,
        num_queries: int = 1000,
        query_strategy: str = "random",
        **kwargs
    ):
        super().__init__(**kwargs)
        self.num_queries = num_queries
        self.query_strategy = query_strategy

    def run(
        self,
        target: BaseTarget,
        input_shape: Tuple[int, ...],
        num_classes: int,
        **kwargs
    ) -> Tuple[List[Any], List[Any]]:
        """Extract model by querying with synthetic inputs."""
        import torch
        import torch.nn as nn
        if not hasattr(target, 'model'):
            raise NotImplementedError("Model extraction requires target with model attribute")
        
        model = target.model
        device = target.device if hasattr(target, 'device') else 'cpu'
        
        queries = []
        responses = []
        
        for i in range(self.num_queries):
            # Generate query based on strategy
            if self.query_strategy == "random":
                query = torch.rand(1, *input_shape, device=device)
            elif self.query_strategy == "uniform":
                query = torch.ones(1, *input_shape, device=device) * 0.5
            else:
                query = torch.rand(1, *input_shape, device=device)
            
            # Query target model
            with torch.no_grad():
                output = model(query)
                # Store soft labels (probabilities)
                probs = torch.softmax(output, dim=1)
            
            queries.append(query.cpu())
            responses.append(probs.cpu())
            
            if (i + 1) % 100 == 0:
                print(f"Extracted {i + 1}/{self.num_queries} samples")
        
        return queries, responses

    def evaluate(
        self,
        target: BaseTarget,
        run_output: Tuple[List[Any], List[Any]]
    ) -> AttackResult:
        """Evaluate extraction success."""
        import torch
        import torch.nn as nn
        try:
            queries, responses = run_output
            
            # Success metrics
            num_samples = len(queries)
            avg_confidence = sum(r.max().item() for r in responses) / num_samples
            
            success = num_samples >= self.num_queries * 0.9
            
            return AttackResult(
                attack_name=self.name,
                target_id=target.model_id,
                success=success,
                confidence=avg_confidence,
                mitre_technique=self.mitre_technique,
                owasp_risk=self.owasp_risk,
                metadata={
                    "num_queries": num_samples,
                    "query_strategy": self.query_strategy,
                    "avg_confidence": avg_confidence,
                    "method": "model_extraction"
                }
            )
        except Exception as e:
            return AttackResult(
                attack_name=self.name,
                target_id=target.model_id,
                success=False,
                confidence=0.0,
                metadata={"error": str(e)}
            )
