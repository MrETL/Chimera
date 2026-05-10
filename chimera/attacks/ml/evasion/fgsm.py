"""Fast Gradient Sign Method (FGSM) evasion attack."""

from typing import Optional

from chimera.judges.exploit_verifier import verify_exploitation, is_system_prompt_leaked
from chimera.attacks.base import BaseAttack, AttackResult, AttackCategory
from chimera.targets.base import BaseTarget
from chimera.core.attack_registry import AttackRegistry


@AttackRegistry.register
class FGSMAttack(BaseAttack):
    """Fast Gradient Sign Method (FGSM) evasion attack.
    
    Generates adversarial examples by adding perturbations in the direction
    of the gradient sign.
    
    MITRE ATLAS: T0048 - Adversarial Example
    OWASP ML: ML02 - Model Evasion
    """

    name = "fgsm"
    description = "Fast Gradient Sign Method for adversarial examples."
    category = AttackCategory.ML_EVASION
    mitre_technique = "ATLAS.T0048"
    owasp_risk = "ML02 - Model Evasion"

    def __init__(self, epsilon: float = 0.03, **kwargs):
        super().__init__(**kwargs)
        self.epsilon = epsilon

    def run(
        self,
        target: BaseTarget,
        image,
        true_label: int,
        **kwargs
    ) -> object:
        """Generate adversarial example using FGSM."""
        import torch
        import torch.nn as nn
        if not hasattr(target, 'model'):
            raise NotImplementedError("FGSM requires target with model attribute")
        
        model = target.model
        device = target.device if hasattr(target, 'device') else 'cpu'
        
        # Ensure image requires grad
        image = image.to(device)
        image.requires_grad = True
        
        # Forward pass
        output = model(image)
        
        # Calculate loss
        criterion = nn.CrossEntropyLoss()
        loss = criterion(output, torch.tensor([true_label], device=device))
        
        # Backward pass
        model.zero_grad()
        loss.backward()
        
        # Generate adversarial example
        data_grad = image.grad.data
        perturbed_image = image + self.epsilon * data_grad.sign()
        
        # Clip to valid range [0, 1]
        perturbed_image = torch.clamp(perturbed_image, 0, 1)
        
        return perturbed_image.detach()

    def evaluate(self, target: BaseTarget, run_output) -> AttackResult:
        conf, reason = 0.0, ""
        """Evaluate if adversarial example causes misclassification."""
        import torch
        import torch.nn as nn
        try:
            model = target.model
            device = target.device if hasattr(target, 'device') else 'cpu'
            
            # Get prediction on adversarial example
            with torch.no_grad():
                output = model(run_output.to(device))
                pred_label = output.argmax(dim=1).item()
            
            # Success if prediction changed (assuming we stored original in metadata)
            # For now, we consider any prediction as potential success
            exploited, conf, reason = verify_exploitation(response)

            success = exploited
            confidence = torch.softmax(output, dim=1).max().item()
            
            return AttackResult(
                attack_name=self.name,
                target_id=target.model_id,
                success=success,
                confidence=confidence,
                mitre_technique=self.mitre_technique,
                owasp_risk=self.owasp_risk,
                metadata={
                    "epsilon": self.epsilon,
                    "predicted_label": pred_label,
                    "method": "FGSM"
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
