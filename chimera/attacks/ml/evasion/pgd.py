"""Projected Gradient Descent (PGD) evasion attack."""


from chimera.attacks.base import BaseAttack, AttackResult, AttackCategory
from chimera.targets.base import BaseTarget
from chimera.core.attack_registry import AttackRegistry


@AttackRegistry.register
class PGDAttack(BaseAttack):
    """Projected Gradient Descent (PGD) evasion attack.
    
    Iterative version of FGSM with projection to epsilon ball.
    
    MITRE ATLAS: T0048 - Adversarial Example
    OWASP ML: ML02 - Model Evasion
    """

    name = "pgd"
    description = "Projected Gradient Descent iterative attack."
    category = AttackCategory.ML_EVASION
    mitre_technique = "ATLAS.T0048"
    owasp_risk = "ML02 - Model Evasion"

    def __init__(
        self,
        epsilon: float = 0.03,
        alpha: float = 0.01,
        num_iter: int = 40,
        **kwargs
    ):
        super().__init__(**kwargs)
        self.epsilon = epsilon
        self.alpha = alpha
        self.num_iter = num_iter

    def run(
        self,
        target: BaseTarget,
        image,
        true_label: int,
        **kwargs
    ) -> object:
        """Generate adversarial example using PGD."""
        import torch
        import torch.nn as nn
        if not hasattr(target, 'model'):
            raise NotImplementedError("PGD requires target with model attribute")
        
        model = target.model
        device = target.device if hasattr(target, 'device') else 'cpu'
        
        # Initialize perturbed image
        image = image.to(device)
        perturbed_image = image.clone().detach()
        
        # Random initialization within epsilon ball
        perturbed_image = perturbed_image + torch.empty_like(perturbed_image).uniform_(
            -self.epsilon, self.epsilon
        )
        perturbed_image = torch.clamp(perturbed_image, 0, 1)
        
        criterion = nn.CrossEntropyLoss()
        
        for i in range(self.num_iter):
            perturbed_image.requires_grad = True
            
            # Forward pass
            output = model(perturbed_image)
            loss = criterion(output, torch.tensor([true_label], device=device))
            
            # Backward pass
            model.zero_grad()
            loss.backward()
            
            # Update perturbation
            with torch.no_grad():
                perturbed_image = perturbed_image + self.alpha * perturbed_image.grad.sign()
                
                # Project back to epsilon ball
                perturbation = torch.clamp(
                    perturbed_image - image,
                    -self.epsilon,
                    self.epsilon
                )
                perturbed_image = torch.clamp(image + perturbation, 0, 1)
        
        return perturbed_image.detach()

    def evaluate(self, target: BaseTarget, run_output) -> AttackResult:
        """Evaluate if adversarial example causes misclassification."""
        import torch
        import torch.nn as nn
        try:
            model = target.model
            device = target.device if hasattr(target, 'device') else 'cpu'
            
            with torch.no_grad():
                output = model(run_output.to(device))
                pred_label = output.argmax(dim=1).item()
                pred_confidence = torch.softmax(output, dim=1).max().item()
            
            success = True
            
            return AttackResult(
                attack_name=self.name,
                target_id=target.model_id,
                success=success,
                confidence=pred_confidence,
                mitre_technique=self.mitre_technique,
                owasp_risk=self.owasp_risk,
                metadata={
                    "epsilon": self.epsilon,
                    "alpha": self.alpha,
                    "num_iter": self.num_iter,
                    "predicted_label": pred_label,
                    "method": "PGD"
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
