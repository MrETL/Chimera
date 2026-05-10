"""Carlini & Wagner (C&W) L2 attack."""

# torch imported lazily inside methods
# torch.nn imported lazily
# torch.optim imported lazily

from chimera.attacks.base import BaseAttack, AttackResult, AttackCategory
from chimera.targets.base import BaseTarget
from chimera.core.attack_registry import AttackRegistry


@AttackRegistry.register
class CWAttack(BaseAttack):
    """Carlini & Wagner (C&W) L2 attack.
    
    Optimization-based attack that minimizes L2 distance while causing
    misclassification.
    
    MITRE ATLAS: T0048 - Adversarial Example
    OWASP ML: ML02 - Model Evasion
    """

    name = "cw_l2"
    description = "Carlini & Wagner L2 optimization attack."
    category = AttackCategory.ML_EVASION
    mitre_technique = "ATLAS.T0048"
    owasp_risk = "ML02 - Model Evasion"

    def __init__(
        self,
        c: float = 1.0,
        kappa: float = 0.0,
        num_iter: int = 100,
        learning_rate: float = 0.01,
        **kwargs
    ):
        super().__init__(**kwargs)
        self.c = c
        self.kappa = kappa
        self.num_iter = num_iter
        self.learning_rate = learning_rate

    def run(
        self,
        target: BaseTarget,
        image,
        true_label: int,
        target_label: int = None,
        **kwargs
    ) -> object:
        """Generate adversarial example using C&W attack."""
        import torch
        import torch.nn as nn
        import torch.optim as optim
        if not hasattr(target, 'model'):
            raise NotImplementedError("C&W requires target with model attribute")
        
        model = target.model
        device = target.device if hasattr(target, 'device') else 'cpu'
        
        image = image.to(device)
        
        # Initialize perturbation variable (in tanh space for box constraints)
        w = torch.zeros_like(image, requires_grad=True, device=device)
        optimizer = optim.Adam([w], lr=self.learning_rate)
        
        best_adv = image.clone()
        best_loss = float('inf')
        
        for i in range(self.num_iter):
            # Convert from tanh space to image space
            adv_image = 0.5 * (torch.tanh(w) + 1)
            
            # Forward pass
            output = model(adv_image)
            
            # C&W loss function
            # L2 distance
            l2_dist = torch.sum((adv_image - image) ** 2)
            
            # Classification loss
            if target_label is not None:
                # Targeted attack
                target_onehot = torch.zeros_like(output)
                target_onehot[0, target_label] = 1
                real = torch.sum(output * target_onehot)
                other = torch.max((1 - target_onehot) * output - target_onehot * 10000)
                loss_cls = torch.clamp(other - real + self.kappa, min=0)
            else:
                # Untargeted attack
                true_onehot = torch.zeros_like(output)
                true_onehot[0, true_label] = 1
                real = torch.sum(output * true_onehot)
                other = torch.max((1 - true_onehot) * output - true_onehot * 10000)
                loss_cls = torch.clamp(real - other + self.kappa, min=0)
            
            # Total loss
            loss = l2_dist + self.c * loss_cls
            
            # Optimization step
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
            
            # Track best adversarial example
            if loss.item() < best_loss:
                best_loss = loss.item()
                best_adv = adv_image.detach().clone()
            
            if (i + 1) % 20 == 0:
                print(f"Iter {i + 1}/{self.num_iter}: Loss={loss.item():.4f}, L2={l2_dist.item():.4f}")
        
        return best_adv

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
                    "c": self.c,
                    "kappa": self.kappa,
                    "num_iter": self.num_iter,
                    "predicted_label": pred_label,
                    "method": "C&W L2"
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
