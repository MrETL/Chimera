"""Model inversion attack."""


from chimera.attacks.base import BaseAttack, AttackResult, AttackCategory
from chimera.targets.base import BaseTarget
from chimera.core.attack_registry import AttackRegistry


@AttackRegistry.register
class ModelInversionAttack(BaseAttack):
    """Model inversion attack to reconstruct training data.
    
    Optimizes input to maximize confidence for a target class,
    potentially revealing sensitive training data.
    
    MITRE ATLAS: T0024 - Model Inversion
    OWASP ML: ML07 - Privacy Violation
    """

    name = "model_inversion"
    description = "Reconstructs training data through gradient optimization."
    category = AttackCategory.ML_INVERSION
    mitre_technique = "ATLAS.T0024"
    owasp_risk = "ML07 - Privacy Violation"

    def __init__(
        self,
        num_iter: int = 500,
        learning_rate: float = 0.1,
        regularization: float = 0.01,
        **kwargs
    ):
        super().__init__(**kwargs)
        self.num_iter = num_iter
        self.learning_rate = learning_rate
        self.regularization = regularization

    def run(
        self,
        target: BaseTarget,
        target_class: int,
        input_shape: tuple,
        **kwargs
    ) -> object:
        """Reconstruct input for target class."""
        import torch
        import torch.nn as nn
        import torch.optim as optim
        if not hasattr(target, 'model'):
            raise NotImplementedError("Model inversion requires target with model attribute")
        
        model = target.model
        device = target.device if hasattr(target, 'device') else 'cpu'
        
        # Initialize random input
        reconstructed = torch.randn(1, *input_shape, device=device, requires_grad=True)
        optimizer = optim.Adam([reconstructed], lr=self.learning_rate)
        
        best_input = reconstructed.clone()
        best_confidence = 0.0
        
        for i in range(self.num_iter):
            optimizer.zero_grad()
            
            # Forward pass
            output = model(reconstructed)
            probs = torch.softmax(output, dim=1)
            
            # Loss: maximize confidence for target class + regularization
            target_confidence = probs[0, target_class]
            reg_loss = self.regularization * torch.norm(reconstructed)
            loss = -target_confidence + reg_loss
            
            # Backward pass
            loss.backward()
            optimizer.step()
            
            # Clip to valid range
            with torch.no_grad():
                reconstructed.clamp_(0, 1)
            
            # Track best reconstruction
            if target_confidence.item() > best_confidence:
                best_confidence = target_confidence.item()
                best_input = reconstructed.detach().clone()
            
            if (i + 1) % 100 == 0:
                print(f"Iter {i + 1}/{self.num_iter}: Confidence={target_confidence.item():.4f}")
        
        return best_input

    def evaluate(self, target: BaseTarget, run_output) -> AttackResult:
        """Evaluate inversion success."""
        import torch
        import torch.nn as nn
        try:
            model = target.model
            device = target.device if hasattr(target, 'device') else 'cpu'
            
            with torch.no_grad():
                output = model(run_output.to(device))
                probs = torch.softmax(output, dim=1)
                pred_class = output.argmax(dim=1).item()
                confidence = probs.max().item()
            
            # Success if high confidence achieved
            success = confidence > 0.8
            
            return AttackResult(
                attack_name=self.name,
                target_id=target.model_id,
                success=success,
                confidence=confidence,
                mitre_technique=self.mitre_technique,
                owasp_risk=self.owasp_risk,
                metadata={
                    "num_iter": self.num_iter,
                    "predicted_class": pred_class,
                    "final_confidence": confidence,
                    "method": "model_inversion"
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
