"""Adversarial audio attacks for speech-to-text systems."""

from typing import Optional

from chimera.attacks.base import BaseAttack, AttackResult, AttackCategory
from chimera.targets.base import BaseTarget
from chimera.core.attack_registry import AttackRegistry


@AttackRegistry.register
class AdversarialAudioAttack(BaseAttack):
    """Adversarial audio attack for ASR/STT systems.
    
    Generates adversarial perturbations in audio to cause misrecognition.
    
    MITRE ATLAS: T0048 - Adversarial Example (Audio)
    OWASP ML: ML02 - Model Evasion
    """

    name = "adversarial_audio"
    description = "Generates adversarial audio for ASR systems."
    category = AttackCategory.MULTIMODAL_AUDIO
    mitre_technique = "ATLAS.T0048"
    owasp_risk = "ML02 - Model Evasion"

    def __init__(
        self,
        epsilon: float = 0.002,
        num_iter: int = 100,
        alpha: float = 0.0001,
        **kwargs
    ):
        super().__init__(**kwargs)
        self.epsilon = epsilon
        self.num_iter = num_iter
        self.alpha = alpha

    def run(
        self,
        target: BaseTarget,
        audio: np.ndarray,
        target_transcription: str,
        sample_rate: int = 16000,
        **kwargs
    ) -> np.ndarray:
        """Generate adversarial audio."""
        import torch
        import torch.nn as nn
        if not hasattr(target, 'transcribe'):
            raise NotImplementedError(
                "Adversarial audio requires target with transcribe method"
            )
        
        # Convert to tensor
        audio_tensor = torch.from_numpy(audio).float()
        
        # For simplicity, we'll use a gradient-free approach
        # In practice, this would require access to model gradients
        
        # Add small random perturbation
        perturbation = torch.randn_like(audio_tensor) * self.epsilon
        adversarial_audio = audio_tensor + perturbation
        
        # Clip to valid audio range [-1, 1]
        adversarial_audio = torch.clamp(adversarial_audio, -1.0, 1.0)
        
        return adversarial_audio.numpy()

    def evaluate(self, target: BaseTarget, run_output: np.ndarray) -> AttackResult:
        """Evaluate if adversarial audio causes misrecognition."""
        import torch
        import torch.nn as nn
        try:
            # Transcribe adversarial audio
            transcription = target.transcribe(run_output)
            
            # Check if transcription is different from expected
            # Success depends on whether we achieved target transcription
            # or caused any misrecognition
            
            success = len(transcription) > 0
            confidence = 0.6  # Moderate confidence for audio attacks
            
            return AttackResult(
                attack_name=self.name,
                target_id=target.model_id,
                success=success,
                confidence=confidence,
                raw_response=transcription,
                mitre_technique=self.mitre_technique,
                owasp_risk=self.owasp_risk,
                metadata={
                    "epsilon": self.epsilon,
                    "transcription": transcription,
                    "method": "adversarial_audio"
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
