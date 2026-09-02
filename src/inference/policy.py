"""
Decision Policy & Selective Abstention Engine for UniDetect Threat Classification
"""

from typing import Any, Dict, List, Optional
import numpy as np

from src.features.schema import THREAT_CLASSES

DEFAULT_ABSTAIN_THRESHOLD = 0.40
DEFAULT_RECON_THRESHOLD = 0.35


class DecisionPolicy:
    """
    Decoupled decision policy encapsulating:
    1. Multi-class probability thresholding
    2. Selective classification / analyst review abstention (confidence < 0.40)
    3. Class-specific threshold adjustments for low-prevalence threats (RECON = 0.35)
    """

    def __init__(
        self,
        abstain_threshold: float = DEFAULT_ABSTAIN_THRESHOLD,
        recon_threshold: float = DEFAULT_RECON_THRESHOLD,
        classes: Optional[List[str]] = None,
        active_label_ids: Optional[List[int]] = None,
    ) -> None:
        self.abstain_threshold = float(abstain_threshold)
        self.recon_threshold = float(recon_threshold)
        self.classes = classes or ["BENIGN", "DDOS", "RECON", "DNS_TUNNEL", "C2_BEACON", "SLOW_HTTP"]
        self.active_label_ids = active_label_ids or [THREAT_CLASSES.index(c) for c in self.classes]
        self.label_id_to_name = {cid: THREAT_CLASSES[cid] for cid in self.active_label_ids}

    def evaluate(
        self,
        probabilities: np.ndarray,
        model_classes: np.ndarray,
    ) -> Dict[str, Any]:
        """
        Evaluates a probability distribution across model classes and applies
        operational threshold and abstention rules.

        Returns structured inference verdict.
        """
        probs_1d = np.asarray(probabilities, dtype=np.float64)
        if probs_1d.ndim != 1:
            raise ValueError(f"Expected 1D probability array, got shape {probs_1d.shape}")

        prob_dict = {
            THREAT_CLASSES[cid]: float(probs_1d[idx])
            for idx, cid in enumerate(model_classes)
        }

        # 1. Base Argmax Prediction
        max_idx = int(np.argmax(probs_1d))
        max_prob = float(probs_1d[max_idx])
        predicted_cid = int(model_classes[max_idx])
        predicted_label = THREAT_CLASSES[predicted_cid]

        # 2. Class-Specific RECON Threshold Rule
        recon_cid = THREAT_CLASSES.index("RECON")
        if recon_cid in model_classes:
            recon_prob_idx = list(model_classes).index(recon_cid)
            recon_prob = float(probs_1d[recon_prob_idx])
            # If RECON probability exceeds specialized threshold and exceeds non-DDoS alternatives
            if recon_prob >= self.recon_threshold and recon_prob == max(recon_prob, float(probs_1d[max_idx]) * 0.9):
                predicted_cid = recon_cid
                predicted_label = "RECON"
                max_prob = recon_prob

        # 3. Abstention & Selective Classification Rule
        abstained = max_prob < self.abstain_threshold
        decision = "ANALYST_REVIEW" if abstained else "AUTOMATED_DETECTION"

        return {
            "predicted_class_id": predicted_cid,
            "predicted_label": predicted_label,
            "confidence": round(max_prob, 4),
            "probabilities": {k: round(v, 4) for k, v in prob_dict.items()},
            "abstained": abstained,
            "decision": decision,
            "abstain_threshold": self.abstain_threshold,
            "recon_threshold": self.recon_threshold,
        }

    def export_policy_dict(self) -> Dict[str, Any]:
        """Exports decision policy settings as a serializable dictionary."""
        return {
            "policy_name": "UniDetect Selective Classification Policy",
            "abstain_threshold": self.abstain_threshold,
            "recon_threshold": self.recon_threshold,
            "active_classes": self.classes,
            "active_label_ids": self.active_label_ids,
            "decision_actions": {
                "AUTOMATED_DETECTION": "Confidence >= 0.40 -> Proceed with automated detection pipeline.",
                "ANALYST_REVIEW": "Confidence < 0.40 -> Low confidence traffic flagged for SOC analyst review.",
            },
        }
