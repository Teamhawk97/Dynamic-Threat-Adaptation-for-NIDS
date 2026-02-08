# model.py
import json
import os
import math
from typing import Dict, List, Tuple

class PrototypeClassifier:
    """
    Prototype-based Few-Shot Class Incremental Learning (FSCIL) model.
    """

    def __init__(
        self,
        distance: str = "euclidean",
        known_threshold: float = 3.0,
        min_samples_per_class: int = 1,
    ):
        """
        distance: 'euclidean' or 'cosine'
        known_threshold: distance threshold to accept known class
        min_samples_per_class: minimum samples before a class is considered stable
        """
        self.distance = distance
        self.known_threshold = known_threshold
        self.min_samples_per_class = min_samples_per_class

        # class_name -> {"prototype": [...], "count": int}
        self.classes: Dict[str, Dict] = {}

    # -------------------------------
    # Distance functions
    # -------------------------------

    def _euclidean(self, a: List[float], b: List[float]) -> float:
        return math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b)))

    def _cosine(self, a: List[float], b: List[float]) -> float:
        dot = sum(x * y for x, y in zip(a, b))
        na = math.sqrt(sum(x * x for x in a))
        nb = math.sqrt(sum(y * y for y in b))
        if na == 0 or nb == 0:
            return 1.0
        return 1.0 - (dot / (na * nb))

    def _distance(self, a: List[float], b: List[float]) -> float:
        if self.distance == "cosine":
            return self._cosine(a, b)
        return self._euclidean(a, b)

    # -------------------------------
    # Core classification logic
    # -------------------------------

    def classify(self, vector: List[float]) -> Tuple[str, float]:
        # print("[DEBUG-ML] classify() called")   #for debugging
        """
        Returns (label, distance).
        label may be a class name or 'UNKNOWN'.
        """
        if not self.classes:
            return "UNKNOWN", float("inf")

        best_label = None
        best_dist = float("inf")

        for label, data in self.classes.items():
            proto = data["prototype"]
            d = self._distance(vector, proto)
            if d < best_dist:
                best_dist = d
                best_label = label

        if best_dist <= self.known_threshold:
            return best_label, best_dist

        return "UNKNOWN", best_dist

    # -------------------------------
    # Few-shot incremental learning
    # -------------------------------

    def add_example(self, label: str, vector: List[float]):
        """
        Add one example to a class (few-shot learning).
        Updates the prototype incrementally.
        """
        if label not in self.classes:
            self.classes[label] = {
                "prototype": vector[:],
                "count": 1,
            }
            return

        data = self.classes[label]
        old_proto = data["prototype"]
        n = data["count"]

        # running mean update
        new_proto = [
            (old_proto[i] * n + vector[i]) / (n + 1)
            for i in range(len(vector))
        ]

        data["prototype"] = new_proto
        data["count"] = n + 1

    def has_stable_class(self, label: str) -> bool:
        return (
            label in self.classes
            and self.classes[label]["count"] >= self.min_samples_per_class
        )

    # -------------------------------
    # Persistence
    # -------------------------------

    def save(self, path: str):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump(
                {
                    "distance": self.distance,
                    "known_threshold": self.known_threshold,
                    "min_samples_per_class": self.min_samples_per_class,
                    "classes": self.classes,
                },
                f,
                indent=2,
            )

    @classmethod
    def load(cls, path: str):
        model = cls()
        if not os.path.exists(path):
            return model

        with open(path, "r") as f:
            data = json.load(f)

        model.distance = data["distance"]
        model.known_threshold = data["known_threshold"]
        model.min_samples_per_class = data["min_samples_per_class"]
        model.classes = data["classes"]

        return model
