import json
import os
import math
from typing import Dict, List, Tuple


class PrototypeClassifier:
    """
    Prototype-based classifier with:
    - Dataset-trained base model
    - Few-shot incremental learning
    """

    def __init__(
        self,
        distance: str = "euclidean",
        known_threshold: float = 8.0,
        min_samples_per_class: int = 1,
    ):
        self.distance = distance
        self.known_threshold = known_threshold
        self.min_samples_per_class = min_samples_per_class

        # class_name -> {"prototype": [...], "count": int}
        self.classes: Dict[str, Dict] = {}

    # ------------------------------------------------
    # Distance functions
    # ------------------------------------------------

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

    # ------------------------------------------------
    # Classification
    # ------------------------------------------------

    def classify(self, vector: List[float]) -> Tuple[str, float]:
        """
        Returns (label, distance)
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

    # ------------------------------------------------
    # Few-shot incremental learning
    # ------------------------------------------------

    def add_example(self, label: str, vector: List[float]):
        """
        Update prototype using running mean.
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

        new_proto = [
            (old_proto[i] * n + vector[i]) / (n + 1)
            for i in range(len(vector))
        ]

        data["prototype"] = new_proto
        data["count"] = n + 1

    def has_stable_class(self, label: str) -> bool:

        if label not in self.classes:
            return False

        return self.classes[label]["count"] >= self.min_samples_per_class

    # ------------------------------------------------
    # Model persistence
    # ------------------------------------------------

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
            print("[ML] No existing model found. Starting fresh.")
            return model

        with open(path, "r") as f:
            data = json.load(f)

        model.distance = data.get("distance", "euclidean")
        model.known_threshold = data.get("known_threshold", 3.0)
        model.min_samples_per_class = data.get("min_samples_per_class", 1)

        model.classes = data.get("classes", {})

        print("[ML] Loaded base model with classes:")

        for c in model.classes:
            print("   ", c, "(samples:", model.classes[c]["count"], ")")

        return model