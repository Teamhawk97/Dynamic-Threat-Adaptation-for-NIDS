import math


class StatisticalAnomalyDetector:

    def __init__(self):

        self.count = 0
        self.mean = None
        self.var = None

        self.threshold = 120.0
        self.adaptation_rate = 0.01

        # stability constants
        self.min_variance = 1e-3
        self.max_feature_value = 10

    # ----------------------------
    # Update baseline
    # ----------------------------

    def update(self, vector):

        if self.mean is None:

            self.mean = vector[:]
            self.var = [0.0] * len(vector)
            self.count = 1
            return

        self.count += 1

        alpha = self.adaptation_rate

        for i, x in enumerate(vector):

            # adaptive mean update
            delta = x - self.mean[i]

            self.mean[i] = (1 - alpha) * self.mean[i] + alpha * x

            # adaptive variance update
            self.var[i] = (1 - alpha) * self.var[i] + alpha * (delta ** 2)

    # ----------------------------
    # Distance score
    # ----------------------------

    def score(self, vector):

        if self.mean is None:
            return 0

        dist = 0

        for i, x in enumerate(vector):

            variance = self.var[i] / max(self.count - 1, 1)

            # stability fix
            variance = max(variance, self.min_variance)

            # clamp extreme values
            x = min(x, self.max_feature_value)

            dist += ((x - self.mean[i]) ** 2) / variance

        return math.sqrt(dist)

    # ----------------------------
    # Detect anomaly
    # ----------------------------

    def is_anomaly(self, vector):

        # warm-up learning
        if self.count < 100:
            self.update(vector)
            print(f"[ANOMALY] learning baseline {self.count}/100")
            return False, 0

        score = self.score(vector)

        if score > self.threshold:
            return True, score

        # normal traffic → update baseline
        self.update(vector)

        return False, score