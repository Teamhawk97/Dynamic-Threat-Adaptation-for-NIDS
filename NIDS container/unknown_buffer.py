# unknown_buffer.py

import threading
import time
import math


class UnknownBuffer:
    """
    Stores feature vectors classified as UNKNOWN.
    Includes protections against flooding attacks.
    """

    def __init__(
        self,
        max_vectors=5000,
        max_age_seconds=300,
        rate_limit=20
    ):

        self.vectors = []
        self.timestamps = []

        self.max_vectors = max_vectors
        self.max_age = max_age_seconds

        self.rate_limit = rate_limit
        self.last_add_time = 0
        self.counter = 0

        self.lock = threading.Lock()

    # ------------------------------------------------
    # Vector similarity check (deduplication)
    # ------------------------------------------------

    def _similar(self, a, b, threshold=0.05):

        diff = sum(abs(x - y) for x, y in zip(a, b))

        return diff < threshold

    # ------------------------------------------------
    # Add unknown vector
    # ------------------------------------------------

    def add(self, vector):

        with self.lock:

            now = time.time()

            # ---------- rate limiting ----------
            if now - self.last_add_time > 1:
                self.counter = 0
                self.last_add_time = now

            if self.counter >= self.rate_limit:
                return

            self.counter += 1

            # ---------- deduplication ----------
            for v in self.vectors:

                if self._similar(v, vector):
                    return

            # ---------- add vector ----------
            self.vectors.append(vector)
            self.timestamps.append(now)

            # ---------- cleanup old vectors ----------
            self._cleanup_old()

            # ---------- enforce memory limit ----------
            if len(self.vectors) > self.max_vectors:

                oldest = min(
                    range(len(self.timestamps)),
                    key=lambda i: self.timestamps[i]
                )

                self.vectors.pop(oldest)
                self.timestamps.pop(oldest)

    # ------------------------------------------------
    # Remove old vectors
    # ------------------------------------------------

    def _cleanup_old(self):

        now = time.time()

        new_vectors = []
        new_timestamps = []

        for v, ts in zip(self.vectors, self.timestamps):

            if now - ts < self.max_age:
                new_vectors.append(v)
                new_timestamps.append(ts)

        self.vectors = new_vectors
        self.timestamps = new_timestamps

    # ------------------------------------------------
    # Export vectors to leader
    # ------------------------------------------------

    def export_vectors(self):

        with self.lock:

            if len(self.vectors) < 10:
                return []

            data = self.vectors.copy()

            self.vectors.clear()
            self.timestamps.clear()

            return data

    # ------------------------------------------------
    # Buffer statistics
    # ------------------------------------------------

    def size(self):

        with self.lock:
            return len(self.vectors)