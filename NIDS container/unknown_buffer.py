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
        
        self.last_cleanup = time.time() # 🔥 ADDED: Track last GC run

        self.lock = threading.Lock()

    # ------------------------------------------------
    # Vector similarity check (deduplication)
    # ------------------------------------------------

    def _similar(self, a, b, threshold=0.05):
        # 🔥 FIX: Use Cosine Distance to match model.py perfectly
        dot = sum(x * y for x, y in zip(a, b))
        na = math.sqrt(sum(x * x for x in a))
        nb = math.sqrt(sum(y * y for y in b))

        if na == 0 or nb == 0:
            return False

        dist = 1.0 - (dot / (na * nb))
        return dist < threshold

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

            # ---------- periodic cleanup (CPU Saver) ----------
            # 🔥 FIX: Only run garbage collection every 5 seconds, not every packet
            if now - self.last_cleanup > 5.0:
                self._cleanup_old(now)
                self.last_cleanup = now

            # ---------- enforce memory limit ----------
            # 🔥 FIX: O(1) removal instead of O(N) search. Oldest is always index 0.
            if len(self.vectors) > self.max_vectors:
                self.vectors.pop(0)
                self.timestamps.pop(0)

    # ------------------------------------------------
    # Remove old vectors
    # ------------------------------------------------

    def _cleanup_old(self, now):

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