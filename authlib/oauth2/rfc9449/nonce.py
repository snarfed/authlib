import time
from threading import Lock
from typing import Protocol

from authlib.common.security import generate_token


class DPoPNonceGenerator(Protocol):
    def next(self) -> str:
        """
        Compute and return the next nonce for this server
        :return: the nonce
        """
        ...

    def check(self, nonce: str) -> bool:
        """
        Checks if a nonce is valid
        :param nonce: the nonce
        :return: if the nonce is valid
        """
        ...


class DefaultDPoPNonceGenerator(DPoPNonceGenerator):
    """
    A default implementation of a DPoPNonceGenerator
    """
    DEFAULT_MAX_AGE = 3 * 60  # 3 minutes

    def __init__(self, max_age: int = DEFAULT_MAX_AGE):
        self.interval = max_age / 3
        self.counter = self._current_counter()
        self.prev_nonce = self._compute(self.counter - 1)
        self.cur_nonce = self._compute(self.counter)
        self.next_nonce = self._compute(self.counter + 1)
        self.lock = Lock()

    def next(self) -> str:
        self._rotate()
        return self.next_nonce

    def check(self, nonce: str) -> bool:
        return self.next_nonce == nonce or self.cur_nonce == nonce or self.prev_nonce == nonce

    def _current_counter(self) -> int:
        return int(time.time() / self.interval)

    def _rotate(self):
        with self.lock:
            counter = self._current_counter()
            match counter - self.counter:
                case 0:
                    pass
                case 1:
                    self.prev_nonce = self.cur_nonce
                    self.cur_nonce = self.next_nonce
                    self.next_nonce = self._compute(counter + 1)
                case 2:
                    self.prev_nonce = self.next_nonce
                    self.cur_nonce = self._compute(counter)
                    self.next_nonce = self._compute(counter + 1)
                case 3:
                    self.prev_nonce = self._compute(counter - 1)
                    self.cur_nonce = self._compute(counter)
                    self.next_nonce = self._compute(counter + 1)
            self.counter = counter

    @staticmethod
    def _compute(counter: int) -> str:
        return generate_token()
