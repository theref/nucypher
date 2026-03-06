"""Base classes for the condition system."""

from abc import ABC, abstractmethod
from typing import Any, Tuple


class Condition(ABC):
    """Abstract base class for all conditions."""

    CONDITION_TYPE = NotImplemented

    @abstractmethod
    def verify(self, *args, **kwargs) -> Tuple[bool, Any]:
        """Returns the boolean result of the evaluation and the returned value in a two-tuple."""
        raise NotImplementedError

    def __repr__(self):
        return f"{self.__class__.__name__}"
