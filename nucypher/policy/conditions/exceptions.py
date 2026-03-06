# Lingo Validation Errors (Grammar)
class InvalidConditionLingo(Exception):
    """Invalid lingo grammar."""


# Connectivity
class NoConnectionToChain(RuntimeError):
    """Raised when a node does not have an associated provider for a chain."""

    def __init__(self, chain: int, message: str = None):
        self.chain = chain
        message = message or f"No connection to chain ID {chain}"
        super().__init__(message)


# Context Variable
class InvalidConditionContext(Exception):
    """Raised when invalid context is encountered."""


# Conditions
class InvalidCondition(ValueError):
    """Invalid value for condition."""


class ConditionEvaluationFailed(Exception):
    """Could not evaluate condition."""
