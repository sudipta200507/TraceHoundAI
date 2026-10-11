"""TraceHoundAI safety exceptions (Phase 2)."""


class TraceHoundSafetyError(Exception):
    """Base class for all safety-gate errors."""


class ScopeViolationError(TraceHoundSafetyError):
    """Raised when a target is outside the authorized scope."""


class InvalidTargetError(TraceHoundSafetyError):
    """Raised when a target is malformed and cannot be normalized safely."""


class ExecutionPolicyError(TraceHoundSafetyError):
    """Raised when the execution policy refuses an operation."""


class ScopeConfigurationError(TraceHoundSafetyError):
    """Raised when scope configuration is missing or malformed."""
