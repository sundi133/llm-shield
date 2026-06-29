"""Custom exceptions for the Votal Shield LangChain SDK."""


class ShieldError(Exception):
    """Base exception for all SDK errors."""


class ShieldAPIError(ShieldError):
    """Raised when the Shield API returns an unexpected error."""


class ShieldAuthenticationError(ShieldAPIError):
    """Raised when Shield rejects authentication credentials."""


class ShieldAuthorizationError(ShieldAPIError):
    """Raised when Shield blocks a tool call."""


class ShieldToolExecutionError(ShieldError):
    """Raised when the wrapped tool fails during execution."""