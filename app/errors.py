"""
Shared error hierarchy for the TrustLens backend.

Every error this service raises on purpose answers two questions: what HTTP
status should the caller see, and what can the caller safely be told. Before
this module each exception answered those implicitly, at the call site, which
meant the same class of failure could surface as a 400 in one handler and a
500 in another.

TrustLensError makes both answers part of the exception's own contract via
abstract members, so a new error type cannot be added without deciding them.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Final

# Fallback status for an error that somehow reaches the caller without a more
# specific one. 500 is the safe default: it never implies the caller can fix
# the request by retrying with different input.
DEFAULT_ERROR_STATUS: Final[int] = 500


class TrustLensError(Exception, ABC):
    """
    Base class for every error the backend raises deliberately.

    Subclasses must declare the HTTP status the caller should receive. They
    inherit a user_message that defaults to the exception text, and may
    override it when the raw text is not safe or not useful to show.

    Attributes:
        _detail (str): The message passed at construction, kept private so
            subclasses control how (and whether) it reaches the caller.

    Abstract:
        http_status (int): Status code this error maps to. Declared abstract
            so a new error type cannot be defined without choosing one.
    """

    def __init__(self, detail: str = "") -> None:
        """
        Initialize the error and enforce the abstract contract.

        ABCMeta normally blocks instantiation of a class with unimplemented
        abstract members, but that check lives in object.__new__ and
        BaseException.__new__ does not perform it. On an Exception subclass
        @abstractmethod is therefore documentation only: __abstractmethods__
        is populated correctly and then never consulted. The check is done
        here instead so an incomplete subclass fails loudly at raise time
        rather than silently reaching a handler with no status.

        Parameters:
            detail (str): Human-readable description of what went wrong.

        Raises:
            TypeError: If the concrete subclass left an abstract member
                unimplemented.
        """
        missing = getattr(type(self), "__abstractmethods__", frozenset())
        if missing:
            raise TypeError(
                f"Cannot instantiate {type(self).__name__}: "
                f"abstract member(s) not implemented: {', '.join(sorted(missing))}"
            )
        super().__init__(detail)
        self._detail: str = detail

    @property
    def detail(self) -> str:
        """
        Get the raw detail text this error was constructed with.

        Returns:
            str: The detail string, which may be empty.
        """
        return self._detail

    @property
    @abstractmethod
    def http_status(self) -> int:
        """
        Get the HTTP status code this error should be reported as.

        Returns:
            int: A valid HTTP status code.
        """

    @property
    def user_message(self) -> str:
        """
        Get the text that is safe to show the caller.

        Defaults to the detail string. Override in a subclass when the detail
        carries internal specifics that should not leave the service.

        Returns:
            str: Caller-facing description of the failure.
        """
        return self._detail

    def __str__(self) -> str:
        """
        Return a readable representation of the error.

        Returns:
            str: The class name, the status it maps to, and its detail.
        """
        return f"{type(self).__name__}(status={self.http_status}): {self._detail}"
