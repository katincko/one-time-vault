"""One-time secret vault."""

from one_time_vault.storage import (
    MAX_ATTEMPTS,
    NotFound,
    OpenResult,
    PasswordRequired,
    Revealed,
    SecretStorage,
    WrongPassword,
)

__all__ = [
    "MAX_ATTEMPTS",
    "NotFound",
    "OpenResult",
    "PasswordRequired",
    "Revealed",
    "SecretStorage",
    "WrongPassword",
]
