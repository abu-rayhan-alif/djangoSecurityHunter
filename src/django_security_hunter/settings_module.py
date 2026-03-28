"""Dotted Django settings module names: normalize and reject unsafe values."""


class InvalidSettingsModule(ValueError):
    """Raised when a settings module string is not a safe dotted import path."""


def normalize_django_settings_module(settings: str | None) -> str | None:
    """Return a normalized module name, or None if unset/blank.

    Rejects values that could abuse ``DJANGO_SETTINGS_MODULE`` (control chars,
    path-like segments, non-ASCII) or confuse importers.
    """
    if settings is None:
        return None
    if not isinstance(settings, str):
        raise InvalidSettingsModule("Django settings module must be a string.")
    s = settings.strip()
    if not s:
        return None
    if s != settings:
        raise InvalidSettingsModule(
            "Django settings module must not have leading or trailing whitespace."
        )
    if any(c in s for c in "\n\r\x00"):
        raise InvalidSettingsModule(
            "Invalid Django settings module: control characters are not allowed."
        )
    for ch in s:
        if ch in "._":
            continue
        if ch.isascii() and ch.isalnum():
            continue
        raise InvalidSettingsModule(
            "Django settings module may only contain ASCII letters, digits, "
            "underscores, and dots."
        )
    if ".." in s:
        raise InvalidSettingsModule(
            "Django settings module must not contain empty package segments (..)."
        )
    return s
