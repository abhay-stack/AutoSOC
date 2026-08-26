"""Small, non-interpolating configuration helpers for local secrets."""

from __future__ import annotations

from collections.abc import Iterable
import os
from pathlib import Path
import re


_DOTENV_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def clean_setting(value: str | None) -> str | None:
    """Return a stripped one-line value, or ``None`` when it is unusable."""

    if value is None:
        return None
    cleaned = value.strip()
    if not cleaned or "\r" in cleaned or "\n" in cleaned:
        return None
    return cleaned


def read_dotenv(path: str | Path) -> dict[str, str]:
    """Read literal ``KEY=VALUE`` pairs without expansion or code execution."""

    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except (FileNotFoundError, IsADirectoryError, PermissionError, OSError):
        return {}

    values: dict[str, str] = {}
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        key, separator, raw_value = line.partition("=")
        key = key.strip()
        if not separator or _DOTENV_KEY.fullmatch(key) is None:
            continue

        value = raw_value.strip()
        if value.startswith(("'", '"')):
            quote = value[0]
            closing_quote = value.find(quote, 1)
            if closing_quote == -1:
                continue
            remainder = value[closing_quote + 1 :].strip()
            if remainder and not remainder.startswith("#"):
                continue
            value = value[1:closing_quote]
        else:
            value = re.split(r"\s+#", value, maxsplit=1)[0].strip()
        values[key] = value
    return values


def load_setting(
    names: Iterable[str],
    *,
    env_file: str | Path = ".env",
) -> str | None:
    """Load the first setting, with process environment taking precedence."""

    ordered_names = tuple(names)
    for name in ordered_names:
        value = clean_setting(os.environ.get(name))
        if value is not None:
            return value

    dotenv_values = read_dotenv(env_file)
    for name in ordered_names:
        value = clean_setting(dotenv_values.get(name))
        if value is not None:
            return value
    return None


__all__ = ["clean_setting", "load_setting", "read_dotenv"]
