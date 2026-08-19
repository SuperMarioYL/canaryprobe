"""Deployment configuration for CanaryProbe.

A single ``deployment.yaml`` describes where the decoy zone lives, what the
sensors bind to, and where the audit trail is written.  Every command
(``init`` / ``watch`` / ``report``) reads the same config object so the
operator configures the tool once and the whole pipeline agrees on paths,
the decoy DNS zone, and the sensor binds.

The config is intentionally small and stdlib-parseable.  We ship a tiny
hand-rolled YAML reader/writer for the flat ``key: value`` / one-level-nested
shape we use, so the package has zero YAML dependency and works in an
air-gapped install where ``pyyaml`` may not be present.  ``deployment.yaml``
never needs anything more exotic than scalars and one level of nesting.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, ValidationError, field_validator

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

DEFAULT_CONFIG_FILENAME = "deployment.yaml"

#: The DNS zone the decoy hostnames live under.  The DNS sensor is
#: authoritative *only* for this zone; a resolve of ``<something>.<zone>`` is a
#: trip.  ``corp.local`` reads like a real internal corporate zone, which is
#: exactly the point — it should look boringly legitimate to the agent.
DEFAULT_DECOY_ZONE = "corp.local"

#: Where the DNS sensor binds.  Port 5353 keeps us off privileged port 53 so
#: the tool runs without root; the operator points the agent host's resolver
#: (or an ``/etc/hosts`` / ``resolv.conf`` entry) at this bind.
DEFAULT_DNS_BIND_HOST = "127.0.0.1"
DEFAULT_DNS_BIND_PORT = 5353

#: Where the TCP connect sensor listens for a direct connect to a decoy.
DEFAULT_CONN_BIND_HOST = "127.0.0.1"
DEFAULT_CONN_BIND_PORT = 5443

#: Files, relative to the config directory unless absolute.
DEFAULT_DECOYS_FILE = "decoys.json"
DEFAULT_MANIFEST_FILE = "decoys.manifest.json"
DEFAULT_AUDIT_FILE = "audit.jsonl"

#: A stable, per-deployment secret is used to sign the decoy manifest and,
#: later, the evidence report.  When unset in the file it is minted on first
#: ``init`` and written back, so the same deployment keeps a stable key.
SIGNING_KEY_ENV = "CANARYPROBE_SIGNING_KEY"


class SensorBind(BaseModel):
    """A host:port a sensor binds to."""

    host: str = Field(default="127.0.0.1")
    port: int = Field(default=0, ge=0, le=65535)

    @field_validator("host")
    @classmethod
    def _host_not_blank(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("sensor bind host must not be blank")
        return v

    @property
    def address(self) -> tuple[str, int]:
        return (self.host, self.port)

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"{self.host}:{self.port}"


class DeploymentConfig(BaseModel):
    """The whole deployment, loaded from / saved to ``deployment.yaml``.

    ``base_dir`` is not persisted — it is the directory the config file lives
    in and is used to resolve the (possibly relative) file paths below into
    absolute paths via the ``*_path`` properties.
    """

    decoy_zone: str = Field(default=DEFAULT_DECOY_ZONE)
    dns_sensor: SensorBind = Field(
        default_factory=lambda: SensorBind(
            host=DEFAULT_DNS_BIND_HOST, port=DEFAULT_DNS_BIND_PORT
        )
    )
    conn_sensor: SensorBind = Field(
        default_factory=lambda: SensorBind(
            host=DEFAULT_CONN_BIND_HOST, port=DEFAULT_CONN_BIND_PORT
        )
    )
    decoys_file: str = Field(default=DEFAULT_DECOYS_FILE)
    manifest_file: str = Field(default=DEFAULT_MANIFEST_FILE)
    audit_file: str = Field(default=DEFAULT_AUDIT_FILE)

    #: Populated at load time, never serialized.
    base_dir: Path = Field(default_factory=Path.cwd, exclude=True)

    @field_validator("decoy_zone")
    @classmethod
    def _zone_normalized(cls, v: str) -> str:
        v = v.strip().strip(".").lower()
        if not v or "." not in v:
            raise ValueError(
                "decoy_zone must be a dotted zone name, e.g. 'corp.local'"
            )
        return v

    # -- path resolution ----------------------------------------------------

    def _resolve(self, value: str) -> Path:
        p = Path(value).expanduser()
        if p.is_absolute():
            return p
        return (self.base_dir / p).resolve()

    @property
    def decoys_path(self) -> Path:
        return self._resolve(self.decoys_file)

    @property
    def manifest_path(self) -> Path:
        return self._resolve(self.manifest_file)

    @property
    def audit_path(self) -> Path:
        return self._resolve(self.audit_file)

    # -- signing key --------------------------------------------------------

    def signing_key(self) -> str:
        """Return the per-deployment signing key.

        Precedence: ``$CANARYPROBE_SIGNING_KEY`` (so an operator can inject a
        secret without writing it to disk) then the key persisted alongside
        the manifest.  ``ensure_signing_key`` mints and persists one when
        neither exists.
        """
        env = os.environ.get(SIGNING_KEY_ENV, "").strip()
        if env:
            return env
        return ensure_signing_key(self.base_dir)

    # -- serialization ------------------------------------------------------

    def to_yaml(self) -> str:
        data: dict[str, Any] = {
            "decoy_zone": self.decoy_zone,
            "dns_sensor": {
                "host": self.dns_sensor.host,
                "port": self.dns_sensor.port,
            },
            "conn_sensor": {
                "host": self.conn_sensor.host,
                "port": self.conn_sensor.port,
            },
            "decoys_file": self.decoys_file,
            "manifest_file": self.manifest_file,
            "audit_file": self.audit_file,
        }
        return _dump_yaml(data)

    def save(self, path: str | os.PathLike[str] | None = None) -> Path:
        target = Path(path) if path is not None else self.base_dir / DEFAULT_CONFIG_FILENAME
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(self.to_yaml(), encoding="utf-8")
        return target

    @classmethod
    def load(cls, path: str | os.PathLike[str]) -> "DeploymentConfig":
        p = Path(path).expanduser().resolve()
        data = _parse_yaml(p.read_text(encoding="utf-8"))
        return cls.from_dict(data, base_dir=p.parent)

    @classmethod
    def from_dict(
        cls, data: dict[str, Any], *, base_dir: str | os.PathLike[str] | None = None
    ) -> "DeploymentConfig":
        data = dict(data or {})
        kwargs: dict[str, Any] = {}
        if "decoy_zone" in data:
            kwargs["decoy_zone"] = data["decoy_zone"]
        if isinstance(data.get("dns_sensor"), dict):
            # Merge the operator's partial block over the per-sensor defaults so
            # an OMITTED key inherits the documented bind (port 5353), not
            # SensorBind.port's own default of 0. ``SensorBind.port`` defaults to
            # 0 (random bind) which is an opt-in the deployment's default_factory
            # lambdas override — but those lambdas don't apply to a partial dict,
            # so without this merge an operator who sets only ``host:`` silently
            # gets ``port=0``: the sensor binds a random port while the config
            # reports 0, the armed banner points the agent at port 0, and the trip
            # never fires. An explicit ``port: 0`` still wins via the merge.
            kwargs["dns_sensor"] = SensorBind(
                **{
                    "host": DEFAULT_DNS_BIND_HOST,
                    "port": DEFAULT_DNS_BIND_PORT,
                    **data["dns_sensor"],
                }
            )
        if isinstance(data.get("conn_sensor"), dict):
            kwargs["conn_sensor"] = SensorBind(
                **{
                    "host": DEFAULT_CONN_BIND_HOST,
                    "port": DEFAULT_CONN_BIND_PORT,
                    **data["conn_sensor"],
                }
            )
        for key in ("decoys_file", "manifest_file", "audit_file"):
            if key in data:
                kwargs[key] = data[key]
        if base_dir is not None:
            kwargs["base_dir"] = Path(base_dir)
        return cls(**kwargs)

    @classmethod
    def default(cls, base_dir: str | os.PathLike[str] | None = None) -> "DeploymentConfig":
        return cls(base_dir=Path(base_dir) if base_dir is not None else Path.cwd())


class DeploymentConfigCorruptError(RuntimeError):
    """Raised by :func:`load_or_default` when ``deployment.yaml`` is present
    but unparseable/invalid.

    ``deployment.yaml`` is the last runtime file the v0.5.0/v0.6.0 corrupt-input
    fail-soft had not hardened — a present-but-corrupt config (a bare scalar key
    like ``audit_file:`` the parser turns into a dict, or ``audit_file: null``
    coerced to ``None``) failed pydantic's ``str`` field and propagated a raw
    ``ValidationError`` out of every CLI command: ``watch`` crashed before the
    sensors armed (no protection), ``report``/``verify`` crashed before rendering
    evidence (denial-of-evidence). Raising a typed error lets the CLI render
    "deployment.yaml corrupt — re-init with canaryprobe init" (exit 2) instead of
    a bare traceback — mirroring :class:`canaryprobe.decoy.DecoysCorruptError`.
    """


def load_or_default(
    base_dir: str | os.PathLike[str] | None = None,
) -> DeploymentConfig:
    """Load ``deployment.yaml`` from ``base_dir`` if present, else return the
    default config anchored at ``base_dir``.

    This is the entry point the CLI uses so ``init`` works with zero prior
    config while ``watch`` / ``report`` pick up an operator's edits.  A
    present-but-corrupt ``deployment.yaml`` raises
    :class:`DeploymentConfigCorruptError` (caught by the CLI as a guided
    "re-init" error) rather than a raw ``ValidationError`` traceback.
    """

    root = Path(base_dir) if base_dir is not None else Path.cwd()
    cfg_path = root / DEFAULT_CONFIG_FILENAME
    if cfg_path.is_file():
        try:
            return DeploymentConfig.load(cfg_path)
        except (ValidationError, ValueError, OSError, TypeError) as exc:
            # ValidationError = a coerced value fails the field type (a bare
            # scalar key -> dict, or `null` -> None, failing a `str` field);
            # ValueError = the zone validator rejecting a bad zone;
            # OSError = unreadable file / bad encoding; TypeError = a
            # non-mapping shape handed to from_dict. All are the
            # present-but-corrupt state — surface a guided error, don't crash.
            import logging

            logging.getLogger(__name__).warning(
                "deployment.yaml corrupt/unparseable at %s: %s", cfg_path, exc
            )
            raise DeploymentConfigCorruptError(
                f"deployment.yaml corrupt/unparseable — re-init with "
                f"`canaryprobe init` ({cfg_path}: {exc.__class__.__name__}: {exc})"
            ) from exc
    return DeploymentConfig.default(root)


# ---------------------------------------------------------------------------
# Signing-key persistence
# ---------------------------------------------------------------------------

_SIGNING_KEY_FILENAME = ".canaryprobe.key"


def ensure_signing_key(base_dir: str | os.PathLike[str]) -> str:
    """Return the deployment signing key, minting + persisting one if absent.

    The key is a hex secret stored in ``.canaryprobe.key`` with ``0600``
    permissions.  It is deliberately *not* checked into ``decoys.json`` so the
    manifest can be shared as evidence without leaking the key.
    """

    root = Path(base_dir)
    key_path = root / _SIGNING_KEY_FILENAME
    if key_path.is_file():
        existing = key_path.read_text(encoding="utf-8").strip()
        if existing:
            return existing
    import secrets

    key = secrets.token_hex(32)
    root.mkdir(parents=True, exist_ok=True)
    # Create the key file with 0o600 at open time (not write-then-chmod) so
    # there is no window where the root-of-trust signing key is group/world
    # readable on a traversable base_dir.  write_text would create at the
    # default mode (0o666 & ~umask, typically 0o644) and only chmod would
    # tighten it afterwards — a TOCTOU window that leaks the key.
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.fchmod(fd, 0o600)  # pin the mode regardless of umask
    except OSError:  # pragma: no cover - non-POSIX best effort
        pass
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(key)
    return key


# ---------------------------------------------------------------------------
# Minimal YAML (flat + one-level nesting) — no third-party dependency
# ---------------------------------------------------------------------------


def _dump_yaml(data: dict[str, Any]) -> str:
    lines: list[str] = [
        "# CanaryProbe deployment config.",
        "# Regenerate defaults with `canaryprobe init`; edit binds/paths here.",
        "",
    ]
    for key, value in data.items():
        if isinstance(value, dict):
            lines.append(f"{key}:")
            for sub_key, sub_value in value.items():
                lines.append(f"  {sub_key}: {_scalar(sub_value)}")
        else:
            lines.append(f"{key}: {_scalar(value)}")
    return "\n".join(lines) + "\n"


def _scalar(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    text = str(value)
    if text == "" or any(c in text for c in "#:{}[],&*!|>'\"%@`") or text != text.strip():
        return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return text


def _parse_yaml(text: str) -> dict[str, Any]:
    """Parse the flat/one-level-nested subset of YAML we emit.

    Understands: comments (``#``), ``key: value`` scalars, and one level of
    two-space-indented nesting under a bare ``key:`` line.  Anything richer is
    outside the config's documented shape and is ignored rather than
    misparsed.
    """

    result: dict[str, Any] = {}
    current_parent: str | None = None
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        stripped = line.strip()
        if ":" not in stripped:
            continue
        key, _, value = stripped.partition(":")
        key = key.strip()
        value = _strip_inline_comment(value.strip())
        if indent == 0:
            if value == "":
                current_parent = key
                result[key] = {}
            else:
                current_parent = None
                result[key] = _coerce(value)
        elif current_parent is not None and isinstance(result.get(current_parent), dict):
            result[current_parent][key] = _coerce(value)
    return result


def _strip_inline_comment(value: str) -> str:
    if not value:
        return value
    if value[0] in "\"'":
        # Quoted scalar: scan to the matching closing quote (honoring
        # backslash escapes) and drop any trailing inline comment after it,
        # so 'foo: "bar" # comment' parses to "bar" rather than the literal
        # '"bar" # comment'.  Content inside the quotes is left untouched
        # because a '#' there is part of the literal value.
        quote = value[0]
        i = 1
        n = len(value)
        while i < n:
            ch = value[i]
            if ch == "\\" and i + 1 < n:
                i += 2
                continue
            if ch == quote:
                return value[: i + 1]
            i += 1
        return value  # no closing quote — leave as-is
    # An unquoted value that STARTS with '#' is comment-only — there is no
    # value before the comment (e.g. 'decoy_zone: # use default corp.local').
    # The ' #' lookup below only matches a SPACE-then-hash, so without this
    # guard the whole '# use default corp.local' is returned as the literal
    # value; for decoy_zone the validator only requires a '.', so it would
    # accept that garbage zone — minting a decoy hostname containing spaces/
    # '#' (trivially detectable as fake) and a DNS sensor zone no real query
    # can ever match, so DNS trips silently never fire. Treat it as empty so
    # the key carries no value (mirroring the v0.4.0 quoted-value inline-comment
    # fix), and let the load-level guard handle the resulting bare key.
    if value.startswith("#"):
        return ""
    hash_idx = value.find(" #")
    if hash_idx != -1:
        return value[:hash_idx].strip()
    return value


def _coerce(value: str) -> Any:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        inner = value[1:-1]
        return inner.replace('\\"', '"').replace("\\\\", "\\")
    low = value.lower()
    if low in ("true", "false"):
        return low == "true"
    if low in ("null", "~", "none", ""):
        return None
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        pass
    return value


__all__ = [
    "SensorBind",
    "DeploymentConfig",
    "DeploymentConfigCorruptError",
    "load_or_default",
    "ensure_signing_key",
    "DEFAULT_CONFIG_FILENAME",
    "DEFAULT_DECOY_ZONE",
    "SIGNING_KEY_ENV",
]
