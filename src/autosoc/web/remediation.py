"""Fail-closed generation of human-approved remediation artifacts.

This module deliberately does not consume an agent-authored playbook or command
preview. Firewall targets are derived again from deterministic SQL-injection
findings and their normalized source events. The resulting shell artifact is
comment-only and is never executed by AutoSOC.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from ipaddress import IPv4Address, IPv6Address, ip_address
import os
from pathlib import Path
import re
import stat
from threading import Lock
from uuid import UUID, uuid4

from autosoc.config import load_setting
from autosoc.models import DetectionCategory, IncidentReport


MAX_FIREWALL_TARGETS = 50
_ARTIFACT_DIRECTORY_NAME = "remediation"
_ARTIFACT_NAME = "firewall_remediation.sh"
_ARTIFACT_RELATIVE_PATH = f"{_ARTIFACT_DIRECTORY_NAME}/{_ARTIFACT_NAME}"
_ARTIFACT_LOCK = Lock()
_PROJECT_DATA_DIRECTORY = Path(__file__).resolve().parents[3] / "data"
_APPROVER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._@+:-]{0,127}$")


class RemediationError(RuntimeError):
    """Base class for safe, user-displayable remediation failures."""


class NoRemediationTargetsError(RemediationError):
    """Raised when the report has no eligible deterministic firewall target."""


class TooManyRemediationTargetsError(RemediationError):
    """Raised rather than silently truncating an approved target set."""


class UnsafeRemediationPathError(RemediationError):
    """Raised when the fixed artifact path cannot be used without following links."""


@dataclass(frozen=True, slots=True)
class GeneratedRemediation:
    """Immutable receipt facts for one generated, non-executed artifact."""

    receipt_id: UUID
    report_id: UUID
    approved_by: str
    approved_at: datetime
    targets: tuple[str, ...]
    artifact_path: str
    artifact_sha256: str
    artifact_size_bytes: int
    replaced_existing: bool


def _is_eligible_unicast(address: IPv4Address | IPv6Address) -> bool:
    """Allow actionable source ranges while rejecting non-host destinations.

    Private, carrier-grade NAT, and documentation ranges are intentionally
    eligible: enterprise incidents commonly originate inside the network, and
    the bundled portfolio sample correctly uses non-routable documentation
    addresses. The resulting artifact is still comment-only and never run.
    """

    in_ipv4_this_network = (
        isinstance(address, IPv4Address)
        and int(address) >> 24 == 0
    )
    is_deprecated_ipv6_site_local = (
        isinstance(address, IPv6Address) and address.is_site_local
    )
    return (
        not address.is_multicast
        and not address.is_unspecified
        and not address.is_loopback
        and not address.is_link_local
        and not address.is_reserved
        and not in_ipv4_this_network
        and not is_deprecated_ipv6_site_local
    )


def derive_firewall_targets(report: IncidentReport) -> tuple[str, ...]:
    """Return bounded unicast source IPs backed by deterministic SQLi findings."""

    sqli_event_ids = {
        finding.event_id
        for finding in report.findings
        if finding.analysis_method == "deterministic_rule"
        and finding.category == DetectionCategory.SQL_INJECTION
    }
    targets: dict[str, IPv4Address | IPv6Address] = {}
    for event in report.events:
        if event.event_id not in sqli_event_ids or event.source_ip is None:
            continue
        address = ip_address(str(event.source_ip))
        if _is_eligible_unicast(address):
            targets[str(address)] = address

    ordered = tuple(
        str(address)
        for address in sorted(
            targets.values(),
            key=lambda item: (item.version, int(item)),
        )
    )
    if not ordered:
        raise NoRemediationTargetsError(
            "No eligible source IP is backed by a deterministic SQL-injection finding."
        )
    if len(ordered) > MAX_FIREWALL_TARGETS:
        raise TooManyRemediationTargetsError(
            f"The report exceeds the {MAX_FIREWALL_TARGETS}-target approval limit."
        )
    return ordered


def _configured_data_directory() -> Path:
    configured = load_setting(("AUTOSOC_DATA_DIR",))
    if configured is None:
        return _PROJECT_DATA_DIRECTORY
    path = Path(configured)
    if not path.is_absolute():
        raise UnsafeRemediationPathError(
            "AUTOSOC_DATA_DIR must be an absolute directory path."
        )
    return path


def _directory_open_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def _open_artifact_directory(data_directory: Path) -> tuple[int, int]:
    """Open data/remediation through directory FDs without following symlinks."""

    remediation_fd = -1
    try:
        data_fd = os.open(data_directory, _directory_open_flags())
    except OSError as exc:
        raise UnsafeRemediationPathError(
            "The configured AutoSOC data directory is unavailable or unsafe."
        ) from exc

    try:
        data_stat = os.fstat(data_fd)
        if not stat.S_ISDIR(data_stat.st_mode):
            raise UnsafeRemediationPathError(
                "The configured AutoSOC data path is not a directory."
            )
        try:
            os.mkdir(
                _ARTIFACT_DIRECTORY_NAME,
                mode=0o700,
                dir_fd=data_fd,
            )
        except FileExistsError:
            pass
        remediation_fd = os.open(
            _ARTIFACT_DIRECTORY_NAME,
            _directory_open_flags(),
            dir_fd=data_fd,
        )
        if not stat.S_ISDIR(os.fstat(remediation_fd).st_mode):
            raise UnsafeRemediationPathError(
                "The remediation artifact path is not a safe directory."
            )
        return data_fd, remediation_fd
    except RemediationError:
        if remediation_fd >= 0:
            os.close(remediation_fd)
        os.close(data_fd)
        raise
    except OSError as exc:
        if remediation_fd >= 0:
            os.close(remediation_fd)
        os.close(data_fd)
        raise UnsafeRemediationPathError(
            "The remediation artifact directory is unavailable or unsafe."
        ) from exc


def _existing_target_is_replaceable(directory_fd: int) -> bool:
    try:
        target_stat = os.stat(
            _ARTIFACT_NAME,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return False
    if stat.S_ISLNK(target_stat.st_mode) or not stat.S_ISREG(target_stat.st_mode):
        raise UnsafeRemediationPathError(
            "The remediation artifact target is not a safe regular file."
        )
    return True


def _render_comment_only_script(
    *,
    report: IncidentReport,
    receipt_id: UUID,
    approved_by: str,
    approved_at: datetime,
    targets: tuple[str, ...],
) -> bytes:
    lines = [
        "# AutoSOC firewall remediation preview",
        "#",
        "# SAFETY: COMMENT-ONLY ARTIFACT; NOTHING HAS BEEN EXECUTED.",
        "# Review through change control before copying any command manually.",
        "# AutoSOC intentionally writes this file without executable permission.",
        f"# Report ID: {report.report_id}",
        f"# Receipt ID: {receipt_id}",
        f"# Approved by: {approved_by}",
        f"# Approved at: {approved_at.isoformat()}",
        "#",
        "# Proposed containment previews:",
    ]
    for target in targets:
        command = "iptables" if ip_address(target).version == 4 else "ip6tables"
        lines.extend(
            [
                f"# sudo {command} -I INPUT 1 -s {target} -j DROP",
                f"# rollback: sudo {command} -D INPUT -s {target} -j DROP",
            ]
        )
    lines.extend(
        [
            "#",
            "# END OF INERT PREVIEW — all command lines remain comments.",
            "",
        ]
    )
    return "\n".join(lines).encode("utf-8")


def _atomic_write_artifact(content: bytes, *, data_directory: Path) -> bool:
    """Atomically replace the fixed artifact while refusing symlink targets."""

    temporary_name = f".{_ARTIFACT_NAME}.{uuid4().hex}.tmp"
    data_fd = -1
    remediation_fd = -1
    temporary_created = False
    try:
        data_fd, remediation_fd = _open_artifact_directory(data_directory)
        replaced_existing = _existing_target_is_replaceable(remediation_fd)
        temporary_fd = os.open(
            temporary_name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=remediation_fd,
        )
        temporary_created = True
        try:
            os.fchmod(temporary_fd, 0o600)
            view = memoryview(content)
            while view:
                written = os.write(temporary_fd, view)
                if written <= 0:
                    raise OSError("short write while generating remediation")
                view = view[written:]
            os.fsync(temporary_fd)
        finally:
            os.close(temporary_fd)

        os.replace(
            temporary_name,
            _ARTIFACT_NAME,
            src_dir_fd=remediation_fd,
            dst_dir_fd=remediation_fd,
        )
        temporary_created = False
        os.fsync(remediation_fd)
        return replaced_existing
    except RemediationError:
        raise
    except OSError as exc:
        raise RemediationError(
            "The remediation artifact could not be generated safely."
        ) from exc
    finally:
        if temporary_created and remediation_fd >= 0:
            try:
                os.unlink(temporary_name, dir_fd=remediation_fd)
            except OSError:
                pass
        if remediation_fd >= 0:
            os.close(remediation_fd)
        if data_fd >= 0:
            os.close(data_fd)


def generate_firewall_remediation(
    report: IncidentReport,
    *,
    approved_by: str,
    data_directory: Path | None = None,
) -> GeneratedRemediation:
    """Generate one inert artifact and return its auditable receipt facts."""

    if _APPROVER_PATTERN.fullmatch(approved_by) is None:
        raise RemediationError("The approver identity is invalid.")
    selected_data_directory = data_directory or _configured_data_directory()
    if not selected_data_directory.is_absolute():
        raise UnsafeRemediationPathError(
            "The remediation data directory must be an absolute path."
        )
    targets = derive_firewall_targets(report)
    receipt_id = uuid4()
    approved_at = datetime.now(timezone.utc)
    content = _render_comment_only_script(
        report=report,
        receipt_id=receipt_id,
        approved_by=approved_by,
        approved_at=approved_at,
        targets=targets,
    )
    with _ARTIFACT_LOCK:
        replaced_existing = _atomic_write_artifact(
            content,
            data_directory=selected_data_directory,
        )
    return GeneratedRemediation(
        receipt_id=receipt_id,
        report_id=report.report_id,
        approved_by=approved_by,
        approved_at=approved_at,
        targets=targets,
        artifact_path=_ARTIFACT_RELATIVE_PATH,
        artifact_sha256=sha256(content).hexdigest(),
        artifact_size_bytes=len(content),
        replaced_existing=replaced_existing,
    )


__all__ = [
    "GeneratedRemediation",
    "MAX_FIREWALL_TARGETS",
    "NoRemediationTargetsError",
    "RemediationError",
    "TooManyRemediationTargetsError",
    "UnsafeRemediationPathError",
    "derive_firewall_targets",
    "generate_firewall_remediation",
]
