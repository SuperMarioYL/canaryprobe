"""CanaryProbe — a honeytoken tripwire for a coding-agent binary you can't read.

Plant decoy hostnames and fake credentials in the reachable environment of a
closed-source coding agent, then alarm — with an audit trail — the instant that
binary resolves or connects one of them.

Public entry point is the CLI (``canaryprobe init | watch | plant | report``);
see :mod:`canaryprobe.cli`.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
