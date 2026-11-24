"""Read-only HID probe workflows, identity comparison, and CLI."""

from fenrir.probe.identity import (
    IdentityVerdict,
    MouseDisconnectedError,
    evaluate_mouse_identity,
    evaluate_receiver_identity,
    format_identity_summary,
    probe_mouse_usb,
    probe_mouse_via_receiver,
    probe_receiver_local,
)

__all__ = [
    "IdentityVerdict",
    "MouseDisconnectedError",
    "evaluate_mouse_identity",
    "evaluate_receiver_identity",
    "format_identity_summary",
    "probe_mouse_usb",
    "probe_mouse_via_receiver",
    "probe_receiver_local",
]
