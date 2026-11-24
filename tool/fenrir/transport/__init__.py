"""HID transport abstractions, Windows hidapi wrapper, capture logger, and offline mocks."""

from fenrir.transport.base import (
    DeviceClassification,
    FeatureTransport,
    HidDeviceInfo,
    classify_hid_device,
    prioritize_feature_devices,
)
from fenrir.transport.capture import CaptureLogger
from fenrir.transport.hid_win import GuardedHidSession, HidApiTransport
from fenrir.transport.mock import MockFeatureTransport, UnicornMockTransport

__all__ = [
    "CaptureLogger",
    "DeviceClassification",
    "FeatureTransport",
    "GuardedHidSession",
    "HidApiTransport",
    "HidDeviceInfo",
    "MockFeatureTransport",
    "UnicornMockTransport",
    "classify_hid_device",
    "prioritize_feature_devices",
]
