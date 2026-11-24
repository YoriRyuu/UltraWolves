"""Phase 1 CLI, configuration schema/service, and safe macro object pool manager."""

from fenrir.config.group5 import Group5CommandError, Group5Service
from fenrir.config.macro import MacroEntry, MacroPoolFree, SafeMacroManager
from fenrir.config.schema import (
    SCHEMA_VERSION,
    MouseConfig,
    diff_configs,
    load_config,
    save_config,
    validate_config,
)
from fenrir.config.service import ApplyReport, ApplyStep, ConfigService

__all__ = [
    "ApplyReport",
    "ApplyStep",
    "ConfigService",
    "Group5CommandError",
    "Group5Service",
    "MacroEntry",
    "MacroPoolFree",
    "MouseConfig",
    "SCHEMA_VERSION",
    "SafeMacroManager",
    "diff_configs",
    "load_config",
    "save_config",
    "validate_config",
]
