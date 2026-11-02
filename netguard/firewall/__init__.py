"""
NetGuard Firewall Management Module
Handles Windows Defender Firewall rules for intrusion prevention.
"""
from .windows_fw import (
    RULE_PREFIX,
    check_firewall_status,
    is_protected_ip,
    block_ip,
    unblock_ip,
    list_managed_rules,
    reconcile_rules,
    expire_blocks,
    emergency_unblock_all,
    get_prevention_config,
    set_prevention_config,
)

__all__ = [
    "RULE_PREFIX",
    "check_firewall_status",
    "is_protected_ip",
    "block_ip",
    "unblock_ip",
    "list_managed_rules",
    "reconcile_rules",
    "expire_blocks",
    "emergency_unblock_all",
    "get_prevention_config",
    "set_prevention_config",
]
