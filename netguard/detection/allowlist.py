import ipaddress
from typing import Any, Dict, List, Tuple
from netguard.detection.base import Finding


class AllowList:
    def __init__(self, allowlist_config: Dict[str, Any]):
        self.src_ips = set(allowlist_config.get("src_ips", []))
        self.dst_ips = set(allowlist_config.get("dst_ips", []))
        self.pairs = set(tuple(p) for p in allowlist_config.get("pairs", []))
        self.dns_suffixes = [s.lower() for s in allowlist_config.get("dns_suffixes", [])]

        dst_cidrs_str = allowlist_config.get("dst_cidrs", [])
        self.dst_cidrs = []
        for cidr in dst_cidrs_str:
            try:
                self.dst_cidrs.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                continue

        self.suppression_counts: Dict[str, int] = {
            "src_ip": 0,
            "dst_ip": 0,
            "dst_cidr": 0,
            "pair": 0,
            "dns_suffix": 0,
        }

    def is_allowed(self, finding: Finding) -> Tuple[bool, str]:
        """
        Check if a finding matches any allowlist rule.
        Returns (is_allowed, reason). If True, the finding should be suppressed.
        """
        # Check source IP
        if finding.src_ip in self.src_ips:
            self.suppression_counts["src_ip"] += 1
            return True, "src_ip"

        # Check destination IP
        if finding.dst_ip and finding.dst_ip in self.dst_ips:
            self.suppression_counts["dst_ip"] += 1
            return True, "dst_ip"

        # Check pair
        if finding.dst_ip and (finding.src_ip, finding.dst_ip) in self.pairs:
            self.suppression_counts["pair"] += 1
            return True, "pair"

        # Check destination CIDR
        if finding.dst_ip:
            try:
                dst_obj = ipaddress.ip_address(finding.dst_ip)
                if any(dst_obj in net for net in self.dst_cidrs):
                    self.suppression_counts["dst_cidr"] += 1
                    return True, "dst_cidr"
            except ValueError:
                pass

        return False, ""

    def filter_findings(self, findings: List[Finding]) -> List[Finding]:
        """
        Filter out suppressed findings matching allowlist rules.
        """
        retained = []
        for f in findings:
            allowed, _ = self.is_allowed(f)
            if not allowed:
                retained.append(f)
        return retained
