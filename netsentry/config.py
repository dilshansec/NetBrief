"""Validated, per-analysis settings; never a global user-editable configuration."""
import ipaddress
from pydantic import BaseModel, Field, ConfigDict, field_validator

class Settings(BaseModel):
    model_config = ConfigDict(extra='forbid')
    window_seconds: int = Field(60, ge=1, le=3600)
    scan_ports: int = Field(20, ge=3, le=10000)
    discovery_hosts: int = Field(20, ge=3, le=10000)
    syn_packets: int = Field(200, ge=10, le=50000)
    brute_connections: int = Field(20, ge=3, le=10000)
    arp_changes: int = Field(2, ge=2, le=100)
    dns_queries: int = Field(20, ge=3, le=10000)
    icmp_packets: int = Field(200, ge=10, le=50000)
    exfil_bytes: int = Field(5000000, ge=1000, le=1000000000)
    beacon_connections: int = Field(8, ge=4, le=10000)
    internal_networks: list[str] = Field(default_factory=lambda:['10.0.0.0/8','172.16.0.0/12','192.168.0.0/16','fc00::/7'], max_length=100)
    trusted_hosts: list[str] = Field(default_factory=list, max_length=100)
    authorized_scanners: list[str] = Field(default_factory=list, max_length=100)
    allowlisted_domains: list[str] = Field(default_factory=list, max_length=100)
    disabled_rules: list[str] = Field(default_factory=list, max_length=9)

    @field_validator('internal_networks')
    @classmethod
    def networks(cls, values):
        return [str(ipaddress.ip_network(v.strip(), strict=False)) for v in values]

    @field_validator('trusted_hosts','authorized_scanners')
    @classmethod
    def hosts(cls, values):
        return [str(ipaddress.ip_address(v.strip())) for v in values]

    @field_validator('allowlisted_domains')
    @classmethod
    def domains(cls, values):
        if any(not v or len(v)>253 or any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789.-' for c in v.lower()) for v in values):
            raise ValueError('Use DNS domain names only')
        return [v.lower().rstrip('.') for v in values]

    @field_validator('disabled_rules')
    @classmethod
    def rules(cls, values):
        if set(values)-{'port_scan','host_discovery','syn_flood','brute_force','arp_spoofing','dns_tunneling','icmp_flood','exfiltration','beaconing'}:
            raise ValueError('Unknown rule')
        return values
