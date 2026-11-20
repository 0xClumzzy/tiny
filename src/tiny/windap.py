"""LDAP enumeration filters and query builders.

This module provides the LDAP filter strings and default attribute list used to perform live queries against a Domain Controller and feed the
results into the existing scoring pipeline.
"""

from __future__ import annotations

from typing import List, Tuple

# Default attributes used by windapsearch for each enumeration type.
USER_ATTRS = [
    "cn", "name", "samAccountName", "userPrincipalName",
    "description", "userAccountControl", "pwdLastSet", "lastLogon",
    "lastLogonTimestamp", "servicePrincipalName",
    "msDS-AllowedToDelegateTo", "msDS-AllowedToActOnBehalfOfOtherIdentity",
    "objectSid", "sIDHistory", "adminCount", "memberOf", "objectClass",
]

COMPUTER_ATTRS = [
    "cn", "name", "samAccountName", "dNSHostName",
    "operatingSystem", "operatingSystemVersion", "operatingSystemServicePack",
    "userAccountControl", "msDS-AllowedToDelegateTo",
    "msDS-AllowedToActOnBehalfOfOtherIdentity", "objectClass",
]

GROUP_ATTRS = [
    "cn", "name", "member", "memberOf", "objectClass", "sAMAccountName",
]

# LDAP filter constants – mirrors windapsearch.py
FILTER_USERS = "(objectClass=user)"
FILTER_GROUPS = "(objectClass=group)"
FILTER_COMPUTERS = "(objectClass=computer)"

# Kerberoastable users: users with an SPN
FILTER_USER_SPN = "(&(objectClass=user)(servicePrincipalName=*))"

# Unconstrained delegation: userAccountControl bitwise AND 0x80000 (TRUSTED_FOR_DELEGATION)
# LDAP_MATCHING_RULE_BIT_AND OID: 1.2.840.113556.1.4.803
FILTER_UNCONSTRAINED = "(&(objectClass=*)(userAccountControl:1.2.840.113556.1.4.803:=524288))"

# AS-REP roastable: DONT_REQ_PREAUTH 0x400000
FILTER_ASREP = "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"

# Constrained delegation candidate: msDS-AllowedToDelegateTo present
FILTER_CONSTRAINED = "(&(objectClass=*)(msDS-AllowedToDelegateTo=*))"

# Resource-based constrained delegation: msDS-AllowedToActOnBehalfOfOtherIdentity present
FILTER_RBCD = "(&(objectClass=*)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))"

# Privileged users via nested membership – Domain Admins
# LDAP_MATCHING_RULE_IN_CHAIN OID: 1.2.840.113556.1.4.1941
def filter_privileged_via_chain(priv_group_dn: str) -> str:
    return f"(&(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:={priv_group_dn}))"


def domain_to_base_dn(domain: str) -> str:
    parts = [p.strip() for p in domain.split(".") if p.strip()]
    return ",".join(f"DC={p}" for p in parts)


def build_ldapsearch_cmd(
    dc_ip: str,
    bind_dn: str | None,
    bind_pass: str | None,
    base_dn: str,
    ldap_filter: str,
    attrs: List[str] | None = None,
) -> List[str]:
    """Return an ldapsearch command list.

    Uses the system ldapsearch binary. Mirrors the behaviour of
    windapsearch.py for each enumeration option.
    """
    cmd = [
        "ldapsearch",
        "-H", f"ldap://{dc_ip}:389",
        "-x",
        "-b", base_dn,
        "-s", "sub",
        "-LLL",
    ]
    if bind_dn:
        cmd += ["-D", bind_dn]
    if bind_pass:
        cmd += ["-w", bind_pass]
    if attrs:
        cmd += attrs
    cmd.append(ldap_filter)
    return cmd


def enumerate_query(
    dc_ip: str,
    bind_dn: str | None,
    bind_pass: str | None,
    base_dn: str,
    ldap_filter: str,
    attrs: List[str] | None = None,
) -> str:
    """Execute ldapsearch and return LDIF text.

    This is a thin wrapper around subprocess. Raises RuntimeError on failure.
    """
    import subprocess

    cmd = build_ldapsearch_cmd(dc_ip, bind_dn, bind_pass, base_dn, ldap_filter, attrs)

    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"ldapsearch failed: {result.stderr}")
    return result.stdout
