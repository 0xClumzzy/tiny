"""Object classification and criticality scoring."""

import datetime
import re
import struct
from collections import deque
from dataclasses import dataclass, field
from typing import Optional

from .ldif import Entry

# group name (lowercase) -> (tier, weight, display name)
PRIVILEGED_GROUPS = {
    "domain admins": (0, 90, "Domain Admins"),
    "enterprise admins": (0, 92, "Enterprise Admins"),
    "schema admins": (0, 88, "Schema Admins"),
    "administrators": (0, 90, "Administrators"),
    "exchange windows permissions": (0, 85, "Exchange Windows Permissions (WriteDACL → DCSync)"),
    "account operators": (1, 55, "Account Operators"),
    "server operators": (1, 55, "Server Operators"),
    "backup operators": (1, 55, "Backup Operators"),
    "print operators": (1, 50, "Print Operators"),
    "dnsadmins": (1, 60, "DnsAdmins (DLL injection into DNS service)"),
    "group policy creator owners": (1, 50, "Group Policy Creator Owners"),
    "key admins": (1, 50, "Key Admins"),
    "enterprise key admins": (1, 55, "Enterprise Key Admins"),
    "exchange trusted subsystem": (1, 50, "Exchange Trusted Subsystem"),
    "remote desktop users": (2, 30, "Remote Desktop Users"),
    "remote management users": (2, 25, "Remote Management Users"),
}

PRIVILEGED_RIDS = {
    512: (0, 90, "Domain Admins"),
    516: (0, 80, "Domain Controllers"),
    517: (1, 70, "Cert Publishers"),
    518: (0, 88, "Schema Admins"),
    519: (0, 92, "Enterprise Admins"),
    520: (0, 85, "Group Policy Creator Owners"),
    521: (1, 50, "Read-only Domain Controllers"),
    522: (1, 60, "Cloneable Domain Controllers"),
    526: (1, 60, "Key Admins"),
    527: (1, 55, "Enterprise Key Admins"),
    544: (0, 90, "Administrators"),
    548: (1, 55, "Account Operators"),
    549: (1, 55, "Server Operators"),
    550: (1, 50, "Print Operators"),
    551: (1, 55, "Backup Operators"),
    553: (2, 30, "Remote Desktop Users"),
}

BASE_SCORES = {"user": 10, "computer": 15, "group": 8, "gpo": 12, "ou": 4, "other": 3}

SERVICE_NAME_RE = re.compile(
    r"^(svc|service|sql|sa[_-]|backup|bkp|admin|app|web|ftp|iis|sccm|veeam|nas)[-_]",
    re.I,
)
SECRET_RE = re.compile(r"\b(pass(word|wd)?|pwd|cred(s|ential)?)\b", re.I)

LAPS_ATTRS = {"ms-mcs-admpwd", "mslaps-password", "mslaps-encryptedpassword"}
CLEARTEXT_ATTRS = {"userpassword", "unixuserpassword"}

# userAccountControl bits (MS-ADTS 2.2.16.1.1 ufAccountControl)
UF_SCRIPT = 0x0001
UF_ACCOUNTDISABLE = 0x0002
UF_HOMEDIR_REQUIRED = 0x0004
UF_LOCKOUT = 0x0008
UF_PASSWD_NOTREQD = 0x0010
UF_PASSWD_CANT_CHANGE = 0x0020
UF_ENCRYPTED_TEXT_PASSWORD = 0x0040
UF_TEMP_DUPLICATE_ACCOUNT = 0x0080
UF_NORMAL_ACCOUNT = 0x0200
UF_INTERDOMAIN_TRUST_ACCOUNT = 0x0800
UF_WORKSTATION_TRUST_ACCOUNT = 0x1000
UF_SERVER_TRUST_ACCOUNT = 0x2000
UF_DONT_EXPIRE_PASSWD = 0x10000
UF_MNS_LOGON_ACCOUNT = 0x20000
UF_SMART_CARD_REQUIRED = 0x40000
UF_TRUSTED_FOR_DELEGATION = 0x80000
UF_DONT_REQ_PREAUTH = 0x400000
UF_PASSWORD_EXPIRED = 0x800000
UF_TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000
UF_PARTIAL_SECRETS_ACCOUNT = 0x04000000

UAC_FLAGS = {
    UF_SCRIPT: "SCRIPT",
    UF_ACCOUNTDISABLE: "ACCOUNTDISABLE",
    UF_HOMEDIR_REQUIRED: "HOMEDIR_REQUIRED",
    UF_LOCKOUT: "LOCKOUT",
    UF_PASSWD_NOTREQD: "PASSWD_NOTREQD",
    UF_PASSWD_CANT_CHANGE: "PASSWD_CANT_CHANGE",
    UF_ENCRYPTED_TEXT_PASSWORD: "ENCRYPTED_TEXT_PWD_ALLOWED",
    UF_TEMP_DUPLICATE_ACCOUNT: "TEMP_DUPLICATE_ACCOUNT",
    UF_NORMAL_ACCOUNT: "NORMAL_ACCOUNT",
    UF_INTERDOMAIN_TRUST_ACCOUNT: "INTERDOMAIN_TRUST_ACCOUNT",
    UF_WORKSTATION_TRUST_ACCOUNT: "WORKSTATION_TRUST_ACCOUNT",
    UF_SERVER_TRUST_ACCOUNT: "SERVER_TRUST_ACCOUNT",
    UF_DONT_EXPIRE_PASSWD: "DONT_EXPIRE_PASSWORD",
    UF_MNS_LOGON_ACCOUNT: "MNS_LOGON_ACCOUNT",
    UF_SMART_CARD_REQUIRED: "SMARTCARD_REQUIRED",
    UF_TRUSTED_FOR_DELEGATION: "TRUSTED_FOR_DELEGATION",
    UF_DONT_REQ_PREAUTH: "DONT_REQ_PREAUTH",
    UF_PASSWORD_EXPIRED: "PASSWORD_EXPIRED",
    UF_TRUSTED_TO_AUTH_FOR_DELEGATION: "TRUSTED_TO_AUTH_FOR_DELEGATION",
    UF_PARTIAL_SECRETS_ACCOUNT: "PARTIAL_SECRETS_ACCOUNT",
}


@dataclass
class Membership:
    """A direct or nested membership in a privileged group."""

    group: str
    tier: int
    score: int
    direct: bool
    path: list[str] = field(default_factory=list)


@dataclass
class Obj:
    """An LDAP entry with a criticality score."""

    entry: Entry
    kind: str
    name: str
    score: int
    tier: int
    reasons: list[str] = field(default_factory=list)
    tags: set[str] = field(default_factory=set)
    memberships: list[Membership] = field(default_factory=list)


def norm_dn(dn: str) -> str:
    """Normalize a DN for comparison (case- and spacing-insensitive)."""
    return re.sub(r"\s+", "", dn or "").lower()


def get_kind(entry: Entry) -> str:
    ocs = {oc.lower() for oc in entry.all("objectclass")}
    if "group" in ocs or "groupofnames" in ocs or "groupofuniquenames" in ocs:
        return "group"
    if "computer" in ocs:
        return "computer"
    if "user" in ocs or "person" in ocs or "organizationalperson" in ocs:
        return "user"
    if "organizationalunit" in ocs:
        return "ou"
    if "grouppolicycontainer" in ocs:
        return "gpo"
    # Inference for partial exports (no objectClass)
    sam = (entry.get("samaccountname") or "").lower()
    if sam.endswith("$"):
        return "computer"
    if entry.all("member") or entry.all("uniquemember"):
        return "group"
    if entry.get("useraccountcontrol") is not None or entry.all("serviceprincipalname"):
        return "user"
    if (entry.get("msds-allowedtoactonbehalfofotheridentity") or entry.all(
        "msds-allowedtodelegateto"
    )) and sam.endswith("$"):
        return "computer"
    dn_lower = (entry.dn or "").lower()
    if "ou=domain controllers" in dn_lower or "cn=domain controllers" in dn_lower:
        return "computer"
    return "other"


def display_name(entry: Entry) -> str:
    return entry.get("samaccountname") or entry.get("cn") or entry.get("name") or entry.dn


def get_uac(entry: Entry) -> Optional[int]:
    """userAccountControl as an int; accepts decimal or 0x-hex exports."""
    return parse_int(entry.get("useraccountcontrol"))


def parse_int(value: Optional[str]) -> Optional[int]:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        return int(text, 0)
    except ValueError:
        try:
            return int(text, 16)
        except ValueError:
            return None


def get_int(entry: Entry, attr: str) -> Optional[int]:
    return parse_int(entry.get(attr))


def get_sid_bytes(entry: Entry) -> Optional[bytes]:
    val = entry.get("objectsid")
    if not val:
        return None
    # stored as latin1-encoded bytes from :: base64
    try:
        return val.encode("latin1")
    except Exception:
        return None


def get_rid(entry: Entry) -> Optional[int]:
    sid = get_sid_bytes(entry)
    if not sid or len(sid) < 8:
        return None
    try:
        sub_auth_count = sid[1]
        if len(sid) < 8 + 4 * sub_auth_count:
            return None
        rid_offset = 8 + 4 * (sub_auth_count - 1)
        return struct.unpack("<I", sid[rid_offset : rid_offset + 4])[0]
    except Exception:
        return None


def uac_flags(value: Optional[int]) -> list[str]:
    if value is None:
        return []
    return [name for bit, name in UAC_FLAGS.items() if value & bit]


def filetime_age_days(value: Optional[str]) -> Optional[int]:
    """Age in days of a Windows FILETIME value, or None when unusable."""
    try:
        filetime = int(value or "")
    except (TypeError, ValueError):
        return None
    if filetime <= 0 or filetime < 116444736000000000:
        return None
    created = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=filetime // 10)
    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    return (now - created).days


def build_memberships(entries: list[Entry]) -> dict[str, list[Membership]]:
    """Resolve direct and nested membership in privileged groups."""
    children: dict[str, list[str]] = {}
    labels: dict[str, str] = {}
    privileged: dict[str, list[str]] = {}

    for entry in entries:
        if get_kind(entry) != "group":
            continue
        gdn = norm_dn(entry.dn)
        label = (entry.get("samaccountname") or entry.get("cn") or entry.get("name") or "").lower()
        labels[gdn] = entry.get("cn") or entry.get("name") or entry.get("samaccountname") or label
        members = [norm_dn(m) for m in entry.all("member") + entry.all("uniquemember")]
        if members:
            children[gdn] = members
        if label in PRIVILEGED_GROUPS:
            privileged.setdefault(label, []).append(gdn)

    memberships: dict[str, list[Membership]] = {}
    for label, dns in privileged.items():
        tier, weight, pretty = PRIVILEGED_GROUPS[label]
        for gdn in dns:
            direct = set(children.get(gdn, []))
            seen = {gdn}
            queue = deque((member, []) for member in direct)
            found: dict[str, Membership] = {}
            while queue:
                member, path = queue.popleft()
                if member in seen:
                    continue
                seen.add(member)
                found.setdefault(
                    member,
                    Membership(
                        group=pretty,
                        tier=tier,
                        score=weight,
                        direct=member in direct,
                        path=[labels.get(p, p) for p in path],
                    ),
                )
                for child in children.get(member, []):
                    queue.append((child, path + [member]))
            for member, info in found.items():
                bucket = memberships.setdefault(member, [])
                if not any(existing.group == info.group for existing in bucket):
                    bucket.append(info)

    for bucket in memberships.values():
        bucket.sort(key=lambda m: (-m.score, m.group))
    return memberships


def score_entries(entries: list[Entry]) -> list[Obj]:
    """Score every entry and assign it to a pyramid tier."""
    memberships = build_memberships(entries)
    objects: list[Obj] = []

    for entry in entries:
        kind = get_kind(entry)
        name = display_name(entry)
        score = BASE_SCORES.get(kind, 3)
        reasons: list[str] = []
        tags: set[str] = set()
        uac = get_uac(entry)
        sam = (entry.get("samaccountname") or "").lower()
        label = sam or (entry.get("cn") or "").lower()
        sid = entry.get("objectsid") or ""
        spns = entry.all("serviceprincipalname")
        ocs = {oc.lower() for oc in entry.all("objectclass")}

        def add(points: int, reason: str, *new_tags: str) -> None:
            nonlocal score
            score += points
            reasons.append(reason)
            tags.update(new_tags)

        # Crown-jewel identities
        rid = get_rid(entry)
        if sam == "krbtgt" or rid == 502:
            score = max(score, 100)
            reasons.append("krbtgt — Golden Ticket material")
            tags.add("crown")
        if (sid.endswith("-500") or rid == 500) and kind == "user":
            score = max(score, 95)
            reasons.append("RID 500 — built-in Administrator")
            tags.add("crown")

        # Privileged group membership (direct / nested)
        member_of = memberships.get(norm_dn(entry.dn), [])
        found_memberships: list[Membership] = list(member_of)
        if member_of:
            best = member_of[0]
            add(
                best.score if best.direct else max(best.score - 10, 20),
                f"member of {best.group}"
                f"{' (direct)' if best.direct else ' (nested)'}"
                + (f" via {' → '.join(best.path)}" if best.path else ""),
                "privileged",
            )
            for extra in member_of[1:3]:
                reasons.append(f"also member of {extra.group}")
            if best.tier == 0:
                tags.add("crown")

        # Fallback for user-only dumps
        seen_groups = {m.group for m in member_of}
        for modn in entry.all("memberof"):
            match = re.match(r"^\s*CN=([^,]+)", modn, re.IGNORECASE)
            if not match:
                continue
            group_name = match.group(1).strip().lower()
            if group_name not in PRIVILEGED_GROUPS:
                continue
            gtier, gweight, gpretty = PRIVILEGED_GROUPS[group_name]
            if gpretty in seen_groups:
                continue
            add(gweight, f"memberOf {gpretty}", "privileged")
            found_memberships.append(
                Membership(group=gpretty, tier=gtier, score=gweight, direct=True)
            )
            if gtier == 0:
                tags.add("crown")
            seen_groups.add(gpretty)

        # Privileged groups themselves
        if kind == "group" and label in PRIVILEGED_GROUPS:
            gtier, gweight, gpretty = PRIVILEGED_GROUPS[label]
            score = max(score, gweight)
            reasons.append(f"privileged group: {gpretty}")
            tags.add("privileged")
            if gtier == 0:
                tags.add("crown")

        # Credentials present in the dump
        for attr in LAPS_ATTRS:
            if entry.all(attr):
                score = max(score, 100)
                reasons.append(f"readable LAPS password ({attr})")
                tags.update({"creds", "crown", "laps"})
                break
        for attr in CLEARTEXT_ATTRS:
            if entry.all(attr):
                score = max(score, 95)
                reasons.append(f"cleartext password attribute ({attr})")
                tags.update({"creds", "cleartext"})
                break
        secrets = " ".join(entry.all("description") + entry.all("info") + entry.all("comment"))
        if secrets and SECRET_RE.search(secrets):
            add(50, "credential-like text in description/comment", "creds")
        if entry.all("msds-keycredentiallink"):
            add(60, "shadow credentials (msDS-KeyCredentialLink)", "shadowcreds")
        if entry.all("msds-allowedtoactonbehalfofotheridentity"):
            add(70, "resource-based constrained delegation (RBCD)", "rbcd", "delegation")

        # Delegation
        if uac is not None and uac & UF_TRUSTED_FOR_DELEGATION:
            add(
                80 if kind == "computer" else 75,
                "unconstrained delegation (TRUSTED_FOR_DELEGATION) — "
                "coerce a DC and capture its TGT",
                "unconstrained",
                "delegation",
                "crown",
            )
        if entry.all("msds-allowedtodelegateto"):
            targets = ", ".join(entry.all("msds-allowedtodelegateto")[:3])
            if uac is not None and uac & UF_TRUSTED_TO_AUTH_FOR_DELEGATION:
                add(50, "constrained delegation to: " + targets, "constrained", "delegation")
            else:
                add(
                    40,
                    "msDS-AllowedToDelegateTo present (candidate "
                    "constrained delegation): "
                    + targets
                    + " — verify TRUSTED_TO_AUTH_FOR_DELEGATION",
                    "constrained",
                    "delegation",
                )
        if uac is not None and uac & UF_TRUSTED_TO_AUTH_FOR_DELEGATION:
            add(
                10,
                "protocol transition enabled (TRUSTED_TO_AUTH_FOR_DELEGATION)",
                "protocol-transition",
                "delegation",
            )

        # AD CS certificate templates
        if "pkicertificatetemplate" in ocs or entry.get("mspki-certificate-name-flag") is not None:
            name_flag = get_int(entry, "mspki-certificate-name-flag") or 0
            enroll_flag = get_int(entry, "mspki-enrollment-flag") or 0
            ekus = {
                eku.lower()
                for eku in entry.all("pkiextendedkeyusage")
                + entry.all("mspki-certificate-application-policy")
            }
            client_auth = bool(ekus & {"1.3.6.1.5.5.7.3.2", "1.3.6.1.4.1.311.20.2.2"})
            any_eku = "2.5.29.37.0" in ekus
            supplies_subject = bool(name_flag & 0x1)
            needs_approval = bool(enroll_flag & 0x2)
            tags.add("adcs")
            if supplies_subject and (client_auth or any_eku) and not needs_approval:
                add(
                    70,
                    "ADCS ESC1 candidate: enrollee-supplied subject + client-auth EKU",
                    "adcs-esc1",
                )
            elif any_eku and not needs_approval:
                add(55, "ADCS ESC2 candidate: any-purpose EKU", "adcs-esc2")
            if "1.3.6.1.4.1.311.20.2.1" in ekus:
                add(40, "ADCS ESC3 candidate: certificate request agent EKU", "adcs-esc3")
            if enroll_flag & 0x10000 and (client_auth or any_eku):
                add(35, "ADCS ESC9 candidate: no security extension + client auth", "adcs-esc9")

        # Roasting and credential primitives
        if uac is not None and uac & UF_DONT_REQ_PREAUTH and kind == "user":
            add(55, "AS-REP roastable (DONT_REQ_PREAUTH — pre-auth disabled)", "asrep")
        if spns and kind == "user" and sam != "krbtgt":
            add(45, "Kerberoastable SPN: " + ", ".join(spns[:3]), "kerberoastable", "service")
        if entry.all("sidhistory"):
            add(55, "SID history present (privilege injection / persistence)", "sidhistory")
        if (entry.get("pwdlastset") or "") == "0" and kind == "user":
            add(35, "pwdLastSet=0 — password must change (possible default cred)")
        if uac is not None and uac & UF_DONT_EXPIRE_PASSWD and kind == "user":
            add(12, "password never expires")
        if uac is not None and uac & UF_PASSWD_NOTREQD and kind == "user":
            add(10, "PASSWD_NOTREQD — password not required")
        if kind == "user" and uac is not None and not uac & UF_ACCOUNTDISABLE:
            if entry.get("mail"):
                add(10, "enabled mailbox — phishing target")
            if entry.get("userprincipalname"):
                score += 5
        if entry.all("altsecurityidentities"):
            add(20, "explicit certificate mapping (altSecurityIdentities)")
        if (entry.get("admincount") or "") == "1":
            add(45, "adminCount=1 — protected by AdminSDHolder", "privileged")

        # Service accounts
        if kind == "user" and SERVICE_NAME_RE.match(sam):
            add(15, "service account naming pattern", "service")
        if "msds-groupmanagedserviceaccount" in ocs:
            add(15, "group managed service account (gMSA)", "gmsa", "service")

        # Domain controllers and servers
        dn_lower = entry.dn.lower()
        is_dc = "ou=domain controllers" in dn_lower or entry.get("primarygroupid") == "516"
        if kind == "computer" and is_dc:
            add(55, "Domain Controller", "dc", "privileged")
        elif kind == "computer" and "ou=servers" in dn_lower:
            add(10, "server")

        # Negative signals
        if uac is not None and uac & UF_ACCOUNTDISABLE:
            add(-30, "account disabled", "disabled")
        pwd_age = filetime_age_days(entry.get("pwdlastset"))
        if pwd_age is not None and pwd_age > 365:
            add(-10, f"password unchanged for {pwd_age} days", "stale")
        logon_age = filetime_age_days(entry.get("lastlogon") or entry.get("lastlogontimestamp"))
        if logon_age is not None and logon_age > 180:
            add(-8, f"no logon for {logon_age} days", "stale")

        score = max(0, min(100, score))
        tier = 0 if score >= 80 else 1 if score >= 50 else 2 if score >= 20 else 3
        if kind == "group" and label in PRIVILEGED_GROUPS:
            tier = min(tier, PRIVILEGED_GROUPS[label][0])
        if not reasons:
            reasons.append("no escalation signals")

        objects.append(
            Obj(
                entry=entry,
                kind=kind,
                name=name,
                score=score,
                tier=tier,
                reasons=reasons,
                tags=tags,
                memberships=found_memberships,
            )
        )

    objects.sort(key=lambda o: (-o.score, o.kind, o.name.lower()))
    return objects
