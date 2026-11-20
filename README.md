# tiny

LDAP triage in one small command.

`tiny` reads an LDIF dump (from `ldapsearch`, `ldapdomaindump`, or anything else
that speaks LDIF) and ranks every object by criticality and usefulness. The
result is a crown-jewel pyramid: the handful of objects that give domain
takeover at the top, background noise at the bottom. It also flags quick wins
and splits the dump into per-tier and per-category files.

No dependencies. Python 3.9+.

## Install

```bash
pipx install --editable ~/Projects/tiny
```

Or run it without installing:

```bash
PYTHONPATH=src python3 -m tiny dump.ldif
```

## Usage

```bash
tiny dump.ldif                    # terminal report
tiny dump.ldif -o tiny-out/       # report + categorized files
tiny ldapdomaindump/ --all        # merge a directory of .ldif files
ldapsearch -x -b dc=corp,dc=local | tiny
tiny dump.ldif --json | jq '.objects[:5]'
tiny dump.ldif --md report.md
```

Useful flags:

| Flag | Meaning |
|------|---------|
| `-o, --out DIR` | write tier/category files, `report.md`, `tiny.json`, `README.txt` |
| `--top N` | priority rows to show, `0` = all (default 12) |
| `--all` | show every object |
| `--json` | print the JSON report instead of the terminal report |
| `--md FILE` | also write a markdown report |
| `--full` | export every attribute, not just the key ones |
| `--no-color` | disable colour |
| `--quiet` | suppress the terminal report (files are still written) |

Exit codes: `0` success, `2` no input or no parsed entries.

## Live enumeration

While `tiny` was built for offline LDIF, it now can pull data directly from a Domain Controller with `ldapsearch`.

Prerequisites: `ldapsearch` must be available on the host.

```bash
tiny --dc-ip 10.10.10.5 --domain corp.local --bind-dn user@corp.local --users --spns -o live-out/
tiny --dc-ip 10.10.10.5 --domain corp.local --bind-dn user@corp.local --unconstrained --asrep --out enum/
tiny --dc-ip 10.10.10.5 --base-dn "DC=corp,DC=local" --bind-dn "CORP\\ldap" --groups --computers
```

Enumeration flags (mirrors windapsearch options):
- `--users`  : all user objects (`objectClass=user`)
- `--groups` : all groups
- `--computers` : all computers
- `--spns`   : users with a servicePrincipalName (kerberoastable)
- `--unconstrained` : accounts with unconstrained delegation (`userAccountControl` BIT AND 524288)
- `--asrep`  : accounts with DONT_REQ_PREAUTH (`userAccountControl` BIT AND 4194304)
- `--constrained` : candidates with `msDS-AllowedToDelegateTo`
- `--rbcd`   : resource-based constrained delegation (`msDS-AllowedToActOnBehalfOfOtherIdentity`)
- `--da`     : users with nested membership in Domain Admins (`LDAP_MATCHING_RULE_IN_CHAIN`)

Credentials can be supplied with `--bind-dn` and `--bind-pass`; if the
password is omitted it will be prompted. The results are parsed as LDIF and
fed into the same scoring / pyramid / export pipeline as offline dumps.

## The pyramid

| Tier | Meaning | Typical signals |
|------|---------|-----------------|
| 0 · Crown Jewels | direct path to domain takeover | `krbtgt`, RID 500, Domain/Enterprise/Schema Admins, Administrators, Exchange Windows Permissions, unconstrained delegation, domain controllers, readable LAPS passwords, SID history |
| 1 · High Value | privilege-escalation primitives | Kerberoastable SPNs, AS-REP roastable users, constrained delegation, RBCD, shadow credentials, Backup/Server/Account/Print Operators, DnsAdmins, `adminCount=1`, credentials in descriptions |
| 2 · Medium | useful targets and context | enabled mailbox users, servers, service accounts, RDP/RM users |
| 3 · Low | background noise | disabled accounts, stale accounts, OUs, ordinary groups |

Nested group membership is resolved transitively:

```text
Carol → Helpdesk → Nested Admins → Domain Admins
       member of Domain Admins (nested) via nested admins → helpdesk
```

If the dump contains users but no group objects, `memberOf` is used as a
fallback so privileged users still surface.

## Exported files

`tiny dump.ldif -o out/` writes:

```text
tier0-crown-jewels.txt     tier1-high-value.txt
tier2-medium.txt           tier3-low.txt
users.txt                  privileged-users.txt
groups.txt                 computers.txt
service-accounts.txt       kerberoastable.txt
asrep-roastable.txt        delegation.txt
credentials.txt            disabled.txt
stale.txt                  tiny.json
report.md                  README.txt
```

Every entry in the text files carries its score, tier and reasons:

```text
# score=100 tier=0 (CROWN JEWELS) | member of Enterprise Admins (direct); Kerberoastable SPN: ...
dn: CN=Alice,OU=Users,DC=corp,DC=local
  kind: user
  name: alice
  ...
```

`tiny.json` is the machine-readable version: counts, quick wins, and every
object with its score, tier, reasons, tags and raw attributes.

## Example

`examples/demo.ldif` is a synthetic domain with nested admins, a Kerberoastable
admin, a service account with a password hint, a DC with unconstrained
delegation and a constrained web server:

```bash
tiny examples/demo.ldif
```

## Input quality tips

- **Best:** a reasonably complete LDIF from `ldapsearch ... '(objectClass=*)'` (or a full `ldapdomaindump` export) that includes `objectClass`, `userAccountControl`, SPNs, `member`/`memberof`, delegation attrs, descriptions, etc.
- **Partial/filtered exports** (e.g. only a few attributes, or missing `objectClass`) cause misclassification: objects often become `other` and key signals are missed. `tiny` will warn when more than ~30% are `other`.
- For computer-heavy filtered files, `tiny` can infer `computer` from `sAMAccountName$`, but you still lose UAC/SPN/delegation context.
- Domain is guessed from `DC=` RDNs in DNs. If the dump is odd, results still run but labels may look off.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

## Limitations

Scoring only sees attributes present in the dump. It does **not** parse
`nTSecurityDescriptor`, so ACL edges such as DCSync rights, `GenericAll`,
`WriteDACL` and GPO abuse are not scored. Privileged group detection prefers
well-known **RIDs** (from `objectSid`) when present, otherwise falls back to
name matching (so renamed/localized groups can be missed). Treat tiers as a
prioritisation aid, not proof of exploitability.

UAC flags are parsed per MS-ADTS; hex and decimal exports are both accepted.
`unconstrained delegation` is detected via `UF_TRUSTED_FOR_DELEGATION` (0x80000),
AS-REP via `UF_DONT_REQ_PREAUTH` (0x400000), protocol transition via
`UF_TRUSTED_TO_AUTH_FOR_DELEGATION` (0x1000000). Earlier releases used the
wrong bits — these are now fixed.
