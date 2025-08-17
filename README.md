<div align="center">

# Sauron

<p>
<img src="./banner.png" alt="Sauron ASCII" width="40%">
</p>

**Fast context enumeration for newly obtained Active Directory credentials**

*"One eye to bind them all"*

</div>

## Table of Contents

- [Why Sauron?](#why-sauron)
- [Key Capabilities](#key-capabilities)
- [Quick Installation](#quick-installation)
- [Usage](#usage)
  - [Basic Syntax](#basic-syntax)
  - [Command Line Options](#command-line-options)
  - [Examples](#examples)
  - [Sample Output](#sample-output)
- [Typical Post-Spray Workflow](#typical-post-spray-workflow)
- [Understanding Sauron's Output](#understanding-saurons-output)
- [Contributing](#contributing)
- [Ethical Notice](#ethical-notice)
- [License](#license)

## Why Sauron?

When you obtain fresh credentials (password spraying, phishing, hash replay, etc.), the first thing you need is context: Who is this account really? What groups (direct and nested) does it belong to? Which OUs does it live in? What descriptions reveal its function or linked applications? Sauron answers that in seconds with a single execution.

Primary objective: quickly convert an isolated credential into a mental map of potential capabilities within AD and third-party software/services that reuse corporate groups or descriptions.

## Key Capabilities

- Auto-detection of object type (user, computer, MSA/gMSA, FSP, DN, SID)
- Nested group resolution (rule `1.2.840.113556.1.4.1941`) + primary group
- Extraction of relevant ascending OUs/containers
- Reading of basic metadata (descriptions, notes, managedBy...) 
- Enumeration of GPOs linked to discovered OUs
- Debug mode with LDAP request counting
- LDAPS → secure/insecure LDAP fallback based on availability

## Quick Installation

Requirements: Python ≥ 3.8

```bash
git clone https://github.com/sikumy/sauron.git
cd sauron
pip install -r requirements.txt
python sauron.py --help
```

## Usage

### Basic Syntax

```bash
python sauron.py -d <DOMAIN> -u <USER> -p <PASSWORD> --dc <DC> -x <IDENTIFIER>
```

Accepted identifiers: sAMAccountName, computer name (with or without $), full DN, SID (FSP), MSA/gMSA name.

### Command Line Options

| Option | Description |
|--------|-------------|
| `-d / --domain` | AD domain (contoso.local) |
| `-u / --user` | Username |
| `-p / --password` | Password |
| `-dc` | Domain controller / IP |
| `-x` | Target identifier |
| `--ssl` | Force LDAPS (recommended) |
| `-s` | Enable silent mode (no banner) |
| `--debug` | Detailed logging + request counting |

### Examples

Standard user:
```bash
python sauron.py -d contoso.local -u pentester -p 'Passw0rd!' --dc dc1.contoso.local -x john.doe --ssl
```

Computer (automatically adds $ if missing):
```bash
python sauron.py -d contoso.local -u pentester -p 'Passw0rd!' --dc dc1.contoso.local -x FILESRV01$ --ssl
```

gMSA account:
```bash
python sauron.py -d contoso.local -u pentester -p 'Passw0rd!' --dc dc1.contoso.local -x sql-svc$ --debug --ssl
```

SID / Foreign Security Principal:
```bash
python sauron.py -d contoso.local -u pentester -p 'Passw0rd!' --dc dc1.contoso.local -x S-1-5-21-111111111-222222222-333333333-4444
```

### Sample Output
```
INFO: LDAP - Login successful
Object:
  sAMAccountName: j.smith
  DisplayName: John Smith
  DN: CN=John Smith,OU=Users,OU=IT,DC=contoso,DC=local
  Description: DevOps Engineer - Access to Jenkins CI/CD and AWS production
  Title: Senior DevOps Engineer
  Department: Information Technology
  adminCount: 1
  primaryGroupID: 513
  objectSid: S-1-5-21-1234567890-987654321-1122334455-1001

Groups (including nested and primary group if applicable):
  - Domain Users
      Description: All domain users
      DN: CN=Domain Users,CN=Users,DC=contoso,DC=local
  - Domain Admins
      Description: Designated administrators of the domain
      DN: CN=Domain Admins,CN=Users,DC=contoso,DC=local
  - AWS-Production-Access
      Description: Access to AWS production environments via SAML federation
      managedBy: CN=CloudOps Team,OU=Groups,OU=IT,DC=contoso,DC=local
      DN: CN=AWS-Production-Access,OU=Groups,OU=IT,DC=contoso,DC=local
  - Jenkins-Administrators
      Description: Full administrative access to Jenkins CI/CD server
      Notes (info): Grants deployment rights to all production pipelines
      DN: CN=Jenkins-Administrators,OU=ServiceGroups,OU=IT,DC=contoso,DC=local
  - VMware-vCenter-Admins
      Description: VMware vCenter full administrative privileges
      DN: CN=VMware-vCenter-Admins,OU=ServiceGroups,OU=IT,DC=contoso,DC=local

OUs/Containers (for the object and its groups, including ancestors):
  - OU=Users,OU=IT,DC=contoso,DC=local
      Name: Users
      Description: IT Department Users
      GPO Links:
        * Default Domain Policy
            Description: Default security settings for domain
            SYSVOL Path: \contoso.local\sysvol\contoso.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}
            versionNumber: 182
            DN: CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=contoso,DC=local
            gPLink flags: 0
        * IT Security Policy
            Description: Enhanced security settings for IT department
            SYSVOL Path: \contoso.local\sysvol\contoso.local\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}
            versionNumber: 45
            DN: CN={6AC1786C-016F-11D2-945F-00C04fB984F9},CN=Policies,CN=System,DC=contoso,DC=local
            gPLink flags: 0
```


## Typical Post-Spray Workflow
1. Obtain valid credentials (maybe using [SpearSpray](https://github.com/sikumy/spearspray) 😉)
2. Run Sauron against the obtained accounts (do any belong to sensitive groups?)
3. Extract implicit roles from descriptions and group names
4. Decide next steps: escalate, lateral movement, pivot to applications, report finding

## Understanding Sauron's Output

### Object Attributes
| Attribute | Meaning | Security Context |
|-----------|---------|------------------|
| `sAMAccountName` | Account login name | Primary identifier for authentication |
| `DisplayName` | Human-readable full name | Often reveals role/function when different from username |
| `DN` | Distinguished Name | Shows exact AD location and organizational structure |
| `Description` | Free-text description | **Critical**: Often contains access details, application references, or functional roles |
| `Title` | Job title | Indicates organizational privilege level |
| `Department` | Business unit | Shows scope of potential access/systems |
| `Manager` | Direct supervisor DN | Potential social engineering target or escalation path |
| `adminCount` | Protected object flag | `1` = high-privilege account (Domain Admins, etc.) |
| `primaryGroupID` | Default group RID | Usually Domain Users (513), Computers (515), or Controllers (516) |
| `objectSid` | Security Identifier | Unique ID for access control decisions |

### Group Information
| Field | Meaning | Security Context |
|-------|---------|------------------|
| `Description` | Group purpose | **Key**: May reveal third-party app access (AWS, Jenkins, VMware, etc.) |
| `Notes (info)` | Additional details | Often contains specific permissions or access scopes |
| `managedBy` | Group manager DN | Administrative contact, **not** necessarily with edit permissions |
| `DN` | Group location | Shows organizational scope (domain-wide vs. OU-specific) |

### OU/Container Information
| Field | Meaning | Security Context |
|-------|---------|------------------|
| `Name` | OU friendly name | Organizational context |
| `Description` | OU purpose | May indicate environment (prod/dev) or function |
| `GPO Links` | Applied policies | Shows inherited security settings and restrictions |
| `gPLink flags` | Policy enforcement | `0`=normal, `2`=enforced (higher priority) |

### GPO Details
| Field | Meaning | Security Context |
|-------|---------|------------------|
| `displayName` | Policy friendly name | Often indicates purpose (security, software deployment, etc.) |
| `Description` | Policy details | May reveal applied restrictions or software |
| `SYSVOL Path` | File system location | Shows policy storage and versioning |
| `versionNumber` | Policy version | Higher numbers indicate recent changes |

> **Pro Tip**: Pay special attention to `Description` fields and group names containing technology names (AWS, Jenkins, VMware, SQL, etc.) - these often indicate access to critical infrastructure or third-party applications that use AD for authentication.

## Contributing
Contributions are welcome! Feel free to open issues for bug reports, feature requests, or submit pull requests to improve the tool.

## Ethical Notice  
Use Sauron only in environments where you have explicit authorization. Misuse may be illegal.

## License
This project is licensed under the GNU General Public License v3.0 - see the LICENSE file for details.

## Author

**sikumy**

---

*Sauron - Fast Active Directory context enumeration for newly obtained credentials.*