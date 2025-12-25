# CloudRaider MSSP Service Principal Setup

Deploy secure service principals for CloudRaider managed security services.

## Three-Tier Model

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  CLOUDRAIDER SERVICE PRINCIPAL ARCHITECTURE                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  CloudRaider-SOC (Required for all customers)                              │
│  └── Continuous monitoring, alert detection, security posture assessment   │
│      Risk: LOW | Permissions: Read-heavy                                    │
│                                                                             │
│  CloudRaider-IR (Break-glass incident response)                            │
│  └── Block accounts, revoke tokens, isolate endpoints during attacks       │
│      Risk: HIGH | Permissions: Full write for IR actions                   │
│                                                                             │
│  CloudRaider-Admin (Managed services only)                                 │
│  └── User provisioning, license management, device enrollment              │
│      Risk: MEDIUM | Permissions: Admin tasks                               │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Quick Start

### SOC Customers (Monitoring Only)
```powershell
# Creates CloudRaider-SOC + CloudRaider-IR
.\Setup-CloudRaider-ServicePrincipal.ps1 -CustomerName "Your Company"
```

### Fully Managed Customers
```powershell
# Creates all three service principals
.\Setup-CloudRaider-ServicePrincipal.ps1 -CustomerName "Your Company" -SPType All
```

### Just Incident Response Capability
```powershell
# Creates only CloudRaider-IR
.\Setup-CloudRaider-ServicePrincipal.ps1 -CustomerName "Your Company" -SPType IR
```

## Requirements

- **PowerShell 7+** ([Download](https://aka.ms/powershell))
- **Global Administrator** role in your Azure AD tenant
- **Internet connection**

## Security Protections

### What the Script Does

1. **Creates app registrations** with minimum required permissions
2. **Grants admin consent** programmatically (no portal popups)
3. **Generates time-limited secrets** (2-year expiration)
4. **Auto-detects and repairs** if run again (idempotent)

### What YOU Should Do After Setup

#### 1. Restrict Service Principal IPs (CRITICAL)

Create a Conditional Access policy to limit SP access to CloudRaider IPs:

```
Name: "Restrict CloudRaider-IR to CloudRaider IPs"
Users: Select the CloudRaider-IR service principal
Conditions:
  - Locations: All locations EXCEPT CloudRaider trusted IPs
Grant: Block access
```

CloudRaider will provide their static IP ranges for this configuration.

#### 2. Enable Sign-in Logging

Ensure these logs are retained:
- **Azure AD Sign-in logs** (at least 30 days)
- **Audit logs** (at least 90 days)
- **Forward to your SIEM** if possible

All CloudRaider SP actions are logged in your tenant.

#### 3. Set Up Alerting

Create alerts for unusual SP activity:
- Sign-ins from unexpected locations
- Failed authentication attempts
- Permission changes

#### 4. Regular Access Reviews

- **Quarterly**: Review SP permissions with CloudRaider
- **Annually**: Rotate secrets (or sooner if compromised)
- **On termination**: Run uninstall script

### Secret Management

```
⚠️  CRITICAL: Secrets are shown ONCE during setup.
    They cannot be retrieved later.

    If you lose a secret, simply re-run the script.
    It will detect the existing SP and generate a new secret.
```

## Uninstall / Revoke Access

### Complete Removal
```powershell
.\Setup-CloudRaider-ServicePrincipal.ps1 -CustomerName "Your Company" -SPType All -Uninstall
```

### Remove Just IR Capability
```powershell
.\Setup-CloudRaider-ServicePrincipal.ps1 -CustomerName "Your Company" -SPType IR -Uninstall
```

### Emergency Revocation

If you need to immediately revoke access:

1. **Azure Portal** → Azure Active Directory → App registrations
2. Find `CloudRaider-SOC`, `CloudRaider-IR`, or `CloudRaider-Admin`
3. Click **Delete**

Or use PowerShell:
```powershell
Connect-MgGraph -Scopes "Application.ReadWrite.All"
Get-MgApplication -Filter "startswith(displayName, 'CloudRaider')" | Remove-MgApplication
```

## Permissions Reference

### CloudRaider-SOC (Monitoring)

| Category | Permissions | Purpose |
|----------|-------------|---------|
| Security | SecurityAlert.Read.All, SecurityEvents.Read.All | Detect threats |
| Identity | User.Read.All, Directory.Read.All | User context |
| Audit | AuditLog.Read.All | Sign-in analysis |
| Mail | Mail.Read (app) | BEC detection |
| Devices | Device.Read.All | Asset inventory |
| MDE | Alert.Read.All, Machine.Read.All | Endpoint threats |

### CloudRaider-IR (Incident Response)

Includes all SOC permissions, PLUS:

| Category | Permissions | Purpose |
|----------|-------------|---------|
| Users | User.ReadWrite.All | Disable compromised accounts |
| Policy | Policy.ReadWrite.ConditionalAccess | Block attackers |
| Apps | Application.ReadWrite.All | Revoke OAuth consents |
| Mail | MailboxSettings.ReadWrite | Remove malicious forwarding |
| MDE | Machine.Isolate, Machine.LiveResponse | Contain threats |

### CloudRaider-Admin (Tenant Management)

| Category | Permissions | Purpose |
|----------|-------------|---------|
| Directory | Directory.ReadWrite.All | Full admin |
| Users | User.ReadWrite.All | User provisioning |
| Devices | Device.ReadWrite.All | Device management |
| Intune | DeviceManagement*.ReadWrite.All | MDM management |
| Policy | Policy.ReadWrite.* | Policy management |

## Troubleshooting

### "Not a Global Administrator"

You must be a Global Administrator to run this script. Check your role:
1. Azure Portal → Azure Active Directory → Users
2. Find yourself → Assigned roles
3. Ensure "Global Administrator" is listed

### "Permission denied" during grant

Some permissions require additional licensing:
- **Threat Hunting**: Requires Microsoft 365 E5 or Defender for Endpoint P2
- **Log Analytics**: Requires Azure Sentinel or Log Analytics workspace

The script will warn you but continue with available permissions.

### Script keeps asking to authenticate

Your Graph session may have expired. Close PowerShell and start fresh.

### Missing MDE permissions

If Microsoft Defender for Endpoint isn't configured in your tenant, MDE permissions will be skipped. This is normal for tenants without MDE.

## Support

- **Email**: support@cloudraider.com
- **GitHub Issues**: [cloudraider-soc-setup](https://github.com/carricdd/cloudraider-soc-setup/issues)

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 3.0 | 2025-12-25 | Three-tier model (SOC/IR/Admin), created during LifeScan incident |
| 2.0 | 2025-12-05 | Smart auto-detection, repair mode |
| 1.0 | 2025-10-01 | Initial release |

---

*Created by CloudRaider Security - Incident-Driven Development*
