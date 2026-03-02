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

45 Graph permissions + 11 MDE permissions. Risk: LOW (read-heavy).

| Category | Permissions | Purpose |
|----------|-------------|---------|
| Security & Alerts | SecurityAlert.Read.All, SecurityIncident.Read.All, SecurityEvents.Read.All, ThreatIndicators.Read.All, AttackSimulation.Read.All, SecurityActions.Read.All | Detect and triage threats |
| Identity & Users | User.Read.All, Group.Read.All, GroupMember.Read.All, Directory.Read.All, AuditLog.Read.All, RoleManagement.Read.All, RoleManagement.Read.Directory, CrossTenantInformation.ReadBasic.All | User and directory context |
| Identity Risk | IdentityRiskEvent.Read.All, IdentityRiskyUser.Read.All, IdentityRiskyServicePrincipal.Read.All, UserAuthenticationMethod.Read.All, IdentityProvider.Read.All | Risky identity detection |
| Mail (BEC) | Mail.Read, MailboxSettings.Read | BEC detection |
| Conditional Access & Policy | Policy.Read.All, Policy.Read.ConditionalAccess, ConsentRequest.Read.All | Policy visibility |
| Devices & Intune | Device.Read.All, DeviceManagementManagedDevices.Read.All, DeviceManagementConfiguration.Read.All, DeviceManagementApps.Read.All, DeviceManagementServiceConfig.Read.All, DeviceManagementRBAC.Read.All, BitlockerKey.Read.All | Endpoint and Intune inventory |
| Reports & Compliance | Reports.Read.All, InformationProtectionPolicy.Read.All, Organization.Read.All, Domain.Read.All, AccessReview.Read.All, EntitlementManagement.Read.All | Compliance posture |
| Applications | Application.Read.All, DelegatedPermissionGrant.Read.All, ServicePrincipalEndpoint.Read.All | App and OAuth visibility |
| SharePoint & OneDrive | Sites.Read.All, Files.Read.All | Data exfil detection |
| Teams | TeamSettings.Read.All, Channel.ReadBasic.All | Teams visibility |
| Threat Hunting | ThreatHunting.Read.All | Advanced hunting |
| MDE - Monitoring | Machine.Read.All, Alert.Read.All, Vulnerability.Read.All, SecurityRecommendation.Read.All, Software.Read.All | Endpoint threat detection |
| MDE - Advanced Hunting & Threat Intel | AdvancedQuery.Read.All, Ti.Read.All, File.Read.All, Ip.Read.All, Url.Read.All, User.Read.All | Advanced hunting and IOC lookup |

### CloudRaider-IR (Incident Response)

Includes all SOC permissions, PLUS 24 additional Graph permissions and 9 MDE permissions. Risk: HIGH.

| Category | Additional Permissions | Purpose |
|----------|------------------------|---------|
| User Containment | User.ReadWrite.All, UserAuthenticationMethod.ReadWrite.All | Disable compromised accounts, reset MFA |
| Identity Response | IdentityRiskyUser.ReadWrite.All, IdentityRiskyServicePrincipal.ReadWrite.All | Confirm/dismiss risky users and SPs |
| Policy Modification | Policy.ReadWrite.ConditionalAccess, Policy.ReadWrite.AuthenticationMethod | Block attackers via CA, modify auth policies |
| Directory Changes | Directory.ReadWrite.All, Group.ReadWrite.All, RoleManagement.ReadWrite.Directory | Modify directory, groups, and role assignments |
| Application Response | Application.ReadWrite.All, AppRoleAssignment.ReadWrite.All, DelegatedPermissionGrant.ReadWrite.All | Revoke OAuth consents, remove malicious apps |
| Mail Response | Mail.ReadWrite, MailboxSettings.ReadWrite, Mail.Send | Remove malicious rules and forwarding |
| Device Response | Device.ReadWrite.All, DeviceManagementManagedDevices.ReadWrite.All, DeviceManagementConfiguration.ReadWrite.All | Wipe or reconfigure compromised devices |
| Security Actions | SecurityAlert.ReadWrite.All, SecurityIncident.ReadWrite.All, SecurityActions.ReadWrite.All, ThreatIndicators.ReadWrite.OwnedBy | Update alerts, incidents, and threat indicators |
| SharePoint Response | Sites.ReadWrite.All, Files.ReadWrite.All | Remove malicious content |
| MDE - Machine Response | Machine.ReadWrite.All, Machine.Isolate, Machine.CollectForensics, Machine.RestrictExecution, Machine.Scan, Machine.LiveResponse, Machine.StopAndQuarantine | Contain and investigate compromised endpoints |
| MDE - Alert & Threat Response | Alert.ReadWrite.All, Ti.ReadWrite | Update alerts and threat indicators |

### CloudRaider-Admin (Tenant Management)

21 Graph permissions + 2 MDE permissions. Risk: MEDIUM.

| Category | Permissions | Purpose |
|----------|-------------|---------|
| Global Administration | RoleManagement.ReadWrite.Directory, Organization.ReadWrite.All, Domain.ReadWrite.All, EntitlementManagement.ReadWrite.All, PrivilegedAccess.ReadWrite.AzureADGroup, PrivilegedAccess.ReadWrite.AzureResources | Full tenant admin and PIM management |
| Directory & Users | Directory.ReadWrite.All, User.ReadWrite.All, Group.ReadWrite.All, Organization.Read.All | User provisioning and directory management |
| Applications | Application.ReadWrite.All, AppRoleAssignment.ReadWrite.All | App registration management |
| Devices & Intune | Device.ReadWrite.All, DeviceManagementManagedDevices.ReadWrite.All, DeviceManagementConfiguration.ReadWrite.All, DeviceManagementApps.ReadWrite.All | Full device and MDM management |
| Policy | Policy.ReadWrite.ConditionalAccess, Policy.ReadWrite.AuthenticationMethod | Policy configuration |
| Mail & Audit | Mail.ReadWrite, MailboxSettings.ReadWrite, AuditLog.Read.All | Mailbox management and audit access |
| MDE - Administration | Machine.Offboard, SecurityBaselinesAssessment.Read.All | Offboard machines and assess security baselines |

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
| 3.1 | 2026-03-01 | Permissions updated to manifest v2.0 - added advanced hunting, threat intel, Intune, Purview, Identity Protection |
| 3.0 | 2025-12-25 | Three-tier model (SOC/IR/Admin), created during LifeScan incident |
| 2.0 | 2025-12-05 | Smart auto-detection, repair mode |
| 1.0 | 2025-10-01 | Initial release |

---

*Created by CloudRaider Security - Incident-Driven Development*
