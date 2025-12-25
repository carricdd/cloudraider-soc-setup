# Security Hardening Guide for CloudRaider Service Principals

This guide documents all security mechanisms that should be implemented to protect CloudRaider service principals in customer tenants.

## Overview

Service principals with elevated permissions are high-value targets. This guide ensures defense-in-depth protection.

## Required Security Controls

### 1. IP-Based Conditional Access (CRITICAL)

**Why**: Prevent attackers from using stolen credentials from unauthorized locations.

**Implementation**:

```powershell
# Create Named Location for CloudRaider IPs
$cloudRaiderIPs = @(
    "203.0.113.10/32",   # CloudRaider Primary
    "203.0.113.20/32",   # CloudRaider Secondary
    # Request current IPs from CloudRaider
)

# Azure Portal: Security → Conditional Access → Named locations
# Create: "CloudRaider Trusted IPs" with above ranges
```

**Conditional Access Policy**:
```
Name: "Block CloudRaider-IR from untrusted IPs"
Assignments:
  Users: Select "CloudRaider-IR" service principal
  Cloud apps: All cloud apps
  Conditions:
    Locations:
      Include: All locations
      Exclude: "CloudRaider Trusted IPs"
Access controls:
  Grant: Block access
State: On
```

**Create policies for each SP**:
- CloudRaider-SOC: More lenient (monitoring can be from multiple locations)
- CloudRaider-IR: Strict (only CloudRaider IPs)
- CloudRaider-Admin: Strict (only CloudRaider IPs)

### 2. Workload Identity Protection (Entra ID P2)

**Why**: Apply risk-based policies to service principals.

**Implementation**:
```
Entra ID → Security → Conditional Access → Workload identities

Create policy:
  Name: "Block risky CloudRaider workload identities"
  Workload identities: CloudRaider-IR, CloudRaider-SOC
  Conditions:
    Service principal risk: High
  Grant: Block
```

### 3. Secret Management

**Rotation Schedule**:
| SP | Rotation Frequency | Trigger |
|----|-------------------|---------|
| CloudRaider-SOC | Annual | Calendar reminder |
| CloudRaider-IR | 6 months | Calendar reminder |
| CloudRaider-Admin | 6 months | Calendar reminder |

**Emergency Rotation**:
```powershell
# If secret is compromised, run setup script again
.\Setup-CloudRaider-ServicePrincipal.ps1 -CustomerName "Your Company" -SPType IR

# Old secret is NOT revoked automatically - delete manually if needed:
Connect-MgGraph -Scopes "Application.ReadWrite.All"
$app = Get-MgApplication -Filter "displayName eq 'CloudRaider-IR'"
# View existing secrets
$app.PasswordCredentials
# Remove old secret by keyId
Remove-MgApplicationPassword -ApplicationId $app.Id -KeyId "old-key-id"
```

### 4. Audit Logging

**Required Log Retention**:
| Log Type | Minimum Retention | Recommended |
|----------|------------------|-------------|
| Sign-in logs | 30 days | 90 days |
| Audit logs | 30 days | 1 year |
| Service principal sign-ins | 30 days | 90 days |

**Log Export to SIEM**:
Configure diagnostic settings to send to:
- Azure Sentinel
- Splunk
- Your SIEM platform

```
Azure Portal → Azure Active Directory → Diagnostic settings
→ Add diagnostic setting
  - SignInLogs
  - AuditLogs
  - ServicePrincipalSignInLogs
  → Send to Log Analytics workspace / Event Hub
```

### 5. Alerting Rules

**Azure Sentinel / Log Analytics Queries**:

```kusto
// CloudRaider SP sign-in from unexpected location
AADServicePrincipalSignInLogs
| where ServicePrincipalName startswith "CloudRaider"
| where IPAddress !in ("203.0.113.10", "203.0.113.20")
| project TimeGenerated, ServicePrincipalName, IPAddress, Location, ResultType

// Failed authentication attempts
AADServicePrincipalSignInLogs
| where ServicePrincipalName startswith "CloudRaider"
| where ResultType != 0
| summarize FailedAttempts = count() by ServicePrincipalName, IPAddress, bin(TimeGenerated, 1h)
| where FailedAttempts > 5

// Permission changes to CloudRaider apps
AuditLogs
| where TargetResources has "CloudRaider"
| where OperationName in ("Add app role assignment to service principal",
                          "Remove app role assignment from service principal",
                          "Update application")
```

**Alert Thresholds**:
| Event | Threshold | Severity |
|-------|-----------|----------|
| Sign-in from non-CloudRaider IP | Any | High |
| Failed auth attempts | 5 in 1 hour | Medium |
| Permission changes | Any | High |
| New secret created | Any | Medium |

### 6. Principle of Least Privilege

**Regular Permission Audits**:

```powershell
# Quarterly audit script
Connect-MgGraph -Scopes "Application.Read.All"

$sps = Get-MgServicePrincipal -Filter "startswith(displayName, 'CloudRaider')"
foreach ($sp in $sps) {
    Write-Host "`n=== $($sp.DisplayName) ===" -ForegroundColor Cyan
    $assignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id
    Write-Host "Total permissions: $($assignments.Count)"

    # Compare to baseline (provide expected count)
    # Flag if more permissions than expected
}
```

### 7. Break-Glass Procedures

**CloudRaider-IR Usage Protocol**:

1. **Before Using IR SP**:
   - Document incident ticket number
   - Notify customer security contact
   - Log start time

2. **During Incident**:
   - All actions logged automatically in Azure AD
   - Take screenshots of critical actions
   - Document reasoning for each action

3. **After Incident**:
   - Provide customer with action summary
   - Review if IR permissions still needed
   - Consider secret rotation

**Customer Visibility**:
```kusto
// Customer can run this to see all CloudRaider IR actions
AuditLogs
| where InitiatedBy has "CloudRaider-IR"
| project TimeGenerated, OperationName, TargetResources, Result
| order by TimeGenerated desc
```

### 8. Tenant Separation

**Multi-Customer Protection**:

- Each customer has separate SPs (not shared)
- Credentials stored separately per customer
- No cross-tenant credential access
- Separate secret vaults per customer

**CloudRaider Internal Controls**:
- Credentials in encrypted vault
- Access requires MFA + justification
- All credential access logged
- Quarterly access reviews

## Emergency Response

### If SP Credentials Are Compromised

1. **Immediate** (< 5 minutes):
   ```powershell
   # Disable the service principal
   Connect-MgGraph
   $sp = Get-MgServicePrincipal -Filter "displayName eq 'CloudRaider-IR'"
   Update-MgServicePrincipal -ServicePrincipalId $sp.Id -AccountEnabled:$false
   ```

2. **Short-term** (< 1 hour):
   - Revoke all secrets
   - Review recent SP activity
   - Check for persistence mechanisms

3. **Recovery**:
   - Re-enable SP with new secret
   - Review and tighten CA policies
   - Post-incident review

### If CloudRaider Is Compromised

1. **Immediate**: Run uninstall script
   ```powershell
   .\Setup-CloudRaider-ServicePrincipal.ps1 -CustomerName "Your Company" -SPType All -Uninstall
   ```

2. **Or via Portal**:
   - Azure AD → App registrations → Delete CloudRaider apps

3. **Review**:
   - Check for any actions taken
   - Review for persistence (new apps, users, rules)

## Compliance Mapping

| Control | NIST | CIS | SOC 2 |
|---------|------|-----|-------|
| IP restriction | AC-3 | 6.1 | CC6.1 |
| Secret rotation | IA-5 | 5.3 | CC6.1 |
| Audit logging | AU-2 | 8.5 | CC7.2 |
| Access reviews | AC-2 | 6.2 | CC6.2 |
| Least privilege | AC-6 | 6.1 | CC6.3 |

## Contact

Security concerns: security@cloudraider.com
Incident response: ir@cloudraider.com
