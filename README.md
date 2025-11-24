# CloudRaider SOC Setup

**Automated Service Principal Configuration for Microsoft 365 Security Monitoring**

This repository contains self-service PowerShell scripts that allow your IT team to quickly and securely grant CloudRaider access to your Microsoft 365 environment for 24/7 security monitoring.

## What This Does

CloudRaider provides Security Operations Center (SOC) as-a-Service. To monitor your environment, we need read-only access to your security logs. This script automates the entire setup process in ~5 minutes.

### Two Access Levels

**1. ReadOnly (Detection & Monitoring)** - Recommended to start
- Detects threats and suspicious activity  
- Alerts your team to security events
- Reads audit logs, security events, and user activity
- Cannot make any changes to your environment

**2. FullResponse (Incident Response)** - Optional upgrade
- Everything in ReadOnly, PLUS:
- Disable compromised accounts during active attacks
- Block attacker IP addresses
- Force password resets on breached accounts
- Take immediate defensive action

## Requirements

- **Global Administrator** access to your Microsoft 365 tenant
- **PowerShell 7+** ([Download](https://aka.ms/powershell))
- **10 minutes** of your time

## Quick Start

### Recommended: Download and Run

1. Download [`Setup-CloudRaider-ServicePrincipal.ps1`](./Setup-CloudRaider-ServicePrincipal.ps1)
2. Right-click → "Run with PowerShell"
3. Enter your company name when prompted
4. Grant admin consent in the browser window
5. Copy credentials and send to CloudRaider via Teams or encrypted email

### Command Line Usage

```powershell
# Clone repository
git clone https://github.com/cloudraider/cloudraider-soc-setup.git
cd cloudraider-soc-setup

# Run setup (ReadOnly monitoring)
.\Setup-CloudRaider-ServicePrincipal.ps1 -CustomerName "Your Company Name"

# Or with full incident response capabilities
.\Setup-CloudRaider-ServicePrincipal.ps1 -CustomerName "Your Company Name" -AccessLevel FullResponse
```

## What Gets Created

The script creates:

1. **App Registration** named "CloudRaiderSOC" in your Azure AD
2. **Service Principal** with least-privilege permissions
3. **Client Secret** valid for 24 months
4. **Credentials file** in copy-paste format

### Permissions Granted (ReadOnly)

**Microsoft Graph API**:
- `AuditLog.Read.All` - Read audit logs
- `Directory.Read.All` - Read directory information
- `SecurityEvents.Read.All` - Read security events
- `SecurityIncident.Read.All` - Read security incidents and alerts
- `User.Read.All` - Read user profiles
- `IdentityRiskEvent.Read.All` - Read identity risk events
- `ThreatHunting.Read.All` - Advanced hunting queries (Defender)
- `SecurityActions.Read.All` - Read secure score

**Azure Log Analytics API**:
- `Data.Read` - Query Sentinel workspace logs

### Additional Permissions (FullResponse)

If you choose FullResponse access level, these are added:

- `User.ReadWrite.All` - Disable compromised accounts
- `SecurityActions.ReadWrite.All` - Block IPs, quarantine devices
- `UserAuthenticationMethod.ReadWrite.All` - Force password resets
- `RoleManagement.ReadWrite.Directory` - Remove admin privileges during attacks

## Security & Compliance

### How CloudRaider Protects Your Data

- **Least Privilege**: Only permissions required for monitoring
- **Audit Trail**: All actions logged in Azure AD audit logs
- **No Data Storage**: We query in real-time, don't store logs
- **Revocable Access**: You can delete the app registration anytime
- **Encrypted Transit**: All API calls use TLS 1.2+
- **SOC 2 Type II Compliant**: Annual third-party audits
- **HIPAA Compliant**: BAA available upon request

### Compliance Frameworks Supported

- HIPAA (Healthcare)
- CJIS (Law Enforcement)
- PCI-DSS (Payment Card Industry)
- NIST CSF (Cybersecurity Framework)
- CIS Controls

### How to Audit CloudRaider Actions

1. Go to **Azure Portal** → **Azure Active Directory**
2. Click **Audit logs** in left menu
3. Search for: `CloudRaiderSOC`
4. Review all actions taken

### How to Revoke Access

If you need to revoke CloudRaider's access:

1. Go to **Azure Portal** → **Azure Active Directory**
2. Click **App registrations** in left menu
3. Find **CloudRaiderSOC**
4. Click **Delete**

Access is immediately revoked.

## Frequently Asked Questions

### Q: Is this safe to run?

**A:** Yes. This script only creates an app registration with read-only permissions (unless you choose FullResponse). You review and approve every permission before granting consent. All actions are logged in Azure AD audit logs.

### Q: What data can CloudRaider see?

**A:** CloudRaider can see:
- Security alerts and incidents
- User sign-in activity
- Audit logs
- Security configuration settings

CloudRaider **cannot** see:
- Email contents
- Files in SharePoint/OneDrive
- Teams messages
- Personal user data (except usernames and sign-in activity)

### Q: Can CloudRaider make changes to my environment?

**A:** Only if you choose **FullResponse** access level AND explicitly grant those permissions. With **ReadOnly** (default), CloudRaider can only read data and alert you - no changes possible.

### Q: How long is the client secret valid?

**A:** 24 months (2 years). You'll receive a notification 30 days before expiration to rotate the secret.

### Q: What if I already have an app named "CloudRaiderSOC"?

**A:** The script will detect it and ask if you want to delete and recreate. This is safe - credentials change but monitoring continues with new credentials.

### Q: Do you support multi-tenant environments?

**A:** Yes! Run the script in each tenant where you want CloudRaider monitoring.

### Q: What if I don't have Global Administrator access?

**A:** You need Global Admin to create app registrations and grant admin consent. Ask your IT administrator to run this script.

## What Happens After Setup

1. **Send Credentials**: Copy credentials output and send to CloudRaider via Teams or encrypted email
2. **We Test Connectivity**: Within 24 hours, CloudRaider tests the connection
3. **You Get Confirmation**: We send you a confirmation email when monitoring starts
4. **24/7 Monitoring Begins**: Our SOC team monitors your environment around the clock

## Support

### CloudRaider Support

- **Email**: support@cloudraider.com
- **Emergency Security Hotline**: [Emergency contact]
- **Teams Channel**: [Your dedicated channel]

### Technical Issues

If the script fails:

1. **Check PowerShell Version**: `$PSVersionTable.PSVersion` (must be 7+)
2. **Verify Admin Rights**: `Get-MgContext` should show your Global Admin account
3. **Check Network**: Ensure you can access `graph.microsoft.com`
4. **Contact Support**: Send error message to support@cloudraider.com

## License

This script is provided by CloudRaider LLC for use by CloudRaider customers and prospects.

**Permitted Use**:
- Download and run to configure CloudRaider monitoring
- Review code for security assessment
- Share with your IT team
- Modify for your specific environment

**Prohibited Use**:
- Resell or redistribute as a service
- Remove copyright notices
- Use for competing SOC services

## Security Disclosure

If you discover a security vulnerability in this script, please email security@cloudraider.com. We'll respond within 24 hours.

## Version History

- **v1.2** (2025-11-24): Added Azure Log Analytics API permissions for Sentinel workspace queries
- **v1.1** (2025-06-15): Added FullResponse access level with incident response capabilities
- **v1.0** (2025-03-01): Initial release with ReadOnly monitoring

---

**Thank you for choosing CloudRaider!**

We're committed to keeping your organization secure. Questions? Contact support@cloudraider.com anytime.
