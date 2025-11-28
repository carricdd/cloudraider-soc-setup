#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Creates CloudRaider Security Monitoring Service Principal

.DESCRIPTION
    This script creates an Azure AD App Registration and Service Principal
    for CloudRaider to perform 24/7 security monitoring and incident response.

    TWO ACCESS LEVELS:

    1. ReadOnly (Detection & Monitoring):
       - Read security logs and audit trails
       - Detect threats and suspicious activity
       - Alert your team
       - Cannot make any changes to your environment

    2. FullResponse (Detection + Incident Response):
       - Everything in ReadOnly, PLUS:
       - Disable compromised accounts during attacks
       - Block attacker IP addresses
       - Force password resets
       - Take immediate defensive action

    WHAT THIS SCRIPT DOES:
    1. Verifies you're a Global Administrator
    2. Creates App Registration named "CloudRaiderSOC"
    3. Grants Microsoft Graph API permissions
    4. Grants Azure Log Analytics API permissions (for Sentinel workspace queries)
    5. Creates 2-year client secret
    6. Outputs credentials in copy-paste format

.PARAMETER CustomerName
    Your company name (used for naming environment variables)

.PARAMETER AccessLevel
    ReadOnly or FullResponse (default: ReadOnly)

.EXAMPLE
    # Detection only (read-only access)
    .\Setup-CloudRaider-ServicePrincipal.ps1 -CustomerName "Acme Corp"

.EXAMPLE
    # Full incident response capabilities
    .\Setup-CloudRaider-ServicePrincipal.ps1 -CustomerName "Acme Corp" -AccessLevel FullResponse

.NOTES
    Requirements:
    - You must be a Global Administrator
    - PowerShell 7+
    - Internet connection

    What gets created:
    - Azure AD App Registration: "CloudRaiderSOC"
    - Service Principal for the app
    - Client secret (expires in 24 months)
    - Microsoft Graph API permissions
    - Azure Log Analytics API permissions (for Sentinel)

    Security:
    - All actions are logged in Azure AD audit logs
    - Service principal can be disabled/deleted at any time
    - Client secret can be rotated
    - Follows principle of least privilege

    Support:
    Email: support@cloudraider.com
    Emergency: [your emergency contact]
#>

param(
    [Parameter(Mandatory=$true, HelpMessage="Your company name (e.g. 'Acme Corp')")]
    [string]$CustomerName,

    [Parameter(Mandatory=$false)]
    [ValidateSet("ReadOnly", "FullResponse")]
    [string]$AccessLevel = "ReadOnly"
)

$ErrorActionPreference = "Stop"

# Colors
$ColorInfo = "Cyan"
$ColorSuccess = "Green"
$ColorWarning = "Yellow"
$ColorError = "Red"
$ColorHighlight = "Magenta"

# Clear screen for clean output
Clear-Host

Write-Host "`n╔════════════════════════════════════════════════════════════════╗" -ForegroundColor $ColorInfo
Write-Host "║   CloudRaider Security Monitoring - Service Principal Setup   ║" -ForegroundColor $ColorInfo
Write-Host "╚════════════════════════════════════════════════════════════════╝`n" -ForegroundColor $ColorInfo

Write-Host "Customer: " -NoNewline -ForegroundColor Gray
Write-Host $CustomerName -ForegroundColor $ColorHighlight

Write-Host "Access Level: " -NoNewline -ForegroundColor Gray
Write-Host $AccessLevel -ForegroundColor $ColorHighlight

if ($AccessLevel -eq "ReadOnly") {
    Write-Host "`n📊 Detection & Monitoring (Read-Only)" -ForegroundColor $ColorInfo
    Write-Host "   - Detects threats and suspicious activity" -ForegroundColor Gray
    Write-Host "   - Alerts your team to security events" -ForegroundColor Gray
    Write-Host "   - Cannot make changes to your environment`n" -ForegroundColor Gray
} else {
    Write-Host "`n🛡️  Full Incident Response (Read + Write)" -ForegroundColor $ColorInfo
    Write-Host "   - Everything in Read-Only, PLUS:" -ForegroundColor Gray
    Write-Host "   - Disable compromised accounts during attacks" -ForegroundColor Gray
    Write-Host "   - Block attacker IPs immediately" -ForegroundColor Gray
    Write-Host "   - Force password resets on breached accounts`n" -ForegroundColor Gray
}

# Check prerequisites
Write-Host "[1/7] Checking prerequisites..." -ForegroundColor $ColorInfo

# Check PowerShell version
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Host "   ✗ PowerShell 7+ required (you have $($PSVersionTable.PSVersion))" -ForegroundColor $ColorError
    Write-Host "   Install from: https://aka.ms/powershell`n" -ForegroundColor Gray
    exit 1
}
Write-Host "   ✓ PowerShell version: $($PSVersionTable.PSVersion)" -ForegroundColor $ColorSuccess

# Check/Install Microsoft.Graph module
Write-Host "`n[2/7] Checking Microsoft.Graph module..." -ForegroundColor $ColorInfo

$GraphModule = Get-Module -ListAvailable -Name Microsoft.Graph.Applications | Select-Object -First 1
if (-not $GraphModule) {
    Write-Host "   ⚠ Microsoft.Graph module not found - installing..." -ForegroundColor $ColorWarning
    try {
        Install-Module Microsoft.Graph -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
        Write-Host "   ✓ Module installed" -ForegroundColor $ColorSuccess
    } catch {
        Write-Host "   ✗ Failed to install module: $($_.Exception.Message)" -ForegroundColor $ColorError
        Write-Host "   Run manually: Install-Module Microsoft.Graph`n" -ForegroundColor Gray
        exit 1
    }
} else {
    Write-Host "   ✓ Module found: $($GraphModule.Version)" -ForegroundColor $ColorSuccess
}

# Import required modules
Import-Module Microsoft.Graph.Applications -ErrorAction Stop
Import-Module Microsoft.Graph.Users -ErrorAction Stop

# Connect to Microsoft Graph
Write-Host "`n[3/7] Connecting to Microsoft Graph..." -ForegroundColor $ColorInfo
Write-Host "   (Browser window will open for authentication)`n" -ForegroundColor Gray

try {
    Connect-MgGraph -Scopes "Application.ReadWrite.All", "Directory.ReadWrite.All", "RoleManagement.ReadWrite.Directory" -ErrorAction Stop | Out-Null
    Write-Host "   ✓ Connected to Microsoft Graph" -ForegroundColor $ColorSuccess
} catch {
    Write-Host "   ✗ Failed to connect: $($_.Exception.Message)" -ForegroundColor $ColorError
    exit 1
}

# Verify user is Global Admin
Write-Host "`n[4/7] Verifying administrator permissions..." -ForegroundColor $ColorInfo

$Context = Get-MgContext
$CurrentUser = Get-MgUser -UserId $Context.Account

# Check for Global Admin role
$GlobalAdminRole = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'" | Select-Object -First 1
if ($GlobalAdminRole) {
    $IsGlobalAdmin = Get-MgDirectoryRoleMember -DirectoryRoleId $GlobalAdminRole.Id | Where-Object { $_.Id -eq $CurrentUser.Id }

    if ($IsGlobalAdmin) {
        Write-Host "   ✓ Confirmed: You are a Global Administrator" -ForegroundColor $ColorSuccess
    } else {
        Write-Host "   ✗ Error: You must be a Global Administrator to run this script" -ForegroundColor $ColorError
        Write-Host "   Current user: $($Context.Account)" -ForegroundColor Gray
        Write-Host "   Required role: Global Administrator`n" -ForegroundColor Gray
        Disconnect-MgGraph | Out-Null
        exit 1
    }
}

# Create App Registration
Write-Host "`n[5/7] Creating CloudRaider App Registration..." -ForegroundColor $ColorInfo

$AppName = "CloudRaiderSOC"

# Check if app already exists
$ExistingApp = Get-MgApplication -Filter "displayName eq '$AppName'" -ErrorAction SilentlyContinue | Select-Object -First 1

if ($ExistingApp) {
    Write-Host "   ⚠ App '$AppName' already exists" -ForegroundColor $ColorWarning
    Write-Host "   Found App ID: $($ExistingApp.AppId)" -ForegroundColor Gray

    $Response = Read-Host "   Delete and recreate? (y/N)"
    if ($Response -ne 'y' -and $Response -ne 'Y') {
        Write-Host "   Exiting without changes.`n" -ForegroundColor Gray
        Disconnect-MgGraph | Out-Null
        exit 0
    }

    Write-Host "   Deleting existing app..." -ForegroundColor Yellow
    Remove-MgApplication -ApplicationId $ExistingApp.Id -ErrorAction Stop
    Start-Sleep -Seconds 5
}

# Define Microsoft Graph permissions based on access level
$ReadOnlyPermissions = @(
    @{ Id = "472e4a4d-bb4a-4026-98d1-0571d7e0f65a"; Type = "Role" }  # SecurityAlert.Read.All (CRITICAL - alerts API)
    @{ Id = "e2a3a72e-5f79-4c64-b1b1-878b674786c9"; Type = "Role" }  # AuditLog.Read.All
    @{ Id = "7ab1d382-f21e-4acd-a863-ba3e13f7da61"; Type = "Role" }  # Directory.Read.All
    @{ Id = "bf394140-e372-4bf9-a898-299cfc7564e5"; Type = "Role" }  # SecurityEvents.Read.All
    @{ Id = "45cc0394-e837-488b-a098-1918f48d186c"; Type = "Role" }  # SecurityIncident.Read.All
    @{ Id = "df021288-bdef-4463-88db-98f22de89214"; Type = "Role" }  # User.Read.All
    @{ Id = "dc5007c0-2d7d-4c42-879c-2dab87571379"; Type = "Role" }  # IdentityRiskyUser.Read.All (risky user detection)
    @{ Id = "6e472fd1-ad78-48da-a0f0-97ab2c6b769e"; Type = "Role" }  # IdentityRiskEvent.Read.All
    @{ Id = "dd98c7f5-2d42-42d3-a0e4-633161547251"; Type = "Role" }  # ThreatHunting.Read.All (MDE Advanced Hunting)
    @{ Id = "5e0edab9-c148-49d0-b423-ac253e121825"; Type = "Role" }  # SecurityActions.Read.All (Secure Score)
)

$FullResponsePermissions = $ReadOnlyPermissions + @(
    @{ Id = "741f803b-c850-494e-b5df-cde7c675a1ca"; Type = "Role" }  # User.ReadWrite.All
    @{ Id = "f2bf083f-0179-402a-bedb-b2784de8a49b"; Type = "Role" }  # SecurityActions.ReadWrite.All
    @{ Id = "50483e42-d915-4231-9639-7fdb7fd190e5"; Type = "Role" }  # UserAuthenticationMethod.ReadWrite.All
    @{ Id = "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8"; Type = "Role" }  # RoleManagement.ReadWrite.Directory
)

$GraphPermissions = if ($AccessLevel -eq "ReadOnly") { $ReadOnlyPermissions } else { $FullResponsePermissions }

# Create app with BOTH Microsoft Graph AND Azure Log Analytics API permissions
Write-Host "   Creating app registration..." -ForegroundColor Gray

$AppParams = @{
    DisplayName = $AppName
    SignInAudience = "AzureADMyOrg"
    RequiredResourceAccess = @(
        @{
            ResourceAppId = "00000003-0000-0000-c000-000000000000"  # Microsoft Graph
            ResourceAccess = $GraphPermissions
        },
        @{
            ResourceAppId = "ca7f3f0b-7d91-482c-8e09-c5d840d0eac5"  # Azure Log Analytics API
            ResourceAccess = @(
                @{ Id = "0c0bf378-bf22-4481-8f81-9e89a9b4960a"; Type = "Role" }  # Data.Read
            )
        }
    )
}

$App = New-MgApplication @AppParams -ErrorAction Stop

Write-Host "   ✓ App created successfully" -ForegroundColor $ColorSuccess
Write-Host "   App ID: $($App.AppId)" -ForegroundColor Gray

# Create Service Principal
Write-Host "`n[6/7] Creating Service Principal..." -ForegroundColor $ColorInfo

$SpParams = @{
    AppId = $App.AppId
}

$ServicePrincipal = New-MgServicePrincipal @SpParams -ErrorAction Stop

Write-Host "   ✓ Service Principal created" -ForegroundColor $ColorSuccess
Write-Host "   Object ID: $($ServicePrincipal.Id)" -ForegroundColor Gray

# Grant admin consent
Write-Host "`n   Granting admin consent to permissions..." -ForegroundColor Gray

Start-Sleep -Seconds 10  # Wait for Azure AD replication

# Admin consent requires manual approval in most tenants
Write-Host "   ⚠ Admin consent may require manual approval" -ForegroundColor $ColorWarning
Write-Host "   If prompted, click 'Accept' in the browser window`n" -ForegroundColor Gray

# Open admin consent URL
$TenantId = $Context.TenantId
$ConsentUrl = "https://login.microsoftonline.com/$TenantId/adminconsent?client_id=$($App.AppId)"

Write-Host "   Opening admin consent page..." -ForegroundColor Gray
Start-Process $ConsentUrl

Write-Host "`n   Waiting for admin consent (check your browser)..." -ForegroundColor Yellow
Read-Host "   Press ENTER after granting consent"

# Create Client Secret
Write-Host "`n[7/7] Creating client secret..." -ForegroundColor $ColorInfo

$SecretParams = @{
    PasswordCredential = @{
        DisplayName = "CloudRaider-Secret-$(Get-Date -Format 'yyyy-MM-dd')"
        EndDateTime = (Get-Date).AddMonths(24)
    }
}

$Secret = Add-MgApplicationPassword -ApplicationId $App.Id -BodyParameter $SecretParams -ErrorAction Stop

Write-Host "   ✓ Client secret created (expires: $($Secret.EndDateTime.ToString('yyyy-MM-dd')))" -ForegroundColor $ColorSuccess

# Disconnect
Disconnect-MgGraph | Out-Null

# Output credentials
Write-Host "`n" -ForegroundColor Gray
Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor $ColorSuccess
Write-Host "║                    SETUP COMPLETE                              ║" -ForegroundColor $ColorSuccess
Write-Host "╚════════════════════════════════════════════════════════════════╝`n" -ForegroundColor $ColorSuccess

Write-Host "📋 CREDENTIALS FOR CLOUDRAIDER TEAM" -ForegroundColor $ColorHighlight
Write-Host "════════════════════════════════════════════════════════════════`n" -ForegroundColor Gray

# Format customer name for environment variable (remove spaces, uppercase)
$EnvPrefix = ($CustomerName -replace '\s','').ToUpper()

Write-Host "Copy these lines to your secure credential sharing method:" -ForegroundColor Yellow
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`n" -ForegroundColor Gray

Write-Host "export ${EnvPrefix}_TENANT_ID=`"$TenantId`"" -ForegroundColor White
Write-Host "export ${EnvPrefix}_CLIENT_ID=`"$($App.AppId)`"" -ForegroundColor White
Write-Host "export ${EnvPrefix}_CLIENT_SECRET=`"$($Secret.SecretText)`"" -ForegroundColor White
Write-Host "export ${EnvPrefix}_ACCESS_LEVEL=`"$AccessLevel`"`n" -ForegroundColor White

Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`n" -ForegroundColor Gray

Write-Host "⚠️  SECURITY REMINDERS:" -ForegroundColor $ColorWarning
Write-Host "   - Send credentials via SECURE channel only (encrypted email, Teams)" -ForegroundColor Gray
Write-Host "   - Do NOT send via regular email" -ForegroundColor Gray
Write-Host "   - Client secret expires: $($Secret.EndDateTime.ToString('yyyy-MM-dd'))" -ForegroundColor Gray
Write-Host "   - All actions logged in Azure AD audit logs`n" -ForegroundColor Gray

Write-Host "📊 WHAT HAPPENS NEXT:" -ForegroundColor $ColorInfo
Write-Host "   1. Send credentials to CloudRaider via secure channel" -ForegroundColor Gray
Write-Host "   2. CloudRaider tests connectivity (within 24 hours)" -ForegroundColor Gray
Write-Host "   3. You receive confirmation email" -ForegroundColor Gray
Write-Host "   4. 24/7 monitoring begins!`n" -ForegroundColor Gray

Write-Host "🔍 TO AUDIT CLOUDRAIDER ACTIONS:" -ForegroundColor $ColorInfo
Write-Host "   Azure Portal → Azure AD → Audit logs" -ForegroundColor Gray
Write-Host "   Search for: `"CloudRaiderSOC`"`n" -ForegroundColor Gray

Write-Host "🗑️  TO REVOKE ACCESS (if needed):" -ForegroundColor $ColorInfo
Write-Host "   Azure Portal → Azure AD → App registrations" -ForegroundColor Gray
Write-Host "   Find `"CloudRaiderSOC`" → Delete`n" -ForegroundColor Gray

Write-Host "✅ Setup complete! Thank you for choosing CloudRaider.`n" -ForegroundColor $ColorSuccess

# Save to file option
$SaveToFile = Read-Host "Save credentials to file? (y/N)"
if ($SaveToFile -eq 'y' -or $SaveToFile -eq 'Y') {
    $FileName = "CloudRaider-Credentials-$($CustomerName -replace '\s','-')-$(Get-Date -Format 'yyyy-MM-dd').txt"

    @"
CloudRaider Security Monitoring - Service Principal Credentials
================================================================

Customer: $CustomerName
Created: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Access Level: $AccessLevel
Expires: $($Secret.EndDateTime.ToString('yyyy-MM-dd'))

CREDENTIALS (Copy to ~/.zsh_env or equivalent):
================================================================

export ${EnvPrefix}_TENANT_ID="$TenantId"
export ${EnvPrefix}_CLIENT_ID="$($App.AppId)"
export ${EnvPrefix}_CLIENT_SECRET="$($Secret.SecretText)"
export ${EnvPrefix}_ACCESS_LEVEL="$AccessLevel"

================================================================

App Registration Details:
- Name: CloudRaiderSOC
- App ID: $($App.AppId)
- Tenant ID: $TenantId
- Service Principal Object ID: $($ServicePrincipal.Id)
- Secret Expires: $($Secret.EndDateTime.ToString('yyyy-MM-dd'))

Permissions Granted:
$(if ($AccessLevel -eq "ReadOnly") {
"- Read-only access to security logs
- Microsoft Graph API:
  - SecurityAlert.Read.All (security alerts)
  - AuditLog.Read.All
  - Directory.Read.All
  - SecurityEvents.Read.All
  - SecurityIncident.Read.All
  - User.Read.All
  - IdentityRiskyUser.Read.All (risky user detection)
  - IdentityRiskEvent.Read.All
  - ThreatHunting.Read.All
  - SecurityActions.Read.All
- Azure Log Analytics API:
  - Data.Read (for Sentinel workspace queries)"
} else {
"- Full incident response access
- All Read-Only permissions, PLUS:
  - User.ReadWrite.All (disable compromised accounts)
  - SecurityActions.ReadWrite.All (block IPs, quarantine devices)
  - UserAuthenticationMethod.ReadWrite.All (reset passwords)
  - RoleManagement.ReadWrite.Directory (remove admin privileges)
- Azure Log Analytics API:
  - Data.Read (for Sentinel workspace queries)"
})

TO AUDIT:
- Azure Portal → Azure AD → Audit logs → Search "CloudRaiderSOC"

TO REVOKE:
- Azure Portal → Azure AD → App registrations → Delete "CloudRaiderSOC"

================================================================
SECURITY: Send this file via encrypted email or secure file share
DO NOT send via regular email
================================================================
"@ | Out-File -FilePath $FileName -Encoding UTF8

    Write-Host "`n✓ Credentials saved to: $FileName" -ForegroundColor $ColorSuccess
    Write-Host "  Send this file to CloudRaider via secure channel`n" -ForegroundColor Gray
}

Write-Host "Questions? Contact support@cloudraider.com`n" -ForegroundColor Gray
