#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Creates or repairs CloudRaider Security Monitoring Service Principal

.DESCRIPTION
    SMART AUTO-DETECTION: This script automatically detects the current state
    and takes the appropriate action:

    SCENARIO 1 - Fresh Install (no existing app):
      → Creates app, service principal, grants permissions, creates secret

    SCENARIO 2 - App exists, needs new secret (lost credentials):
      → Keeps app and permissions, just generates new secret

    SCENARIO 3 - App exists, missing permissions:
      → Keeps app, grants missing permissions, optionally new secret

    SCENARIO 4 - Backout/Uninstall (use -Uninstall flag):
      → Completely removes app registration for clean restart

    TWO ACCESS LEVELS:

    1. ReadOnly (Detection & Monitoring):
       - Read security logs and audit trails
       - Detect threats and suspicious activity
       - Cannot make any changes to your environment

    2. FullResponse (Detection + Incident Response):
       - Everything in ReadOnly, PLUS:
       - Disable compromised accounts during attacks
       - Block attacker IP addresses
       - Take immediate defensive action

.PARAMETER CustomerName
    Your company name (used for naming environment variables)

.PARAMETER AccessLevel
    ReadOnly or FullResponse (default: ReadOnly)

.PARAMETER Uninstall
    Remove CloudRaiderSOC app completely for clean reinstall

.PARAMETER ForceNewSecret
    Force generation of new secret even if permissions are OK

.EXAMPLE
    # First time setup OR re-run after losing secret (auto-detects)
    .\Setup-CloudRaider-ServicePrincipal.ps1 -CustomerName "Acme Corp"

.EXAMPLE
    # Full incident response capabilities
    .\Setup-CloudRaider-ServicePrincipal.ps1 -CustomerName "Acme Corp" -AccessLevel FullResponse

.EXAMPLE
    # Complete removal for clean restart
    .\Setup-CloudRaider-ServicePrincipal.ps1 -CustomerName "Acme Corp" -Uninstall

.EXAMPLE
    # Force new secret generation
    .\Setup-CloudRaider-ServicePrincipal.ps1 -CustomerName "Acme Corp" -ForceNewSecret

.NOTES
    Version: 2.0
    Last Updated: 2025-12-05

    Requirements:
    - You must be a Global Administrator
    - PowerShell 7+
    - Internet connection

    Support:
    Email: support@cloudraider.com
#>

param(
    [Parameter(Mandatory=$true, HelpMessage="Your company name (e.g. 'Acme Corp')")]
    [string]$CustomerName,

    [Parameter(Mandatory=$false)]
    [ValidateSet("ReadOnly", "FullResponse")]
    [string]$AccessLevel = "ReadOnly",

    [Parameter(Mandatory=$false)]
    [switch]$Uninstall,

    [Parameter(Mandatory=$false)]
    [switch]$ForceNewSecret
)

$ErrorActionPreference = "Stop"

# Colors
$ColorInfo = "Cyan"
$ColorSuccess = "Green"
$ColorWarning = "Yellow"
$ColorError = "Red"
$ColorHighlight = "Magenta"

# App name constant
$AppName = "CloudRaiderSOC"

# Microsoft Graph App ID
$GraphAppId = "00000003-0000-0000-c000-000000000000"

# Azure Log Analytics API App ID
$LogAnalyticsAppId = "ca7f3f0b-7d91-482c-8e09-c5d840d0eac5"

# Required permission GUIDs - VERIFIED 2025-12-05
$RequiredPermissions = @{
    # CORE SECURITY - CRITICAL
    "SecurityAlert.Read.All" = "472e4a4d-bb4a-4026-98d1-0b0d74cb74a5"
    "SecurityIncident.Read.All" = "45cc0394-e837-488b-a098-1918f48d186c"
    "SecurityEvents.Read.All" = "bf394140-e372-4bf9-a898-299cfc7564e5"

    # AUDIT & DIRECTORY
    "AuditLog.Read.All" = "b0afded3-3588-46d8-8b3d-9842eff778da"
    "Directory.Read.All" = "7ab1d382-f21e-4acd-a863-ba3e13f7da61"
    "User.Read.All" = "df021288-bdef-4463-88db-98f22de89214"

    # THREAT INTELLIGENCE
    "IdentityRiskEvent.Read.All" = "6e472fd1-ad78-48da-a0f0-97ab2c6b769e"
    "IdentityRiskyUser.Read.All" = "dc5007c0-2d7d-4c42-879c-2dab87571379"
    "ThreatHunting.Read.All" = "dd98c7f5-2d42-42d3-a0e4-633161547251"
    "SecurityActions.Read.All" = "5e0edab9-c148-49d0-b423-ac253e121825"

    # INVESTIGATION SUPPORT
    "Sites.Read.All" = "332a536c-c7ef-4017-ab91-336970924f0d"
    "Mail.Read" = "810c84a8-4a9e-49e6-bf7d-12d183f40d01"
}

$FullResponsePermissions = @{
    "User.ReadWrite.All" = "741f803b-c850-494e-b5df-cde7c675a1ca"
    "SecurityActions.ReadWrite.All" = "f2bf083f-0179-402a-bedb-b2784de8a49b"
    "UserAuthenticationMethod.ReadWrite.All" = "50483e42-d915-4231-9639-7fdb7fd190e5"
    "RoleManagement.ReadWrite.Directory" = "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8"
}

# Log Analytics permission
$LogAnalyticsPermission = @{
    "Data.Read" = "0c0bf378-bf22-4481-8f81-9e89a9b4960a"
}

# Clear screen
Clear-Host

Write-Host "`n╔════════════════════════════════════════════════════════════════╗" -ForegroundColor $ColorInfo
Write-Host "║   CloudRaider Security Monitoring - Service Principal Setup   ║" -ForegroundColor $ColorInfo
Write-Host "║                        Version 2.0                            ║" -ForegroundColor $ColorInfo
Write-Host "╚════════════════════════════════════════════════════════════════╝`n" -ForegroundColor $ColorInfo

Write-Host "Customer: " -NoNewline -ForegroundColor Gray
Write-Host $CustomerName -ForegroundColor $ColorHighlight

if ($Uninstall) {
    Write-Host "Mode: " -NoNewline -ForegroundColor Gray
    Write-Host "UNINSTALL (Complete Removal)" -ForegroundColor $ColorError
} else {
    Write-Host "Access Level: " -NoNewline -ForegroundColor Gray
    Write-Host $AccessLevel -ForegroundColor $ColorHighlight
    Write-Host "Mode: " -NoNewline -ForegroundColor Gray
    Write-Host "AUTO-DETECT (will determine best action)`n" -ForegroundColor $ColorSuccess
}

#region Prerequisites Check
Write-Host "[1/8] Checking prerequisites..." -ForegroundColor $ColorInfo

if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Host "   ✗ PowerShell 7+ required (you have $($PSVersionTable.PSVersion))" -ForegroundColor $ColorError
    Write-Host "   Install from: https://aka.ms/powershell`n" -ForegroundColor Gray
    exit 1
}
Write-Host "   ✓ PowerShell version: $($PSVersionTable.PSVersion)" -ForegroundColor $ColorSuccess
#endregion

#region Module Check
Write-Host "`n[2/8] Checking Microsoft.Graph module..." -ForegroundColor $ColorInfo

$GraphModule = Get-Module -ListAvailable -Name Microsoft.Graph.Applications | Select-Object -First 1
if (-not $GraphModule) {
    Write-Host "   ⚠ Microsoft.Graph module not found - installing..." -ForegroundColor $ColorWarning
    try {
        Install-Module Microsoft.Graph -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
        Write-Host "   ✓ Module installed" -ForegroundColor $ColorSuccess
    } catch {
        Write-Host "   ✗ Failed to install module: $($_.Exception.Message)" -ForegroundColor $ColorError
        exit 1
    }
} else {
    Write-Host "   ✓ Module found: $($GraphModule.Version)" -ForegroundColor $ColorSuccess
}

Import-Module Microsoft.Graph.Applications -ErrorAction Stop
Import-Module Microsoft.Graph.Users -ErrorAction Stop
#endregion

#region Connect to Graph
Write-Host "`n[3/8] Connecting to Microsoft Graph..." -ForegroundColor $ColorInfo
Write-Host "   (Browser window will open for authentication)`n" -ForegroundColor Gray

try {
    Connect-MgGraph -Scopes "Application.ReadWrite.All", "Directory.ReadWrite.All", "RoleManagement.ReadWrite.Directory", "AppRoleAssignment.ReadWrite.All" -ErrorAction Stop | Out-Null
    Write-Host "   ✓ Connected to Microsoft Graph" -ForegroundColor $ColorSuccess
} catch {
    Write-Host "   ✗ Failed to connect: $($_.Exception.Message)" -ForegroundColor $ColorError
    exit 1
}

$Context = Get-MgContext
$TenantId = $Context.TenantId
#endregion

#region Verify Global Admin
Write-Host "`n[4/8] Verifying administrator permissions..." -ForegroundColor $ColorInfo

$CurrentUser = Get-MgUser -UserId $Context.Account
$GlobalAdminRole = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'" | Select-Object -First 1

if ($GlobalAdminRole) {
    $IsGlobalAdmin = Get-MgDirectoryRoleMember -DirectoryRoleId $GlobalAdminRole.Id | Where-Object { $_.Id -eq $CurrentUser.Id }

    if ($IsGlobalAdmin) {
        Write-Host "   ✓ Confirmed: You are a Global Administrator" -ForegroundColor $ColorSuccess
    } else {
        Write-Host "   ✗ Error: You must be a Global Administrator" -ForegroundColor $ColorError
        Disconnect-MgGraph | Out-Null
        exit 1
    }
}
#endregion

#region Detect Current State
Write-Host "`n[5/8] Detecting current state..." -ForegroundColor $ColorInfo

$ExistingApp = Get-MgApplication -Filter "displayName eq '$AppName'" -ErrorAction SilentlyContinue | Select-Object -First 1
$ExistingSP = $null
$GrantedPermissions = @()
$MissingPermissions = @()

if ($ExistingApp) {
    Write-Host "   → Found existing app: $($ExistingApp.AppId)" -ForegroundColor $ColorWarning

    # Get service principal
    $ExistingSP = Get-MgServicePrincipal -Filter "appId eq '$($ExistingApp.AppId)'" -ErrorAction SilentlyContinue | Select-Object -First 1

    if ($ExistingSP) {
        Write-Host "   → Found service principal: $($ExistingSP.Id)" -ForegroundColor $ColorWarning

        # Check granted permissions
        $Assignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ExistingSP.Id -ErrorAction SilentlyContinue
        $GrantedPermissions = $Assignments.AppRoleId

        Write-Host "   → Granted permissions: $($GrantedPermissions.Count)" -ForegroundColor Gray

        # Check for missing permissions
        $AllRequired = $RequiredPermissions.Values
        if ($AccessLevel -eq "FullResponse") {
            $AllRequired += $FullResponsePermissions.Values
        }
        $AllRequired += $LogAnalyticsPermission.Values

        foreach ($perm in $AllRequired) {
            if ($perm -notin $GrantedPermissions) {
                $MissingPermissions += $perm
            }
        }

        if ($MissingPermissions.Count -gt 0) {
            Write-Host "   → Missing permissions: $($MissingPermissions.Count)" -ForegroundColor $ColorWarning
        } else {
            Write-Host "   → All permissions granted" -ForegroundColor $ColorSuccess
        }
    } else {
        Write-Host "   → No service principal found (incomplete setup)" -ForegroundColor $ColorWarning
    }
} else {
    Write-Host "   → No existing app found (fresh install)" -ForegroundColor $ColorSuccess
}
#endregion

#region Determine Action
Write-Host "`n[6/8] Determining action..." -ForegroundColor $ColorInfo

$Action = "Unknown"

if ($Uninstall) {
    if ($ExistingApp) {
        $Action = "Uninstall"
        Write-Host "   → ACTION: Complete removal of CloudRaiderSOC" -ForegroundColor $ColorError
    } else {
        Write-Host "   → Nothing to uninstall - app doesn't exist" -ForegroundColor $ColorWarning
        Disconnect-MgGraph | Out-Null
        exit 0
    }
} elseif (-not $ExistingApp) {
    $Action = "FreshInstall"
    Write-Host "   → ACTION: Fresh installation" -ForegroundColor $ColorSuccess
} elseif (-not $ExistingSP) {
    $Action = "RepairSP"
    Write-Host "   → ACTION: Create missing service principal" -ForegroundColor $ColorWarning
} elseif ($MissingPermissions.Count -gt 0) {
    $Action = "RepairPermissions"
    Write-Host "   → ACTION: Grant $($MissingPermissions.Count) missing permissions + new secret" -ForegroundColor $ColorWarning
} else {
    $Action = "NewSecretOnly"
    Write-Host "   → ACTION: Generate new secret (all permissions OK)" -ForegroundColor $ColorSuccess
}
#endregion

#region Execute Action
Write-Host "`n[7/8] Executing: $Action..." -ForegroundColor $ColorInfo

switch ($Action) {
    "Uninstall" {
        Write-Host "   Removing app registration..." -ForegroundColor Yellow
        Remove-MgApplication -ApplicationId $ExistingApp.Id -ErrorAction Stop
        Write-Host "   ✓ CloudRaiderSOC removed completely" -ForegroundColor $ColorSuccess
        Write-Host "`n   You can now re-run this script for a fresh install.`n" -ForegroundColor Gray
        Disconnect-MgGraph | Out-Null
        exit 0
    }

    "FreshInstall" {
        # Build permission list
        $GraphPermissions = @()
        foreach ($perm in $RequiredPermissions.Values) {
            $GraphPermissions += @{ Id = $perm; Type = "Role" }
        }
        if ($AccessLevel -eq "FullResponse") {
            foreach ($perm in $FullResponsePermissions.Values) {
                $GraphPermissions += @{ Id = $perm; Type = "Role" }
            }
        }

        $LogAnalyticsPermissions = @()
        foreach ($perm in $LogAnalyticsPermission.Values) {
            $LogAnalyticsPermissions += @{ Id = $perm; Type = "Role" }
        }

        # Create app
        Write-Host "   Creating app registration..." -ForegroundColor Gray

        $AppParams = @{
            DisplayName = $AppName
            SignInAudience = "AzureADMyOrg"
            RequiredResourceAccess = @(
                @{
                    ResourceAppId = $GraphAppId
                    ResourceAccess = $GraphPermissions
                },
                @{
                    ResourceAppId = $LogAnalyticsAppId
                    ResourceAccess = $LogAnalyticsPermissions
                }
            )
        }

        $App = New-MgApplication @AppParams -ErrorAction Stop
        Write-Host "   ✓ App created: $($App.AppId)" -ForegroundColor $ColorSuccess

        # Create service principal
        Write-Host "   Creating service principal..." -ForegroundColor Gray
        $ServicePrincipal = New-MgServicePrincipal -AppId $App.AppId -ErrorAction Stop
        Write-Host "   ✓ Service principal created" -ForegroundColor $ColorSuccess

        # Wait for replication
        Write-Host "   Waiting for Azure AD replication (15 seconds)..." -ForegroundColor Gray
        Start-Sleep -Seconds 15

        # Grant admin consent via API
        Write-Host "   Granting admin consent..." -ForegroundColor Gray

        # Get Microsoft Graph service principal
        $GraphSP = Get-MgServicePrincipal -Filter "appId eq '$GraphAppId'" | Select-Object -First 1
        $LogAnalyticsSP = Get-MgServicePrincipal -Filter "appId eq '$LogAnalyticsAppId'" | Select-Object -First 1

        # Grant Graph permissions
        foreach ($perm in $GraphPermissions) {
            try {
                New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ServicePrincipal.Id -PrincipalId $ServicePrincipal.Id -ResourceId $GraphSP.Id -AppRoleId $perm.Id -ErrorAction Stop | Out-Null
                Write-Host "   ✓ Granted: $($perm.Id)" -ForegroundColor Gray
            } catch {
                if ($_.Exception.Message -notlike "*already exists*") {
                    Write-Host "   ⚠ Failed to grant $($perm.Id): $($_.Exception.Message)" -ForegroundColor $ColorWarning
                }
            }
        }

        # Grant Log Analytics permissions
        if ($LogAnalyticsSP) {
            foreach ($perm in $LogAnalyticsPermissions) {
                try {
                    New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ServicePrincipal.Id -PrincipalId $ServicePrincipal.Id -ResourceId $LogAnalyticsSP.Id -AppRoleId $perm.Id -ErrorAction Stop | Out-Null
                    Write-Host "   ✓ Granted Log Analytics: $($perm.Id)" -ForegroundColor Gray
                } catch {
                    if ($_.Exception.Message -notlike "*already exists*") {
                        Write-Host "   ⚠ Log Analytics permission failed (may need manual consent)" -ForegroundColor $ColorWarning
                    }
                }
            }
        }

        Write-Host "   ✓ Permissions granted" -ForegroundColor $ColorSuccess

        $ExistingApp = $App
        $ExistingSP = $ServicePrincipal
    }

    "RepairSP" {
        Write-Host "   Creating missing service principal..." -ForegroundColor Gray
        $ExistingSP = New-MgServicePrincipal -AppId $ExistingApp.AppId -ErrorAction Stop
        Write-Host "   ✓ Service principal created" -ForegroundColor $ColorSuccess

        # Need to grant all permissions since SP was missing
        $MissingPermissions = $RequiredPermissions.Values
        if ($AccessLevel -eq "FullResponse") {
            $MissingPermissions += $FullResponsePermissions.Values
        }
        $MissingPermissions += $LogAnalyticsPermission.Values

        # Fall through to grant permissions
        $Action = "RepairPermissions"
    }

    "RepairPermissions" {
        Write-Host "   Granting missing permissions..." -ForegroundColor Gray

        Start-Sleep -Seconds 5

        $GraphSP = Get-MgServicePrincipal -Filter "appId eq '$GraphAppId'" | Select-Object -First 1
        $LogAnalyticsSP = Get-MgServicePrincipal -Filter "appId eq '$LogAnalyticsAppId'" | Select-Object -First 1

        $GrantedCount = 0
        foreach ($permId in $MissingPermissions) {
            # Determine which resource this permission belongs to
            $ResourceSP = $GraphSP
            if ($permId -in $LogAnalyticsPermission.Values) {
                $ResourceSP = $LogAnalyticsSP
            }

            if (-not $ResourceSP) { continue }

            try {
                New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ExistingSP.Id -PrincipalId $ExistingSP.Id -ResourceId $ResourceSP.Id -AppRoleId $permId -ErrorAction Stop | Out-Null
                $GrantedCount++
                Write-Host "   ✓ Granted: $permId" -ForegroundColor Gray
            } catch {
                if ($_.Exception.Message -like "*already exists*") {
                    Write-Host "   → Already granted: $permId" -ForegroundColor Gray
                } else {
                    Write-Host "   ⚠ Failed: $permId - $($_.Exception.Message)" -ForegroundColor $ColorWarning
                }
            }
        }

        Write-Host "   ✓ Granted $GrantedCount new permissions" -ForegroundColor $ColorSuccess
    }

    "NewSecretOnly" {
        Write-Host "   All permissions already granted - generating new secret only" -ForegroundColor $ColorSuccess
    }
}

# Generate new secret (for all actions except Uninstall)
if ($Action -ne "Uninstall") {
    Write-Host "`n   Generating new client secret..." -ForegroundColor Gray

    $SecretParams = @{
        PasswordCredential = @{
            DisplayName = "CloudRaider-Secret-$(Get-Date -Format 'yyyy-MM-dd-HHmmss')"
            EndDateTime = (Get-Date).AddMonths(24)
        }
    }

    $Secret = Add-MgApplicationPassword -ApplicationId $ExistingApp.Id -BodyParameter $SecretParams -ErrorAction Stop
    Write-Host "   ✓ New secret created (expires: $($Secret.EndDateTime.ToString('yyyy-MM-dd')))" -ForegroundColor $ColorSuccess
}
#endregion

#region Verify Permissions
Write-Host "`n[8/8] Verifying final state..." -ForegroundColor $ColorInfo

# Refresh service principal data
$FinalSP = Get-MgServicePrincipal -Filter "appId eq '$($ExistingApp.AppId)'" | Select-Object -First 1
$FinalAssignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $FinalSP.Id -ErrorAction SilentlyContinue
$FinalGranted = $FinalAssignments.AppRoleId

$AllRequired = $RequiredPermissions.Values + $LogAnalyticsPermission.Values
if ($AccessLevel -eq "FullResponse") {
    $AllRequired += $FullResponsePermissions.Values
}

$FinalMissing = @()
foreach ($perm in $AllRequired) {
    if ($perm -notin $FinalGranted) {
        $FinalMissing += $perm
    }
}

if ($FinalMissing.Count -eq 0) {
    Write-Host "   ✓ All $($FinalGranted.Count) permissions verified" -ForegroundColor $ColorSuccess
} else {
    Write-Host "   ⚠ $($FinalMissing.Count) permissions still missing:" -ForegroundColor $ColorWarning
    foreach ($perm in $FinalMissing) {
        $permName = ($RequiredPermissions.GetEnumerator() + $FullResponsePermissions.GetEnumerator() + $LogAnalyticsPermission.GetEnumerator() | Where-Object { $_.Value -eq $perm }).Key
        Write-Host "      - $permName ($perm)" -ForegroundColor Gray
    }
    Write-Host "`n   You may need to grant admin consent manually:" -ForegroundColor $ColorWarning
    Write-Host "   https://login.microsoftonline.com/$TenantId/adminconsent?client_id=$($ExistingApp.AppId)" -ForegroundColor Gray
}
#endregion

#region Output Credentials
Disconnect-MgGraph | Out-Null

Write-Host "`n" -ForegroundColor Gray
Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor $ColorSuccess
Write-Host "║                    SETUP COMPLETE                              ║" -ForegroundColor $ColorSuccess
Write-Host "╚════════════════════════════════════════════════════════════════╝`n" -ForegroundColor $ColorSuccess

Write-Host "📋 CREDENTIALS FOR CLOUDRAIDER TEAM" -ForegroundColor $ColorHighlight
Write-Host "════════════════════════════════════════════════════════════════`n" -ForegroundColor Gray

$EnvPrefix = ($CustomerName -replace '\s','').ToUpper()

Write-Host "Copy these lines to your secure credential sharing method:" -ForegroundColor Yellow
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`n" -ForegroundColor Gray

Write-Host "export ${EnvPrefix}_TENANT_ID=`"$TenantId`"" -ForegroundColor White
Write-Host "export ${EnvPrefix}_CLIENT_ID=`"$($ExistingApp.AppId)`"" -ForegroundColor White
Write-Host "export ${EnvPrefix}_CLIENT_SECRET=`"$($Secret.SecretText)`"" -ForegroundColor White
Write-Host "export ${EnvPrefix}_ACCESS_LEVEL=`"$AccessLevel`"`n" -ForegroundColor White

Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`n" -ForegroundColor Gray

Write-Host "⚠️  IMPORTANT:" -ForegroundColor $ColorWarning
Write-Host "   - COPY THE SECRET NOW - it cannot be retrieved later!" -ForegroundColor $ColorError
Write-Host "   - Send via secure channel (Teams, encrypted email)" -ForegroundColor Gray
Write-Host "   - Secret expires: $($Secret.EndDateTime.ToString('yyyy-MM-dd'))" -ForegroundColor Gray

Write-Host "`n📊 WHAT THIS SCRIPT DID:" -ForegroundColor $ColorInfo
Write-Host "   Action: $Action" -ForegroundColor Gray
Write-Host "   App ID: $($ExistingApp.AppId)" -ForegroundColor Gray
Write-Host "   Permissions: $($FinalGranted.Count) granted" -ForegroundColor Gray
if ($FinalMissing.Count -gt 0) {
    Write-Host "   Missing: $($FinalMissing.Count) (may need manual consent)" -ForegroundColor $ColorWarning
}

Write-Host "`n🔄 TO RE-RUN THIS SCRIPT:" -ForegroundColor $ColorInfo
Write-Host "   - Lost secret? Just run again - it auto-detects and generates new secret" -ForegroundColor Gray
Write-Host "   - Need clean start? Run with -Uninstall first, then run again" -ForegroundColor Gray

Write-Host "`n🗑️  TO REVOKE ACCESS:" -ForegroundColor $ColorInfo
Write-Host "   .\Setup-CloudRaider-ServicePrincipal.ps1 -CustomerName `"$CustomerName`" -Uninstall" -ForegroundColor Gray
Write-Host "   OR: Azure Portal → Azure AD → App registrations → Delete `"CloudRaiderSOC`"`n" -ForegroundColor Gray

# Save to file option
$SaveToFile = Read-Host "Save credentials to file? (y/N)"
if ($SaveToFile -eq 'y' -or $SaveToFile -eq 'Y') {
    $FileName = "CloudRaider-Credentials-$($CustomerName -replace '\s','-')-$(Get-Date -Format 'yyyy-MM-dd-HHmmss').txt"

    @"
CloudRaider Security Monitoring - Service Principal Credentials
================================================================

Customer: $CustomerName
Created: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Access Level: $AccessLevel
Action Performed: $Action
Secret Expires: $($Secret.EndDateTime.ToString('yyyy-MM-dd'))

CREDENTIALS (Copy to ~/.zsh_env or equivalent):
================================================================

export ${EnvPrefix}_TENANT_ID="$TenantId"
export ${EnvPrefix}_CLIENT_ID="$($ExistingApp.AppId)"
export ${EnvPrefix}_CLIENT_SECRET="$($Secret.SecretText)"
export ${EnvPrefix}_ACCESS_LEVEL="$AccessLevel"

================================================================

App Registration Details:
- Name: CloudRaiderSOC
- App ID: $($ExistingApp.AppId)
- Tenant ID: $TenantId
- Permissions Granted: $($FinalGranted.Count)
- Missing Permissions: $($FinalMissing.Count)

RE-RUN INSTRUCTIONS:
- Lost secret? Just run the script again (auto-detects state)
- Need clean start? Run with -Uninstall flag first

TO REVOKE:
- Run: .\Setup-CloudRaider-ServicePrincipal.ps1 -CustomerName "$CustomerName" -Uninstall

================================================================
SECURITY: Send this file via encrypted email or secure file share
DO NOT send via regular email - DELETE after sending
================================================================
"@ | Out-File -FilePath $FileName -Encoding UTF8

    Write-Host "`n✓ Credentials saved to: $FileName" -ForegroundColor $ColorSuccess
    Write-Host "  DELETE THIS FILE after sending to CloudRaider!`n" -ForegroundColor $ColorWarning
}

Write-Host "Questions? Contact support@cloudraider.com`n" -ForegroundColor Gray
