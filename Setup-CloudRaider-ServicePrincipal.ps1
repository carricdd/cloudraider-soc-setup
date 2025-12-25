#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Creates or repairs CloudRaider Service Principals for MSSP operations.

.DESCRIPTION
    THREE-TIER SERVICE PRINCIPAL MODEL:

    ┌─────────────────────────────────────────────────────────────────────────┐
    │  CLOUDRAIDER SERVICE PRINCIPAL ARCHITECTURE                             │
    ├─────────────────────────────────────────────────────────────────────────┤
    │                                                                         │
    │  CloudRaider-SOC (Required for all customers)                          │
    │  ├── Continuous security monitoring                                     │
    │  ├── Alert detection and triage                                         │
    │  ├── Security posture assessment                                        │
    │  ├── Vulnerability management                                           │
    │  └── Threat hunting                                                     │
    │                                                                         │
    │  CloudRaider-IR (Break-glass for incident response)                    │
    │  ├── Block compromised accounts                                         │
    │  ├── Revoke OAuth consents                                              │
    │  ├── Update Conditional Access                                          │
    │  ├── Isolate endpoints (MDE)                                            │
    │  └── Remove malicious persistence                                       │
    │                                                                         │
    │  CloudRaider-Admin (For managed services customers)                    │
    │  ├── User provisioning                                                  │
    │  ├── License management                                                 │
    │  ├── Device management                                                  │
    │  └── Policy configuration                                               │
    │                                                                         │
    └─────────────────────────────────────────────────────────────────────────┘

    SMART AUTO-DETECTION: This script automatically detects the current state
    and takes the appropriate action (create, repair, or update).

.PARAMETER CustomerName
    Your company name (used for naming environment variables)

.PARAMETER SPType
    Which SP to create/update: 'SOC', 'IR', 'Admin', or 'All'
    Default: 'SOC' (minimum required for all customers)

.PARAMETER Uninstall
    Remove specified SP(s) completely for clean restart

.PARAMETER ForceNewSecret
    Force generation of new secret even if permissions are OK

.EXAMPLE
    # SOC customers (monitoring only) - creates SOC + IR
    .\Setup-CloudRaider-ServicePrincipal.ps1 -CustomerName "Acme Corp"

.EXAMPLE
    # Full managed services customer - creates all three
    .\Setup-CloudRaider-ServicePrincipal.ps1 -CustomerName "Acme Corp" -SPType All

.EXAMPLE
    # Just IR for incident response capability
    .\Setup-CloudRaider-ServicePrincipal.ps1 -CustomerName "Acme Corp" -SPType IR

.EXAMPLE
    # Complete removal
    .\Setup-CloudRaider-ServicePrincipal.ps1 -CustomerName "Acme Corp" -Uninstall -SPType All

.NOTES
    Version: 3.0 - Three-Tier Model
    Last Updated: 2025-12-25 (Created during LifeScan AiTM Incident #9428)

    This version was developed based on real-world incident response experience
    where missing permissions prevented effective incident response.

    Requirements:
    - Global Administrator role
    - PowerShell 7+
    - Internet connection

    GitHub: https://github.com/carricdd/cloudraider-soc-setup
    Support: support@cloudraider.com
#>

param(
    [Parameter(Mandatory=$true, HelpMessage="Your company name (e.g. 'Acme Corp')")]
    [string]$CustomerName,

    [Parameter(Mandatory=$false)]
    [ValidateSet("SOC", "IR", "Admin", "All")]
    [string]$SPType = "SOC",

    [Parameter(Mandatory=$false)]
    [switch]$Uninstall,

    [Parameter(Mandatory=$false)]
    [switch]$ForceNewSecret
)

$ErrorActionPreference = "Stop"

#region Colors and Constants
$ColorInfo = "Cyan"
$ColorSuccess = "Green"
$ColorWarning = "Yellow"
$ColorError = "Red"
$ColorHighlight = "Magenta"

# Microsoft App IDs
$GraphAppId = "00000003-0000-0000-c000-000000000000"
$MDEAppId = "fc780465-2017-40d4-a0c5-307022471b92"
$LogAnalyticsAppId = "ca7f3f0b-7d91-482c-8e09-c5d840d0eac5"
#endregion

#region Permission Definitions

# =============================================================================
# CLOUDRAIDER-SOC PERMISSIONS
# Purpose: Continuous monitoring, detection, security posture assessment
# Risk Level: LOW (mostly read access)
# =============================================================================
$SOCPermissions = @{
    Graph = @{
        # AUDIT & LOGGING
        "AuditLog.Read.All" = "b0afded3-3588-46d8-8b3d-9842eff778da"
        "Reports.Read.All" = "230c1aed-a721-4c5d-9cb4-a90514e508ef"

        # DIRECTORY & IDENTITY
        "Directory.Read.All" = "7ab1d382-f21e-4acd-a863-ba3e13f7da61"
        "User.Read.All" = "df021288-bdef-4463-88db-98f22de89214"
        "Group.Read.All" = "5b567255-7703-4780-807c-7be8301ae99b"
        "RoleManagement.Read.Directory" = "483bed4a-2ad3-4361-a73b-c83ccdbdc53c"

        # RISK & THREAT
        "IdentityRiskEvent.Read.All" = "6e472fd1-ad78-48da-a0f0-97ab2c6b769e"
        "IdentityRiskyUser.Read.All" = "dc5007c0-2d7d-4c42-879c-2dab87571379"
        "ThreatHunting.Read.All" = "dd98c7f5-2d42-42d3-a0e4-633161547251"

        # SECURITY
        "SecurityEvents.Read.All" = "bf394140-e372-4bf9-a898-299cfc7564e5"
        "SecurityAlert.Read.All" = "472e4a4d-bb4a-4026-98d1-0b0d74cb74a5"
        "SecurityIncident.Read.All" = "45cc0394-e837-488b-a098-1918f48d186c"

        # POLICY
        "Policy.Read.All" = "246dd0d5-5bd0-4def-940b-0421030a5b68"

        # MAIL (for BEC detection)
        "Mail.Read" = "810c84a8-4a9e-49e6-bf7d-12d183f40d01"
        "MailboxSettings.Read" = "40f97065-369a-49f4-947c-6a255697ae91"

        # APPLICATIONS (OAuth consent monitoring)
        "Application.Read.All" = "9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30"

        # DEVICES
        "Device.Read.All" = "7438b122-aefc-4978-80ed-43db9fcc7715"
        "BitlockerKey.Read.All" = "57f1cf28-c0c4-4ec3-9a30-19a2eaaf2f6e"

        # SITES
        "Sites.Read.All" = "332a536c-c7ef-4017-ab91-336970924f0d"

        # INTUNE
        "DeviceManagementManagedDevices.Read.All" = "2f51be20-0bb4-4fed-bf7b-db946066c75e"
        "DeviceManagementConfiguration.Read.All" = "dc377aa6-52d8-4e23-b271-2a7ae04cedf3"
    }
    MDE = @{
        "Alert.Read.All" = "93489bf5-0fbc-4f2d-b901-33f2fe08ff05"
        "Machine.Read.All" = "ea8291d3-4b9a-44b5-bc3a-6cea3026dc79"
        "Vulnerability.Read.All" = "41269fc5-d04d-4bfd-bce7-43a51cea049a"
        "AdvancedQuery.Read.All" = "528ca142-c849-4a5b-935e-10b8b9c38a84"
        "Ti.Read.All" = "a8bc2240-f96a-46a1-bad5-6a960b7327a1"
        "Software.Read.All" = "c1b496f4-5f52-4e62-8cba-6f8b8ec0dbec"
    }
    LogAnalytics = @{
        "Data.Read" = "0c0bf378-bf22-4481-8f81-9e89a9b4960a"
    }
}

# =============================================================================
# CLOUDRAIDER-IR PERMISSIONS (Break-Glass Incident Response)
# Purpose: Take immediate action during security incidents
# Risk Level: HIGH (requires careful usage during incidents only)
# =============================================================================
$IRPermissions = @{
    Graph = @{
        # Inherit all SOC permissions (copied at runtime)

        # USER MANAGEMENT
        "User.ReadWrite.All" = "741f803b-c850-494e-b5df-cde7c675a1ca"
        "Directory.ReadWrite.All" = "19dbc75e-c2e2-444c-a770-ec69d8559fc7"
        "Group.ReadWrite.All" = "62a82d76-70ea-41e2-9197-370581804d09"
        "RoleManagement.ReadWrite.Directory" = "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8"
        "UserAuthenticationMethod.ReadWrite.All" = "50483e42-d915-4231-9639-7fdb7fd190e5"

        # CONDITIONAL ACCESS
        "Policy.ReadWrite.ConditionalAccess" = "01c0a623-fc9b-48e9-b794-0756f8e8f067"

        # APPLICATIONS
        "Application.ReadWrite.All" = "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9"

        # DEVICES
        "Device.ReadWrite.All" = "1138cb37-bd11-4084-a2b7-9f71582aeddb"

        # MAIL
        "Mail.ReadWrite" = "e2a3a72e-5f79-4c64-b1b1-878b674786c9"
        "Mail.Send" = "b633e1c5-b582-4048-a93e-9f11b44c7e96"
        "MailboxSettings.ReadWrite" = "6931bccd-447a-43d1-b442-00a195474933"

        # SECURITY
        "SecurityAlert.ReadWrite.All" = "ed4fca05-be46-441f-9803-1873825f8fdb"
        "SecurityIncident.ReadWrite.All" = "34bf0e97-1971-4929-b999-9e2442d941d7"
        "ThreatIndicators.ReadWrite.OwnedBy" = "21792b6c-c986-4ffc-85de-df9da54b52fa"
    }
    MDE = @{
        # Inherit SOC MDE permissions (copied at runtime)

        "Alert.ReadWrite.All" = "2261fd4a-5f23-4b74-9e4d-f4ac92dc86a2"
        "Machine.ReadWrite.All" = "0f7000ec-157b-497f-b70e-ef0b0584f140"
        "Machine.Isolate" = "7f615ee9-7c4d-48d6-86fa-f46dce27d0e0"
        "Machine.CollectForensics" = "c70c1c67-fdeb-443c-9e0d-6d7a9a1f2c84"
        "Machine.RestrictExecution" = "eccf22fd-5f8a-4e9c-a023-bc39d5e8a5c9"
        "Machine.Scan" = "b0ffcbf3-d6d8-46b1-9f89-93e2b7e8a5c7"
        "Machine.StopAndQuarantine" = "d6efc87e-8bed-4c63-abc8-5d52e9e4e0a5"
        "Machine.LiveResponse" = "f5e9d2d9-b6d7-4d82-a0c7-6e9e7e8a5c8d"
        "Ti.ReadWrite" = "aa027352-232b-4ed4-b963-a705fc4d6d2c"
    }
    LogAnalytics = @{
        "Data.Read" = "0c0bf378-bf22-4481-8f81-9e89a9b4960a"
    }
}

# =============================================================================
# CLOUDRAIDER-ADMIN PERMISSIONS (Tenant Administration)
# Purpose: Manage users, licenses, devices for managed services customers
# Risk Level: MEDIUM (admin tasks, not security-specific)
# =============================================================================
$AdminPermissions = @{
    Graph = @{
        # DIRECTORY FULL ACCESS
        "Directory.ReadWrite.All" = "19dbc75e-c2e2-444c-a770-ec69d8559fc7"
        "User.ReadWrite.All" = "741f803b-c850-494e-b5df-cde7c675a1ca"
        "Group.ReadWrite.All" = "62a82d76-70ea-41e2-9197-370581804d09"
        "RoleManagement.ReadWrite.Directory" = "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8"

        # LICENSING
        "Organization.Read.All" = "498476ce-e0fe-48b0-b801-37ba7e2685c6"

        # APPLICATIONS
        "Application.ReadWrite.All" = "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9"
        "AppRoleAssignment.ReadWrite.All" = "06b708a9-e830-4db3-a914-8e69da51d44f"

        # DEVICES
        "Device.ReadWrite.All" = "1138cb37-bd11-4084-a2b7-9f71582aeddb"

        # POLICIES
        "Policy.ReadWrite.ConditionalAccess" = "01c0a623-fc9b-48e9-b794-0756f8e8f067"
        "Policy.ReadWrite.AuthenticationMethod" = "29c18626-4985-4dcd-85c0-193eef327366"

        # INTUNE
        "DeviceManagementManagedDevices.ReadWrite.All" = "243333ab-4d21-40cb-a475-36241f0c327c"
        "DeviceManagementConfiguration.ReadWrite.All" = "9241abd9-d0e6-425a-bd4f-47ba86e767a4"
        "DeviceManagementApps.ReadWrite.All" = "78145de6-330d-4800-a6ce-494ff2d33d07"

        # MAIL
        "Mail.ReadWrite" = "e2a3a72e-5f79-4c64-b1b1-878b674786c9"
        "MailboxSettings.ReadWrite" = "6931bccd-447a-43d1-b442-00a195474933"

        # AUDIT
        "AuditLog.Read.All" = "b0afded3-3588-46d8-8b3d-9842eff778da"
    }
    MDE = @{}  # No MDE needed for admin tasks
    LogAnalytics = @{}
}

#endregion

#region Helper Functions

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Success', 'Warning', 'Error')]
        [string]$Level = 'Info'
    )

    $icons = @{
        Info = "[*]"
        Success = "[+]"
        Warning = "[!]"
        Error = "[-]"
    }

    $colors = @{
        Info = $ColorInfo
        Success = $ColorSuccess
        Warning = $ColorWarning
        Error = $ColorError
    }

    Write-Host "$($icons[$Level]) $Message" -ForegroundColor $colors[$Level]
}

function Get-SPConfig {
    param([string]$Type)

    $configs = @{
        SOC = @{
            AppName = "CloudRaider-SOC"
            Description = "CloudRaider MSSP - Security Operations Center (Monitoring & Assessment)"
            Permissions = $SOCPermissions
        }
        IR = @{
            AppName = "CloudRaider-IR"
            Description = "CloudRaider MSSP - Incident Response (Break-Glass)"
            Permissions = $IRPermissions
        }
        Admin = @{
            AppName = "CloudRaider-Admin"
            Description = "CloudRaider MSSP - Tenant Administration"
            Permissions = $AdminPermissions
        }
    }

    return $configs[$Type]
}

function Grant-AppPermissions {
    param(
        [string]$ServicePrincipalId,
        [hashtable]$Permissions
    )

    $granted = 0
    $skipped = 0
    $failed = 0

    # Get resource SPs
    $GraphSP = Get-MgServicePrincipal -Filter "appId eq '$GraphAppId'" | Select-Object -First 1
    $MDESP = Get-MgServicePrincipal -Filter "appId eq '$MDEAppId'" -ErrorAction SilentlyContinue | Select-Object -First 1
    $LogAnalyticsSP = Get-MgServicePrincipal -Filter "appId eq '$LogAnalyticsAppId'" -ErrorAction SilentlyContinue | Select-Object -First 1

    # Get current assignments
    $currentAssignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ServicePrincipalId -ErrorAction SilentlyContinue
    $currentRoleIds = $currentAssignments.AppRoleId

    # Grant Graph permissions
    foreach ($perm in $Permissions.Graph.GetEnumerator()) {
        if ($perm.Value -in $currentRoleIds) {
            $skipped++
            continue
        }
        try {
            New-MgServicePrincipalAppRoleAssignment `
                -ServicePrincipalId $ServicePrincipalId `
                -PrincipalId $ServicePrincipalId `
                -ResourceId $GraphSP.Id `
                -AppRoleId $perm.Value `
                -ErrorAction Stop | Out-Null
            $granted++
            Write-Host "      + $($perm.Key)" -ForegroundColor Gray
        } catch {
            if ($_.Exception.Message -notlike "*already exists*") {
                $failed++
                Write-Host "      ! $($perm.Key): $($_.Exception.Message)" -ForegroundColor $ColorWarning
            } else {
                $skipped++
            }
        }
    }

    # Grant MDE permissions
    if ($MDESP -and $Permissions.MDE.Count -gt 0) {
        foreach ($perm in $Permissions.MDE.GetEnumerator()) {
            if ($perm.Value -in $currentRoleIds) {
                $skipped++
                continue
            }
            try {
                New-MgServicePrincipalAppRoleAssignment `
                    -ServicePrincipalId $ServicePrincipalId `
                    -PrincipalId $ServicePrincipalId `
                    -ResourceId $MDESP.Id `
                    -AppRoleId $perm.Value `
                    -ErrorAction Stop | Out-Null
                $granted++
                Write-Host "      + MDE: $($perm.Key)" -ForegroundColor Gray
            } catch {
                if ($_.Exception.Message -notlike "*already exists*") {
                    $failed++
                } else {
                    $skipped++
                }
            }
        }
    }

    # Grant Log Analytics permissions
    if ($LogAnalyticsSP -and $Permissions.LogAnalytics.Count -gt 0) {
        foreach ($perm in $Permissions.LogAnalytics.GetEnumerator()) {
            if ($perm.Value -in $currentRoleIds) {
                $skipped++
                continue
            }
            try {
                New-MgServicePrincipalAppRoleAssignment `
                    -ServicePrincipalId $ServicePrincipalId `
                    -PrincipalId $ServicePrincipalId `
                    -ResourceId $LogAnalyticsSP.Id `
                    -AppRoleId $perm.Value `
                    -ErrorAction Stop | Out-Null
                $granted++
            } catch {
                if ($_.Exception.Message -notlike "*already exists*") {
                    $failed++
                } else {
                    $skipped++
                }
            }
        }
    }

    return @{ Granted = $granted; Skipped = $skipped; Failed = $failed }
}

function New-OrUpdateSP {
    param([string]$Type)

    $config = Get-SPConfig -Type $Type
    Write-Log "Processing: $($config.AppName)" -Level Info

    # Check if app exists
    $existingApp = Get-MgApplication -Filter "displayName eq '$($config.AppName)'" -ErrorAction SilentlyContinue | Select-Object -First 1
    $sp = $null

    if ($existingApp) {
        Write-Log "   Found existing app: $($existingApp.AppId)" -Level Info
        $sp = Get-MgServicePrincipal -Filter "appId eq '$($existingApp.AppId)'" -ErrorAction SilentlyContinue | Select-Object -First 1

        if (-not $sp) {
            Write-Log "   Creating missing service principal..." -Level Warning
            $sp = New-MgServicePrincipal -AppId $existingApp.AppId -ErrorAction Stop
        }
    } else {
        Write-Log "   Creating new app registration..." -Level Info
        $existingApp = New-MgApplication -DisplayName $config.AppName -SignInAudience "AzureADMyOrg" -Notes $config.Description -ErrorAction Stop
        Write-Log "   Created app: $($existingApp.AppId)" -Level Success

        $sp = New-MgServicePrincipal -AppId $existingApp.AppId -ErrorAction Stop
        Write-Log "   Created service principal" -Level Success

        Start-Sleep -Seconds 5  # Wait for replication
    }

    # Grant permissions
    Write-Log "   Granting permissions..." -Level Info
    $result = Grant-AppPermissions -ServicePrincipalId $sp.Id -Permissions $config.Permissions
    Write-Log "   Permissions: $($result.Granted) granted, $($result.Skipped) already present, $($result.Failed) failed" -Level Success

    # Generate secret
    Write-Log "   Generating client secret..." -Level Info
    $secret = Add-MgApplicationPassword -ApplicationId $existingApp.Id -PasswordCredential @{
        displayName = "CloudRaider-$(Get-Date -Format 'yyyy-MM-dd')"
        endDateTime = (Get-Date).AddYears(2)
    }
    Write-Log "   Secret created (expires: $($secret.EndDateTime.ToString('yyyy-MM-dd')))" -Level Success

    return @{
        Type = $Type
        AppName = $config.AppName
        AppId = $existingApp.AppId
        ObjectId = $sp.Id
        Secret = $secret.SecretText
        SecretExpires = $secret.EndDateTime
    }
}

function Remove-SP {
    param([string]$Type)

    $config = Get-SPConfig -Type $Type
    $existingApp = Get-MgApplication -Filter "displayName eq '$($config.AppName)'" -ErrorAction SilentlyContinue | Select-Object -First 1

    if ($existingApp) {
        Write-Log "Removing: $($config.AppName)" -Level Warning
        Remove-MgApplication -ApplicationId $existingApp.Id -ErrorAction Stop
        Write-Log "   Removed successfully" -Level Success
        return $true
    } else {
        Write-Log "$($config.AppName) not found - nothing to remove" -Level Info
        return $false
    }
}

#endregion

#region Main Script

Clear-Host

Write-Host "`n" -ForegroundColor Gray
Write-Host "╔════════════════════════════════════════════════════════════════════╗" -ForegroundColor $ColorInfo
Write-Host "║     CloudRaider MSSP - Service Principal Setup v3.0               ║" -ForegroundColor $ColorInfo
Write-Host "║     Three-Tier Model: SOC | IR | Admin                            ║" -ForegroundColor $ColorInfo
Write-Host "╚════════════════════════════════════════════════════════════════════╝`n" -ForegroundColor $ColorInfo

Write-Host "Customer: " -NoNewline -ForegroundColor Gray
Write-Host $CustomerName -ForegroundColor $ColorHighlight

Write-Host "SP Type:  " -NoNewline -ForegroundColor Gray
Write-Host $SPType -ForegroundColor $ColorHighlight

if ($Uninstall) {
    Write-Host "Mode:     " -NoNewline -ForegroundColor Gray
    Write-Host "UNINSTALL" -ForegroundColor $ColorError
}
Write-Host ""

# Determine which SPs to process
$spTypes = switch ($SPType) {
    "All"   { @("SOC", "IR", "Admin") }
    "SOC"   { @("SOC", "IR") }  # SOC customers get both SOC and IR
    "IR"    { @("IR") }
    "Admin" { @("Admin") }
}

# Prerequisites
Write-Log "Checking prerequisites..." -Level Info

if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Log "PowerShell 7+ required (you have $($PSVersionTable.PSVersion))" -Level Error
    exit 1
}
Write-Host "   PowerShell: $($PSVersionTable.PSVersion)" -ForegroundColor Gray

# Module check
$module = Get-Module -ListAvailable -Name Microsoft.Graph.Applications | Select-Object -First 1
if (-not $module) {
    Write-Log "Installing Microsoft.Graph module..." -Level Warning
    Install-Module Microsoft.Graph -Scope CurrentUser -Force -AllowClobber
}
Write-Host "   Microsoft.Graph: Installed" -ForegroundColor Gray

Import-Module Microsoft.Graph.Applications -ErrorAction Stop
Import-Module Microsoft.Graph.Users -ErrorAction Stop

# Connect
Write-Host ""
Write-Log "Connecting to Microsoft Graph..." -Level Info
Write-Host "   (Browser window will open for authentication)`n" -ForegroundColor Gray

try {
    Connect-MgGraph -Scopes @(
        "Application.ReadWrite.All"
        "AppRoleAssignment.ReadWrite.All"
        "Directory.ReadWrite.All"
        "RoleManagement.ReadWrite.Directory"
    ) -ErrorAction Stop | Out-Null
    $context = Get-MgContext
    Write-Log "Connected to tenant: $($context.TenantId)" -Level Success
} catch {
    Write-Log "Failed to connect: $_" -Level Error
    exit 1
}

# Verify Global Admin
Write-Log "Verifying Global Admin permissions..." -Level Info
$currentUser = Get-MgUser -UserId $context.Account -ErrorAction SilentlyContinue
$gaRole = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'" | Select-Object -First 1
if ($gaRole) {
    $isGA = Get-MgDirectoryRoleMember -DirectoryRoleId $gaRole.Id | Where-Object { $_.Id -eq $currentUser.Id }
    if ($isGA) {
        Write-Log "Confirmed: You are a Global Administrator" -Level Success
    } else {
        Write-Log "You must be a Global Administrator to run this script" -Level Error
        Disconnect-MgGraph | Out-Null
        exit 1
    }
}

# Process SPs
Write-Host ""
$results = @()

if ($Uninstall) {
    foreach ($type in $spTypes) {
        Remove-SP -Type $type
    }
    Write-Host ""
    Write-Log "Uninstall complete. You can re-run this script to reinstall." -Level Success
    Disconnect-MgGraph | Out-Null
    exit 0
}

foreach ($type in $spTypes) {
    Write-Host ""
    Write-Host "─────────────────────────────────────────────────────────────" -ForegroundColor Gray
    $result = New-OrUpdateSP -Type $type
    $results += $result
}

# Output
Disconnect-MgGraph | Out-Null

Write-Host "`n"
Write-Host "╔════════════════════════════════════════════════════════════════════╗" -ForegroundColor $ColorSuccess
Write-Host "║                        SETUP COMPLETE                              ║" -ForegroundColor $ColorSuccess
Write-Host "╚════════════════════════════════════════════════════════════════════╝`n" -ForegroundColor $ColorSuccess

$envPrefix = ($CustomerName -replace '\s','').ToUpper()

Write-Host "📋 CREDENTIALS FOR CLOUDRAIDER TEAM" -ForegroundColor $ColorHighlight
Write-Host "════════════════════════════════════════════════════════════════════`n" -ForegroundColor Gray

foreach ($r in $results) {
    $suffix = $r.Type.ToUpper()
    Write-Host "# CloudRaider-$($r.Type)" -ForegroundColor Cyan
    Write-Host "export ${envPrefix}_${suffix}_TENANT_ID=`"$($context.TenantId)`"" -ForegroundColor White
    Write-Host "export ${envPrefix}_${suffix}_CLIENT_ID=`"$($r.AppId)`"" -ForegroundColor White
    Write-Host "export ${envPrefix}_${suffix}_CLIENT_SECRET=`"$($r.Secret)`"" -ForegroundColor White
    Write-Host ""
}

Write-Host "════════════════════════════════════════════════════════════════════`n" -ForegroundColor Gray

Write-Host "⚠️  IMPORTANT:" -ForegroundColor $ColorWarning
Write-Host "   COPY THE SECRETS NOW - they cannot be retrieved later!" -ForegroundColor $ColorError
Write-Host "   Send via secure channel (Teams, encrypted email)" -ForegroundColor Gray

Write-Host "`n📊 WHAT WAS CREATED:" -ForegroundColor $ColorInfo
foreach ($r in $results) {
    Write-Host "   $($r.AppName): $($r.AppId)" -ForegroundColor Gray
}

Write-Host "`n🔄 TO RE-RUN:" -ForegroundColor $ColorInfo
Write-Host "   Just run again - it auto-detects and repairs/updates" -ForegroundColor Gray

Write-Host "`n🗑️  TO REVOKE ACCESS:" -ForegroundColor $ColorInfo
Write-Host "   .\Setup-CloudRaider-ServicePrincipal.ps1 -CustomerName `"$CustomerName`" -SPType $SPType -Uninstall`n" -ForegroundColor Gray

# Save to file option
$saveToFile = Read-Host "Save credentials to file? (y/N)"
if ($saveToFile -eq 'y' -or $saveToFile -eq 'Y') {
    $fileName = "CloudRaider-Credentials-$($CustomerName -replace '\s','-')-$(Get-Date -Format 'yyyy-MM-dd-HHmmss').txt"

    $content = @"
CloudRaider MSSP - Service Principal Credentials
═══════════════════════════════════════════════════════════════

Customer: $CustomerName
Created: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Tenant ID: $($context.TenantId)

"@

    foreach ($r in $results) {
        $suffix = $r.Type.ToUpper()
        $content += @"

# CloudRaider-$($r.Type)
# $($r.AppName)
# Secret expires: $($r.SecretExpires.ToString('yyyy-MM-dd'))

export ${envPrefix}_${suffix}_TENANT_ID="$($context.TenantId)"
export ${envPrefix}_${suffix}_CLIENT_ID="$($r.AppId)"
export ${envPrefix}_${suffix}_CLIENT_SECRET="$($r.Secret)"

"@
    }

    $content += @"

═══════════════════════════════════════════════════════════════

SERVICE PRINCIPAL MODEL:
- CloudRaider-SOC: Monitoring, detection, security posture
- CloudRaider-IR: Incident response (break-glass)
- CloudRaider-Admin: User/device/license management

RE-RUN: Just run the script again (auto-detects state)
UNINSTALL: Add -Uninstall flag

═══════════════════════════════════════════════════════════════
SECURITY: Delete this file after sending to CloudRaider
═══════════════════════════════════════════════════════════════
"@

    $content | Out-File -FilePath $fileName -Encoding UTF8
    Write-Host "`n✓ Saved to: $fileName" -ForegroundColor $ColorSuccess
    Write-Host "  DELETE after sending to CloudRaider!`n" -ForegroundColor $ColorWarning
}

Write-Host "Questions? support@cloudraider.com`n" -ForegroundColor Gray

#endregion
