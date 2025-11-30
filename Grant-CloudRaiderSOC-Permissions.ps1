#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Grants admin consent for existing CloudRaiderSOC service principal

.DESCRIPTION
    Use this script when CloudRaiderSOC app exists but has no permissions granted.
    This happens if the original setup script failed at the consent step.

    This script programmatically grants all required Graph API permissions.

.EXAMPLE
    .\Grant-CloudRaiderSOC-Permissions.ps1

.NOTES
    Requirements:
    - You must be a Global Administrator
    - PowerShell 7+
    - CloudRaiderSOC app must already exist
#>

$ErrorActionPreference = "Stop"

Write-Host "`n╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║   CloudRaider - Grant Permissions to Existing App         ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan

# Import required modules
Write-Host "[1/5] Loading Microsoft Graph module..." -ForegroundColor Cyan
Import-Module Microsoft.Graph.Applications -ErrorAction Stop
Write-Host "   ✓ Module loaded" -ForegroundColor Green

# Connect to Microsoft Graph
Write-Host "`n[2/5] Connecting to Microsoft Graph..." -ForegroundColor Cyan
Write-Host "   (Browser window will open for authentication)`n" -ForegroundColor Gray

try {
    Connect-MgGraph -Scopes "Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All" -ErrorAction Stop | Out-Null
    $Context = Get-MgContext
    Write-Host "   ✓ Connected as: $($Context.Account)" -ForegroundColor Green
    Write-Host "   Tenant ID: $($Context.TenantId)" -ForegroundColor Gray
} catch {
    Write-Host "   ✗ Failed to connect: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Find CloudRaiderSOC
Write-Host "`n[3/5] Finding CloudRaiderSOC service principal..." -ForegroundColor Cyan
$CloudRaiderSP = Get-MgServicePrincipal -Filter "displayName eq 'CloudRaiderSOC'" -ErrorAction SilentlyContinue | Select-Object -First 1

if (-not $CloudRaiderSP) {
    Write-Host "   ✗ CloudRaiderSOC not found in this tenant" -ForegroundColor Red
    Write-Host "   Run Setup-CloudRaider-ServicePrincipal.ps1 first" -ForegroundColor Gray
    Disconnect-MgGraph | Out-Null
    exit 1
}

Write-Host "   ✓ Found CloudRaiderSOC" -ForegroundColor Green
Write-Host "   App ID: $($CloudRaiderSP.AppId)" -ForegroundColor Gray
Write-Host "   Object ID: $($CloudRaiderSP.Id)" -ForegroundColor Gray

# Check current permissions
$ExistingAssignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $CloudRaiderSP.Id -ErrorAction SilentlyContinue
Write-Host "   Current permissions: $($ExistingAssignments.Count)" -ForegroundColor Gray

# Find Microsoft Graph service principal
Write-Host "`n[4/5] Finding Microsoft Graph service principal..." -ForegroundColor Cyan
$GraphSP = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'" -ErrorAction Stop | Select-Object -First 1

if (-not $GraphSP) {
    Write-Host "   ✗ Microsoft Graph not found" -ForegroundColor Red
    exit 1
}

Write-Host "   ✓ Found Microsoft Graph (Object ID: $($GraphSP.Id))" -ForegroundColor Green

# Define all required permissions
# VERIFIED GUIDs from Microsoft Graph AppRoles query on 2025-11-30
# Source: Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'" | Select -Expand AppRoles
$PermissionsToGrant = @(
    # SECURITY - Core monitoring (VERIFIED FROM GRAPH API)
    @{ Id = "472e4a4d-bb4a-4026-98d1-0b0d74cb74a5"; Name = "SecurityAlert.Read.All" }
    @{ Id = "45cc0394-e837-488b-a098-1918f48d186c"; Name = "SecurityIncident.Read.All" }  # CRITICAL!
    @{ Id = "bf394140-e372-4bf9-a898-299cfc7564e5"; Name = "SecurityEvents.Read.All" }
    @{ Id = "5e0edab9-c148-49d0-b423-ac253e121825"; Name = "SecurityActions.Read.All" }
    @{ Id = "dd98c7f5-2d42-42d3-a0e4-633161547251"; Name = "ThreatHunting.Read.All" }

    # IDENTITY - User and risk detection
    @{ Id = "df021288-bdef-4463-88db-98f22de89214"; Name = "User.Read.All" }
    @{ Id = "7ab1d382-f21e-4acd-a863-ba3e13f7da61"; Name = "Directory.Read.All" }
    @{ Id = "dc5007c0-2d7d-4c42-879c-2dab87571379"; Name = "IdentityRiskyUser.Read.All" }
    @{ Id = "6e472fd1-ad78-48da-a0f0-97ab2c6b769e"; Name = "IdentityRiskEvent.Read.All" }  # Verified

    # AUDIT & REPORTING
    @{ Id = "b0afded3-3588-46d8-8b3d-9842eff778da"; Name = "AuditLog.Read.All" }
    @{ Id = "230c1aed-a721-4c5d-9cb4-a90514e508ef"; Name = "Reports.Read.All" }

    # DEVICE & POLICY
    @{ Id = "7438b122-aefc-4978-80ed-43db9fcc7715"; Name = "Device.Read.All" }
    @{ Id = "246dd0d5-5bd0-4def-940b-0421030a5b68"; Name = "Policy.Read.All" }
    @{ Id = "498476ce-e0fe-48b0-b801-37ba7e2685c6"; Name = "Organization.Read.All" }
)

# Grant each permission
Write-Host "`n[5/5] Granting permissions..." -ForegroundColor Cyan

$Granted = 0
$AlreadyExists = 0
$Failed = 0

foreach ($Permission in $PermissionsToGrant) {
    # Check if already granted
    $Existing = $ExistingAssignments | Where-Object { $_.AppRoleId -eq $Permission.Id }

    if ($Existing) {
        Write-Host "   [EXISTS] $($Permission.Name)" -ForegroundColor Yellow
        $AlreadyExists++
        continue
    }

    try {
        $Params = @{
            PrincipalId = $CloudRaiderSP.Id
            ResourceId = $GraphSP.Id
            AppRoleId = $Permission.Id
        }

        New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $CloudRaiderSP.Id -BodyParameter $Params -ErrorAction Stop | Out-Null
        Write-Host "   [OK] $($Permission.Name)" -ForegroundColor Green
        $Granted++
    }
    catch {
        Write-Host "   [FAIL] $($Permission.Name): $($_.Exception.Message)" -ForegroundColor Red
        $Failed++
    }
}

# Try Log Analytics permission
Write-Host "`n   Checking Log Analytics API..." -ForegroundColor Gray
$LogAnalyticsSP = Get-MgServicePrincipal -Filter "appId eq 'ca7f3f0b-7d91-482c-8e09-c5d840d0eac5'" -ErrorAction SilentlyContinue | Select-Object -First 1

if ($LogAnalyticsSP) {
    try {
        $Params = @{
            PrincipalId = $CloudRaiderSP.Id
            ResourceId = $LogAnalyticsSP.Id
            AppRoleId = "0c0bf378-bf22-4481-8f81-9e89a9b4960a"
        }
        New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $CloudRaiderSP.Id -BodyParameter $Params -ErrorAction Stop | Out-Null
        Write-Host "   [OK] Log Analytics Data.Read" -ForegroundColor Green
    }
    catch {
        if ($_.Exception.Message -match "already exists") {
            Write-Host "   [EXISTS] Log Analytics Data.Read" -ForegroundColor Yellow
        } else {
            Write-Host "   [FAIL] Log Analytics: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
} else {
    Write-Host "   [SKIP] Log Analytics API not found in tenant" -ForegroundColor Gray
}

# Disconnect
Disconnect-MgGraph | Out-Null

# Summary
Write-Host "`n════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "SUMMARY" -ForegroundColor Cyan
Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "   New grants:      $Granted" -ForegroundColor Green
Write-Host "   Already existed: $AlreadyExists" -ForegroundColor Yellow
Write-Host "   Failed:          $Failed" -ForegroundColor $(if ($Failed -gt 0) { "Red" } else { "Gray" })
Write-Host ""

if ($Failed -eq 0) {
    Write-Host "✓ SUCCESS - CloudRaiderSOC now has Graph API permissions!" -ForegroundColor Green
    Write-Host ""
    Write-Host "CloudRaider can now access:" -ForegroundColor Gray
    Write-Host "  - Security alerts and incidents" -ForegroundColor Gray
    Write-Host "  - Audit logs and user data" -ForegroundColor Gray
    Write-Host "  - Threat hunting and risk data" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Next step: Notify CloudRaider that permissions are granted" -ForegroundColor Cyan
} else {
    Write-Host "⚠ Some permissions failed to grant" -ForegroundColor Yellow
    Write-Host "  You may need to grant them manually in Azure Portal:" -ForegroundColor Gray
    Write-Host "  Azure AD → Enterprise applications → CloudRaiderSOC → Permissions" -ForegroundColor Gray
}

Write-Host ""
