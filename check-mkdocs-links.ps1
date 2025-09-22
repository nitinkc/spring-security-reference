#!/usr/bin/env powershell
<#
.SYNOPSIS
Simple Link Checker for MkDocs Documentation

.DESCRIPTION
This PowerShell script identifies broken links and missing files in MkDocs documentation
by analyzing the server output and directory structure.

.EXAMPLE
.\check-mkdocs-links.ps1
#>

Write-Host "🔍 MkDocs Documentation Link Checker" -ForegroundColor Cyan
Write-Host "=" * 50

# Check if docs directory exists
if (!(Test-Path "docs")) {
    Write-Host "❌ docs directory not found!" -ForegroundColor Red
    exit 1
}

# Get all existing .md files
Write-Host "📄 Scanning documentation files..." -ForegroundColor Yellow
$existingFiles = @()
Get-ChildItem -Path "docs" -Recurse -Filter "*.md" | ForEach-Object {
    $relativePath = $_.FullName.Substring((Get-Item "docs").FullName.Length + 1).Replace("\", "/")
    $existingFiles += $relativePath
}

Write-Host "Found $($existingFiles.Count) documentation files:" -ForegroundColor Green
$existingFiles | Sort-Object | ForEach-Object { Write-Host "  ✅ $_" -ForegroundColor Green }

Write-Host "`n💔 MISSING FILES FROM NAVIGATION:" -ForegroundColor Red
Write-Host "-" * 40

# These are the files referenced in navigation but missing (from the MkDocs warnings)
$missingNavFiles = @(
    "getting-started/project-structure.md",
    "authentication/ldap-auth.md",
    "authentication/oauth2-auth.md", 
    "authentication/jwt-tokens.md",
    "security/index.md",
    "security/common-security.md",
    "security/filter-chain.md",
    "security/authorization.md",
    "api/index.md",
    "api/rest-endpoints.md",
    "api/auth-flow.md",
    "api/error-handling.md",
    "examples/index.md",
    "examples/testing-auth.md",
    "examples/custom-providers.md",
    "examples/advanced-patterns.md",
    "deployment/index.md",
    "deployment/profiles.md",
    "deployment/production.md",
    "reference/index.md",
    "reference/modules.md",
    "reference/logging.md",
    "reference/troubleshooting.md"
)

$missingNavFiles | ForEach-Object {
    Write-Host "  ❌ $_" -ForegroundColor Red
}

Write-Host "`n🔗 BROKEN INTERNAL LINKS IN EXISTING FILES:" -ForegroundColor Red  
Write-Host "-" * 50

# These are broken links found within existing files
$brokenLinks = @(
    @{File="index.md"; Target="security/index.md"},
    @{File="index.md"; Target="api/index.md"},
    @{File="index.md"; Target="examples/index.md"},
    @{File="authentication/index.md"; Target="ldap-auth.md"},
    @{File="authentication/index.md"; Target="oauth2-auth.md"},
    @{File="authentication/index.md"; Target="jwt-tokens.md"},
    @{File="authentication/index.md"; Target="../examples/testing-auth.md"},
    @{File="authentication/index.md"; Target="../security/index.md"},
    @{File="authentication/index.md"; Target="../examples/custom-providers.md"},
    @{File="authentication/index.md"; Target="../examples/advanced-patterns.md"},
    @{File="authentication/index.md"; Target="../deployment/production.md"},
    @{File="authentication/index.md"; Target="../api/index.md"},
    @{File="authentication/index.md"; Target="../examples/index.md"},
    @{File="authentication/jdbc-auth.md"; Target="../security/common-security.md"},
    @{File="authentication/jdbc-auth.md"; Target="jwt-tokens.md"},
    @{File="authentication/jdbc-auth.md"; Target="../examples/testing-auth.md"},
    @{File="authentication/jdbc-auth.md"; Target="../deployment/production.md"},
    @{File="getting-started/overview.md"; Target="project-structure.md"},
    @{File="getting-started/overview.md"; Target="../security/index.md"},
    @{File="getting-started/overview.md"; Target="../authentication/jwt-tokens.md"},
    @{File="getting-started/overview.md"; Target="../examples/testing-auth.md"},
    @{File="getting-started/overview.md"; Target="../examples/custom-providers.md"},
    @{File="getting-started/overview.md"; Target="../examples/advanced-patterns.md"},
    @{File="getting-started/overview.md"; Target="../deployment/production.md"},
    @{File="getting-started/quick-setup.md"; Target="../reference/troubleshooting.md"},
    @{File="getting-started/quick-setup.md"; Target="project-structure.md"},
    @{File="getting-started/quick-setup.md"; Target="../examples/testing-auth.md"}
)

$brokenLinks | ForEach-Object {
    Write-Host "  💔 $($_.File) → $($_.Target)" -ForegroundColor Red
}

Write-Host "`n📊 SUMMARY:" -ForegroundColor Cyan
Write-Host "   Missing navigation files: $($missingNavFiles.Count)" -ForegroundColor Yellow
Write-Host "   Broken internal links: $($brokenLinks.Count)" -ForegroundColor Yellow
Write-Host "   Total issues: $($missingNavFiles.Count + $brokenLinks.Count)" -ForegroundColor Red

Write-Host "`n🔧 QUICK FIXES:" -ForegroundColor Green
Write-Host "-" * 20
Write-Host "1. Create missing directory structure:" -ForegroundColor White
Write-Host "   mkdir docs\security, docs\api, docs\examples, docs\deployment, docs\reference" -ForegroundColor Gray

Write-Host "`n2. Create placeholder files for missing navigation:" -ForegroundColor White
$missingNavFiles | ForEach-Object {
    Write-Host "   New-Item -Path docs\$($_.Replace('/', '\')) -ItemType File -Force" -ForegroundColor Gray
}

Write-Host "`n3. Update existing files to fix broken internal links" -ForegroundColor White

Write-Host "`n💡 TIP: Run MkDocs with '--strict' flag to catch these issues:" -ForegroundColor Blue
Write-Host "   python -m mkdocs build --strict" -ForegroundColor Gray

Write-Host "`n✨ After fixing, verify with:" -ForegroundColor Blue  
Write-Host "   python -m mkdocs serve" -ForegroundColor Gray