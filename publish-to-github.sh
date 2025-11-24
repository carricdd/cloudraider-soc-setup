#!/bin/bash
# Publish CloudRaider SOC Setup to GitHub

set -e  # Exit on error

echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║   Publishing CloudRaider SOC Setup to GitHub                  ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

# Navigate to the repository directory
cd /tmp/cloudraider-soc-setup

# Check if gh is logged in
if ! gh auth status &> /dev/null; then
  echo "❌ GitHub CLI not authenticated. Run: gh auth login"
  exit 1
fi

echo "✓ GitHub CLI authenticated"
echo ""

# Initialize git repository
if [ ! -d .git ]; then
  echo "Initializing git repository..."
  git init
  echo "✓ Git repository initialized"
else
  echo "✓ Git repository already initialized"
fi

# Add all files
echo ""
echo "Adding files..."
git add .
echo "✓ Files added"

# Create initial commit
echo ""
echo "Creating commit..."
git commit -m "Initial commit: CloudRaider Service Principal Setup v1.2

- PowerShell script for automated service principal creation
- Two access levels: ReadOnly and FullResponse
- Microsoft Graph API permissions for M365 security monitoring
- Azure Log Analytics API permissions for Sentinel workspace queries
- Comprehensive README with security documentation
- Self-service customer onboarding" || echo "✓ Files already committed"

# Check if repository already exists
REPO_EXISTS=$(gh repo view carricdd/cloudraider-soc-setup &> /dev/null && echo "yes" || echo "no")

if [ "$REPO_EXISTS" = "yes" ]; then
  echo ""
  echo "⚠️  Repository carricdd/cloudraider-soc-setup already exists"
  echo ""
  read -p "Delete and recreate? (y/N): " -n 1 -r
  echo ""
  if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Deleting existing repository..."
    gh repo delete carricdd/cloudraider-soc-setup --yes
    echo "✓ Repository deleted"
    sleep 2
  else
    echo "Aborting. Repository already exists."
    exit 1
  fi
fi

# Create GitHub repository and push
echo ""
echo "Creating GitHub repository and pushing..."
gh repo create carricdd/cloudraider-soc-setup \
  --public \
  --source=. \
  --description="Automated Service Principal Setup for CloudRaider SOC Monitoring - Self-service M365 security configuration" \
  --push

echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║   ✅ SUCCESS! Repository Published                            ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""
echo "Repository URL: https://github.com/carricdd/cloudraider-soc-setup"
echo ""
echo "Next steps:"
echo "1. Add topics to the repository:"
echo "   gh repo edit carricdd/cloudraider-soc-setup --add-topic microsoft-365,sentinel,security,powershell,soc,cloudraider"
echo ""
echo "2. Create v1.2 release:"
echo "   gh release create v1.2 --title 'v1.2 - Azure Log Analytics API Support' --notes 'Added Azure Log Analytics API permissions for Sentinel workspace queries'"
echo ""
echo "3. Send to CGL:"
echo "   'Run this 5-minute script: https://github.com/carricdd/cloudraider-soc-setup'"
echo ""
