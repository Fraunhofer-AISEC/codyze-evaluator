#!/bin/bash

# Check if .gitignore exists and add gradle.properties if needed
if [ ! -f .gitignore ] || ! grep -q "gradle.properties" .gitignore; then
    echo "gradle.properties" >> .gitignore
fi

# Prompt for GitHub username
read -p "Enter your GitHub username: " username

# Create gradle.properties with current timestamp and warning
cat > gradle.properties << EOF
# WARNING: This file contains sensitive information - DO NOT commit to version control!

gpr.user=$username
EOF

# Prompt for GitHub token with link to create one
echo "Create a Personal Access Token (PAT) with 'read:packages' scope at:"
echo "https://github.com/settings/tokens/new?scopes=read:packages&description=Read-only%20access%20to%20GitHub%20Package%20Registry"
read -p "Enter your GitHub Personal Access Token: " token
echo "gpr.token=$token" >> gradle.properties
