#!/bin/bash
set -e

echo "Starting EC2 Setup..."

# 1. Setup 4GB Swap
if [ ! -f /swapfile ]; then
    echo "Setting up swap..."
    sudo fallocate -l 4G /swapfile
    sudo chmod 600 /swapfile
    sudo mkswap /swapfile
    sudo swapon /swapfile
    echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
    echo "Swap configured."
else
    echo "Swap already exists."
fi

# 2. Install Docker
if ! command -v docker &> /dev/null; then
    echo "Installing Docker..."
    curl -fsSL https://get.docker.com -o get-docker.sh
    sudo sh get-docker.sh
    sudo apt-get install -y git make
    sudo usermod -aG docker ubuntu
    echo "Docker installed."
else
    echo "Docker already installed."
fi

# 3. Clone repo
if [ ! -d "tsengine" ]; then
    echo "Cloning repo..."
    git clone https://github.com/ClatTribe/tsengine.git
fi

cd tsengine

# 4. Setup .env
cat <<EOF > .env
TSENGINE_SECRET_KEY=$(openssl rand -base64 32)
TSENGINE_PLATFORM_TOKEN=$(openssl rand -hex 32)
TSENGINE_PLATFORM_DB=postgresql://postgres.ppxwwbtfcceofbbtacao:TensorShield2026Secure@aws-0-ap-south-1.pooler.supabase.com:6543/postgres?sslmode=require
TSENGINE_SITE_ADDRESS=13-232-90-121.sslip.io
TSENGINE_ACME_EMAIL=admin@13-232-90-121.sslip.io
TSENGINE_PLATFORM_PUBLIC=https://13-232-90-121.sslip.io

# Connectors - GitHub
GITHUB_CLIENT_ID=
GITHUB_CLIENT_SECRET=

# Connectors - AWS
AWS_CFN_TEMPLATE_URL=
AWS_TRUST_ACCOUNT_ID=
AWS_REGION=us-east-1
EOF

# Drop 'tls internal' from Caddyfile so it uses public ACME Let's Encrypt
sed -i 's/tls internal//g' docker/caddy/Caddyfile

# 5. Build and deploy
echo "Building sandbox image..."
# use newgrp docker conceptually, but script runs under sudo or we just use sudo docker if needed
sudo docker compose version
sudo make sandbox-image

echo "Deploying prod..."
sudo make deploy-prod

echo "Setup Complete!"
