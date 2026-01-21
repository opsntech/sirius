#!/bin/bash
# Installation script for Sirius AI DevOps Agent

set -e

echo "=== Sirius AI DevOps Agent Installation ==="

# Check Python version
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}' | cut -d. -f1,2)
REQUIRED_VERSION="3.11"

if [[ "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]]; then
    echo "Error: Python $REQUIRED_VERSION or higher is required (found $PYTHON_VERSION)"
    exit 1
fi

echo "Python version: $PYTHON_VERSION"

# Create installation directory
INSTALL_DIR="${INSTALL_DIR:-/opt/sirius}"
echo "Installing to: $INSTALL_DIR"

if [ ! -d "$INSTALL_DIR" ]; then
    sudo mkdir -p "$INSTALL_DIR"
    sudo chown $(whoami):$(whoami) "$INSTALL_DIR"
fi

# Copy files
echo "Copying files..."
cp -r src "$INSTALL_DIR/"
cp -r config "$INSTALL_DIR/"
cp requirements.txt "$INSTALL_DIR/"

# Create virtual environment
echo "Creating virtual environment..."
python3 -m venv "$INSTALL_DIR/venv"
source "$INSTALL_DIR/venv/bin/activate"

# Install dependencies
echo "Installing dependencies..."
pip install --upgrade pip
pip install -r "$INSTALL_DIR/requirements.txt"

# Create log directory
sudo mkdir -p /var/log/sirius
sudo chown $(whoami):$(whoami) /var/log/sirius

# Create systemd service user
if ! id "sirius" &>/dev/null; then
    echo "Creating sirius user..."
    sudo useradd -r -s /bin/false sirius
fi

# Set permissions
sudo chown -R sirius:sirius "$INSTALL_DIR"
sudo chown -R sirius:sirius /var/log/sirius

echo ""
echo "=== Installation Complete ==="
echo ""
echo "Next steps:"
echo "1. Configure NVIDIA API key:"
echo "   export NVIDIA_API_KEY='your-api-key'"
echo ""
echo "2. Edit configuration:"
echo "   vi $INSTALL_DIR/config/config.yaml"
echo ""
echo "3. Set up SSH keys for server access:"
echo "   ssh-keygen -t ed25519 -f ~/.ssh/sirius"
echo "   # Copy public key to target servers"
echo ""
echo "4. Start the agent:"
echo "   source $INSTALL_DIR/venv/bin/activate"
echo "   python -m src.main"
echo ""
echo "Or install as systemd service:"
echo "   sudo cp systemd/sirius.service /etc/systemd/system/"
echo "   sudo systemctl enable sirius"
echo "   sudo systemctl start sirius"
