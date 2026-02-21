#!/bin/bash

set -e

KEY_DIR="./keys"

echo "🔑 Generating RS256 key pair for JWT signing..."
echo ""

# Create keys directory if it doesn't exist
mkdir -p "$KEY_DIR"

# Generate private key (2048-bit RSA)
openssl genrsa -out "$KEY_DIR/private.pem" 2048

# Extract public key from private key
openssl rsa -in "$KEY_DIR/private.pem" -pubout -out "$KEY_DIR/public.pem"

# Set restrictive permissions
chmod 600 "$KEY_DIR/private.pem"
chmod 644 "$KEY_DIR/public.pem"

echo ""
echo "✅ Keys generated successfully:"
echo "   Private key: $KEY_DIR/private.pem"
echo "   Public key:  $KEY_DIR/public.pem"
echo ""
echo "⚠️  IMPORTANT: Never commit private.pem to version control!"
echo ""