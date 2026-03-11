#!/bin/bash

# Restart the gateway with proper environment variables for Phase 2 testing

set -euo pipefail

echo "🔄 Restarting gateway with Phase 2 environment variables..."

# Kill existing boring_sandbox processes
echo "Stopping existing servers..."
pkill -f "uvicorn.*boring_sandbox" || true
sleep 2

# Set up required environment variables
export VAULT_FALLBACK_SECRET_AGENT_BORING_UI_SUPABASE_PROJECT_URL_URL="https://dummy-supabase-url.com"
export VAULT_FALLBACK_SECRET_AGENT_BORING_UI_SUPABASE_PUBLISHABLE_KEY_KEY="dummy-anon-key"
export VAULT_FALLBACK_SECRET_AGENT_BORING_UI_SUPABASE_SERVICE_ROLE_KEY_KEY="dummy-service-key"
export VAULT_FALLBACK_SECRET_AGENT_BORING_UI_SUPABASE_DB_URL_URL="postgresql://dummy-db-url"

# Session and bearer token for testing
export BORING_SESSION_SECRET="test-session-secret-123"
export SPRITE_BEARER_TOKEN="test-token-for-verification"

# Development environment
export ENV="dev"

echo "Environment variables set:"
echo "  BORING_SESSION_SECRET: ${BORING_SESSION_SECRET}"
echo "  SPRITE_BEARER_TOKEN: ${SPRITE_BEARER_TOKEN}"
echo "  ENV: ${ENV}"
echo ""

# Start the server
echo "Starting gateway server..."
cd /home/ubuntu/projects/boring-swarm
python -m uvicorn src.boring_sandbox.main:app --host 0.0.0.0 --port 8077 --reload &

# Wait a moment for server to start
sleep 3

# Test server is responding
echo "Testing server startup..."
if curl -s http://localhost:8077/health > /dev/null; then
    echo "✅ Gateway server started successfully on port 8077"
    echo ""
    echo "🧪 Ready for Phase 2 gate verification"
else
    echo "❌ Gateway server failed to start"
    exit 1
fi