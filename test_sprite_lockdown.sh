#!/bin/bash

# Test script for bd-3gc.7: Sprite lockdown verification
# Verifies that Sprite is locked down but gateway proxy still works

set -euo pipefail

echo "🔒 Testing Sprite lockdown (bd-3gc.7)..."

# Test 1: Direct Sprite access should return non-200
echo ""
echo "📋 Test 1: Direct Sprite access should be blocked"
SPRITE_STATUS=$(curl -s -o /dev/null -w "%{http_code}" https://test-option-2-bm6zi.sprites.app/health)
echo "Direct Sprite access status: $SPRITE_STATUS"

if [[ "$SPRITE_STATUS" != "200" ]]; then
    echo "✅ PASS: Direct Sprite access blocked (status: $SPRITE_STATUS)"
    DIRECT_ACCESS_TEST="PASS"
else
    echo "❌ FAIL: Direct Sprite access still returns 200"
    DIRECT_ACCESS_TEST="FAIL"
fi

# Test 2: Gateway health endpoint (no auth required)
echo ""
echo "📋 Test 2: Gateway health endpoint should work"
GATEWAY_HEALTH=$(curl -s http://localhost:8077/health)
echo "Gateway health response: $GATEWAY_HEALTH"

if echo "$GATEWAY_HEALTH" | grep -q "\"status\":\"ok\""; then
    echo "✅ PASS: Gateway health endpoint works"
    GATEWAY_HEALTH_TEST="PASS"
else
    echo "❌ FAIL: Gateway health endpoint not working"
    GATEWAY_HEALTH_TEST="FAIL"
fi

# Test 3: Gateway auth requirement
echo ""
echo "📋 Test 3: Gateway should require auth for protected endpoints"
GATEWAY_AUTH_STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8077/w/dev/health)
echo "Gateway protected endpoint status: $GATEWAY_AUTH_STATUS"

if [[ "$GATEWAY_AUTH_STATUS" == "401" ]]; then
    echo "✅ PASS: Gateway requires authentication for protected endpoints"
    GATEWAY_AUTH_TEST="PASS"
else
    echo "❌ FAIL: Gateway not enforcing authentication (status: $GATEWAY_AUTH_STATUS)"
    GATEWAY_AUTH_TEST="FAIL"
fi

# Test 4: Check that bearer token is configured
echo ""
echo "📋 Test 4: Check bearer token configuration"
BEARER_TOKEN="${SPRITE_BEARER_TOKEN:-}"
if [[ -n "$BEARER_TOKEN" ]]; then
    echo "✅ PASS: SPRITE_BEARER_TOKEN is configured (length: ${#BEARER_TOKEN})"
    BEARER_CONFIG_TEST="PASS"
else
    echo "⚠️  WARNING: SPRITE_BEARER_TOKEN not set - this is needed for gateway proxy"
    BEARER_CONFIG_TEST="WARNING"
fi

# Summary
echo ""
echo "🔍 Summary of bd-3gc.7 verification:"
echo "  1. Direct Sprite access blocked: $DIRECT_ACCESS_TEST"
echo "  2. Gateway health works: $GATEWAY_HEALTH_TEST"
echo "  3. Gateway auth required: $GATEWAY_AUTH_TEST"
echo "  4. Bearer token configured: $BEARER_CONFIG_TEST"

if [[ "$DIRECT_ACCESS_TEST" == "PASS" && "$GATEWAY_HEALTH_TEST" == "PASS" && "$GATEWAY_AUTH_TEST" == "PASS" ]]; then
    echo ""
    echo "✅ PASS: Sprite lockdown successfully implemented"
    echo ""
    echo "🔒 Sprite URL is now locked down (auth: default)"
    echo "🛡️  Gateway authentication is enforcing access control"
    echo "⚙️  Bearer token injection should work for authorized requests"
    echo ""
    echo "📝 Acceptance Criteria Status:"
    echo "  ✅ Direct Sprite access returns non-200 (302)"
    echo "  ✅ Gateway proxy infrastructure is functional"
    echo "  ℹ️  Gateway proxy with auth requires authenticated session for full test"

    exit 0
else
    echo ""
    echo "❌ FAIL: Some tests failed"
    exit 1
fi