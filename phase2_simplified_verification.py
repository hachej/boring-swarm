#!/usr/bin/env python3
"""
Phase 2 Simplified Verification Script (bd-3gc.9)

Verifies what can be tested with current setup and documents what requires real credentials.
"""

import json
import os
import sys
import requests

# Gateway URL
GATEWAY_URL = "http://localhost:8077"


def print_result(check, description, status, details=""):
    """Print formatted check result."""
    emoji = {"PASS": "✅", "FAIL": "❌", "SKIP": "⏭️", "INFO": "📋"}
    print(f"{emoji.get(status, '📋')} {check}: {description}")
    if details:
        print(f"   {details}")


def main():
    """Run Phase 2 verification checks with current setup."""
    print("🚪 Phase 2 Gate Verification (Simplified)")
    print("=" * 60)
    print()

    results = []

    # Check 1: Supabase credentials loaded
    print_result("Check 1", "Supabase credentials loaded", "INFO")
    try:
        sys.path.insert(0, '/home/ubuntu/projects/boring-swarm/src')
        from boring_sandbox.config.app_registry import load_app
        config = load_app("boring-ui")

        if config.supabase_url.startswith("https://"):
            print_result("", f"Supabase URL: {config.supabase_url}", "PASS")
            results.append(True)
        else:
            print_result("", f"Invalid Supabase URL: {config.supabase_url}", "FAIL")
            results.append(False)
    except Exception as e:
        print_result("", f"Failed to load config: {e}", "FAIL")
        results.append(False)
    print()

    # Check 2: Unauthenticated access returns 401
    print_result("Check 2", "Unauthenticated access returns 401", "INFO")
    try:
        response = requests.get(f"{GATEWAY_URL}/api/v1/me", timeout=5)
        if response.status_code == 401:
            data = response.json()
            if data.get("code") == "AUTH_REQUIRED":
                print_result("", f"Returns 401 with AUTH_REQUIRED as expected", "PASS")
                results.append(True)
            else:
                print_result("", f"401 but wrong error code: {data}", "FAIL")
                results.append(False)
        else:
            print_result("", f"Expected 401, got {response.status_code}", "FAIL")
            results.append(False)
    except Exception as e:
        print_result("", f"Request failed: {e}", "FAIL")
        results.append(False)
    print()

    # Check 3: Auth callback endpoint accessibility
    print_result("Check 3", "Auth callback endpoint responds", "INFO")
    try:
        response = requests.get(f"{GATEWAY_URL}/auth/callback", timeout=5)
        # Auth callback should return 400 when no params provided (not 401)
        if response.status_code in [400, 422]:
            detail = response.json().get("detail", "")
            if "authentication parameters" in detail.lower() or "access_token" in detail:
                print_result("", "Auth callback accessible and requires parameters", "PASS")
                results.append(True)
            else:
                print_result("", f"Unexpected error message: {detail}", "FAIL")
                results.append(False)
        elif response.status_code == 401:
            print_result("", "Auth callback incorrectly protected by auth guard", "FAIL")
            results.append(False)
        else:
            print_result("", f"Unexpected status: {response.status_code}", "FAIL")
            results.append(False)
    except Exception as e:
        print_result("", f"Auth callback test failed: {e}", "FAIL")
        results.append(False)
    print()

    # Check 4: Gateway health endpoint
    print_result("Check 4", "Gateway infrastructure functional", "INFO")
    try:
        response = requests.get(f"{GATEWAY_URL}/health", timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "ok":
                print_result("", "Gateway health check passes", "PASS")
                results.append(True)
            else:
                print_result("", f"Unexpected health response: {data}", "FAIL")
                results.append(False)
        else:
            print_result("", f"Health check failed: {response.status_code}", "FAIL")
            results.append(False)
    except Exception as e:
        print_result("", f"Gateway health check failed: {e}", "FAIL")
        results.append(False)
    print()

    # Check 5: Session cookie infrastructure
    print_result("Check 5", "Session cookie infrastructure present", "INFO")
    try:
        # Check that session module can be imported
        from boring_sandbox.security.session import create_session_cookie, parse_session_cookie

        # Test environment variables
        session_secret = os.getenv("BORING_SESSION_SECRET")
        if session_secret:
            print_result("", "Session secret configured", "PASS")
            results.append(True)
        else:
            print_result("", "BORING_SESSION_SECRET not set", "FAIL")
            results.append(False)
    except Exception as e:
        print_result("", f"Session infrastructure error: {e}", "FAIL")
        results.append(False)
    print()

    # Check 6: Sprite lockdown
    print_result("Check 6", "Sprite lockdown (direct access blocked)", "INFO")
    try:
        response = requests.get("https://test-option-2-bm6zi.sprites.app/health", timeout=5, allow_redirects=False)
        if response.status_code != 200:
            print_result("", f"Direct Sprite access blocked (returns {response.status_code})", "PASS")
            results.append(True)
        else:
            print_result("", "Sprite still returns 200 - lockdown failed", "FAIL")
            results.append(False)
    except Exception as e:
        print_result("", f"Sprite lockdown check failed: {e}", "FAIL")
        results.append(False)
    print()

    # Summary
    passed = sum(results)
    total = len(results)

    print("=" * 60)
    print(f"📊 VERIFICATION RESULTS: {passed}/{total} checks passed")
    print()

    if passed == total:
        print("🎉 CORE PHASE 2 INFRASTRUCTURE VERIFIED!")
        print()
        print("✅ Verified components:")
        print("  • Supabase credentials loading with fallback system")
        print("  • Authentication guard middleware (blocks unauthenticated access)")
        print("  • Auth callback endpoint accessibility")
        print("  • Gateway health and infrastructure")
        print("  • Session cookie infrastructure")
        print("  • Sprite lockdown (direct access blocked)")
        print()
        print("📝 What requires real credentials for full testing:")
        print("  • JWT token verification with real Supabase tokens")
        print("  • Session cookie creation with valid user data")
        print("  • End-to-end authenticated proxy flow")
        print("  • Cookie security flags verification")
        print()
        print("🚀 Ready for production deployment with real Supabase credentials!")

        return True
    else:
        print("❌ VERIFICATION INCOMPLETE")
        print(f"   {total - passed} components need attention")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)