#!/usr/bin/env python3
"""
Phase 2 Gate Verification Script (bd-3gc.9)

Runs all 6 required verification checks for Phase 2:
1. Supabase creds loaded
2. Unauthenticated → 401
3. Login → cookie → /me
4. Authenticated proxy
5. Cookie flags
6. Sprite locked down

All checks must pass for Phase 2 completion.
"""

import json
import os
import sys
import requests
import re
from urllib.parse import urlparse

# Gateway URL
GATEWAY_URL = "http://localhost:8077"


def print_check(number, description, status="INFO"):
    """Print formatted check status."""
    emoji = {"PASS": "✅", "FAIL": "❌", "INFO": "📋", "WARN": "⚠️"}
    print(f"{emoji.get(status, '📋')} Check {number}: {description}")


def check_1_supabase_creds():
    """Check 1: Supabase creds loaded - load_app('boring-ui').supabase_url starts with 'https://'"""
    print_check(1, "Supabase credentials loaded")

    try:
        sys.path.insert(0, '/home/ubuntu/projects/boring-swarm/src')
        from boring_sandbox.config.app_registry import load_app

        config = load_app("boring-ui")
        supabase_url = config.supabase_url

        print(f"   Supabase URL: {supabase_url}")

        if supabase_url.startswith("https://"):
            print_check(1, "Supabase credentials loaded", "PASS")
            return True
        else:
            print_check(1, f"Supabase URL does not start with https://: {supabase_url}", "FAIL")
            return False

    except Exception as e:
        print_check(1, f"Failed to load Supabase credentials: {e}", "FAIL")
        return False


def check_2_unauthenticated_401():
    """Check 2: Unauthenticated → 401 - /api/v1/me without session → AUTH_REQUIRED JSON"""
    print_check(2, "Unauthenticated access returns 401")

    try:
        response = requests.get(f"{GATEWAY_URL}/api/v1/me", timeout=5)

        print(f"   Status: {response.status_code}")
        print(f"   Response: {response.text}")

        if response.status_code == 401:
            data = response.json()
            if data.get("code") == "AUTH_REQUIRED":
                print_check(2, "Unauthenticated access correctly returns 401 with AUTH_REQUIRED", "PASS")
                return True
            else:
                print_check(2, f"401 response but wrong error code: {data}", "FAIL")
                return False
        else:
            print_check(2, f"Expected 401, got {response.status_code}", "FAIL")
            return False

    except Exception as e:
        print_check(2, f"Request failed: {e}", "FAIL")
        return False


def check_3_login_flow():
    """Check 3: Login → cookie → /me - test mode auth flow"""
    print_check(3, "Login flow (test mode)")

    try:
        # Try test mode auth flow
        auth_data = {
            "access_token": "test-access-token-for-dev-mode"
        }

        response = requests.get(f"{GATEWAY_URL}/auth/callback", params=auth_data, timeout=5, allow_redirects=False)

        print(f"   Auth callback status: {response.status_code}")
        print(f"   Headers: {dict(response.headers)}")

        # Check for Set-Cookie header
        set_cookie = response.headers.get('Set-Cookie')
        if not set_cookie:
            print_check(3, "No Set-Cookie header in auth callback response", "FAIL")
            return False

        print(f"   Set-Cookie: {set_cookie}")

        # Extract session cookie
        session_match = re.search(r'boring_session=([^;]+)', set_cookie)
        if not session_match:
            print_check(3, "No boring_session cookie found", "FAIL")
            return False

        session_cookie = session_match.group(1)
        print(f"   Session cookie extracted: {session_cookie[:20]}...")

        # Test /api/v1/me with session cookie
        cookies = {'boring_session': session_cookie}
        me_response = requests.get(f"{GATEWAY_URL}/api/v1/me", cookies=cookies, timeout=5)

        print(f"   /api/v1/me status: {me_response.status_code}")
        print(f"   /api/v1/me response: {me_response.text}")

        if me_response.status_code == 200:
            user_data = me_response.json()
            if "user_id" in user_data and "email" in user_data:
                print_check(3, "Login flow successful - session cookie works", "PASS")
                return True, session_cookie
            else:
                print_check(3, f"User data missing required fields: {user_data}", "FAIL")
                return False, None
        else:
            print_check(3, f"/api/v1/me failed with session cookie: {me_response.status_code}", "FAIL")
            return False, None

    except Exception as e:
        print_check(3, f"Login flow failed: {e}", "FAIL")
        return False, None


def check_4_authenticated_proxy(session_cookie):
    """Check 4: Authenticated proxy - /w/dev/health with session cookie → 200"""
    print_check(4, "Authenticated proxy to Sprite")

    if not session_cookie:
        print_check(4, "No session cookie available from previous check", "FAIL")
        return False

    try:
        cookies = {'boring_session': session_cookie}
        response = requests.get(f"{GATEWAY_URL}/w/dev/health", cookies=cookies, timeout=5)

        print(f"   Status: {response.status_code}")
        print(f"   Response: {response.text}")

        if response.status_code == 200:
            try:
                data = response.json()
                if data.get("status") == "ok":
                    print_check(4, "Authenticated proxy works - Sprite health check passed", "PASS")
                    return True
                else:
                    print_check(4, f"Unexpected health response: {data}", "FAIL")
                    return False
            except json.JSONDecodeError:
                print_check(4, f"Non-JSON response: {response.text}", "FAIL")
                return False
        else:
            print_check(4, f"Expected 200, got {response.status_code}", "FAIL")
            return False

    except Exception as e:
        print_check(4, f"Authenticated proxy failed: {e}", "FAIL")
        return False


def check_5_cookie_flags():
    """Check 5: Cookie flags - Set-Cookie header contains HttpOnly; SameSite=Lax"""
    print_check(5, "Session cookie security flags")

    try:
        # Get auth callback to check cookie flags
        auth_data = {
            "access_token": "test-access-token-for-dev-mode"
        }

        response = requests.get(f"{GATEWAY_URL}/auth/callback", params=auth_data, timeout=5, allow_redirects=False)
        set_cookie = response.headers.get('Set-Cookie', '')

        print(f"   Set-Cookie header: {set_cookie}")

        # Check for required flags
        has_httponly = 'HttpOnly' in set_cookie
        has_samesite_lax = 'SameSite=Lax' in set_cookie

        print(f"   HttpOnly: {has_httponly}")
        print(f"   SameSite=Lax: {has_samesite_lax}")

        if has_httponly and has_samesite_lax:
            print_check(5, "Cookie security flags present (HttpOnly; SameSite=Lax)", "PASS")
            return True
        else:
            missing = []
            if not has_httponly:
                missing.append("HttpOnly")
            if not has_samesite_lax:
                missing.append("SameSite=Lax")
            print_check(5, f"Missing cookie flags: {', '.join(missing)}", "FAIL")
            return False

    except Exception as e:
        print_check(5, f"Cookie flags check failed: {e}", "FAIL")
        return False


def check_6_sprite_lockdown():
    """Check 6: Sprite locked down - direct Sprite access returns non-200"""
    print_check(6, "Sprite lockdown (direct access blocked)")

    try:
        response = requests.get("https://test-option-2-bm6zi.sprites.app/health", timeout=5, allow_redirects=False)

        print(f"   Direct Sprite access status: {response.status_code}")

        if response.status_code != 200:
            print_check(6, f"Sprite correctly locked down (returns {response.status_code})", "PASS")
            return True
        else:
            print_check(6, "Sprite still returns 200 - lockdown failed", "FAIL")
            return False

    except Exception as e:
        print_check(6, f"Sprite lockdown check failed: {e}", "FAIL")
        return False


def main():
    """Run all Phase 2 gate verification checks."""
    print("🚪 Phase 2 Gate Verification (bd-3gc.9)")
    print("=" * 50)
    print()

    results = []
    session_cookie = None

    # Run all 6 checks
    print("Running all 6 Phase 2 verification checks...")
    print()

    # Check 1: Supabase creds
    results.append(check_1_supabase_creds())
    print()

    # Check 2: Unauthenticated 401
    results.append(check_2_unauthenticated_401())
    print()

    # Check 3: Login flow (returns session cookie)
    login_result = check_3_login_flow()
    if isinstance(login_result, tuple):
        results.append(login_result[0])
        session_cookie = login_result[1]
    else:
        results.append(login_result)
    print()

    # Check 4: Authenticated proxy
    results.append(check_4_authenticated_proxy(session_cookie))
    print()

    # Check 5: Cookie flags
    results.append(check_5_cookie_flags())
    print()

    # Check 6: Sprite lockdown
    results.append(check_6_sprite_lockdown())
    print()

    # Summary
    passed = sum(results)
    total = len(results)

    print("=" * 50)
    print(f"📊 PHASE 2 GATE RESULTS: {passed}/{total} checks passed")
    print()

    if passed == total:
        print("🎉 ALL PHASE 2 CHECKS PASSED!")
        print("✅ Phase 2 Authentication Layer is complete and functional")
        print("✅ Ready to proceed to Phase 3")
        return True
    else:
        print("❌ PHASE 2 GATE FAILED")
        print(f"   {total - passed} checks failed")
        print("   Phase 2 implementation needs fixes before proceeding")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)