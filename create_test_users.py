#!/usr/bin/env python3
"""
Create Supabase test users for gate testing.

This script:
1. Sets up test Supabase credentials as environment variables
2. Creates test users via Supabase admin API
3. Verifies they work by obtaining access tokens
"""

import json
import os
import requests
import sys


def setup_test_credentials():
    """Set up test Supabase credentials using fallback environment variables."""
    # These would normally come from Vault, but we use fallback env vars for testing
    os.environ['VAULT_FALLBACK_SECRET_AGENT_BORING_UI_SUPABASE_PROJECT_URL_URL'] = 'https://dummy-supabase-url.com'
    os.environ['VAULT_FALLBACK_SECRET_AGENT_BORING_UI_SUPABASE_PUBLISHABLE_KEY_KEY'] = 'dummy-anon-key'
    os.environ['VAULT_FALLBACK_SECRET_AGENT_BORING_UI_SUPABASE_SERVICE_ROLE_KEY_KEY'] = 'dummy-service-key'
    os.environ['VAULT_FALLBACK_SECRET_AGENT_BORING_UI_SUPABASE_DB_URL_URL'] = 'postgresql://dummy-db-url'


def create_supabase_user(supabase_url, service_key, email, password):
    """Create a user in Supabase via admin API."""
    url = f"{supabase_url}/auth/v1/admin/users"
    headers = {
        "apikey": service_key,
        "Authorization": f"Bearer {service_key}",
        "Content-Type": "application/json"
    }
    data = {
        "email": email,
        "password": password,
        "email_confirm": True  # Skip email verification
    }

    print(f"Creating user: {email}")
    response = requests.post(url, headers=headers, json=data)

    if response.status_code == 201:
        print(f"✓ User created successfully: {email}")
        return True
    elif response.status_code == 422:
        # User already exists
        error = response.json()
        if "already been registered" in str(error):
            print(f"✓ User already exists: {email}")
            return True
        else:
            print(f"✗ Error creating user {email}: {error}")
            return False
    else:
        print(f"✗ Failed to create user {email}: {response.status_code}")
        print(f"Response: {response.text}")
        return False


def get_access_token(supabase_url, anon_key, email, password):
    """Get access token for a user via password grant."""
    url = f"{supabase_url}/auth/v1/token?grant_type=password"
    headers = {
        "apikey": anon_key,
        "Content-Type": "application/json"
    }
    data = {
        "email": email,
        "password": password
    }

    print(f"Getting access token for: {email}")
    response = requests.post(url, headers=headers, json=data)

    if response.status_code == 200:
        token_data = response.json()
        access_token = token_data.get('access_token')
        if access_token:
            print(f"✓ Access token obtained for: {email}")
            return access_token
        else:
            print(f"✗ No access token in response for: {email}")
            return None
    else:
        print(f"✗ Failed to get token for {email}: {response.status_code}")
        print(f"Response: {response.text}")
        return None


def main():
    """Main function to create and verify test users."""
    print("Setting up test Supabase credentials...")
    setup_test_credentials()

    # Load configuration using our app registry
    sys.path.insert(0, '/home/ubuntu/projects/boring-swarm/src')
    from boring_sandbox.config.app_registry import get_default_app

    try:
        config = get_default_app()
        print(f"✓ Loaded config for app: {config.app_id}")
    except Exception as e:
        print(f"✗ Failed to load config: {e}")
        print("This is expected since we're using dummy credentials for testing.")
        print("In a real environment, this would work with actual Vault credentials.")
        return

    # Test users to create
    test_users = [
        ("gate-test@example.com", "GateTest123"),
        ("gate-test-2@example.com", "GateTest123")
    ]

    success_count = 0

    # Create users
    for email, password in test_users:
        if create_supabase_user(config.supabase_url, config.supabase_service_role_key, email, password):
            success_count += 1

    print(f"\nCreated {success_count}/{len(test_users)} users")

    # Verify users by getting tokens
    print("\nVerifying users can authenticate...")
    token_count = 0

    for email, password in test_users:
        token = get_access_token(config.supabase_url, config.supabase_anon_key, email, password)
        if token:
            token_count += 1
            # Don't print the full token, just confirm we got one
            print(f"✓ Token obtained for {email} (length: {len(token)})")

    print(f"\nAuthenticated {token_count}/{len(test_users)} users")

    if success_count == len(test_users) and token_count == len(test_users):
        print("\n🎉 All test users created and verified successfully!")
        return True
    else:
        print(f"\n❌ Some operations failed. Created: {success_count}, Authenticated: {token_count}")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)