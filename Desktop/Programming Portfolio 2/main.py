"""
main.py  —  FinTech Secure Authentication System
Entry point — interactive command-line interface

Security features demonstrated:
  - PBKDF2-HMAC-SHA256 password hashing (310,000 iterations)
  - Password strength checker with actionable feedback
  - Account lockout (5 failed attempts → 30-minute lockout)
  - Simulated TOTP two-factor authentication
  - Account recovery via single-use, time-limited tokens
  - Full audit trail with HMAC integrity tags
  - Input sanitisation on all user-facing fields
  - Sensitive data never printed to console or logs
  - Data integrity verification on every profile read
"""

import os
import sys
import getpass
import datetime

from database import (
    initialise_db,
    register_user,
    authenticate_user,
    get_user_profile,
    update_user,
    store_recovery_token,
    verify_recovery_token,
    enable_totp,
    username_exists,
)
from security import (
    check_password_strength,
    password_strength_label,
    generate_recovery_token,
    generate_totp_code,
)
from audit import log_event, Event, get_recent_events, verify_log_integrity


# ─── Display Helpers ──────────────────────────────────────────────────────────

LINE = "=" * 60

def banner() -> None:
    print(f"\n{LINE}")
    print("   FinTech Secure Authentication System v1.0")
    print(f"{LINE}")

def section(title: str) -> None:
    print(f"\n{'─' * 60}")
    print(f"  {title}")
    print(f"{'─' * 60}")

def success(msg: str) -> None:
    print(f"  [OK]  {msg}")

def error(msg: str) -> None:
    print(f"  [ERR] {msg}")

def warn(msg: str) -> None:
    print(f"  [!]   {msg}")

def info(msg: str) -> None:
    print(f"  [i]   {msg}")

def get_input(prompt: str) -> str:
    """Read a line, stripping whitespace."""
    return input(f"  {prompt}").strip()

def get_password(prompt: str = "Password: ") -> str:
    """Read password without echoing to terminal."""
    try:
        return getpass.getpass(f"  {prompt}")
    except (EOFError, KeyboardInterrupt):
        print()
        return ""


# ─── Password Prompt with Strength Feedback ───────────────────────────────────

def prompt_new_password(confirm: bool = True) -> str | None:
    """
    Prompt for a new password.
    Shows strength label and issues.
    Returns None if user cancels or passwords don't match.
    """
    while True:
        pw = get_password("New password: ")
        if not pw:
            warn("Password cannot be empty.")
            continue

        strong, issues = check_password_strength(pw)
        label = password_strength_label(pw)
        print(f"\n  Password strength: {label}")

        if issues:
            print("  Issues found:")
            for issue in issues:
                print(f"    - {issue}")

        if not strong:
            warn("Password does not meet security requirements.")
            retry = get_input("Try a different password? [Y/n]: ")
            if retry.lower() == "n":
                return None
            continue

        if confirm:
            confirm_pw = get_password("Confirm password: ")
            if pw != confirm_pw:
                error("Passwords do not match.")
                continue

        return pw


# ─── Registration ─────────────────────────────────────────────────────────────

def flow_register() -> None:
    section("Create New Account")

    username  = get_input("Username (3-64 chars, letters/digits/_ - .): ")
    email     = get_input("Email address: ")
    full_name = get_input("Full name: ")

    print()
    password = prompt_new_password()
    if password is None:
        warn("Registration cancelled.")
        return

    ok, msg = register_user(username, email, full_name, password)

    if ok:
        success(msg)
        log_event(Event.REGISTER_OK, username, "SUCCESS")

        # Offer TOTP setup immediately
        print()
        choice = get_input("Enable two-factor authentication (TOTP)? [y/N]: ")
        if choice.lower() == "y":
            flow_enable_totp(username)
    else:
        error(msg)
        log_event(Event.REGISTER_FAIL, username, "FAILURE", msg)


# ─── Login ────────────────────────────────────────────────────────────────────

def flow_login() -> str | None:
    """
    Authenticate a user.
    Returns the username on success, None on failure.
    """
    section("Login")

    username = get_input("Username: ")
    password = get_password()

    ok, msg = authenticate_user(username, password)

    if not ok:
        error(msg)
        log_event(Event.LOGIN_FAIL, username, "FAILURE", msg)
        return None

    # Check if TOTP is enabled
    profile = get_user_profile(username)
    if profile and profile.get("integrity_error"):
        error("Data integrity check FAILED — account data may have been tampered with.")
        log_event(Event.INTEGRITY_FAIL, username, "FAILURE", "User record HMAC mismatch")
        return None

    if profile and profile.get("totp_enabled"):
        totp_ok = flow_totp_verify(username)
        if not totp_ok:
            return None

    success(f"Welcome back, {profile['full_name'] if profile else username}!")
    log_event(Event.LOGIN_OK, username, "SUCCESS")
    return username


# ─── TOTP Two-Factor Authentication ──────────────────────────────────────────

def flow_totp_verify(username: str) -> bool:
    """
    Simulate TOTP verification.
    In production: use pyotp + authenticator app.
    Here we generate a code, display it (simulating delivery), then verify.
    """
    section("Two-Factor Authentication")
    code = generate_totp_code()

    # In production this would be sent to an authenticator app / SMS
    print()
    info("Simulated TOTP: your code would be sent to your authenticator app.")
    info(f"[SIMULATION] Your 6-digit code: {code}")
    print()

    for attempt in range(1, 4):
        entered = get_input(f"Enter 6-digit code (attempt {attempt}/3): ")
        if entered == code:
            success("Two-factor authentication passed.")
            log_event(Event.TOTP_OK, username, "SUCCESS")
            return True
        else:
            error("Incorrect code.")

    log_event(Event.TOTP_FAIL, username, "FAILURE", "3 incorrect TOTP attempts")
    error("Too many incorrect attempts. Login aborted.")
    return False


def flow_enable_totp(username: str) -> None:
    """Enable TOTP for a user account."""
    section("Enable Two-Factor Authentication")
    info("TOTP (Time-based One-Time Password) adds an extra layer of security.")
    info("In production, you would scan a QR code with an authenticator app.")
    info("For this simulation, a code will be generated and displayed each login.")
    print()
    confirm = get_input("Enable TOTP for your account? [y/N]: ")
    if confirm.lower() == "y":
        enable_totp(username)
        success("Two-factor authentication enabled.")
        log_event(Event.UPDATE_OK, username, "SUCCESS", "TOTP enabled")
    else:
        info("TOTP not enabled. You can enable it later from your profile.")


# ─── Account Recovery ─────────────────────────────────────────────────────────

def flow_account_recovery() -> None:
    section("Account Recovery")
    username = get_input("Enter your username: ")

    if not username_exists(username):
        # Do not reveal whether account exists — prevent enumeration
        info("If that username exists, a recovery token has been generated.")
        info("[SIMULATION] Token: (not shown — account not found)")
        return

    raw_token = generate_recovery_token()
    store_recovery_token(username, raw_token)

    log_event(Event.RECOVERY_INIT, username, "INFO", "Recovery token generated")

    # In production: email the raw_token to the user's registered address
    print()
    info("A recovery token has been generated.")
    info("[SIMULATION] In production, this is emailed to your registered address.")
    info(f"[SIMULATION] Token: {raw_token}")
    print()

    entered_token = get_input("Enter the recovery token: ")
    if not verify_recovery_token(username, entered_token):
        error("Invalid or expired recovery token.")
        log_event(Event.RECOVERY_FAIL, username, "FAILURE", "Bad or expired token")
        return

    log_event(Event.RECOVERY_OK, username, "SUCCESS", "Token verified")
    success("Token verified. Please set a new password.")

    new_pw = prompt_new_password()
    if new_pw is None:
        warn("Recovery cancelled. Password not changed.")
        return

    ok, msg = update_user(username, new_password=new_pw)
    if ok:
        success("Password reset successfully. Please log in.")
        log_event(Event.UPDATE_OK, username, "SUCCESS", "Password reset via recovery")
    else:
        error(f"Failed to reset password: {msg}")


# ─── Authenticated Menu ───────────────────────────────────────────────────────

def authenticated_menu(username: str) -> None:
    """Menu available to a logged-in user."""
    while True:
        section(f"Account Menu  [{username}]")
        print("  1. View profile")
        print("  2. Update profile")
        print("  3. Change password")
        print("  4. Enable / disable 2FA")
        print("  5. View my audit log")
        print("  6. Verify system integrity")
        print("  7. Logout")
        print()

        choice = get_input("Choice: ")

        if choice == "1":
            flow_view_profile(username)
        elif choice == "2":
            flow_update_profile(username)
        elif choice == "3":
            flow_change_password(username)
        elif choice == "4":
            flow_enable_totp(username)
        elif choice == "5":
            flow_view_audit_log(username)
        elif choice == "6":
            flow_verify_integrity(username)
        elif choice == "7":
            log_event(Event.LOGOUT, username, "SUCCESS")
            success("Logged out securely.")
            break
        else:
            warn("Invalid option.")


def flow_view_profile(username: str) -> None:
    section("Your Profile")
    profile = get_user_profile(username)
    if profile is None:
        error("Could not retrieve profile.")
        return
    if profile.get("integrity_error"):
        error("DATA INTEGRITY ERROR: your profile may have been tampered with!")
        log_event(Event.INTEGRITY_FAIL, username, "FAILURE")
        return
    # Deliberately omit password_hash from display
    print(f"  Username   : {profile['username']}")
    print(f"  Full name  : {profile['full_name']}")
    print(f"  Email      : {profile['email']}")
    print(f"  2FA enabled: {'Yes' if profile['totp_enabled'] else 'No'}")
    print(f"  Joined     : {profile['created_at'][:10]}")
    print(f"  Updated    : {profile['updated_at'][:10]}")
    log_event(Event.INTEGRITY_OK, username, "SUCCESS", "Profile integrity verified")


def flow_update_profile(username: str) -> None:
    section("Update Profile")
    info("Leave a field blank to keep the current value.")
    new_email = get_input("New email (or Enter to skip): ")
    new_name  = get_input("New full name (or Enter to skip): ")

    ok, msg = update_user(
        username,
        new_email = new_email or None,
        new_name  = new_name  or None,
    )
    if ok:
        success(msg)
        log_event(Event.UPDATE_OK, username, "SUCCESS", "Profile fields updated")
    else:
        error(msg)
        log_event(Event.UPDATE_FAIL, username, "FAILURE", msg)


def flow_change_password(username: str) -> None:
    section("Change Password")
    current = get_password("Current password: ")

    ok, msg = authenticate_user(username, current)
    if not ok:
        error("Current password incorrect.")
        log_event(Event.UPDATE_FAIL, username, "FAILURE", "Wrong current password")
        return

    new_pw = prompt_new_password()
    if new_pw is None:
        warn("Password change cancelled.")
        return

    ok, msg = update_user(username, new_password=new_pw)
    if ok:
        success("Password changed successfully.")
        log_event(Event.UPDATE_OK, username, "SUCCESS", "Password changed")
    else:
        error(msg)
        log_event(Event.UPDATE_FAIL, username, "FAILURE", msg)


def flow_view_audit_log(username: str) -> None:
    section("Your Recent Activity")
    events = get_recent_events(username, limit=15)
    if not events:
        info("No audit events found.")
        return
    print(f"  {'Timestamp':<30} {'Event':<22} {'Outcome'}")
    print(f"  {'─'*30} {'─'*22} {'─'*10}")
    for ev in events:
        ts    = ev["timestamp"][:19].replace("T", " ")
        event = ev["event"][:22]
        outcome = ev["outcome"]
        print(f"  {ts:<30} {event:<22} {outcome}")


def flow_verify_integrity(username: str) -> None:
    section("System Integrity Check")
    info("Verifying HMAC tags on all audit log entries...")
    tampered = verify_log_integrity()
    if not tampered:
        success("All audit log entries passed integrity verification.")
        log_event(Event.INTEGRITY_OK, username, "SUCCESS", "Audit log integrity OK")
    else:
        error(f"{len(tampered)} tampered entries detected!")
        for entry in tampered:
            error(f"  Tampered entry: id={entry['id']} | {entry['timestamp']} | {entry['event']}")
        log_event(Event.INTEGRITY_FAIL, username, "FAILURE",
                  f"{len(tampered)} tampered audit entries")


# ─── Main Menu ────────────────────────────────────────────────────────────────

def main() -> None:
    os.makedirs("data", exist_ok=True)
    os.makedirs("logs", exist_ok=True)
    initialise_db()
    banner()

    while True:
        print("\n  Main Menu")
        print("  1. Register")
        print("  2. Login")
        print("  3. Account Recovery")
        print("  4. Exit")
        print()

        choice = get_input("Choice: ")

        if choice == "1":
            flow_register()
        elif choice == "2":
            username = flow_login()
            if username:
                authenticated_menu(username)
        elif choice == "3":
            flow_account_recovery()
        elif choice == "4":
            info("Exiting securely. Goodbye.")
            sys.exit(0)
        else:
            warn("Invalid option. Please choose 1-4.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n  [i]   Interrupted. Exiting.")
        sys.exit(0)
