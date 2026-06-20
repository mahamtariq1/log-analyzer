"""
Log Analyzer
------------
A simple security log analysis tool that parses authentication (SSH/auth)
and firewall logs to detect suspicious activity such as brute-force login
attempts, repeated blocked connections, and unusual access patterns.

Author: Maham Tariq
"""

import re
import argparse
import sys
from collections import defaultdict
from datetime import datetime

# ---------------------------------------------------------
# Configuration
# ---------------------------------------------------------
AUTH_LOG_FILE = "sample_auth.log"
FIREWALL_LOG_FILE = "sample_firewall.log"
REPORT_FILE = "report.txt"

FAILED_LOGIN_THRESHOLD = 3      # flag an IP after this many failed attempts
BLOCK_THRESHOLD = 3             # flag an IP after this many firewall blocks
UNUSUAL_HOUR_START = 0          # 12 AM
UNUSUAL_HOUR_END = 5            # 5 AM  -> logins in this window are flagged


# ---------------------------------------------------------
# Auth log parsing
# ---------------------------------------------------------
def parse_auth_log(filepath):
    """
    Parses an SSH auth log and returns:
    - failed_attempts: dict of {ip: [list of usernames tried]}
    - successful_logins: list of (timestamp, user, ip)
    - stats: dict with total_lines and matched_lines (used to detect format mismatches)
    """
    failed_attempts = defaultdict(list)
    successful_logins = []
    total_lines = 0
    matched_lines = 0

    failed_pattern = re.compile(
        r"^(\w+ \d+ \d+:\d+:\d+).*Failed password for (\S+) from (\S+)"
    )
    success_pattern = re.compile(
        r"^(\w+ \d+ \d+:\d+:\d+).*Accepted password for (\S+) from (\S+)"
    )

    with open(filepath, "r") as f:
        for line in f:
            if not line.strip():
                continue
            total_lines += 1

            fail_match = failed_pattern.search(line)
            if fail_match:
                timestamp, user, ip = fail_match.groups()
                failed_attempts[ip].append((timestamp, user))
                matched_lines += 1
                continue

            success_match = success_pattern.search(line)
            if success_match:
                timestamp, user, ip = success_match.groups()
                successful_logins.append((timestamp, user, ip))
                matched_lines += 1

    stats = {"total_lines": total_lines, "matched_lines": matched_lines}
    return failed_attempts, successful_logins, stats


# ---------------------------------------------------------
# Firewall log parsing
# ---------------------------------------------------------
def parse_firewall_log(filepath):
    """
    Parses a firewall log and returns:
    - blocked_ips: dict of {ip: block_count}
    - stats: dict with total_lines and matched_lines
    """
    blocked_ips = defaultdict(int)
    total_lines = 0
    matched_lines = 0

    block_pattern = re.compile(r"BLOCK \w+ (\S+) ->")

    with open(filepath, "r") as f:
        for line in f:
            if not line.strip():
                continue
            total_lines += 1

            match = block_pattern.search(line)
            if match:
                ip = match.group(1)
                blocked_ips[ip] += 1
                matched_lines += 1

    stats = {"total_lines": total_lines, "matched_lines": matched_lines}
    return blocked_ips, stats


# ---------------------------------------------------------
# Detection logic
# ---------------------------------------------------------
def detect_brute_force(failed_attempts, threshold=FAILED_LOGIN_THRESHOLD):
    """Flags IPs with failed login attempts above the threshold."""
    flagged = {}
    for ip, attempts in failed_attempts.items():
        if len(attempts) >= threshold:
            usernames_tried = [user for _, user in attempts]
            flagged[ip] = {
                "attempt_count": len(attempts),
                "usernames_tried": usernames_tried,
            }
    return flagged


def detect_firewall_threats(blocked_ips, threshold=BLOCK_THRESHOLD):
    """Flags IPs with repeated firewall blocks above the threshold."""
    return {ip: count for ip, count in blocked_ips.items() if count >= threshold}


def detect_unusual_hour_logins(successful_logins):
    """Flags successful logins that happened during unusual hours (e.g. 12AM-5AM)."""
    flagged = []
    for timestamp, user, ip in successful_logins:
        try:
            # timestamp format: "Jun 18 03:14:21"
            time_part = timestamp.split(" ")[-1]
            hour = int(time_part.split(":")[0])
            if UNUSUAL_HOUR_START <= hour <= UNUSUAL_HOUR_END:
                flagged.append((timestamp, user, ip))
        except (ValueError, IndexError):
            continue
    return flagged


# ---------------------------------------------------------
# Report generation
# ---------------------------------------------------------
def generate_report(brute_force, firewall_threats, unusual_logins, auth_stats, firewall_stats):
    lines = []
    lines.append("=" * 60)
    lines.append("LOG ANALYZER REPORT")
    lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("=" * 60)

    # Format-mismatch warnings — tells the user if their log format
    # wasn't recognized, instead of silently reporting "all clear"
    lines.append("\n[i] PARSING SUMMARY")
    lines.append(
        f"  Auth log: {auth_stats['matched_lines']}/{auth_stats['total_lines']} lines recognized"
    )
    if auth_stats["total_lines"] > 0 and auth_stats["matched_lines"] == 0:
        lines.append(
            "  ⚠ WARNING: No lines matched the expected auth log format. "
            "Results below may be incomplete — check that your log format "
            "matches a standard SSH auth log (see README)."
        )

    lines.append(
        f"  Firewall log: {firewall_stats['matched_lines']}/{firewall_stats['total_lines']} lines recognized"
    )
    if firewall_stats["total_lines"] > 0 and firewall_stats["matched_lines"] == 0:
        lines.append(
            "  ⚠ WARNING: No lines matched the expected firewall log format. "
            "Results below may be incomplete — check that your log format "
            "matches the expected pattern (see README)."
        )

    lines.append("\n[!] BRUTE-FORCE LOGIN ATTEMPTS DETECTED")
    if brute_force:
        for ip, info in brute_force.items():
            lines.append(f"  - IP: {ip}")
            lines.append(f"    Failed attempts: {info['attempt_count']}")
            lines.append(f"    Usernames tried: {', '.join(set(info['usernames_tried']))}")
    else:
        lines.append("  None detected.")

    lines.append("\n[!] REPEATED FIREWALL BLOCKS")
    if firewall_threats:
        for ip, count in firewall_threats.items():
            lines.append(f"  - IP: {ip} | Blocked {count} times")
    else:
        lines.append("  None detected.")

    lines.append("\n[!] LOGINS DURING UNUSUAL HOURS (12AM - 5AM)")
    if unusual_logins:
        for timestamp, user, ip in unusual_logins:
            lines.append(f"  - {timestamp} | User: {user} | IP: {ip}")
    else:
        lines.append("  None detected.")

    # Cross-reference: IPs that both failed SSH logins AND got firewall-blocked
    overlap = set(brute_force.keys()) & set(firewall_threats.keys())
    lines.append("\n[!] HIGH-CONFIDENCE THREATS (flagged in both auth & firewall logs)")
    if overlap:
        for ip in overlap:
            lines.append(f"  - {ip} is a strong attack indicator (brute force + firewall blocks)")
    else:
        lines.append("  None detected.")

    lines.append("\n" + "=" * 60)
    lines.append("END OF REPORT")
    lines.append("=" * 60)

    return "\n".join(lines)


# ---------------------------------------------------------
# Main
# ---------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Analyze SSH auth and firewall logs for suspicious activity."
    )
    parser.add_argument(
        "--auth", default=AUTH_LOG_FILE,
        help=f"Path to the auth/SSH log file (default: {AUTH_LOG_FILE})"
    )
    parser.add_argument(
        "--firewall", default=FIREWALL_LOG_FILE,
        help=f"Path to the firewall log file (default: {FIREWALL_LOG_FILE})"
    )
    parser.add_argument(
        "--output", default=REPORT_FILE,
        help=f"Path to save the report (default: {REPORT_FILE})"
    )
    args = parser.parse_args()

    print("[*] Starting log analysis...\n")
    print(f"[*] Auth log:     {args.auth}")
    print(f"[*] Firewall log: {args.firewall}\n")

    try:
        failed_attempts, successful_logins, auth_stats = parse_auth_log(args.auth)
    except FileNotFoundError:
        print(f"[ERROR] Auth log file not found: {args.auth}")
        sys.exit(1)

    try:
        blocked_ips, firewall_stats = parse_firewall_log(args.firewall)
    except FileNotFoundError:
        print(f"[ERROR] Firewall log file not found: {args.firewall}")
        sys.exit(1)

    brute_force = detect_brute_force(failed_attempts)
    firewall_threats = detect_firewall_threats(blocked_ips)
    unusual_logins = detect_unusual_hour_logins(successful_logins)

    report = generate_report(
        brute_force, firewall_threats, unusual_logins, auth_stats, firewall_stats
    )

    print(report)

    with open(args.output, "w") as f:
        f.write(report)

    print(f"\n[*] Report saved to {args.output}")


if __name__ == "__main__":
    main()
