#!/usr/bin/env python3
"""
Firewall Rules for SYN Flood Defense

This script provides functions to apply iptables-based firewall rules
to mitigate SYN flood attacks.
"""

import argparse
import subprocess
import sys


def run_command(cmd, check=True):
    """Run a shell command and return the result."""
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            check=check
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Error running command: {cmd}")
        print(f"Error: {e.stderr}")
        return None


def enable_syn_cookies():
    """Enable SYN cookies to protect against SYN flood attacks."""
    print("[*] Enabling SYN cookies...")
    run_command("sysctl -w net.ipv4.tcp_syncookies=1")
    print("[+] SYN cookies enabled")


def disable_syn_cookies():
    """Disable SYN cookies."""
    print("[*] Disabling SYN cookies...")
    run_command("sysctl -w net.ipv4.tcp_syncookies=0")
    print("[+] SYN cookies disabled")


def set_syn_backlog(size=2048):
    """Set the SYN backlog queue size."""
    print(f"[*] Setting SYN backlog to {size}...")
    run_command(f"sysctl -w net.ipv4.tcp_max_syn_backlog={size}")
    print(f"[+] SYN backlog set to {size}")


def apply_rate_limit_rules(interface="eth0", rate="25/second", burst=50):
    """
    Apply iptables rules to rate limit incoming SYN packets.
    
    Args:
        interface: Network interface to apply rules to
        rate: Rate limit (e.g., "25/second")
        burst: Burst limit
    """
    print(f"[*] Applying SYN rate limiting rules on {interface}...")
    
    # Flush existing rules in the SYN_FLOOD chain if it exists
    run_command("iptables -F SYN_FLOOD 2>/dev/null", check=False)
    run_command("iptables -X SYN_FLOOD 2>/dev/null", check=False)
    
    # Create a new chain for SYN flood protection
    run_command("iptables -N SYN_FLOOD")
    
    # Add rules to the SYN_FLOOD chain
    # Limit SYN packets rate
    run_command(f"iptables -A SYN_FLOOD -m limit --limit {rate} --limit-burst {burst} -j RETURN")
    # Log and drop packets exceeding the rate
    run_command("iptables -A SYN_FLOOD -j LOG --log-prefix 'SYN_FLOOD_DROP: ' --log-level 4")
    run_command("iptables -A SYN_FLOOD -j DROP")
    
    # Direct SYN packets to the SYN_FLOOD chain
    run_command(f"iptables -I INPUT -i {interface} -p tcp --syn -j SYN_FLOOD")
    
    print(f"[+] Rate limiting rules applied: {rate}, burst {burst}")


def apply_connection_limit_rules(interface="eth0", conn_limit=20):
    """
    Apply iptables rules to limit concurrent connections per source IP.
    
    Args:
        interface: Network interface to apply rules to
        conn_limit: Maximum connections per source IP
    """
    print(f"[*] Applying connection limit rules on {interface}...")
    
    # Limit connections per source IP
    run_command(f"iptables -A INPUT -i {interface} -p tcp --syn -m connlimit --connlimit-above {conn_limit} -j DROP")
    
    print(f"[+] Connection limit applied: {conn_limit} connections per IP")


def apply_invalid_packet_rules():
    """Drop invalid TCP packets."""
    print("[*] Applying invalid packet rules...")
    
    # Drop invalid packets
    run_command("iptables -A INPUT -m state --state INVALID -j DROP")
    
    # Drop packets with all TCP flags set (XMAS scan)
    run_command("iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP")
    
    # Drop NULL packets
    run_command("iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP")
    
    print("[+] Invalid packet rules applied")


def clear_all_rules():
    """Clear all iptables rules."""
    print("[*] Clearing all iptables rules...")
    
    # Flush all chains
    run_command("iptables -F")
    run_command("iptables -X SYN_FLOOD 2>/dev/null", check=False)
    
    # Reset default policies
    run_command("iptables -P INPUT ACCEPT")
    run_command("iptables -P FORWARD ACCEPT")
    run_command("iptables -P OUTPUT ACCEPT")
    
    print("[+] All iptables rules cleared")


def show_rules():
    """Display current iptables rules."""
    print("[*] Current iptables rules:")
    print("-" * 60)
    result = run_command("iptables -L -n -v")
    if result:
        print(result)
    print("-" * 60)


def apply_all_defenses(interface="eth0"):
    """Apply all defense mechanisms."""
    print("=" * 60)
    print("[*] Applying all SYN flood defense mechanisms")
    print("=" * 60)
    
    enable_syn_cookies()
    set_syn_backlog(4096)
    apply_rate_limit_rules(interface)
    apply_connection_limit_rules(interface)
    apply_invalid_packet_rules()
    
    print("=" * 60)
    print("[+] All defense mechanisms applied successfully")
    print("=" * 60)


def main():
    """Main function to parse arguments and apply defenses."""
    parser = argparse.ArgumentParser(
        description="Firewall Rules for SYN Flood Defense"
    )
    
    parser.add_argument(
        "--action",
        choices=["enable", "disable", "show", "clear"],
        default="enable",
        help="Action to perform (default: enable)"
    )
    parser.add_argument(
        "-i", "--interface",
        default="eth0",
        help="Network interface (default: eth0)"
    )
    parser.add_argument(
        "--rate",
        default="25/second",
        help="Rate limit for SYN packets (default: 25/second)"
    )
    parser.add_argument(
        "--burst",
        type=int,
        default=50,
        help="Burst limit (default: 50)"
    )
    parser.add_argument(
        "--conn-limit",
        type=int,
        default=20,
        help="Connection limit per IP (default: 20)"
    )
    
    args = parser.parse_args()
    
    if args.action == "enable":
        apply_all_defenses(args.interface)
    elif args.action == "disable":
        disable_syn_cookies()
        clear_all_rules()
    elif args.action == "show":
        show_rules()
    elif args.action == "clear":
        clear_all_rules()


if __name__ == "__main__":
    main()
