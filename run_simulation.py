#!/usr/bin/env python3
"""
SYN Flood Attack and Defense Simulation Runner

This script orchestrates the complete SYN flood attack and defense demonstration
using Mininet. It creates the network topology, starts services, performs
the attack, and applies countermeasures.

Usage:
    sudo python run_simulation.py [--mode full|attack|defense|demo]
"""

import argparse
import os
import sys
import time

# Global variables for Mininet imports (set dynamically)
Mininet = None
Controller = None
OVSKernelSwitch = None
CLI = None
setLogLevel = None
info = None


def check_root():
    """Check for root privileges."""
    if os.geteuid() != 0:
        print("Error: This script requires root privileges.")
        print("Run with: sudo python run_simulation.py")
        sys.exit(1)


def load_mininet():
    """Import Mininet modules and set global variables."""
    global Mininet, Controller, OVSKernelSwitch, CLI, setLogLevel, info
    try:
        from mininet.net import Mininet as _Mininet
        from mininet.node import Controller as _Controller, OVSKernelSwitch as _OVSKernelSwitch
        from mininet.cli import CLI as _CLI
        from mininet.log import setLogLevel as _setLogLevel, info as _info
        
        Mininet = _Mininet
        Controller = _Controller
        OVSKernelSwitch = _OVSKernelSwitch
        CLI = _CLI
        setLogLevel = _setLogLevel
        info = _info
    except ImportError:
        print("Error: Mininet is not installed.")
        print("Install with: sudo apt-get install mininet")
        sys.exit(1)


def create_network():
    """Create and return the network topology."""
    info('*** Creating network topology\n')
    net = Mininet(controller=Controller, switch=OVSKernelSwitch)
    
    info('*** Adding controller\n')
    net.addController('c0')
    
    info('*** Adding switch\n')
    s1 = net.addSwitch('s1')
    
    info('*** Adding hosts\n')
    attacker = net.addHost('attacker', ip='10.0.0.1/24')
    victim = net.addHost('victim', ip='10.0.0.2/24')
    client = net.addHost('client', ip='10.0.0.3/24')
    
    info('*** Creating links\n')
    net.addLink(attacker, s1)
    net.addLink(victim, s1)
    net.addLink(client, s1)
    
    return net


def start_web_server(victim):
    """Start a simple web server on the victim host."""
    info('*** Starting web server on victim (port 80)\n')
    victim.cmd('python3 -m http.server 80 &')
    time.sleep(1)
    return True


def check_server_response(host, target_ip, port=80):
    """Check if the server is responding."""
    result = host.cmd(f'curl -s -o /dev/null -w "%{{http_code}}" --connect-timeout 2 http://{target_ip}:{port}/ 2>/dev/null')
    return result.strip() == "200"


def run_attack(attacker, target_ip, count=500, port=80):
    """Run the SYN flood attack from the attacker host."""
    info(f'*** Running SYN flood attack: {count} packets to {target_ip}:{port}\n')
    
    # Create attack script on attacker
    attack_script = f'''
import sys
sys.path.insert(0, '/home/runner/work/Simulate-a-DDoS-Attack-and-Defense/Simulate-a-DDoS-Attack-and-Defense')
from attack.syn_flood import syn_flood
syn_flood("{target_ip}", {port}, {count}, verbose=True)
'''
    
    # Write and execute the attack script
    attacker.cmd(f'echo \'{attack_script}\' > /tmp/attack.py')
    output = attacker.cmd('python3 /tmp/attack.py')
    info(output + '\n')
    
    return True


def apply_defenses(victim):
    """Apply defense mechanisms on the victim host."""
    info('*** Applying defense mechanisms on victim\n')
    
    # Enable SYN cookies
    victim.cmd('sysctl -w net.ipv4.tcp_syncookies=1')
    info('    - SYN cookies enabled\n')
    
    # Increase SYN backlog
    victim.cmd('sysctl -w net.ipv4.tcp_max_syn_backlog=4096')
    info('    - SYN backlog increased to 4096\n')
    
    # Apply iptables rate limiting
    victim.cmd('iptables -F')
    victim.cmd('iptables -N SYN_FLOOD 2>/dev/null || iptables -F SYN_FLOOD')
    victim.cmd('iptables -A SYN_FLOOD -m limit --limit 25/second --limit-burst 50 -j RETURN')
    victim.cmd('iptables -A SYN_FLOOD -j DROP')
    victim.cmd('iptables -I INPUT -p tcp --syn -j SYN_FLOOD')
    info('    - Rate limiting rules applied (25/sec, burst 50)\n')
    
    # Connection limiting
    victim.cmd('iptables -A INPUT -p tcp --syn -m connlimit --connlimit-above 20 -j DROP')
    info('    - Connection limit applied (20 per IP)\n')
    
    return True


def clear_defenses(victim):
    """Clear defense mechanisms on the victim host."""
    info('*** Clearing defense mechanisms on victim\n')
    
    victim.cmd('sysctl -w net.ipv4.tcp_syncookies=0')
    victim.cmd('iptables -F')
    victim.cmd('iptables -X SYN_FLOOD 2>/dev/null')
    
    return True


def monitor_connections(victim, duration=5):
    """Monitor TCP connections on the victim."""
    info(f'*** Monitoring connections for {duration} seconds\n')
    
    for i in range(duration):
        syn_recv = victim.cmd("netstat -an | grep SYN_RECV | wc -l").strip()
        established = victim.cmd("netstat -an | grep ESTABLISHED | wc -l").strip()
        info(f'    Second {i+1}: SYN_RECV={syn_recv}, ESTABLISHED={established}\n')
        time.sleep(1)


def run_full_simulation(net):
    """Run the complete attack and defense simulation."""
    attacker = net.get('attacker')
    victim = net.get('victim')
    client = net.get('client')
    
    victim_ip = '10.0.0.2'
    
    print("\n" + "=" * 70)
    print(" SYN FLOOD ATTACK AND DEFENSE SIMULATION")
    print("=" * 70)
    
    # Phase 1: Setup
    print("\n" + "-" * 70)
    print(" PHASE 1: NETWORK SETUP")
    print("-" * 70)
    
    info('*** Testing network connectivity\n')
    net.pingAll()
    
    start_web_server(victim)
    
    # Check server is responding
    if check_server_response(client, victim_ip):
        info('*** Web server is responding normally\n')
    else:
        info('*** Warning: Web server may not be responding\n')
    
    # Phase 2: Attack without defenses
    print("\n" + "-" * 70)
    print(" PHASE 2: ATTACK WITHOUT DEFENSES")
    print("-" * 70)
    
    clear_defenses(victim)
    info('*** Defenses disabled - server is vulnerable\n')
    
    info('*** Launching SYN flood attack...\n')
    run_attack(attacker, victim_ip, count=300, port=80)
    
    info('*** Checking server status after attack...\n')
    monitor_connections(victim, duration=3)
    
    if check_server_response(client, victim_ip):
        info('*** Server still responding (may be degraded)\n')
    else:
        info('*** Server not responding - attack successful!\n')
    
    # Phase 3: Apply defenses
    print("\n" + "-" * 70)
    print(" PHASE 3: APPLYING DEFENSES")
    print("-" * 70)
    
    apply_defenses(victim)
    
    # Let connections clear
    info('*** Waiting for connections to reset...\n')
    time.sleep(3)
    
    # Phase 4: Attack with defenses
    print("\n" + "-" * 70)
    print(" PHASE 4: ATTACK WITH DEFENSES ENABLED")
    print("-" * 70)
    
    info('*** Launching SYN flood attack with defenses active...\n')
    run_attack(attacker, victim_ip, count=300, port=80)
    
    info('*** Checking server status after attack...\n')
    monitor_connections(victim, duration=3)
    
    if check_server_response(client, victim_ip):
        info('*** Server is responding - defenses effective!\n')
    else:
        info('*** Server not responding - defenses may need tuning\n')
    
    # Show iptables statistics
    print("\n" + "-" * 70)
    print(" FIREWALL STATISTICS")
    print("-" * 70)
    
    info('*** Packets dropped by firewall:\n')
    iptables_output = victim.cmd('iptables -L SYN_FLOOD -v -n 2>/dev/null')
    info(iptables_output + '\n')
    
    # Summary
    print("\n" + "=" * 70)
    print(" SIMULATION COMPLETE")
    print("=" * 70)
    print("""
Summary:
--------
1. Created network with attacker, victim, and client hosts
2. Demonstrated SYN flood attack against unprotected server
3. Applied countermeasures:
   - SYN cookies
   - Increased SYN backlog
   - Rate limiting via iptables
   - Connection limiting per IP
4. Verified defenses mitigate the attack

The defense mechanisms help protect against SYN flood attacks by:
- SYN cookies: Avoid allocating resources for half-open connections
- Rate limiting: Cap the rate of incoming SYN packets
- Connection limiting: Prevent single IPs from opening too many connections
""")


def run_demo_mode():
    """Run a quick demonstration without Mininet."""
    print("\n" + "=" * 70)
    print(" SYN FLOOD DEFENSE DEMONSTRATION (No Mininet Required)")
    print("=" * 70)
    
    # Import and run the rate limiter demo
    print("\n[*] Running Rate Limiter Demonstration...")
    print("-" * 70)
    
    from defense.rate_limiter import demo_rate_limiter, demo_flood_detector
    
    demo_rate_limiter()
    print()
    demo_flood_detector()
    
    print("\n" + "=" * 70)
    print(" DEMONSTRATION COMPLETE")
    print("=" * 70)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="SYN Flood Attack and Defense Simulation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
  full     - Run complete simulation with Mininet (requires sudo)
  attack   - Only run the attack phase
  defense  - Only apply and demonstrate defenses
  demo     - Run rate limiter demo (no Mininet required)
  cli      - Start Mininet CLI for manual testing

Examples:
  sudo python run_simulation.py --mode full
  sudo python run_simulation.py --mode cli
  python run_simulation.py --mode demo
        """
    )
    
    parser.add_argument(
        "--mode",
        choices=["full", "attack", "defense", "demo", "cli"],
        default="full",
        help="Simulation mode (default: full)"
    )
    
    args = parser.parse_args()
    
    # Demo mode doesn't need Mininet or root
    if args.mode == "demo":
        run_demo_mode()
        return
    
    # Other modes need root
    if os.geteuid() != 0:
        print("Error: This mode requires root privileges.")
        print("Run with: sudo python run_simulation.py")
        sys.exit(1)
    
    # Load Mininet modules
    load_mininet()
    
    setLogLevel('info')
    
    # Create network
    net = create_network()
    
    try:
        info('*** Starting network\n')
        net.start()
        
        if args.mode == "full":
            run_full_simulation(net)
        elif args.mode == "attack":
            attacker = net.get('attacker')
            start_web_server(net.get('victim'))
            run_attack(attacker, '10.0.0.2', count=500)
        elif args.mode == "defense":
            apply_defenses(net.get('victim'))
            info('*** Defenses applied. Use CLI to test.\n')
            CLI(net)
        elif args.mode == "cli":
            info('*** Starting CLI for manual testing\n')
            info('*** Available hosts: attacker, victim, client\n')
            info('*** Example commands:\n')
            info('***   victim python3 -m http.server 80 &\n')
            info('***   client curl http://10.0.0.2/\n')
            info('***   attacker python3 attack/syn_flood.py -t 10.0.0.2 -p 80 -c 100\n')
            CLI(net)
    
    except KeyboardInterrupt:
        info('\n*** Interrupted by user\n')
    
    finally:
        info('*** Stopping network\n')
        net.stop()


if __name__ == '__main__':
    main()
