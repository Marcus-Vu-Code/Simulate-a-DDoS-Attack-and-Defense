# Simulate-a-DDoS-Attack-and-Defense

A demonstration of SYN flood attacks and defense mechanisms using Mininet virtual network testbed.

## Overview

This project demonstrates:
1. **SYN Flood Attack**: A type of DDoS attack that exploits the TCP handshake by sending a flood of SYN packets with spoofed source IPs
2. **Defense Mechanisms**: Countermeasures including firewall rules, rate limiting, and SYN cookies

## ⚠️ Disclaimer

**This project is for educational purposes only.** The attack scripts should only be used in controlled, authorized environments. Unauthorized use against systems you do not own or have explicit permission to test is illegal and unethical.

## Project Structure

```
├── attack/
│   ├── __init__.py
│   └── syn_flood.py          # SYN flood attack script
├── defense/
│   ├── __init__.py
│   ├── firewall_rules.py     # iptables-based firewall rules
│   └── rate_limiter.py       # Application-level rate limiting
├── topology.py               # Mininet network topology
├── run_simulation.py         # Main simulation runner
└── README.md
```

## Requirements

- Python 3.7+
- Mininet (for full simulation)
- Scapy (for packet crafting)
- Root/sudo privileges (for network operations)

### Installation

```bash
# Install Mininet (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install mininet

# Install Python dependencies
pip install scapy

# Verify Mininet installation
sudo mn --test pingall
```

## Usage

### Full Simulation (requires Mininet and root)

Run the complete attack and defense demonstration:

```bash
sudo python run_simulation.py --mode full
```

This will:
1. Create a virtual network with attacker, victim, and client hosts
2. Demonstrate the attack without defenses
3. Apply countermeasures (SYN cookies, rate limiting, firewall rules)
4. Demonstrate the attack with defenses active

### Interactive Mode

Start Mininet CLI for manual testing:

```bash
sudo python run_simulation.py --mode cli
```

Available commands in CLI:
```
# Start web server on victim
victim python3 -m http.server 80 &

# Test connectivity from client
client curl http://10.0.0.2/

# Run attack from attacker
attacker python3 attack/syn_flood.py -t 10.0.0.2 -p 80 -c 500
```

### Demo Mode (No Mininet Required)

Run a demonstration of the rate limiter and flood detector:

```bash
python run_simulation.py --mode demo
```

### Individual Components

#### SYN Flood Attack

```bash
sudo python attack/syn_flood.py -t <target_ip> -p <port> -c <packet_count>

Options:
  -t, --target    Target IP address (required)
  -p, --port      Target port (default: 80)
  -c, --count     Number of packets (default: 1000)
  -d, --delay     Delay between packets in seconds (default: 0)
  -q, --quiet     Suppress output
```

#### Firewall Rules

```bash
# Enable all defenses
sudo python defense/firewall_rules.py --action enable

# Clear all rules
sudo python defense/firewall_rules.py --action clear

# Show current rules
sudo python defense/firewall_rules.py --action show

Options:
  --interface     Network interface (default: eth0)
  --rate          SYN rate limit (default: 25/second)
  --burst         Burst limit (default: 50)
  --conn-limit    Connections per IP (default: 20)
```

#### Rate Limiter Demo

```bash
python defense/rate_limiter.py --demo both
```

## Defense Mechanisms

### 1. SYN Cookies

SYN cookies avoid allocating resources for half-open connections by encoding connection state in the TCP sequence number.

```bash
# Enable SYN cookies
sysctl -w net.ipv4.tcp_syncookies=1
```

### 2. Rate Limiting (iptables)

Limit the rate of incoming SYN packets:

```bash
# Create SYN flood protection chain
iptables -N SYN_FLOOD
iptables -A SYN_FLOOD -m limit --limit 25/second --limit-burst 50 -j RETURN
iptables -A SYN_FLOOD -j DROP
iptables -I INPUT -p tcp --syn -j SYN_FLOOD
```

### 3. Connection Limiting

Limit concurrent connections per source IP:

```bash
iptables -A INPUT -p tcp --syn -m connlimit --connlimit-above 20 -j DROP
```

### 4. SYN Backlog Tuning

Increase the SYN backlog queue size:

```bash
sysctl -w net.ipv4.tcp_max_syn_backlog=4096
```

## Network Topology

```
    attacker (10.0.0.1)
           |
           |
    [    Switch    ]
      /          \
     /            \
victim (10.0.0.2)  client (10.0.0.3)
```

## How SYN Flood Works

1. **Normal TCP Handshake**:
   - Client sends SYN
   - Server responds with SYN-ACK, allocates resources
   - Client sends ACK, connection established

2. **SYN Flood Attack**:
   - Attacker sends many SYN packets with spoofed source IPs
   - Server responds with SYN-ACK to non-existent hosts
   - Server's SYN backlog fills up with half-open connections
   - Legitimate clients cannot establish connections

## Example Output

```
======================================================================
 SYN FLOOD ATTACK AND DEFENSE SIMULATION
======================================================================

----------------------------------------------------------------------
 PHASE 2: ATTACK WITHOUT DEFENSES
----------------------------------------------------------------------
*** Launching SYN flood attack...
[*] Starting SYN flood attack on 10.0.0.2:80
[*] Sending 300 SYN packets...
[*] Sent 100 packets (452.35 packets/sec)
[*] Sent 200 packets (448.21 packets/sec)
[*] Sent 300 packets (445.67 packets/sec)
[+] Attack completed: 300 packets sent in 0.67 seconds

*** Server not responding - attack successful!

----------------------------------------------------------------------
 PHASE 4: ATTACK WITH DEFENSES ENABLED
----------------------------------------------------------------------
*** Server is responding - defenses effective!
```

## References

- [TCP SYN Flood Attack](https://en.wikipedia.org/wiki/SYN_flood)
- [Mininet Documentation](http://mininet.org/)
- [Scapy Documentation](https://scapy.readthedocs.io/)
- [iptables Tutorial](https://www.netfilter.org/documentation/)

## License

This project is for educational purposes only. Use responsibly and only in authorized environments.