#!/usr/bin/env python3
"""
Mininet Network Topology for SYN Flood Attack Demonstration

This script creates a simple network topology with:
- 1 attacker host
- 1 victim/server host  
- 1 legitimate client host
- 1 switch connecting all hosts
"""

from mininet.net import Mininet
from mininet.node import Controller, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info


def create_topology():
    """Create and return the network topology."""
    
    info('*** Creating network\n')
    net = Mininet(controller=Controller, switch=OVSKernelSwitch)

    info('*** Adding controller\n')
    net.addController('c0')

    info('*** Adding switch\n')
    s1 = net.addSwitch('s1')

    info('*** Adding hosts\n')
    # Attacker host
    attacker = net.addHost('attacker', ip='10.0.0.1/24')
    # Victim/Server host
    victim = net.addHost('victim', ip='10.0.0.2/24')
    # Legitimate client host
    client = net.addHost('client', ip='10.0.0.3/24')

    info('*** Creating links\n')
    net.addLink(attacker, s1)
    net.addLink(victim, s1)
    net.addLink(client, s1)

    return net


def run_topology():
    """Run the network topology with CLI."""
    setLogLevel('info')
    
    net = create_topology()
    
    info('*** Starting network\n')
    net.start()
    
    info('*** Network topology created:\n')
    info('    attacker (10.0.0.1) -- s1 -- victim (10.0.0.2)\n')
    info('                          |                      \n')
    info('                       client (10.0.0.3)         \n')
    info('\n')
    info('*** Testing connectivity\n')
    net.pingAll()
    
    info('*** Running CLI\n')
    CLI(net)
    
    info('*** Stopping network\n')
    net.stop()


if __name__ == '__main__':
    run_topology()
