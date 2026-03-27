#!/usr/bin/env python3
"""
Network Diagnostic Tool
Checks if controller is receiving packets and switches are properly configured
"""

from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
import subprocess
import time

def check_controller_connection():
    """Check if Ryu controller is running"""
    info("*** Checking controller...\n")
    try:
        result = subprocess.run(['netstat', '-tlnp'], capture_output=True, text=True)
        if ':6653' in result.stdout or ':6633' in result.stdout:
            info("✓ Controller is listening\n")
            return True
        else:
            info("✗ Controller NOT listening on port 6653/6633\n")
            return False
    except:
        info("⚠ Could not check controller status\n")
        return False

def diagnose_network():
    """Run diagnostic tests"""
    setLogLevel('info')
    
    info("="*70 + "\n")
    info("NETWORK DIAGNOSTICS\n")
    info("="*70 + "\n")
    
    # Check controller first
    if not check_controller_connection():
        info("\n⚠ WARNING: Start Ryu controller first!\n")
        info("   Run: ryu-manager controller.py\n\n")
    
    info("*** Creating simple test network (2 hosts, 1 switch)\n")
    
    net = Mininet(
        controller=RemoteController,
        switch=OVSSwitch,
        autoSetMacs=True,
        autoStaticArp=True
    )
    
    info("*** Adding controller\n")
    c0 = net.addController(
        'c0',
        controller=RemoteController,
        ip='127.0.0.1',
        port=6653
    )
    
    info("*** Adding switch\n")
    s1 = net.addSwitch('s1', protocols='OpenFlow13')
    
    info("*** Adding hosts\n")
    h1 = net.addHost('h1', ip='10.0.0.1/24')
    h2 = net.addHost('h2', ip='10.0.0.2/24')
    
    info("*** Creating links\n")
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    
    info("*** Starting network\n")
    net.start()
    
    # Wait for controller connection
    info("*** Waiting for controller connection...\n")
    time.sleep(2)
    
    # Check switch connection
    info("*** Checking switch connection:\n")
    result = s1.cmd('ovs-vsctl show')
    info(result)
    
    info("\n*** Checking OpenFlow connection:\n")
    result = s1.cmd('ovs-ofctl show s1 -O OpenFlow13')
    info(result)
    
    info("\n*** Checking controller connection:\n")
    result = s1.cmd('ovs-vsctl get-controller s1')
    info(result)
    
    info("\n*** Checking if switch is connected:\n")
    result = s1.cmd('ovs-vsctl get Bridge s1 controller | grep -q tcp && echo CONNECTED || echo DISCONNECTED')
    info(result)
    
    info("\n*** Current flows on switch:\n")
    result = s1.cmd('ovs-ofctl dump-flows s1 -O OpenFlow13')
    info(result)
    
    info("\n" + "="*70 + "\n")
    info("CONNECTIVITY TESTS\n")
    info("="*70 + "\n")
    
    info("*** Test 1: Direct ping (h1 -> h2)\n")
    result = h1.cmd('ping -c 3 10.0.0.2')
    info(result)
    
    if 'bytes from' in result:
        info("✓ Ping successful!\n")
    else:
        info("✗ Ping failed!\n")
        info("\n*** Checking ARP table:\n")
        info(h1.cmd('arp -n'))
        
        info("\n*** Checking routes:\n")
        info(h1.cmd('ip route'))
        
        info("\n*** Checking if packets reach switch:\n")
        info("Run 'tcpdump -i s1-eth1' in another terminal\n")
    
    info("\n*** Flows after ping:\n")
    result = s1.cmd('ovs-ofctl dump-flows s1 -O OpenFlow13')
    info(result)
    
    info("\n" + "="*70 + "\n")
    info("DIAGNOSIS COMPLETE\n")
    info("="*70 + "\n")
    info("\nIf ping worked: Your controller is functioning!\n")
    info("If ping failed: Check controller logs for packet_in events\n")
    info("\nStarting CLI for manual testing...\n")
    info("Try: pingall, h1 ping h2, dump\n")
    info("="*70 + "\n\n")
    
    CLI(net)
    
    info("*** Stopping network\n")
    net.stop()

if __name__ == '__main__':
    diagnose_network()
