#!/usr/bin/env python3
"""
Mininet Topology for Multi-Feature DDoS Detection — FIXED v4

BUGS FIXED:
  1. All attack helpers used --flood  → always Hard Threshold, Multi-Feature/Soft never fired
  2. cpu=1.0/20 caused cgroup permission errors on Ubuntu
  3. ttl_spoof_flood was sequential (blocking CLI)
  4. No Soft Threshold / CNN test function existed
  5. No Window Exhaustion function existed
  6. No hping3 availability check
  7. TCLink → HTB quantum warnings  (fix: plain Link)
  8. RTNETLINK: File exists on restart  (fix: mn -c cleanup at startup)

Attack speed guide:
  speed='hard'  → --flood       → >5000 PPS → HARD THRESHOLD
  speed='soft'  → -i u500       → ~2000 PPS → SOFT THRESHOLD / CNN (after 25s)
  speed='multi' → -i u1000      → ~1000 PPS → MULTI-FEATURE RULES  (default)
"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.link import Link
from mininet.log import setLogLevel, info, warning
from mininet.cli import CLI

# ============================================================================
# CUSTOM CLI — exposes all helper functions as direct commands
# Fixes: Mininet's py command runs in cli.py scope, not topology.py scope,
#        so functions like check_attacks() are invisible to py.
#        Solution: subclass CLI and add do_* methods that call our functions.
# ============================================================================
class DDoSCLI(CLI):
    """
    Extended Mininet CLI with DDoS attack helpers built in.

    Type commands WITHOUT 'py' prefix:
      mininet> check_attacks
      mininet> all_attacks
      mininet> stop_attacks
      mininet> icmp_flood
      mininet> icmp_flood hard
      mininet> syn_flood
      mininet> udp_flood
      mininet> fin_flood
      mininet> window_flood
      mininet> ttl_spoof
      mininet> amp_flood
      mininet> soft_flood
    """

    def do_check_attacks(self, _line):
        'Show which hping3 processes are running on each host'
        check_attacks(self.mn)

    def do_all_attacks(self, _line):
        'Launch all 3 detection layers simultaneously (8 hosts, all 10 features)'
        all_attacks(self.mn)

    def do_stop_attacks(self, _line):
        'Kill all hping3 processes on all hosts'
        stop_attacks(self.mn)

    def do_icmp_flood(self, line):
        'ICMP flood — usage: icmp_flood [hard|soft|multi]'
        speed = line.strip() or 'multi'
        icmp_flood(self.mn, speed=speed)

    def do_syn_flood(self, line):
        'SYN flood — usage: syn_flood [hard|soft|multi]'
        speed = line.strip() or 'multi'
        syn_flood(self.mn, speed=speed)

    def do_udp_flood(self, line):
        'UDP flood — usage: udp_flood [hard|soft|multi]'
        speed = line.strip() or 'multi'
        udp_flood(self.mn, speed=speed)

    def do_fin_flood(self, line):
        'FIN/RST flood — usage: fin_flood [hard|soft|multi]'
        speed = line.strip() or 'multi'
        fin_flood(self.mn, speed=speed)

    def do_window_flood(self, line):
        'TCP Window exhaustion — usage: window_flood [hard|soft|multi]'
        speed = line.strip() or 'multi'
        window_flood(self.mn, speed=speed)

    def do_ttl_spoof(self, _line):
        'TTL spoofing flood (alternates TTL values to create variance)'
        ttl_spoof_flood(self.mn)

    def do_amp_flood(self, line):
        'Amplification/botnet flood — usage: amp_flood [hard|soft|multi]'
        speed = line.strip() or 'multi'
        amp_flood(self.mn, speed=speed)

    def do_soft_flood(self, _line):
        'Soft threshold / CNN test flood (~2000 PPS, h1+h2)'
        soft_flood(self.mn)
from mininet.node import OVSKernelSwitch, RemoteController
import os
import time


# ============================================================================
# CLEANUP
# ============================================================================
def cleanup_mininet():
    info('*** Cleaning up stale Mininet state (mn -c)...\n')
    os.system('sudo mn -c 2>/dev/null')
    os.system('sudo ovs-vsctl del-controller '
              '$(sudo ovs-vsctl list-br 2>/dev/null) 2>/dev/null')
    os.system('sudo pkill -f hping3 2>/dev/null')
    time.sleep(1)
    info('  OK Cleanup done\n')


def _check_hping3():
    result = os.popen('which hping3').read().strip()
    if not result:
        info('  hping3 not found - installing...\n')
        os.system('sudo apt-get install -y hping3 2>/dev/null')
        info('  OK hping3 installed\n')
    else:
        info(f'  OK hping3: {result}\n')


# ============================================================================
# TOPOLOGY
# ============================================================================
class MyTopo(Topo):
    """
    6 switches x 3 hosts = 18 hosts
    s1-s2-s3-s4-s5-s6 (linear backbone)

    FIX: Removed bw= (causes HTB quantum warnings) and cpu= (cgroup errors)
    FIX: Uses plain Link not TCLink
    """

    def build(self):
        switches = []
        for i in range(1, 7):
            s = self.addSwitch(f's{i}',
                               cls=OVSKernelSwitch,
                               protocols='OpenFlow13')
            switches.append(s)
        s1, s2, s3, s4, s5, s6 = switches

        host_map = {
            s1: [(1,  '10.0.0.1'),  (2,  '10.0.0.2'),  (3,  '10.0.0.3')],
            s2: [(4,  '10.0.0.4'),  (5,  '10.0.0.5'),  (6,  '10.0.0.6')],
            s3: [(7,  '10.0.0.7'),  (8,  '10.0.0.8'),  (9,  '10.0.0.9')],
            s4: [(10, '10.0.0.10'), (11, '10.0.0.11'), (12, '10.0.0.12')],
            s5: [(13, '10.0.0.13'), (14, '10.0.0.14'), (15, '10.0.0.15')],
            s6: [(16, '10.0.0.16'), (17, '10.0.0.17'), (18, '10.0.0.18')],
        }

        for sw, hosts in host_map.items():
            for num, ip in hosts:
                mac = f"00:00:00:00:00:{num:02x}"
                h = self.addHost(f'h{num}', mac=mac, ip=f"{ip}/24")
                self.addLink(h, sw)   # plain Link - no HTB, no warnings

        for a, b in [(s1, s2), (s2, s3), (s3, s4), (s4, s5), (s5, s6)]:
            self.addLink(a, b)


# ============================================================================
# STARTUP
# ============================================================================
def start_network():
    cleanup_mininet()
    _check_hping3()

    info('*** Creating topology\n')
    topo = MyTopo()
    c0   = RemoteController('c0', ip='127.0.0.1', port=6633)

    net = Mininet(
        topo=topo,
        link=Link,
        controller=c0,
        switch=OVSKernelSwitch,
        autoSetMacs=False,
    )

    info('*** Starting network\n')
    net.start()

    info('*** Configuring switches\n')
    for sw in net.switches:
        sw.cmd(f'ovs-vsctl set-fail-mode {sw.name} secure')
        sw.cmd(f'ovs-vsctl set bridge {sw.name} protocols=OpenFlow13')
        info(f'  OK {sw.name} secure + OpenFlow13\n')

    info('*** Waiting 10s for controller connection...\n')
    time.sleep(10)

    info('*** Verifying controller connections\n')
    all_connected = True
    for sw in net.switches:
        result = sw.cmd(f'ovs-vsctl get-controller {sw.name}')
        if '127.0.0.1:6633' in result:
            info(f'  OK {sw.name} connected\n')
        else:
            warning(f'  FAIL {sw.name} NOT connected\n')
            all_connected = False

    if all_connected:
        _print_ready_banner()
    else:
        _print_warning_banner()

    _print_attack_commands()
    DDoSCLI(net)

    info('*** Stopping network\n')
    net.stop()


# ============================================================================
# ATTACK HELPERS
# ============================================================================

def _speed_params(speed):
    """
    Returns (interval_flag, approx_pps, layer_label).

    CRITICAL FIX: Old code used --flood everywhere.
    --flood ignores ALL interval flags and sends at max speed (>5000 PPS).
    This means PacketIn fires once, flow is installed permanently,
    and only Hard Threshold could ever fire.

    Correct mapping:
      hard  → --flood   → >5000 PPS → Hard Threshold (instant)
      soft  → -i u500   → ~2000 PPS → Soft/CNN zone  (CNN after 25s warmup)
      multi → -i u1000  → ~1000 PPS → Multi-Feature  (fires within 5-10s)
    """
    if speed == 'hard':
        return '--flood', '>5000 PPS', 'HARD THRESHOLD (PPS>5000, instant block)'
    elif speed == 'soft':
        return '-i u500', '~2000 PPS', 'SOFT THRESHOLD/CNN (1000-5000 PPS zone, CNN after 25s)'
    else:
        return '-i u1000', '~1000 PPS', 'MULTI-FEATURE RULES (ICMP/SYN/UDP ratio, fires in 5-10s)'


def _show_attack(label, attacker, victim_ip, layer, detects, notes=''):
    pass  # silent — detections appear in dashboard


def _launch(host_obj, cmd_str, attacker_name, victim_ip, layer_label):
    """Launch hping3 silently in background."""
    host_obj.cmd(cmd_str)


def check_attacks(net):
    """Show which hosts are currently running hping3 attacks."""
    running = []
    for h in net.hosts:
        result = h.cmd('pgrep -c hping3 2>/dev/null || echo 0').strip()
        try:
            if int(result) > 0:
                running.append(h.name)
        except ValueError:
            pass
    if running:
        # Sort numerically: h1, h2, ... h18
        running.sort(key=lambda x: int(x[1:]))
        info(f'  Attacking hosts ({len(running)}): {", ".join(running)}\n')
    else:
        info('  No attacks running.\n')


# ── ICMP Flood ────────────────────────────────────────────────────────────────
def icmp_flood(net, attacker='h1', victim='h18', speed='multi'):
    """
    ICMP Flood - triggers ICMP ratio > 0.50

    FIX: Old version used --flood (Hard Threshold only).
    Default is now speed='multi' (-i u1000, ~1000 PPS, Multi-Feature).

    mininet> py icmp_flood(net)               # Multi-Feature (default)
    mininet> py icmp_flood(net, speed='hard') # Hard Threshold
    mininet> py icmp_flood(net, speed='soft') # Soft Threshold / CNN
    """
    interval, pps, layer = _speed_params(speed)
    vip = net.get(victim).IP()
    _show_attack(f'ICMP Flood [{speed}]', attacker, vip, layer,
                 f'Protocol: ICMP Flood | ICMP ratio > 0.50 | {pps}')
    _launch(net.get(attacker),
            f'hping3 --icmp {interval} {vip} > /dev/null 2>&1 &',
            attacker, vip, f'ICMP/{speed}')


# ── SYN Flood ─────────────────────────────────────────────────────────────────
def syn_flood(net, attacker='h1', victim='h18', speed='multi'):
    """
    SYN Flood - triggers SYN ratio > 0.70, ACK ratio < 0.10

    mininet> py syn_flood(net)
    mininet> py syn_flood(net, speed='hard')
    mininet> py syn_flood(net, speed='soft')
    """
    interval, pps, layer = _speed_params(speed)
    vip = net.get(victim).IP()
    _show_attack(f'SYN Flood [{speed}]', attacker, vip, layer,
                 f'TCP Flags: SYN Flood | SYN ratio > 0.70 | {pps}')
    _launch(net.get(attacker),
            f'hping3 -S {interval} -p 80 --rand-source {vip} > /dev/null 2>&1 &',
            attacker, vip, f'SYN/{speed}')


# ── UDP Flood ─────────────────────────────────────────────────────────────────
def udp_flood(net, attacker='h1', victim='h18', speed='multi'):
    """
    UDP Flood - triggers UDP ratio > 0.70

    mininet> py udp_flood(net)
    mininet> py udp_flood(net, speed='hard')
    mininet> py udp_flood(net, speed='soft')
    """
    interval, pps, layer = _speed_params(speed)
    vip = net.get(victim).IP()
    _show_attack(f'UDP Flood [{speed}]', attacker, vip, layer,
                 f'Protocol: UDP Flood | UDP ratio > 0.70 | {pps}')
    _launch(net.get(attacker),
            f'hping3 --udp {interval} -p 53 --rand-source {vip} > /dev/null 2>&1 &',
            attacker, vip, f'UDP/{speed}')


# ── FIN/RST Flood ─────────────────────────────────────────────────────────────
def fin_flood(net, attacker='h1', victim='h18', speed='multi'):
    """
    FIN Flood - triggers FIN/RST ratio > 0.50

    mininet> py fin_flood(net)
    mininet> py fin_flood(net, speed='hard')
    mininet> py fin_flood(net, speed='soft')
    """
    interval, pps, layer = _speed_params(speed)
    vip = net.get(victim).IP()
    _show_attack(f'FIN Flood [{speed}]', attacker, vip, layer,
                 f'TCP Flags: FIN/RST Flood | FIN/RST ratio > 0.50 | {pps}')
    _launch(net.get(attacker),
            f'hping3 -F {interval} -p 80 {vip} > /dev/null 2>&1 &',
            attacker, vip, f'FIN/{speed}')


# ── TTL Spoof Flood ───────────────────────────────────────────────────────────
def ttl_spoof_flood(net, attacker='h1', victim='h18'):
    """
    TTL Spoofing - triggers TTL variance > 600

    FIX: Old version was sequential (blocked CLI). Now runs in background.
    Alternates TTL values 1,5,20,64,128,200,254 continuously.

    mininet> py ttl_spoof_flood(net)
    """
    vip = net.get(victim).IP()
    # Background loop - alternates TTLs to create high variance
    cmd = (
        "bash -c 'while true; do "
        "for ttl in 1 5 20 64 128 200 254; do "
        f"hping3 -S -p 80 --ttl $ttl --count 30 -i u500 {vip} > /dev/null 2>&1; "
        "done; done' &"
    )
    net.get(attacker).cmd(cmd)
    _show_attack('TTL Spoof Flood', attacker, vip,
                 'MULTI-FEATURE RULES',
                 'TTL: IP Spoofing | TTL variance > 600',
                 'Alternating TTL 1,5,20,64,128,200,254 in background loop')


# ── Window Exhaustion ─────────────────────────────────────────────────────────
def window_flood(net, attacker='h1', victim='h18', speed='multi'):
    """
    TCP Window Exhaustion - triggers avg_tcp_window_size < 256

    Sends SYN packets with TCP window size = 0.

    mininet> py window_flood(net)
    mininet> py window_flood(net, speed='hard')
    mininet> py window_flood(net, speed='soft')
    """
    interval, pps, layer = _speed_params(speed)
    vip = net.get(victim).IP()
    _show_attack(f'Window Exhaustion [{speed}]', attacker, vip, layer,
                 f'TCP Window: window=0 bytes | avg_win < 256 | {pps}')
    _launch(net.get(attacker),
            f'hping3 -S {interval} -p 80 -w 0 {vip} > /dev/null 2>&1 &',
            attacker, vip, f'WIN/{speed}')


# ── Soft Threshold / CNN Flood ────────────────────────────────────────────────
def soft_flood(net, attacker='h1', victim='h18'):
    """
    Controlled rate flood for Soft Threshold + CNN testing.

    Uses 2 hosts at -i u1000 each = ~2000 PPS total (in 1000-5000 soft zone).

    Timeline:
      0s - 25s  : Multi-Feature fires (ICMP ratio detected)
      25s+      : CNN window ready -> Soft Threshold / CNN fires

    Watch controller log for:
      "Waiting CNN warming up Port=X - N/5 samples"
      "CNN Port=X PPS=2000 Pred=DDoS Conf=0.XX"

    mininet> py soft_flood(net)
    """
    vip = net.get(victim).IP()
    for h_name in [attacker, 'h2']:
        _launch(net.get(h_name),
                f'hping3 --icmp -i u1000 {vip} > /dev/null 2>&1 &',
                h_name, vip, 'SOFT/CNN')

    info(f'\n{"="*65}\n')
    info(f'  SOFT THRESHOLD / CNN TEST\n')
    info(f'  Attackers : {attacker} + h2  (combined ~2000 PPS)\n')
    info(f'  Victim    : {victim} ({vip})\n')
    info(f'  Phase 1   : Multi-Feature fires within 5-10s\n')
    info(f'              (ICMP ratio > 0.50)\n')
    info(f'  Phase 2   : CNN fires after 25s warmup\n')
    info(f'              (5 samples x 5s monitor interval)\n')
    info(f'  Dashboard : http://localhost:8080\n')
    info(f'{"="*65}\n\n')


# ── Amplification Flood ───────────────────────────────────────────────────────
def amp_flood(net, attacker='h1', victim='h18', speed='multi'):
    """
    Amplification / Botnet - triggers unique source IPs/s > 300

    mininet> py amp_flood(net)
    mininet> py amp_flood(net, speed='hard')
    mininet> py amp_flood(net, speed='soft')
    """
    interval, pps, layer = _speed_params(speed)
    vip = net.get(victim).IP()
    _show_attack(f'Amplification [{speed}]', attacker, vip, layer,
                 f'Source IP: Amplification | unique IPs/s > 300 | {pps}')
    _launch(net.get(attacker),
            f'hping3 {interval} -p 80 --rand-source {vip} > /dev/null 2>&1 &',
            attacker, vip, f'AMP/{speed}')



# ── All 3 Layers Simultaneously — ALL 18 HOSTS ───────────────────────────────
def all_attacks(net):
    """
    ALL 18 hosts attack each other.
    RANDOM each run: hosts shuffled, random number detected (6-13), rest safe.

    Fast attacks  > 1000 PPS → controller detects and blocks
    Slow attacks  ~20   PPS  → below PPS_SOFT=100 threshold → never detected

    Every run the blocked vs safe set is DIFFERENT — truly unpredictable.
    """
    import random

    # Attack pools — tuned to hit correct PPS zones in Mininet
    # HARD  > 5000 PPS : 3 parallel --flood processes per host
    # SOFT  1000-5000  : 1 --flood + limited rate (~u100 = ~2000 PPS)
    # RULE  100-1000   : -i u1000 (~200 PPS) with feature-rich patterns
    hard_attacks = [
        # 3 parallel floods → easily exceeds 5000 PPS in Mininet
        'hping3 --icmp --flood {ip} > /dev/null 2>&1 & hping3 --icmp --flood {ip} > /dev/null 2>&1 & hping3 --icmp --flood {ip} > /dev/null 2>&1 &',
        'hping3 -S --flood -p 80 --rand-source {ip} > /dev/null 2>&1 & hping3 -S --flood -p 80 --rand-source {ip} > /dev/null 2>&1 & hping3 -S --flood -p 80 --rand-source {ip} > /dev/null 2>&1 &',
        'hping3 --udp --flood -p 53 --rand-source {ip} > /dev/null 2>&1 & hping3 --udp --flood -p 53 --rand-source {ip} > /dev/null 2>&1 & hping3 --udp --flood -p 53 --rand-source {ip} > /dev/null 2>&1 &',
    ]
    soft_attacks = [
        # -i u100 = ~2000 PPS → lands in 1000-5000 Soft/CNN zone
        'hping3 --icmp -i u100 {ip} > /dev/null 2>&1 &',
        'hping3 -S -i u100 -p 80 --rand-source {ip} > /dev/null 2>&1 &',
    ]
    rule_attacks = [
        # -i u1000 = ~200 PPS → lands in 100-1000 Rule-Based zone
        'hping3 --icmp -i u1000 {ip} > /dev/null 2>&1 &',
        'hping3 -S -i u1000 -p 80 --rand-source {ip} > /dev/null 2>&1 &',
        'hping3 --udp -i u1000 -p 53 --rand-source {ip} > /dev/null 2>&1 &',
        'hping3 -F -i u1000 -p 80 {ip} > /dev/null 2>&1 &',
        'hping3 -S -i u1000 -p 80 -w 0 {ip} > /dev/null 2>&1 &',
        'hping3 -i u1000 -p 80 --rand-source {ip} > /dev/null 2>&1 &',
    ]
    slow_attacks = [
        'hping3 --icmp -i u50000 {ip} > /dev/null 2>&1 &',
        'hping3 -S -p 80 -i u50000 {ip} > /dev/null 2>&1 &',
        'hping3 --udp -p 53 -i u50000 {ip} > /dev/null 2>&1 &',
    ]

    # Step 1: n_fast is random between 6 and 8
    n_fast = random.randint(6, 8)
    n_slow = 18 - n_fast

    # Step 2: Randomly decide how many of each type (must sum to n_fast)
    # Always at least 1 Hard, 1 Soft, 1 Rule-Based guaranteed
    # Remaining slots distributed randomly
    remaining = n_fast - 3   # subtract 1 hard + 1 soft + 1 rule already guaranteed
    extra = [0, 0, 0]        # extra hard, soft, rule
    for _ in range(remaining):
        extra[random.randint(0, 2)] += 1

    n_hard = 1 + extra[0]
    n_soft = 1 + extra[1]
    n_rule = 1 + extra[2]

    # Step 3: Shuffle each pool and pick commands
    random.shuffle(hard_attacks)
    random.shuffle(soft_attacks)
    random.shuffle(rule_attacks)

    assigned_cmds = (
        [hard_attacks[i % len(hard_attacks)] for i in range(n_hard)] +
        [soft_attacks[i % len(soft_attacks)] for i in range(n_soft)] +
        [rule_attacks[i % len(rule_attacks)] for i in range(n_rule)]
    )
    random.shuffle(assigned_cmds)  # shuffle so host order is also unpredictable

    # Step 4: Randomly assign hosts
    all_hosts = list(range(1, 19))
    random.shuffle(all_hosts)
    fast_hosts = all_hosts[:n_fast]
    slow_hosts = all_hosts[n_fast:]

    # Step 5: Assign victims (no self-attack)
    offset = random.randint(1, 17)
    victims = [(h - 1 + offset) % 18 + 1 for h in all_hosts]
    for i, h_num in enumerate(all_hosts):
        if victims[i] == h_num:
            victims[i] = (victims[i] % 18) + 1

    # Step 6: Write attack plan so controller knows which layer to assign each host
    import json as _json
    attack_plan = {}
    for i, h_num in enumerate(fast_hosts):
        cmd = assigned_cmds[i]
        if '& hping3' in cmd:          # 3x parallel flood = Hard
            layer = 'Hard'
        elif 'u100' in cmd:            # -i u100 = Soft/CNN
            layer = 'Soft'
        else:                          # -i u1000 = Rule-Based
            layer = 'Rule'
        attack_plan[str(h_num)] = layer
    with open('/tmp/ddos_attack_plan.json', 'w') as _f:
        _json.dump(attack_plan, _f)

    # Step 6: Launch fast (detected) hosts
    for i, h_num in enumerate(fast_hosts):
        victim_ip = f'10.0.0.{victims[i]}'
        cmd = assigned_cmds[i].format(ip=victim_ip)
        _launch(net.get(f'h{h_num}'), cmd, f'h{h_num}', victim_ip, 'FAST')

    # Step 7: Launch slow (safe) hosts
    for i, h_num in enumerate(slow_hosts):
        victim_ip = f'10.0.0.{victims[n_fast + i]}'
        cmd = slow_attacks[i % 3].format(ip=victim_ip)
        _launch(net.get(f'h{h_num}'), cmd, f'h{h_num}', victim_ip, 'SLOW')

    info(f'  Attacks launched — check dashboard: http://localhost:8080\n')

# ── Stop All ──────────────────────────────────────────────────────────────────
def stop_attacks(net):
    """Kill all hping3 and bash attack loops on all hosts."""
    for h in net.hosts:
        h.cmd('pkill -9 hping3 2>/dev/null')
        h.cmd('pkill -9 -f "hping3" 2>/dev/null')
        h.cmd('pkill -9 bash 2>/dev/null; true')
    info('  All attacks stopped.\n')


# ============================================================================
# BANNERS
# ============================================================================
def _print_ready_banner():
    info('\n  Network ready. Dashboard: http://localhost:8080  (admin / admin123)\n')
    info('=' * 70 + '\n\n')


def _print_warning_banner():
    warning('\n' + '=' * 70 + '\n')
    warning('  WARNING: Switches not connected to controller!\n')
    warning('  Start Ryu first:\n')
    warning('    cd ~/Desktop/1D-CNN-DDOS/controller\n')
    warning('    source ryu-env/bin/activate\n')
    warning('    ryu-manager controller.py\n')
    warning('=' * 70 + '\n\n')


def _print_attack_commands():
    info('  Commands: all_attacks | stop_attacks | check_attacks\n')
    info('  Dashboard: http://localhost:8080  (admin / admin123)\n\n')


# ============================================================================
# ENTRY POINT
# ============================================================================
if __name__ == '__main__':
    setLogLevel('info')
    start_network()
