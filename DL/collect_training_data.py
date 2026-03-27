#!/usr/bin/env python3
"""
ENHANCED Real Traffic Data Collector
Extracts 10 features instead of 4:

ORIGINAL (4):
- rx_packets_delta
- tx_packets_delta  
- pps
- bps

NEW (10):
- rx_packets_delta
- tx_packets_delta
- pps
- bps
- rx_bytes_variance (NEW)
- tx_bytes_variance (NEW)
- flow_ratio (NEW)
- avg_packet_size (NEW)
- packet_size_std (NEW)
- flow_duration (NEW)
"""

import time
import pickle
import logging
import sys
import os
import select
from collections import deque
import numpy as np

from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.base import app_manager

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONTROLLER_DIR = os.path.join(BASE_DIR, '..', 'controller')
sys.path.insert(0, CONTROLLER_DIR)

import switch

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)


class EnhancedTrafficDataCollector(switch.SimpleSwitch13):
    """
    Enhanced data collector with rich feature extraction
    """

    def __init__(self, *args, **kwargs):
        super(EnhancedTrafficDataCollector, self).__init__(*args, **kwargs)

        # Switch tracking
        self.datapaths = {}

        # Port statistics history (for variance/std calculation)
        self.port_stats_history = {}  # NEW: Store last N measurements
        self.port_stats_time = {}
        
        # Flow tracking (NEW)
        self.flow_counts = {}  # (dpid, port) -> flow count
        self.flow_start_time = {}  # Track when flow started

        # Feature windows (now 10 features)
        self.feature_windows = {}

        # Dataset
        self.benign_samples = []
        self.ddos_samples = []

        # Config
        self.WINDOW_SIZE = 5
        self.MONITOR_INTERVAL = 5
        self.TARGET_SAMPLES = 300
        self.HISTORY_SIZE = 10  # NEW: For variance calculation

        # State
        self.collection_mode = None
        self.samples_collected = 0
        self.running = True

        # Threads
        self.monitor_thread = hub.spawn(self._monitor)
        self.keyboard_thread = hub.spawn(self._keyboard_listener)

        self._print_banner()

    def _print_banner(self):
        logger.info("=" * 72)
        logger.info("ENHANCED TRAFFIC DATA COLLECTOR (10 FEATURES)")
        logger.info("=" * 72)
        logger.info("Features extracted:")
        logger.info("  1. rx_packets_delta")
        logger.info("  2. tx_packets_delta")
        logger.info("  3. packets_per_second")
        logger.info("  4. bytes_per_second")
        logger.info("  5. rx_bytes_variance (NEW)")
        logger.info("  6. tx_bytes_variance (NEW)")
        logger.info("  7. flow_ratio (NEW)")
        logger.info("  8. avg_packet_size (NEW)")
        logger.info("  9. packet_size_std (NEW)")
        logger.info("  10. flow_duration (NEW)")
        logger.info("=" * 72)
        logger.info("Commands: b=benign | d=ddos | s=save")
        logger.info("=" * 72)

    # ========================================================================
    # KEYBOARD LISTENER
    # ========================================================================
    def _keyboard_listener(self):
        while self.running:
            if select.select([sys.stdin], [], [], 1)[0]:
                cmd = sys.stdin.readline().strip().lower()

                if cmd == 'b':
                    self._start_benign()
                elif cmd == 'd':
                    self._start_ddos()
                elif cmd == 's':
                    self._save_and_exit()

    # ========================================================================
    # DATAPATH TRACKING
    # ========================================================================
    @set_ev_cls(ofp_event.EventOFPStateChange, MAIN_DISPATCHER)
    def _state_change_handler(self, ev):
        dp = ev.datapath
        self.datapaths[dp.id] = dp
        logger.info(f"✓ Switch connected: {dp.id}")

    # ========================================================================
    # MONITORING LOOP
    # ========================================================================
    def _monitor(self):
        while self.running:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(self.MONITOR_INTERVAL)

    def _request_stats(self, dp):
        parser = dp.ofproto_parser
        ofproto = dp.ofproto
        
        # Request port stats
        dp.send_msg(parser.OFPPortStatsRequest(dp, 0, ofproto.OFPP_ANY))
        
        # NEW: Request flow stats for flow counting
        match = parser.OFPMatch()
        dp.send_msg(parser.OFPFlowStatsRequest(dp, 0, ofproto.OFPTT_ALL,
                                                ofproto.OFPP_ANY, ofproto.OFPG_ANY,
                                                0, 0, match))

    # ========================================================================
    # FLOW STATS HANDLER (NEW)
    # ========================================================================
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        """Count flows per port"""
        dp = ev.msg.datapath
        dpid = dp.id
        
        # Count flows by ingress port
        port_flows = {}
        for stat in ev.msg.body:
            if 'in_port' in stat.match:
                port = stat.match['in_port']
                port_flows[port] = port_flows.get(port, 0) + 1
        
        # Update flow counts
        for port, count in port_flows.items():
            key = (dpid, port)
            self.flow_counts[key] = count

    # ========================================================================
    # PORT STATS HANDLER - ENHANCED FEATURE EXTRACTION
    # ========================================================================
    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):

        if self.collection_mode is None:
            return

        if self.samples_collected >= self.TARGET_SAMPLES:
            logger.info(f"✓ Target reached ({self.TARGET_SAMPLES})")
            self.collection_mode = None
            return

        dp = ev.msg.datapath
        dpid = dp.id
        now = time.time()

        for stat in ev.msg.body:
            port = stat.port_no

            if port <= 0 or port > 0xffffff00:
                continue

            key = (dpid, port)

            # Initialize history tracking
            if key not in self.port_stats_history:
                self.port_stats_history[key] = deque(maxlen=self.HISTORY_SIZE)
                self.flow_start_time[key] = now

            # Get previous stats
            if len(self.port_stats_history[key]) > 0:
                prev = self.port_stats_history[key][-1]
                dt = now - prev['time']

                if dt > 0:
                    # ===== BASIC DELTAS =====
                    rx_delta = stat.rx_packets - prev['rx_packets']
                    tx_delta = stat.tx_packets - prev['tx_packets']
                    rx_bytes_delta = stat.rx_bytes - prev['rx_bytes']
                    tx_bytes_delta = stat.tx_bytes - prev['tx_bytes']

                    if rx_delta >= 0 and tx_delta >= 0:
                        # ===== ORIGINAL 4 FEATURES =====
                        pps = rx_delta / dt
                        bps = rx_bytes_delta / dt

                        # ===== NEW FEATURE 5-6: BYTE VARIANCE =====
                        rx_bytes_var = self._calculate_variance(
                            self.port_stats_history[key], 'rx_bytes'
                        )
                        tx_bytes_var = self._calculate_variance(
                            self.port_stats_history[key], 'tx_bytes'
                        )

                        # ===== NEW FEATURE 7: FLOW RATIO =====
                        flow_count = self.flow_counts.get(key, 1)
                        flow_ratio = rx_delta / max(flow_count, 1)

                        # ===== NEW FEATURE 8-9: PACKET SIZE STATS =====
                        avg_pkt_size = rx_bytes_delta / max(rx_delta, 1)
                        pkt_size_std = self._calculate_packet_size_std(
                            self.port_stats_history[key], dt
                        )

                        # ===== NEW FEATURE 10: FLOW DURATION =====
                        flow_duration = now - self.flow_start_time.get(key, now)

                        # ===== ASSEMBLE 10-FEATURE VECTOR =====
                        features = [
                            rx_delta,           # 1
                            tx_delta,           # 2
                            pps,                # 3
                            bps,                # 4
                            rx_bytes_var,       # 5 NEW
                            tx_bytes_var,       # 6 NEW
                            flow_ratio,         # 7 NEW
                            avg_pkt_size,       # 8 NEW
                            pkt_size_std,       # 9 NEW
                            flow_duration       # 10 NEW
                        ]

                        # Add to feature window
                        if key not in self.feature_windows:
                            self.feature_windows[key] = deque(maxlen=self.WINDOW_SIZE)

                        self.feature_windows[key].append(features)

                        # Collect sample when window is full
                        if len(self.feature_windows[key]) == self.WINDOW_SIZE:
                            window = list(self.feature_windows[key])

                            if self.collection_mode == 'benign':
                                self.benign_samples.append(window)
                            else:
                                self.ddos_samples.append(window)

                            self.samples_collected += 1

                            if self.samples_collected % 20 == 0:
                                logger.info(
                                    f"{self.collection_mode.upper()}: "
                                    f"{self.samples_collected}/{self.TARGET_SAMPLES}"
                                )

            # Store current stats in history
            self.port_stats_history[key].append({
                'time': now,
                'rx_packets': stat.rx_packets,
                'tx_packets': stat.tx_packets,
                'rx_bytes': stat.rx_bytes,
                'tx_bytes': stat.tx_bytes
            })

    # ========================================================================
    # HELPER FUNCTIONS FOR NEW FEATURES
    # ========================================================================
    def _calculate_variance(self, history, field):
        """Calculate variance of a field over history"""
        if len(history) < 2:
            return 0.0
        
        values = [entry[field] for entry in history]
        deltas = [values[i] - values[i-1] for i in range(1, len(values))]
        
        if len(deltas) == 0:
            return 0.0
        
        return np.var(deltas)
    
    def _calculate_packet_size_std(self, history, dt):
        """Estimate packet size standard deviation"""
        if len(history) < 2:
            return 0.0
        
        # Calculate packet sizes from deltas
        sizes = []
        for i in range(1, len(history)):
            rx_bytes_delta = history[i]['rx_bytes'] - history[i-1]['rx_bytes']
            rx_pkt_delta = history[i]['rx_packets'] - history[i-1]['rx_packets']
            
            if rx_pkt_delta > 0:
                avg_size = rx_bytes_delta / rx_pkt_delta
                sizes.append(avg_size)
        
        if len(sizes) < 2:
            return 0.0
        
        return np.std(sizes)

    # ========================================================================
    # MODE SWITCHING
    # ========================================================================
    def _start_benign(self):
        self.collection_mode = 'benign'
        self.samples_collected = 0
        logger.info("\n[MODE] BENIGN COLLECTION STARTED")
        logger.info("Generate normal traffic (pingall, iperf)")

    def _start_ddos(self):
        self.collection_mode = 'ddos'
        self.samples_collected = 0
        logger.info("\n[MODE] DDOS COLLECTION STARTED")
        logger.info("Generate hping3/scapy flood")

    # ========================================================================
    # SAVE & EXIT
    # ========================================================================
    def _save_and_exit(self):
        output = os.path.join(BASE_DIR, 'training_data_enhanced.pkl')

        with open(output, 'wb') as f:
            pickle.dump({
                'benign': self.benign_samples,
                'ddos': self.ddos_samples,
                'features': 10  # Metadata
            }, f)

        logger.info("=" * 72)
        logger.info("✓ ENHANCED DATA SAVED")
        logger.info(f"File: {output}")
        logger.info(f"Features: 10")
        logger.info(f"Benign samples: {len(self.benign_samples)}")
        logger.info(f"DDoS samples: {len(self.ddos_samples)}")
        logger.info("=" * 72)

        self.running = False
        hub.kill(self.monitor_thread)
        hub.kill(self.keyboard_thread)
        sys.exit(0)
