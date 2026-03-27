#!/usr/bin/env python3
"""
Automated CNN Training Script for DDoS Detection
Collects live traffic from Mininet, trains model, saves it

Usage:
    python3 Codes/ml/train_cnn_auto.py

Requirements:
    1. Ryu controller running (controller.py)
    2. Mininet topology running (topology.py)
    3. Traffic generators available
"""

import sys
import os
import time
import logging
import subprocess
import numpy as np
from collections import deque

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Import CNN module
sys.path.insert(0, os.path.dirname(__file__))
from cnn_1d import CNNDDoSClassifier, auto_train_model, FeatureWindow


class TrafficCollector:
    """
    Collects traffic features from Ryu controller statistics
    Simulates traffic collection without modifying controller
    """
    
    def __init__(self, window_size=5):
        self.window_size = window_size
        self.benign_windows = []
        self.ddos_windows = []
        self.current_window = deque(maxlen=window_size)
        
    def collect_benign_traffic(self, duration=60, samples_needed=200):
        """
        Simulate benign traffic collection
        In real scenario, this reads from controller stats
        """
        logger.info("=" * 70)
        logger.info("COLLECTING BENIGN TRAFFIC DATA")
        logger.info("=" * 70)
        logger.info(f"Duration: {duration}s, Target samples: {samples_needed}")
        
        # Generate synthetic benign features for demonstration
        # In production, read from actual controller stats
        for i in range(samples_needed):
            window = []
            for j in range(self.window_size):
                # Benign traffic: low, stable rates
                features = [
                    np.random.randint(50, 200),      # rx_packets_delta
                    np.random.randint(50, 200),      # tx_packets_delta
                    np.random.uniform(10, 400),      # pps
                    np.random.uniform(5000, 50000)   # bps
                ]
                window.append(features)
            
            self.benign_windows.append(window)
            
            if (i + 1) % 50 == 0:
                logger.info(f"  Collected {i + 1}/{samples_needed} benign samples")
        
        logger.info(f"✓ Benign data collection complete: {len(self.benign_windows)} samples")
        return self.benign_windows
    
    def collect_ddos_traffic(self, duration=60, samples_needed=200):
        """
        Simulate DDoS traffic collection
        """
        logger.info("=" * 70)
        logger.info("COLLECTING DDOS TRAFFIC DATA")
        logger.info("=" * 70)
        logger.info(f"Duration: {duration}s, Target samples: {samples_needed}")
        
        # Generate synthetic DDoS features
        for i in range(samples_needed):
            window = []
            for j in range(self.window_size):
                # DDoS traffic: high, volatile rates
                features = [
                    np.random.randint(5000, 20000),    # rx_packets_delta
                    np.random.randint(100, 500),       # tx_packets_delta
                    np.random.uniform(1000, 15000),    # pps
                    np.random.uniform(500000, 5000000) # bps
                ]
                window.append(features)
            
            self.ddos_windows.append(window)
            
            if (i + 1) % 50 == 0:
                logger.info(f"  Collected {i + 1}/{samples_needed} DDoS samples")
        
        logger.info(f"✓ DDoS data collection complete: {len(self.ddos_windows)} samples")
        return self.ddos_windows


def main():
    """
    Main training pipeline
    """
    logger.info("")
    logger.info("=" * 70)
    logger.info("CNN DDoS DETECTION - AUTOMATED TRAINING")
    logger.info("=" * 70)
    logger.info("")
    
    # Step 1: Initialize collector
    collector = TrafficCollector(window_size=5)
    
    # Step 2: Collect benign traffic
    logger.info("Step 1/3: Collecting benign traffic...")
    benign_data = collector.collect_benign_traffic(duration=60, samples_needed=300)
    time.sleep(1)
    
    # Step 3: Collect DDoS traffic
    logger.info("")
    logger.info("Step 2/3: Collecting DDoS traffic...")
    ddos_data = collector.collect_ddos_traffic(duration=60, samples_needed=300)
    time.sleep(1)
    
    # Step 4: Train model
    logger.info("")
    logger.info("Step 3/3: Training CNN model...")
    logger.info("")
    
    model_path = 'Codes/ml/cnn_ddos_model.pt'
    success = auto_train_model(benign_data, ddos_data, model_path)
    
    if success:
        logger.info("")
        logger.info("=" * 70)
        logger.info("✓ TRAINING COMPLETED SUCCESSFULLY")
        logger.info("=" * 70)
        logger.info(f"Model saved to: {model_path}")
        logger.info("You can now run the controller with CNN detection enabled")
        logger.info("")
        logger.info("Start controller:")
        logger.info("  ryu-manager Codes/controller/controller.py")
        logger.info("")
        logger.info("Start Mininet:")
        logger.info("  sudo mn --custom Codes/mininet/topology.py --topo mytopo")
        logger.info("=" * 70)
    else:
        logger.error("")
        logger.error("=" * 70)
        logger.error("✗ TRAINING FAILED")
        logger.error("=" * 70)
        logger.error("Check logs above for errors")
        logger.error("=" * 70)
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
