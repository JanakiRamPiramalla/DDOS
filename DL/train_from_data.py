#!/usr/bin/env python3
"""
Enhanced CNN Training Script
✨ Supports both 4-feature and 10-feature datasets
✨ Automatically detects feature count
✨ Improved training pipeline
"""

import os
import sys
import pickle
import logging

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from enhanced_cnn_1d import auto_train_model

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)
logger = logging.getLogger("ENHANCED-TRAINER")


def main():
    logger.info("=" * 70)
    logger.info("ENHANCED 1D CNN TRAINING PIPELINE")
    logger.info("=" * 70)
    
    # ===== DETECT DATA FILE =====
    # Try enhanced data first, fallback to original
    enhanced_data = os.path.join(BASE_DIR, "training_data_enhanced.pkl")
    original_data = os.path.join(BASE_DIR, "training_data.pkl")
    
    if os.path.exists(enhanced_data):
        data_file = enhanced_data
        logger.info("✓ Using ENHANCED dataset (10 features)")
    elif os.path.exists(original_data):
        data_file = original_data
        logger.info("⚠ Using ORIGINAL dataset (4 features)")
        logger.info("  Recommendation: Use collect_training_data_enhanced.py")
    else:
        logger.error("✗ No training data found!")
        logger.error(f"  Expected: {enhanced_data}")
        logger.error(f"  Or: {original_data}")
        return 1
    
    # ===== LOAD DATA =====
    logger.info(f"Loading: {data_file}")
    try:
        with open(data_file, "rb") as f:
            data = pickle.load(f)
    except Exception as e:
        logger.exception("Failed to load training data")
        return 1
    
    benign_data = data.get("benign", [])
    ddos_data = data.get("ddos", [])
    feature_count = data.get("features", "auto-detect")
    
    logger.info(f"Benign samples: {len(benign_data)}")
    logger.info(f"DDoS samples  : {len(ddos_data)}")
    logger.info(f"Features      : {feature_count}")
    
    # ===== VALIDATE DATA =====
    MIN_SAMPLES = 50
    if len(benign_data) < MIN_SAMPLES or len(ddos_data) < MIN_SAMPLES:
        logger.error(f"Insufficient data! Need ≥ {MIN_SAMPLES} per class")
        return 1
    
    # ===== AUTO-DETECT FEATURE COUNT =====
    if benign_data:
        detected_features = len(benign_data[0][0])
        logger.info(f"Detected {detected_features} features per sample")
        
        if detected_features == 4:
            logger.warning("⚠ Training with only 4 features")
            logger.warning("  Expected accuracy: ~60-70%")
            logger.warning("  Recommendation: Collect 10-feature dataset")
        elif detected_features == 10:
            logger.info("✓ Training with 10 enhanced features")
            logger.info("  Expected accuracy: ~80-90%")
    
    # ===== TRAIN MODEL =====
    model_file = os.path.join(BASE_DIR, "cnn_ddos_model.pt")
    
    logger.info("")
    logger.info("Starting enhanced CNN training...")
    logger.info("")
    
    success = auto_train_model(
        benign_data=benign_data,
        ddos_data=ddos_data,
        model_path=model_file
    )
    
    # ===== RESULT =====
    if success:
        logger.info("")
        logger.info("=" * 70)
        logger.info("✓ TRAINING COMPLETED SUCCESSFULLY")
        logger.info("=" * 70)
        logger.info(f"Model saved: {model_file}")
        logger.info(f"Scaler saved: {model_file.replace('.pt', '_scaler.pkl')}")
        logger.info("")
        logger.info("Next steps:")
        logger.info("  1. Test model accuracy with validation data")
        logger.info("  2. Deploy in controller_enhanced.py")
        logger.info("  3. Monitor false positive/negative rates")
        logger.info("=" * 70)
        return 0
    else:
        logger.error("✗ Training failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
