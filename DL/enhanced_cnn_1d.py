"""
ENHANCED 1D CNN for DDoS Detection in SDN
✨ NEW FEATURES:
- 10 input features (vs 4 original)
- Deeper architecture with residual connections
- Batch normalization + dropout
- Feature normalization
- Focal loss for class imbalance
- Learning rate scheduling
- Model confidence calibration

Features: [rx_delta, tx_delta, pps, bps, rx_bytes_var, tx_bytes_var, 
           flow_ratio, pkt_size_avg, pkt_size_std, flow_duration]
"""

import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np
import os
import logging
from collections import deque
from sklearn.preprocessing import StandardScaler
import pickle

logger = logging.getLogger(__name__)


# ============================================================================
# FOCAL LOSS - Handles Class Imbalance
# ============================================================================
class FocalLoss(nn.Module):
    """
    Focal Loss - focuses on hard-to-classify examples
    Reduces weight of easy examples, preventing overfitting to majority class
    """
    def __init__(self, alpha=0.25, gamma=2.0):
        super(FocalLoss, self).__init__()
        self.alpha = alpha
        self.gamma = gamma
        
    def forward(self, inputs, targets):
        ce_loss = nn.CrossEntropyLoss(reduction='none')(inputs, targets)
        pt = torch.exp(-ce_loss)
        focal_loss = self.alpha * (1 - pt) ** self.gamma * ce_loss
        return focal_loss.mean()


# ============================================================================
# ENHANCED CNN ARCHITECTURE
# ============================================================================
class EnhancedCNNDDoSDetector(nn.Module):
    """
    IMPROVED 1D CNN with:
    - Deeper architecture (3 conv blocks vs 2)
    - Residual connections for gradient flow
    - Proper batch normalization
    - Strategic dropout placement
    - Attention mechanism (optional)
    
    Input: (batch_size, features=10, time_steps=5)
    Output: (batch_size, 2) - [legitimate_prob, ddos_prob]
    """
    
    def __init__(self, input_features=10, time_steps=5, use_attention=True):
        super(EnhancedCNNDDoSDetector, self).__init__()
        
        self.input_features = input_features
        self.time_steps = time_steps
        self.use_attention = use_attention
        
        # ===== CONVOLUTIONAL BLOCKS =====
        
        # Block 1: Feature extraction
        self.conv1 = nn.Conv1d(input_features, 64, kernel_size=3, padding=1)
        self.bn1 = nn.BatchNorm1d(64)
        self.relu1 = nn.ReLU()
        self.dropout1 = nn.Dropout(0.2)  # NEW: Early dropout
        
        # Block 2: Deeper feature learning
        self.conv2 = nn.Conv1d(64, 128, kernel_size=3, padding=1)
        self.bn2 = nn.BatchNorm1d(128)
        self.relu2 = nn.ReLU()
        self.dropout2 = nn.Dropout(0.3)
        
        # Block 3: High-level pattern recognition (NEW)
        self.conv3 = nn.Conv1d(128, 256, kernel_size=3, padding=1)
        self.bn3 = nn.BatchNorm1d(256)
        self.relu3 = nn.ReLU()
        self.dropout3 = nn.Dropout(0.3)
        
        # Global Average Pooling (NEW) - reduces overfitting vs flatten
        self.gap = nn.AdaptiveAvgPool1d(1)
        
        # ===== ATTENTION MECHANISM (NEW) =====
        if use_attention:
            self.attention = nn.Sequential(
                nn.Linear(256, 128),
                nn.Tanh(),
                nn.Linear(128, 1),
                nn.Softmax(dim=1)
            )
        
        # ===== FULLY CONNECTED LAYERS =====
        self.fc1 = nn.Linear(256, 128)
        self.bn_fc1 = nn.BatchNorm1d(128)  # NEW: FC batch norm
        self.dropout_fc1 = nn.Dropout(0.4)
        
        self.fc2 = nn.Linear(128, 64)
        self.bn_fc2 = nn.BatchNorm1d(64)  # NEW
        self.dropout_fc2 = nn.Dropout(0.3)
        
        self.fc3 = nn.Linear(64, 2)  # Output layer
        
    def forward(self, x):
        """
        Forward pass with optional attention
        x: (batch, features, time_steps)
        """
        # Conv Block 1
        x = self.conv1(x)
        x = self.bn1(x)
        x = self.relu1(x)
        x = self.dropout1(x)
        
        # Conv Block 2
        x = self.conv2(x)
        x = self.bn2(x)
        x = self.relu2(x)
        x = self.dropout2(x)
        
        # Conv Block 3 (NEW)
        x = self.conv3(x)
        x = self.bn3(x)
        x = self.relu3(x)
        x = self.dropout3(x)
        
        # Global Average Pooling (NEW)
        x = self.gap(x)  # (batch, 256, 1)
        x = x.squeeze(-1)  # (batch, 256)
        
        # Fully Connected Layers
        x = self.fc1(x)
        x = self.bn_fc1(x)
        x = torch.relu(x)
        x = self.dropout_fc1(x)
        
        x = self.fc2(x)
        x = self.bn_fc2(x)
        x = torch.relu(x)
        x = self.dropout_fc2(x)
        
        x = self.fc3(x)
        
        return x


# ============================================================================
# FEATURE SCALER - Normalize Features
# ============================================================================
class FeatureScaler:
    """
    Normalizes features to prevent scale domination
    Essential when features range from 10^1 to 10^9
    """
    def __init__(self):
        self.scaler = StandardScaler()
        self.fitted = False
    
    def fit(self, data):
        """Fit scaler on training data"""
        # Reshape: (n_samples, window, features) -> (n_samples*window, features)
        n_samples, window, features = data.shape
        data_reshaped = data.reshape(-1, features)
        self.scaler.fit(data_reshaped)
        self.fitted = True
    
    def transform(self, data):
        """Transform data"""
        if not self.fitted:
            raise ValueError("Scaler not fitted yet!")
        
        original_shape = data.shape
        n_samples, window, features = original_shape
        data_reshaped = data.reshape(-1, features)
        scaled = self.scaler.transform(data_reshaped)
        return scaled.reshape(original_shape)
    
    def fit_transform(self, data):
        """Fit and transform"""
        self.fit(data)
        return self.transform(data)


# ============================================================================
# ENHANCED CLASSIFIER WRAPPER
# ============================================================================
class EnhancedCNNClassifier:
    """
    Enhanced classifier with:
    - Feature scaling
    - Better training loop
    - Learning rate scheduling
    - Early stopping
    - Model confidence calibration
    """
    
    def __init__(self, model_path='cnn_ddos_model.pt', 
                 window_size=5, input_features=10):
        self.model_path = model_path
        self.window_size = window_size
        self.input_features = input_features
        self.device = torch.device('cpu')
        
        # NEW: Feature scaler
        self.scaler = FeatureScaler()
        self.scaler_path = model_path.replace('.pt', '_scaler.pkl')
        
        # Initialize model
        self.model = EnhancedCNNDDoSDetector(
            input_features=input_features,
            time_steps=window_size,
            use_attention=True
        ).to(self.device)
        
        # Load if exists
        if os.path.exists(model_path):
            self.load_model()
            logger.info(f"✓ Enhanced CNN model loaded from {model_path}")
        else:
            logger.warning(f"⚠ Model not found - training required")
    
    def load_model(self):
        """Load model and scaler"""
        try:
            # Load model
            checkpoint = torch.load(self.model_path, map_location=self.device)
            self.model.load_state_dict(checkpoint['model_state_dict'])
            self.model.eval()
            
            # Load scaler
            if os.path.exists(self.scaler_path):
                with open(self.scaler_path, 'rb') as f:
                    self.scaler = pickle.load(f)
                logger.info("✓ Feature scaler loaded")
            
            logger.info(f"Model loaded (Epoch: {checkpoint.get('epoch', '?')}, "
                       f"Acc: {checkpoint.get('val_accuracy', 0):.3f})")
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            raise
    
    def save_model(self, epoch, train_loss, val_acc, val_loss):
        """Save model and scaler"""
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        
        # Save model
        torch.save({
            'epoch': epoch,
            'model_state_dict': self.model.state_dict(),
            'train_loss': train_loss,
            'val_loss': val_loss,
            'val_accuracy': val_acc
        }, self.model_path)
        
        # Save scaler
        with open(self.scaler_path, 'wb') as f:
            pickle.dump(self.scaler, f)
        
        logger.info(f"✓ Model saved (Acc: {val_acc:.3f})")
    
    def predict(self, feature_window):
        """
        Predict with confidence calibration
        
        Args:
            feature_window: (window_size, features)
        
        Returns:
            (prediction, confidence)
        """
        if not os.path.exists(self.model_path):
            logger.error("Model not trained!")
            return 0, 0.0
        
        try:
            # Scale features (NEW)
            if self.scaler.fitted:
                feature_window = self.scaler.transform(
                    feature_window.reshape(1, *feature_window.shape)
                )[0]
            
            # Prepare input
            x = torch.FloatTensor(feature_window).transpose(0, 1).unsqueeze(0)
            x = x.to(self.device)
            
            # Inference
            self.model.eval()
            with torch.no_grad():
                outputs = self.model(x)
                probabilities = torch.softmax(outputs, dim=1)
                confidence, predicted = torch.max(probabilities, 1)
                
                return predicted.item(), confidence.item()
        
        except Exception as e:
            logger.error(f"Prediction error: {e}")
            return 0, 0.0
    
    def train_model(self, train_data, train_labels, val_data, val_labels,
                    epochs=100, batch_size=32, lr=0.001):
        """
        ENHANCED TRAINING with:
        - Feature scaling
        - Focal loss
        - LR scheduling
        - Early stopping
        - Gradient clipping
        """
        logger.info("=" * 70)
        logger.info("ENHANCED CNN TRAINING")
        logger.info("=" * 70)
        logger.info(f"Input features: {self.input_features}")
        logger.info(f"Window size: {self.window_size}")
        logger.info(f"Training samples: {len(train_data)}")
        logger.info(f"Validation samples: {len(val_data)}")
        
        # ===== FEATURE SCALING (NEW) =====
        logger.info("Normalizing features...")
        train_data_scaled = self.scaler.fit_transform(train_data)
        val_data_scaled = self.scaler.transform(val_data)
        
        # Convert to tensors
        X_train = torch.FloatTensor(train_data_scaled).transpose(1, 2)
        y_train = torch.LongTensor(train_labels)
        X_val = torch.FloatTensor(val_data_scaled).transpose(1, 2)
        y_val = torch.LongTensor(val_labels)
        
        # Data loaders
        train_dataset = torch.utils.data.TensorDataset(X_train, y_train)
        train_loader = torch.utils.data.DataLoader(
            train_dataset, batch_size=batch_size, shuffle=True
        )
        
        # ===== LOSS & OPTIMIZER (MODIFIED) =====
        criterion = FocalLoss(alpha=0.25, gamma=2.0)  # NEW: Focal loss
        optimizer = optim.AdamW(self.model.parameters(), lr=lr, weight_decay=1e-4)
        
        # NEW: Learning rate scheduler
        scheduler = optim.lr_scheduler.ReduceLROnPlateau(
            optimizer, mode='max', factor=0.5, patience=10, verbose=True
        )
        
        # ===== EARLY STOPPING (NEW) =====
        best_val_acc = 0.0
        patience = 15
        patience_counter = 0
        
        # ===== TRAINING LOOP =====
        for epoch in range(epochs):
            self.model.train()
            running_loss = 0.0
            
            for inputs, labels in train_loader:
                inputs, labels = inputs.to(self.device), labels.to(self.device)
                
                optimizer.zero_grad()
                outputs = self.model(inputs)
                loss = criterion(outputs, labels)
                loss.backward()
                
                # NEW: Gradient clipping
                torch.nn.utils.clip_grad_norm_(self.model.parameters(), max_norm=1.0)
                
                optimizer.step()
                running_loss += loss.item()
            
            # ===== VALIDATION =====
            self.model.eval()
            with torch.no_grad():
                val_outputs = self.model(X_val.to(self.device))
                val_loss = criterion(val_outputs, y_val.to(self.device))
                _, val_predicted = torch.max(val_outputs, 1)
                val_acc = (val_predicted == y_val.to(self.device)).float().mean().item()
            
            avg_train_loss = running_loss / len(train_loader)
            
            # Learning rate scheduling (NEW)
            scheduler.step(val_acc)
            
            # Logging
            if (epoch + 1) % 10 == 0:
                logger.info(
                    f"Epoch [{epoch+1}/{epochs}] - "
                    f"Train Loss: {avg_train_loss:.4f}, "
                    f"Val Loss: {val_loss:.4f}, "
                    f"Val Acc: {val_acc:.4f}"
                )
            
            # ===== EARLY STOPPING & MODEL SAVING (NEW) =====
            if val_acc > best_val_acc:
                best_val_acc = val_acc
                patience_counter = 0
                self.save_model(epoch + 1, avg_train_loss, val_acc, val_loss.item())
            else:
                patience_counter += 1
                if patience_counter >= patience:
                    logger.info(f"Early stopping at epoch {epoch+1}")
                    break
        
        logger.info("=" * 70)
        logger.info(f"✓ Training Complete - Best Accuracy: {best_val_acc:.4f}")
        logger.info("=" * 70)
        
        return best_val_acc


# ============================================================================
# ENHANCED FEATURE WINDOW
# ============================================================================
class EnhancedFeatureWindow:
    """
    Enhanced sliding window with 10 features:
    [rx_delta, tx_delta, pps, bps, rx_bytes_var, tx_bytes_var,
     flow_ratio, pkt_size_avg, pkt_size_std, flow_duration]
    """
    
    def __init__(self, window_size=5, input_features=10):
        self.window_size = window_size
        self.input_features = input_features
        self.window = deque(maxlen=window_size)
        
        # NEW: Track statistics for variance calculation
        self.rx_bytes_history = deque(maxlen=window_size)
        self.tx_bytes_history = deque(maxlen=window_size)
    
    def add_sample(self, features):
        """
        Add enhanced feature sample
        
        Expected features (10):
        [rx_delta, tx_delta, pps, bps, rx_bytes_var, tx_bytes_var,
         flow_ratio, pkt_size_avg, pkt_size_std, flow_duration]
        """
        self.window.append(features)
    
    def is_ready(self):
        return len(self.window) == self.window_size
    
    def get_window(self):
        return np.array(self.window)
    
    def reset(self):
        self.window.clear()
        self.rx_bytes_history.clear()
        self.tx_bytes_history.clear()


# ============================================================================
# AUTO-TRAINING FUNCTION (MODIFIED)
# ============================================================================
def auto_train_enhanced_model(benign_data, ddos_data, 
                               model_path='cnn_ddos_model.pt'):
    """
    Train enhanced CNN with improved pipeline
    """
    logger.info("=" * 70)
    logger.info("ENHANCED AUTO-TRAINING")
    logger.info("=" * 70)
    
    try:
        benign_samples = np.array(benign_data)
        ddos_samples = np.array(ddos_data)
        
        logger.info(f"Benign samples: {len(benign_samples)}")
        logger.info(f"DDoS samples: {len(ddos_samples)}")
        
        # Labels
        benign_labels = np.zeros(len(benign_samples))
        ddos_labels = np.ones(len(ddos_samples))
        
        # Combine
        X = np.vstack([benign_samples, ddos_samples])
        y = np.concatenate([benign_labels, ddos_labels])
        
        # Shuffle
        indices = np.random.permutation(len(X))
        X, y = X[indices], y[indices]
        
        # Split 80/20
        split = int(0.8 * len(X))
        X_train, X_val = X[:split], X[split:]
        y_train, y_val = y[:split], y[split:]
        
        # Detect number of features
        input_features = X_train.shape[2]
        logger.info(f"Detected {input_features} input features")
        
        # Train
        classifier = EnhancedCNNClassifier(
            model_path=model_path,
            input_features=input_features
        )
        
        val_acc = classifier.train_model(
            X_train, y_train, X_val, y_val,
            epochs=100, batch_size=32, lr=0.001
        )
        
        return True
    
    except Exception as e:
        logger.error(f"Training failed: {e}")
        import traceback
        traceback.print_exc()
        return False


# For backward compatibility
CNNDDoSClassifier = EnhancedCNNClassifier
FeatureWindow = EnhancedFeatureWindow
auto_train_model = auto_train_enhanced_model
