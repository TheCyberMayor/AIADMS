"""
Model Trainer Module for AI-ADMS

This module handles training data preparation and model training for the
DDoS classifier using synthetic and real network traffic data.
"""

import numpy as np
import pandas as pd
from typing import List, Dict, Tuple, Optional
import logging
import os
import time
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import matplotlib.pyplot as plt
import seaborn as sns

from .ddos_classifier import DDoSClassifier


class ModelTrainer:
    """
    Model training and data preparation for DDoS classification
    
    This class handles the preparation of training data, model training,
    and evaluation of the DDoS classifier.
    """
    
    def __init__(self, 
                 data_dir: str = "data/training",
                 model_dir: str = "data/models",
                 test_size: float = 0.2,
                 random_state: int = 42):
        """
        Initialize the model trainer
        
        Args:
            data_dir: Directory containing training data
            model_dir: Directory to save trained models
            test_size: Proportion of data for testing
            random_state: Random seed for reproducibility
        """
        self.data_dir = data_dir
        self.model_dir = model_dir
        self.test_size = test_size
        self.random_state = random_state
        
        # Logging
        self.logger = logging.getLogger(__name__)
        
        # Create directories if they don't exist
        os.makedirs(data_dir, exist_ok=True)
        os.makedirs(model_dir, exist_ok=True)
    
    def generate_synthetic_data(self, 
                               num_samples: int = 10000,
                               attack_ratio: float = 0.3) -> Tuple[np.ndarray, np.ndarray]:
        """
        Generate synthetic training data
        
        Args:
            num_samples: Number of samples to generate
            attack_ratio: Ratio of attack samples to normal samples
            
        Returns:
            Tuple[np.ndarray, np.ndarray]: Features and labels
        """
        self.logger.info(f"Generating {num_samples} synthetic samples")
        
        # Calculate sample counts
        num_normal = int(num_samples * (1 - attack_ratio))
        num_attacks = num_samples - num_normal
        
        # Generate normal traffic features
        normal_features = self._generate_normal_traffic(num_normal)
        normal_labels = ['normal'] * num_normal
        
        # Generate attack traffic features
        attack_features, attack_labels = self._generate_attack_traffic(num_attacks)
        
        # Combine data
        all_features = np.vstack([normal_features, attack_features])
        all_labels = np.array(normal_labels + attack_labels)
        
        # Shuffle data
        indices = np.random.permutation(len(all_features))
        all_features = all_features[indices]
        all_labels = all_labels[indices]
        
        self.logger.info(f"Generated {len(all_features)} samples: {len(normal_labels)} normal, {len(attack_labels)} attacks")
        
        return all_features, all_labels
    
    def _generate_normal_traffic(self, num_samples: int) -> np.ndarray:
        """Generate features for normal network traffic"""
        features = []
        
        for _ in range(num_samples):
            # Packet size: normally distributed around 500-1500 bytes
            packet_size_mean = np.random.normal(1000, 200)
            packet_size_std = np.random.uniform(50, 300)
            
            # Flow rate: low to moderate
            flow_rate = np.random.exponential(10) + 1
            
            # SYN/ACK ratio: low for normal traffic
            syn_ack_ratio = np.random.beta(1, 10)
            
            # Protocol distribution: mostly TCP
            tcp_ratio = np.random.beta(8, 2)
            udp_ratio = np.random.beta(2, 8)
            
            # TTL: typical values
            ttl_mean = np.random.uniform(30, 64)
            ttl_std = np.random.uniform(1, 5)
            
            # Payload length
            payload_mean = np.random.normal(800, 150)
            payload_std = np.random.uniform(50, 200)
            
            # Source/destination diversity
            unique_sources = np.random.poisson(5) + 1
            unique_destinations = np.random.poisson(3) + 1
            
            # Entropy: moderate
            port_entropy = np.random.uniform(2, 4)
            ip_entropy = np.random.uniform(2, 4)
            
            feature_vector = [
                packet_size_mean, packet_size_std, flow_rate, syn_ack_ratio,
                tcp_ratio, udp_ratio, ttl_mean, ttl_std,
                payload_mean, payload_std, unique_sources, unique_destinations,
                port_entropy, ip_entropy
            ]
            
            features.append(feature_vector)
        
        return np.array(features)
    
    def _generate_attack_traffic(self, num_samples: int) -> Tuple[np.ndarray, List[str]]:
        """Generate features for different types of attack traffic"""
        features = []
        labels = []
        
        # Distribute attacks across different types
        attack_types = ['udp_flood', 'syn_flood', 'http_flood']
        samples_per_type = num_samples // len(attack_types)
        
        for attack_type in attack_types:
            type_features = self._generate_attack_type(attack_type, samples_per_type)
            features.extend(type_features)
            labels.extend([attack_type] * samples_per_type)
        
        # Add remaining samples
        remaining = num_samples - len(features)
        if remaining > 0:
            extra_features = self._generate_attack_type('udp_flood', remaining)
            features.extend(extra_features)
            labels.extend(['udp_flood'] * remaining)
        
        return np.array(features), labels
    
    def _generate_attack_type(self, attack_type: str, num_samples: int) -> List[List[float]]:
        """Generate features for a specific attack type"""
        features = []
        
        for _ in range(num_samples):
            if attack_type == 'udp_flood':
                # UDP flood characteristics
                packet_size_mean = np.random.uniform(50, 200)  # Small packets
                packet_size_std = np.random.uniform(10, 50)
                flow_rate = np.random.exponential(100) + 50  # High rate
                syn_ack_ratio = 0.0  # No SYN/ACK for UDP
                tcp_ratio = 0.0
                udp_ratio = 1.0
                ttl_mean = np.random.uniform(20, 40)
                ttl_std = np.random.uniform(1, 3)
                payload_mean = np.random.uniform(20, 100)
                payload_std = np.random.uniform(5, 30)
                unique_sources = np.random.poisson(20) + 5  # Many sources
                unique_destinations = 1  # Single target
                port_entropy = np.random.uniform(0, 1)  # Low entropy
                ip_entropy = np.random.uniform(4, 6)  # High IP entropy
                
            elif attack_type == 'syn_flood':
                # SYN flood characteristics
                packet_size_mean = np.random.uniform(40, 80)  # Small SYN packets
                packet_size_std = np.random.uniform(5, 20)
                flow_rate = np.random.exponential(200) + 100  # Very high rate
                syn_ack_ratio = np.random.uniform(0.8, 1.0)  # High SYN ratio
                tcp_ratio = 1.0
                udp_ratio = 0.0
                ttl_mean = np.random.uniform(20, 40)
                ttl_std = np.random.uniform(1, 3)
                payload_mean = 0  # No payload in SYN
                payload_std = 0
                unique_sources = np.random.poisson(50) + 10  # Many sources
                unique_destinations = 1
                port_entropy = np.random.uniform(0, 1)
                ip_entropy = np.random.uniform(4, 6)
                
            elif attack_type == 'http_flood':
                # HTTP flood characteristics
                packet_size_mean = np.random.uniform(200, 800)  # Larger packets
                packet_size_std = np.random.uniform(50, 200)
                flow_rate = np.random.exponential(50) + 20  # Moderate rate
                syn_ack_ratio = np.random.uniform(0.1, 0.3)  # Normal SYN/ACK
                tcp_ratio = 1.0
                udp_ratio = 0.0
                ttl_mean = np.random.uniform(30, 64)
                ttl_std = np.random.uniform(2, 8)
                payload_mean = np.random.uniform(100, 500)
                payload_std = np.random.uniform(30, 150)
                unique_sources = np.random.poisson(10) + 2
                unique_destinations = 1
                port_entropy = np.random.uniform(0, 1)
                ip_entropy = np.random.uniform(2, 4)
            
            feature_vector = [
                packet_size_mean, packet_size_std, flow_rate, syn_ack_ratio,
                tcp_ratio, udp_ratio, ttl_mean, ttl_std,
                payload_mean, payload_std, unique_sources, unique_destinations,
                port_entropy, ip_entropy
            ]
            
            features.append(feature_vector)
        
        return features
    
    def load_training_data(self, filename: str) -> Tuple[np.ndarray, np.ndarray]:
        """
        Load training data from file
        
        Args:
            filename: Name of the data file
            
        Returns:
            Tuple[np.ndarray, np.ndarray]: Features and labels
        """
        filepath = os.path.join(self.data_dir, filename)
        
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Training data file not found: {filepath}")
        
        try:
            data = pd.read_csv(filepath)
            
            # Separate features and labels
            feature_columns = [col for col in data.columns if col != 'label']
            features = data[feature_columns].values
            labels = data['label'].values
            
            self.logger.info(f"Loaded {len(features)} samples from {filename}")
            return features, labels
            
        except Exception as e:
            self.logger.error(f"Error loading training data: {e}")
            raise
    
    def save_training_data(self, 
                          features: np.ndarray, 
                          labels: np.ndarray, 
                          filename: str) -> None:
        """
        Save training data to file
        
        Args:
            features: Feature array
            labels: Label array
            filename: Output filename
        """
        filepath = os.path.join(self.data_dir, filename)
        
        try:
            # Create DataFrame
            feature_names = [
                'packet_size_mean', 'packet_size_std', 'flow_rate', 'syn_ack_ratio',
                'tcp_ratio', 'udp_ratio', 'ttl_mean', 'ttl_std',
                'payload_length_mean', 'payload_length_std', 'unique_sources', 
                'unique_destinations', 'port_entropy', 'ip_entropy'
            ]
            
            df = pd.DataFrame(features, columns=feature_names)
            df['label'] = labels
            
            # Save to CSV
            df.to_csv(filepath, index=False)
            self.logger.info(f"Saved {len(features)} samples to {filename}")
            
        except Exception as e:
            self.logger.error(f"Error saving training data: {e}")
            raise
    
    def train_model(self, 
                   features: np.ndarray, 
                   labels: np.ndarray,
                   model_config: Dict = None) -> DDoSClassifier:
        """
        Train a new DDoS classifier model
        
        Args:
            features: Training features
            labels: Training labels
            model_config: Model configuration parameters
            
        Returns:
            DDoSClassifier: Trained classifier
        """
        self.logger.info("Starting model training")
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            features, labels, 
            test_size=self.test_size, 
            random_state=self.random_state,
            stratify=labels
        )
        
        # Create classifier
        config = model_config or {}
        classifier = DDoSClassifier(
            model_path=os.path.join(self.model_dir, "ddos_classifier.h5"),
            scaler_path=os.path.join(self.model_dir, "feature_scaler.pkl"),
            **config
        )
        
        # Train model
        start_time = time.time()
        history = classifier.train(X_train, y_train, X_test, y_test)
        training_time = time.time() - start_time
        
        # Evaluate model
        metrics = classifier.evaluate(X_test, y_test)
        
        # Log results
        self.logger.info(f"Training completed in {training_time:.2f} seconds")
        self.logger.info(f"Test accuracy: {metrics['accuracy']:.4f}")
        
        return classifier
    
    def plot_training_history(self, history: Dict, save_path: str = None) -> None:
        """
        Plot training history
        
        Args:
            history: Training history from model.fit()
            save_path: Path to save the plot
        """
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 4))
        
        # Plot accuracy
        ax1.plot(history['accuracy'], label='Training Accuracy')
        if 'val_accuracy' in history:
            ax1.plot(history['val_accuracy'], label='Validation Accuracy')
        ax1.set_title('Model Accuracy')
        ax1.set_xlabel('Epoch')
        ax1.set_ylabel('Accuracy')
        ax1.legend()
        ax1.grid(True)
        
        # Plot loss
        ax2.plot(history['loss'], label='Training Loss')
        if 'val_loss' in history:
            ax2.plot(history['val_loss'], label='Validation Loss')
        ax2.set_title('Model Loss')
        ax2.set_xlabel('Epoch')
        ax2.set_ylabel('Loss')
        ax2.legend()
        ax2.grid(True)
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            self.logger.info(f"Training history plot saved to {save_path}")
        
        plt.show()
    
    def plot_confusion_matrix(self, 
                            y_true: np.ndarray, 
                            y_pred: np.ndarray, 
                            save_path: str = None) -> None:
        """
        Plot confusion matrix
        
        Args:
            y_true: True labels
            y_pred: Predicted labels
            save_path: Path to save the plot
        """
        from sklearn.metrics import confusion_matrix
        
        cm = confusion_matrix(y_true, y_pred)
        class_names = ['normal', 'udp_flood', 'syn_flood', 'http_flood']
        
        plt.figure(figsize=(8, 6))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                   xticklabels=class_names, yticklabels=class_names)
        plt.title('Confusion Matrix')
        plt.xlabel('Predicted')
        plt.ylabel('True')
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            self.logger.info(f"Confusion matrix plot saved to {save_path}")
        
        plt.show()
    
    def create_training_pipeline(self, 
                                num_samples: int = 10000,
                                attack_ratio: float = 0.3,
                                save_data: bool = True) -> DDoSClassifier:
        """
        Complete training pipeline
        
        Args:
            num_samples: Number of training samples
            attack_ratio: Ratio of attack samples
            save_data: Whether to save generated data
            
        Returns:
            DDoSClassifier: Trained classifier
        """
        self.logger.info("Starting complete training pipeline")
        
        # Generate or load data
        try:
            features, labels = self.load_training_data("training_data.csv")
            self.logger.info("Loaded existing training data")
        except FileNotFoundError:
            self.logger.info("Generating synthetic training data")
            features, labels = self.generate_synthetic_data(num_samples, attack_ratio)
            
            if save_data:
                self.save_training_data(features, labels, "training_data.csv")
        
        # Train model
        classifier = self.train_model(features, labels)
        
        self.logger.info("Training pipeline completed successfully")
        return classifier 