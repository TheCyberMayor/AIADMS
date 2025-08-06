"""
DDoS Classifier Module for AI-ADMS

This module implements a deep learning-based classifier for detecting and
classifying different types of DDoS attacks.
"""

import numpy as np
import pandas as pd
from typing import List, Dict, Tuple, Optional, Union
import logging
import time
import os
import pickle
from dataclasses import dataclass

try:
    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras import layers, models
    from tensorflow.keras.optimizers import Adam
    from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint
except ImportError:
    print("Warning: TensorFlow not available. Install with: pip install tensorflow")
    tf = keras = None

from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import joblib

from ..traffic_capture.feature_extractor import FeatureVector


@dataclass
class ClassificationResult:
    """Data class for classification results"""
    timestamp: float
    predicted_class: str
    confidence: float
    probabilities: Dict[str, float]
    is_attack: bool
    attack_type: Optional[str] = None
    anomaly_score: float = 0.0


class DDoSClassifier:
    """
    Deep learning-based DDoS attack classifier
    
    This class implements a multi-layer perceptron (MLP) neural network
    for real-time classification of network traffic into normal and
    various DDoS attack types.
    """
    
    def __init__(self, 
                 model_path: str = "data/models/ddos_classifier.h5",
                 scaler_path: str = "data/models/feature_scaler.pkl",
                 input_dim: int = 14,
                 hidden_layers: List[int] = None,
                 output_classes: int = 4,
                 learning_rate: float = 0.001,
                 confidence_threshold: float = 0.8):
        """
        Initialize the DDoS classifier
        
        Args:
            model_path: Path to saved model file
            scaler_path: Path to saved feature scaler
            input_dim: Number of input features
            hidden_layers: List of hidden layer sizes
            output_classes: Number of output classes
            learning_rate: Learning rate for training
            confidence_threshold: Minimum confidence for classification
        """
        self.model_path = model_path
        self.scaler_path = scaler_path
        self.input_dim = input_dim
        self.hidden_layers = hidden_layers or [64, 32, 16]
        self.output_classes = output_classes
        self.learning_rate = learning_rate
        self.confidence_threshold = confidence_threshold
        
        # Class labels
        self.class_labels = ['normal', 'udp_flood', 'syn_flood', 'http_flood']
        self.label_encoder = LabelEncoder()
        self.label_encoder.fit(self.class_labels)
        
        # Model and scaler
        self.model = None
        self.scaler = StandardScaler()
        
        # Performance tracking
        self.classification_count = 0
        self.avg_confidence = 0.0
        self.accuracy_history = []
        
        # Logging
        self.logger = logging.getLogger(__name__)
        
        # Load or create model
        self._load_or_create_model()
    
    def _load_or_create_model(self) -> None:
        """Load existing model or create a new one"""
        try:
            if os.path.exists(self.model_path) and os.path.exists(self.scaler_path):
                self._load_model()
                self.logger.info("Loaded existing model and scaler")
            else:
                self._create_model()
                self.logger.info("Created new model")
        except Exception as e:
            self.logger.error(f"Error loading/creating model: {e}")
            self._create_model()
    
    def _create_model(self) -> None:
        """Create a new MLP model"""
        if tf is None:
            raise ImportError("TensorFlow is required for model creation")
        
        # Build the model
        model = models.Sequential()
        
        # Input layer
        model.add(layers.Dense(self.hidden_layers[0], 
                              activation='relu', 
                              input_shape=(self.input_dim,)))
        model.add(layers.Dropout(0.3))
        
        # Hidden layers
        for units in self.hidden_layers[1:]:
            model.add(layers.Dense(units, activation='relu'))
            model.add(layers.Dropout(0.2))
        
        # Output layer
        model.add(layers.Dense(self.output_classes, activation='softmax'))
        
        # Compile model
        model.compile(
            optimizer=Adam(learning_rate=self.learning_rate),
            loss='sparse_categorical_crossentropy',
            metrics=['accuracy']
        )
        
        self.model = model
        self.logger.info(f"Created MLP model with {len(self.hidden_layers)} hidden layers")
    
    def _load_model(self) -> None:
        """Load existing model and scaler"""
        if tf is None:
            raise ImportError("TensorFlow is required for model loading")
        
        # Load model
        self.model = models.load_model(self.model_path)
        
        # Load scaler
        with open(self.scaler_path, 'rb') as f:
            self.scaler = pickle.load(f)
    
    def save_model(self) -> None:
        """Save model and scaler"""
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
            
            # Save model
            self.model.save(self.model_path)
            
            # Save scaler
            with open(self.scaler_path, 'wb') as f:
                pickle.dump(self.scaler, f)
            
            self.logger.info("Model and scaler saved successfully")
        except Exception as e:
            self.logger.error(f"Error saving model: {e}")
    
    def train(self, 
              X_train: np.ndarray, 
              y_train: np.ndarray,
              X_val: np.ndarray = None,
              y_val: np.ndarray = None,
              epochs: int = 100,
              batch_size: int = 32,
              validation_split: float = 0.2) -> Dict:
        """
        Train the classifier
        
        Args:
            X_train: Training features
            y_train: Training labels
            X_val: Validation features
            y_val: Validation labels
            epochs: Number of training epochs
            batch_size: Batch size for training
            validation_split: Validation split ratio
            
        Returns:
            Dict: Training history
        """
        if self.model is None:
            raise ValueError("Model not initialized")
        
        # Prepare data
        X_train_scaled = self.scaler.fit_transform(X_train)
        y_train_encoded = self.label_encoder.transform(y_train)
        
        # Prepare validation data
        if X_val is not None and y_val is not None:
            X_val_scaled = self.scaler.transform(X_val)
            y_val_encoded = self.label_encoder.transform(y_val)
            validation_data = (X_val_scaled, y_val_encoded)
        else:
            validation_data = None
        
        # Callbacks
        callbacks = [
            EarlyStopping(monitor='val_loss', patience=10, restore_best_weights=True),
            ModelCheckpoint(self.model_path, monitor='val_accuracy', save_best_only=True)
        ]
        
        # Train model
        history = self.model.fit(
            X_train_scaled, y_train_encoded,
            epochs=epochs,
            batch_size=batch_size,
            validation_data=validation_data,
            validation_split=validation_split if validation_data is None else 0.0,
            callbacks=callbacks,
            verbose=1
        )
        
        # Save model
        self.save_model()
        
        self.logger.info("Model training completed")
        return history.history
    
    def predict(self, features: Union[FeatureVector, np.ndarray]) -> ClassificationResult:
        """
        Predict class for given features
        
        Args:
            features: Feature vector or array
            
        Returns:
            ClassificationResult: Classification result
        """
        if self.model is None:
            raise ValueError("Model not initialized")
        
        # Convert FeatureVector to array if needed
        if isinstance(features, FeatureVector):
            features_array = np.array([
                features.packet_size_mean, features.packet_size_std,
                features.flow_rate, features.syn_ack_ratio,
                features.protocol_distribution['TCP'], features.protocol_distribution['UDP'],
                features.ttl_mean, features.ttl_std,
                features.payload_length_mean, features.payload_length_std,
                features.unique_sources, features.unique_destinations,
                features.port_entropy, features.ip_entropy
            ], dtype=np.float32).reshape(1, -1)
        else:
            features_array = features.reshape(1, -1)
        
        # Scale features
        features_scaled = self.scaler.transform(features_array)
        
        # Get predictions
        probabilities = self.model.predict(features_scaled, verbose=0)[0]
        predicted_class_idx = np.argmax(probabilities)
        confidence = probabilities[predicted_class_idx]
        
        # Get class label
        predicted_class = self.class_labels[predicted_class_idx]
        
        # Determine if it's an attack
        is_attack = predicted_class != 'normal'
        attack_type = predicted_class if is_attack else None
        
        # Update performance metrics
        self._update_performance_metrics(confidence)
        
        # Create result
        result = ClassificationResult(
            timestamp=time.time(),
            predicted_class=predicted_class,
            confidence=confidence,
            probabilities=dict(zip(self.class_labels, probabilities)),
            is_attack=is_attack,
            attack_type=attack_type
        )
        
        return result
    
    def predict_batch(self, features_list: List[Union[FeatureVector, np.ndarray]]) -> List[ClassificationResult]:
        """
        Predict classes for a batch of features
        
        Args:
            features_list: List of feature vectors or arrays
            
        Returns:
            List[ClassificationResult]: List of classification results
        """
        results = []
        for features in features_list:
            results.append(self.predict(features))
        return results
    
    def evaluate(self, X_test: np.ndarray, y_test: np.ndarray) -> Dict:
        """
        Evaluate model performance
        
        Args:
            X_test: Test features
            y_test: Test labels
            
        Returns:
            Dict: Evaluation metrics
        """
        if self.model is None:
            raise ValueError("Model not initialized")
        
        # Prepare test data
        X_test_scaled = self.scaler.transform(X_test)
        y_test_encoded = self.label_encoder.transform(y_test)
        
        # Get predictions
        y_pred_proba = self.model.predict(X_test_scaled, verbose=0)
        y_pred = np.argmax(y_pred_proba, axis=1)
        
        # Calculate metrics
        accuracy = accuracy_score(y_test_encoded, y_pred)
        
        # Classification report
        report = classification_report(
            y_test_encoded, y_pred, 
            target_names=self.class_labels,
            output_dict=True
        )
        
        # Confusion matrix
        cm = confusion_matrix(y_test_encoded, y_pred)
        
        # Store accuracy
        self.accuracy_history.append(accuracy)
        
        metrics = {
            'accuracy': accuracy,
            'classification_report': report,
            'confusion_matrix': cm,
            'predictions': y_pred,
            'probabilities': y_pred_proba
        }
        
        self.logger.info(f"Model evaluation completed. Accuracy: {accuracy:.4f}")
        return metrics
    
    def _update_performance_metrics(self, confidence: float) -> None:
        """Update performance tracking metrics"""
        self.classification_count += 1
        
        # Update average confidence
        if self.classification_count == 1:
            self.avg_confidence = confidence
        else:
            self.avg_confidence = (
                (self.avg_confidence * (self.classification_count - 1) + confidence) / 
                self.classification_count
            )
    
    def get_performance_stats(self) -> Dict:
        """Get current performance statistics"""
        return {
            'total_classifications': self.classification_count,
            'average_confidence': self.avg_confidence,
            'recent_accuracy': self.accuracy_history[-10:] if self.accuracy_history else [],
            'model_path': self.model_path,
            'input_dim': self.input_dim,
            'output_classes': self.output_classes
        }
    
    def get_model_summary(self) -> str:
        """Get model architecture summary"""
        if self.model is None:
            return "Model not initialized"
        
        # Capture model summary
        summary_list = []
        self.model.summary(print_fn=lambda x: summary_list.append(x))
        return '\n'.join(summary_list)
    
    def is_high_confidence(self, result: ClassificationResult) -> bool:
        """Check if classification result has high confidence"""
        return result.confidence >= self.confidence_threshold
    
    def get_attack_probability(self, result: ClassificationResult) -> float:
        """Get probability that the traffic is an attack"""
        if result.is_attack:
            return result.confidence
        else:
            # Return 1 - normal probability
            return 1.0 - result.probabilities.get('normal', 0.0) 