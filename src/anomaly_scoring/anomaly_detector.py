"""
Anomaly Detector Module for AI-ADMS

This module implements statistical anomaly detection to complement AI-based
classification and provide additional security validation.
"""

import numpy as np
import pandas as pd
from typing import List, Dict, Tuple, Optional, Union
import logging
import time
from collections import deque
from dataclasses import dataclass

from ..traffic_capture.feature_extractor import FeatureVector


@dataclass
class AnomalyScore:
    """Data class for anomaly detection results"""
    timestamp: float
    overall_score: float
    feature_scores: Dict[str, float]
    is_anomalous: bool
    severity_level: str
    contributing_features: List[str]


class AnomalyDetector:
    """
    Statistical anomaly detection for network traffic
    
    This class implements multiple statistical methods to detect anomalies
    in network traffic patterns, providing a failsafe mechanism for the
    AI-based classification system.
    """
    
    def __init__(self, 
                 baseline_window: int = 1000,
                 update_frequency: int = 100,
                 anomaly_threshold: float = 0.7,
                 high_anomaly_threshold: float = 0.9,
                 feature_weights: Optional[Dict[str, float]] = None):
        """
        Initialize the anomaly detector
        
        Args:
            baseline_window: Number of samples for baseline calculation
            update_frequency: How often to update baseline
            anomaly_threshold: Threshold for anomaly detection
            high_anomaly_threshold: Threshold for high severity anomalies
            feature_weights: Weights for different features
        """
        self.baseline_window = baseline_window
        self.update_frequency = update_frequency
        self.anomaly_threshold = anomaly_threshold
        self.high_anomaly_threshold = high_anomaly_threshold
        
        # Default feature weights
        self.feature_weights = feature_weights or {
            'packet_size': 0.2,
            'flow_rate': 0.3,
            'syn_ack_ratio': 0.25,
            'protocol': 0.15,
            'ttl': 0.1
        }
        
        # Baseline statistics
        self.baseline_stats = {}
        self.baseline_initialized = False
        
        # Feature history for baseline calculation
        self.feature_history = deque(maxlen=baseline_window)
        
        # Performance tracking
        self.detection_count = 0
        self.anomaly_count = 0
        self.avg_score = 0.0
        
        # Logging
        self.logger = logging.getLogger(__name__)
        
        # Statistical models
        self.z_score_threshold = 3.0
        self.iqr_multiplier = 1.5
    
    def add_feature_vector(self, feature_vector: FeatureVector) -> None:
        """
        Add a feature vector to the anomaly detection system
        
        Args:
            feature_vector: Feature vector to analyze
        """
        self.feature_history.append(feature_vector)
        
        # Update baseline if needed
        if len(self.feature_history) >= self.baseline_window and \
           len(self.feature_history) % self.update_frequency == 0:
            self._update_baseline()
    
    def detect_anomaly(self, feature_vector: FeatureVector) -> AnomalyScore:
        """
        Detect anomalies in a feature vector
        
        Args:
            feature_vector: Feature vector to analyze
            
        Returns:
            AnomalyScore: Anomaly detection result
        """
        if not self.baseline_initialized:
            # Return low score if baseline not ready
            return AnomalyScore(
                timestamp=time.time(),
                overall_score=0.0,
                feature_scores={},
                is_anomalous=False,
                severity_level="normal",
                contributing_features=[]
            )
        
        # Calculate individual feature scores
        feature_scores = self._calculate_feature_scores(feature_vector)
        
        # Calculate overall anomaly score
        overall_score = self._calculate_overall_score(feature_scores)
        
        # Determine if anomalous and severity
        is_anomalous = overall_score >= self.anomaly_threshold
        severity_level = self._determine_severity(overall_score)
        
        # Find contributing features
        contributing_features = [
            feature for feature, score in feature_scores.items()
            if score > self.anomaly_threshold
        ]
        
        # Update performance metrics
        self._update_performance_metrics(overall_score, is_anomalous)
        
        return AnomalyScore(
            timestamp=time.time(),
            overall_score=overall_score,
            feature_scores=feature_scores,
            is_anomalous=is_anomalous,
            severity_level=severity_level,
            contributing_features=contributing_features
        )
    
    def _calculate_feature_scores(self, feature_vector: FeatureVector) -> Dict[str, float]:
        """Calculate anomaly scores for individual features"""
        scores = {}
        
        # Packet size anomaly
        size_score = self._z_score_anomaly(
            feature_vector.packet_size_mean,
            self.baseline_stats.get('packet_size_mean', 0),
            self.baseline_stats.get('packet_size_std', 1)
        )
        scores['packet_size'] = size_score
        
        # Flow rate anomaly
        rate_score = self._z_score_anomaly(
            feature_vector.flow_rate,
            self.baseline_stats.get('flow_rate', 0),
            self.baseline_stats.get('flow_rate_std', 1)
        )
        scores['flow_rate'] = rate_score
        
        # SYN/ACK ratio anomaly
        syn_score = self._z_score_anomaly(
            feature_vector.syn_ack_ratio,
            self.baseline_stats.get('syn_ack_ratio', 0),
            self.baseline_stats.get('syn_ack_ratio_std', 1)
        )
        scores['syn_ack_ratio'] = syn_score
        
        # Protocol distribution anomaly
        tcp_score = self._z_score_anomaly(
            feature_vector.protocol_distribution['TCP'],
            self.baseline_stats.get('tcp_ratio', 0),
            self.baseline_stats.get('tcp_ratio_std', 1)
        )
        scores['protocol'] = tcp_score
        
        # TTL anomaly
        ttl_score = self._z_score_anomaly(
            feature_vector.ttl_mean,
            self.baseline_stats.get('ttl_mean', 0),
            self.baseline_stats.get('ttl_std', 1)
        )
        scores['ttl'] = ttl_score
        
        # Entropy anomalies
        port_entropy_score = self._entropy_anomaly(
            feature_vector.port_entropy,
            self.baseline_stats.get('port_entropy_mean', 0),
            self.baseline_stats.get('port_entropy_std', 1)
        )
        scores['port_entropy'] = port_entropy_score
        
        ip_entropy_score = self._entropy_anomaly(
            feature_vector.ip_entropy,
            self.baseline_stats.get('ip_entropy_mean', 0),
            self.baseline_stats.get('ip_entropy_std', 1)
        )
        scores['ip_entropy'] = ip_entropy_score
        
        return scores
    
    def _z_score_anomaly(self, value: float, mean: float, std: float) -> float:
        """Calculate Z-score based anomaly"""
        if std == 0:
            return 0.0
        
        z_score = abs((value - mean) / std)
        # Convert to 0-1 scale using sigmoid
        return 1.0 / (1.0 + np.exp(-(z_score - self.z_score_threshold)))
    
    def _entropy_anomaly(self, value: float, mean: float, std: float) -> float:
        """Calculate entropy-based anomaly"""
        if std == 0:
            return 0.0
        
        # Entropy anomalies can be both high and low
        z_score = abs((value - mean) / std)
        return 1.0 / (1.0 + np.exp(-(z_score - 2.0)))
    
    def _iqr_anomaly(self, value: float, q1: float, q3: float) -> float:
        """Calculate IQR-based anomaly"""
        iqr = q3 - q1
        if iqr == 0:
            return 0.0
        
        lower_bound = q1 - self.iqr_multiplier * iqr
        upper_bound = q3 + self.iqr_multiplier * iqr
        
        if value < lower_bound or value > upper_bound:
            # Calculate how far outside the bounds
            if value < lower_bound:
                distance = (lower_bound - value) / iqr
            else:
                distance = (value - upper_bound) / iqr
            
            return min(1.0, distance / 2.0)
        
        return 0.0
    
    def _calculate_overall_score(self, feature_scores: Dict[str, float]) -> float:
        """Calculate weighted overall anomaly score"""
        if not feature_scores:
            return 0.0
        
        weighted_sum = 0.0
        total_weight = 0.0
        
        for feature, score in feature_scores.items():
            weight = self.feature_weights.get(feature, 0.1)
            weighted_sum += weight * score
            total_weight += weight
        
        if total_weight == 0:
            return 0.0
        
        return weighted_sum / total_weight
    
    def _determine_severity(self, score: float) -> str:
        """Determine severity level based on anomaly score"""
        if score >= self.high_anomaly_threshold:
            return "high"
        elif score >= self.anomaly_threshold:
            return "medium"
        else:
            return "normal"
    
    def _update_baseline(self) -> None:
        """Update baseline statistics from feature history"""
        if len(self.feature_history) < self.baseline_window // 2:
            return
        
        # Extract features
        packet_sizes = [f.packet_size_mean for f in self.feature_history]
        flow_rates = [f.flow_rate for f in self.feature_history]
        syn_ack_ratios = [f.syn_ack_ratio for f in self.feature_history]
        tcp_ratios = [f.protocol_distribution['TCP'] for f in self.feature_history]
        ttls = [f.ttl_mean for f in self.feature_history]
        port_entropies = [f.port_entropy for f in self.feature_history]
        ip_entropies = [f.ip_entropy for f in self.feature_history]
        
        # Calculate statistics
        self.baseline_stats = {
            'packet_size_mean': np.mean(packet_sizes),
            'packet_size_std': np.std(packet_sizes),
            'flow_rate': np.mean(flow_rates),
            'flow_rate_std': np.std(flow_rates),
            'syn_ack_ratio': np.mean(syn_ack_ratios),
            'syn_ack_ratio_std': np.std(syn_ack_ratios),
            'tcp_ratio': np.mean(tcp_ratios),
            'tcp_ratio_std': np.std(tcp_ratios),
            'ttl_mean': np.mean(ttls),
            'ttl_std': np.std(ttls),
            'port_entropy_mean': np.mean(port_entropies),
            'port_entropy_std': np.std(port_entropies),
            'ip_entropy_mean': np.mean(ip_entropies),
            'ip_entropy_std': np.std(ip_entropies)
        }
        
        self.baseline_initialized = True
        self.logger.info("Baseline statistics updated")
    
    def _update_performance_metrics(self, score: float, is_anomalous: bool) -> None:
        """Update performance tracking metrics"""
        self.detection_count += 1
        
        if is_anomalous:
            self.anomaly_count += 1
        
        # Update average score
        if self.detection_count == 1:
            self.avg_score = score
        else:
            self.avg_score = (
                (self.avg_score * (self.detection_count - 1) + score) / 
                self.detection_count
            )
    
    def get_performance_stats(self) -> Dict:
        """Get current performance statistics"""
        return {
            'total_detections': self.detection_count,
            'anomaly_count': self.anomaly_count,
            'anomaly_rate': self.anomaly_count / max(1, self.detection_count),
            'average_score': self.avg_score,
            'baseline_initialized': self.baseline_initialized,
            'baseline_window': self.baseline_window,
            'anomaly_threshold': self.anomaly_threshold,
            'high_anomaly_threshold': self.high_anomaly_threshold
        }
    
    def get_baseline_stats(self) -> Dict:
        """Get current baseline statistics"""
        return self.baseline_stats.copy()
    
    def reset_baseline(self) -> None:
        """Reset baseline statistics"""
        self.baseline_stats = {}
        self.baseline_initialized = False
        self.feature_history.clear()
        self.logger.info("Baseline statistics reset")
    
    def set_thresholds(self, 
                      anomaly_threshold: float = None,
                      high_anomaly_threshold: float = None) -> None:
        """Update anomaly detection thresholds"""
        if anomaly_threshold is not None:
            self.anomaly_threshold = anomaly_threshold
        
        if high_anomaly_threshold is not None:
            self.high_anomaly_threshold = high_anomaly_threshold
        
        self.logger.info(f"Thresholds updated: anomaly={self.anomaly_threshold}, high={self.high_anomaly_threshold}")
    
    def validate_classification(self, 
                              ai_result: bool, 
                              anomaly_score: float) -> bool:
        """
        Validate AI classification using anomaly detection
        
        Args:
            ai_result: AI classification result (True for attack)
            anomaly_score: Anomaly detection score
            
        Returns:
            bool: Whether the classification is validated
        """
        # If AI says it's an attack but anomaly score is low, flag for review
        if ai_result and anomaly_score < self.anomaly_threshold * 0.5:
            return False
        
        # If AI says it's normal but anomaly score is high, flag for review
        if not ai_result and anomaly_score > self.anomaly_threshold:
            return False
        
        return True 