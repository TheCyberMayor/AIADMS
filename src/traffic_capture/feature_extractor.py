"""
Feature Extractor Module for AI-ADMS

This module extracts and normalizes features from captured network packets
for use in AI-based DDoS detection and classification.
"""

import numpy as np
import pandas as pd
from typing import List, Dict, Tuple, Optional
from collections import defaultdict, deque
import time
import logging
from dataclasses import dataclass

from .packet_capture import PacketInfo


@dataclass
class FeatureVector:
    """Data class for extracted features"""
    timestamp: float
    packet_size_mean: float
    packet_size_std: float
    flow_rate: float
    syn_ack_ratio: float
    protocol_distribution: Dict[str, float]
    ttl_mean: float
    ttl_std: float
    payload_length_mean: float
    payload_length_std: float
    unique_sources: int
    unique_destinations: int
    port_entropy: float
    ip_entropy: float
    attack_probability: float = 0.0


class FeatureExtractor:
    """
    Feature extraction and normalization for network traffic analysis
    
    This class processes raw packet data and extracts statistical features
    that are relevant for DDoS attack detection and classification.
    """
    
    def __init__(self, 
                 window_size: int = 100,
                 update_interval: float = 1.0,
                 feature_weights: Optional[Dict[str, float]] = None):
        """
        Initialize the feature extractor
        
        Args:
            window_size: Number of packets to consider for feature extraction
            update_interval: Time interval between feature updates (seconds)
            feature_weights: Weights for different features in anomaly scoring
        """
        self.window_size = window_size
        self.update_interval = update_interval
        
        # Default feature weights
        self.feature_weights = feature_weights or {
            'packet_size': 0.2,
            'flow_rate': 0.3,
            'syn_ack_ratio': 0.25,
            'protocol': 0.15,
            'ttl': 0.1
        }
        
        # Packet buffer for feature calculation
        self.packet_buffer = deque(maxlen=window_size)
        
        # Baseline statistics (for anomaly detection)
        self.baseline_stats = {}
        self.baseline_initialized = False
        
        # Logging
        self.logger = logging.getLogger(__name__)
        
        # Performance tracking
        self.last_update = 0.0
        self.feature_count = 0
        
    def add_packet(self, packet_info: PacketInfo) -> None:
        """
        Add a packet to the feature extraction buffer
        
        Args:
            packet_info: Packet information to process
        """
        self.packet_buffer.append(packet_info)
        
        # Update features if enough time has passed
        current_time = time.time()
        if (current_time - self.last_update) >= self.update_interval:
            self._update_baseline()
            self.last_update = current_time
    
    def extract_features(self, packets: List[PacketInfo]) -> FeatureVector:
        """
        Extract features from a list of packets
        
        Args:
            packets: List of packet information
            
        Returns:
            FeatureVector: Extracted features
        """
        if not packets:
            return self._create_empty_feature_vector()
        
        # Basic statistics
        packet_sizes = [p.packet_size for p in packets]
        ttls = [p.ttl for p in packets]
        payload_lengths = [p.payload_length for p in packets]
        
        # Protocol analysis
        protocols = [p.protocol for p in packets]
        protocol_counts = defaultdict(int)
        for protocol in protocols:
            protocol_counts[protocol] += 1
        
        protocol_distribution = {
            'TCP': protocol_counts.get('TCP', 0) / len(packets),
            'UDP': protocol_counts.get('UDP', 0) / len(packets),
            'ICMP': protocol_counts.get('ICMP', 0) / len(packets),
            'OTHER': protocol_counts.get('OTHER', 0) / len(packets)
        }
        
        # Flow analysis
        unique_sources = len(set(p.source_ip for p in packets))
        unique_destinations = len(set(p.dest_ip for p in packets))
        
        # SYN/ACK ratio calculation
        syn_count = sum(1 for p in packets if 'S' in p.flags and 'A' not in p.flags)
        ack_count = sum(1 for p in packets if 'A' in p.flags)
        syn_ack_ratio = syn_count / (ack_count + 1) if ack_count > 0 else 0.0
        
        # Flow rate calculation
        if len(packets) > 1:
            time_span = packets[-1].timestamp - packets[0].timestamp
            flow_rate = len(packets) / time_span if time_span > 0 else 0.0
        else:
            flow_rate = 0.0
        
        # Entropy calculations
        port_entropy = self._calculate_entropy([p.dest_port for p in packets])
        ip_entropy = self._calculate_entropy([p.source_ip for p in packets])
        
        return FeatureVector(
            timestamp=time.time(),
            packet_size_mean=np.mean(packet_sizes),
            packet_size_std=np.std(packet_sizes) if len(packet_sizes) > 1 else 0.0,
            flow_rate=flow_rate,
            syn_ack_ratio=syn_ack_ratio,
            protocol_distribution=protocol_distribution,
            ttl_mean=np.mean(ttls),
            ttl_std=np.std(ttls) if len(ttls) > 1 else 0.0,
            payload_length_mean=np.mean(payload_lengths),
            payload_length_std=np.std(payload_lengths) if len(payload_lengths) > 1 else 0.0,
            unique_sources=unique_sources,
            unique_destinations=unique_destinations,
            port_entropy=port_entropy,
            ip_entropy=ip_entropy
        )
    
    def get_current_features(self) -> FeatureVector:
        """
        Get features from the current packet buffer
        
        Returns:
            FeatureVector: Current feature vector
        """
        return self.extract_features(list(self.packet_buffer))
    
    def normalize_features(self, feature_vector: FeatureVector) -> np.ndarray:
        """
        Normalize features for AI model input
        
        Args:
            feature_vector: Raw feature vector
            
        Returns:
            np.ndarray: Normalized feature array
        """
        # Convert feature vector to array
        features = [
            feature_vector.packet_size_mean,
            feature_vector.packet_size_std,
            feature_vector.flow_rate,
            feature_vector.syn_ack_ratio,
            feature_vector.protocol_distribution['TCP'],
            feature_vector.protocol_distribution['UDP'],
            feature_vector.ttl_mean,
            feature_vector.ttl_std,
            feature_vector.payload_length_mean,
            feature_vector.payload_length_std,
            feature_vector.unique_sources,
            feature_vector.unique_destinations,
            feature_vector.port_entropy,
            feature_vector.ip_entropy
        ]
        
        # Normalize using baseline statistics if available
        if self.baseline_initialized:
            features = self._normalize_with_baseline(features)
        
        return np.array(features, dtype=np.float32)
    
    def calculate_anomaly_score(self, feature_vector: FeatureVector) -> float:
        """
        Calculate anomaly score based on deviation from baseline
        
        Args:
            feature_vector: Feature vector to evaluate
            
        Returns:
            float: Anomaly score (0.0 to 1.0)
        """
        if not self.baseline_initialized:
            return 0.0
        
        # Calculate weighted deviation from baseline
        deviations = []
        
        # Packet size deviation
        size_dev = abs(feature_vector.packet_size_mean - self.baseline_stats.get('packet_size_mean', 0))
        deviations.append(self.feature_weights['packet_size'] * size_dev)
        
        # Flow rate deviation
        rate_dev = abs(feature_vector.flow_rate - self.baseline_stats.get('flow_rate', 0))
        deviations.append(self.feature_weights['flow_rate'] * rate_dev)
        
        # SYN/ACK ratio deviation
        syn_dev = abs(feature_vector.syn_ack_ratio - self.baseline_stats.get('syn_ack_ratio', 0))
        deviations.append(self.feature_weights['syn_ack_ratio'] * syn_dev)
        
        # Protocol distribution deviation
        tcp_dev = abs(feature_vector.protocol_distribution['TCP'] - self.baseline_stats.get('tcp_ratio', 0))
        deviations.append(self.feature_weights['protocol'] * tcp_dev)
        
        # TTL deviation
        ttl_dev = abs(feature_vector.ttl_mean - self.baseline_stats.get('ttl_mean', 0))
        deviations.append(self.feature_weights['ttl'] * ttl_dev)
        
        # Calculate weighted average
        total_weight = sum(self.feature_weights.values())
        anomaly_score = sum(deviations) / total_weight if total_weight > 0 else 0.0
        
        # Normalize to 0-1 range
        return min(1.0, max(0.0, anomaly_score))
    
    def _update_baseline(self) -> None:
        """Update baseline statistics from current traffic"""
        if len(self.packet_buffer) < self.window_size // 2:
            return
        
        current_features = self.get_current_features()
        
        # Update baseline statistics
        if not self.baseline_initialized:
            self.baseline_stats = {
                'packet_size_mean': current_features.packet_size_mean,
                'packet_size_std': current_features.packet_size_std,
                'flow_rate': current_features.flow_rate,
                'syn_ack_ratio': current_features.syn_ack_ratio,
                'tcp_ratio': current_features.protocol_distribution['TCP'],
                'ttl_mean': current_features.ttl_mean,
                'ttl_std': current_features.ttl_std
            }
            self.baseline_initialized = True
        else:
            # Exponential moving average for baseline update
            alpha = 0.1
            self.baseline_stats['packet_size_mean'] = (
                alpha * current_features.packet_size_mean + 
                (1 - alpha) * self.baseline_stats['packet_size_mean']
            )
            self.baseline_stats['flow_rate'] = (
                alpha * current_features.flow_rate + 
                (1 - alpha) * self.baseline_stats['flow_rate']
            )
            # Update other statistics similarly...
    
    def _normalize_with_baseline(self, features: List[float]) -> List[float]:
        """Normalize features using baseline statistics"""
        normalized = []
        
        for i, feature in enumerate(features):
            if i < len(self.baseline_stats):
                baseline = list(self.baseline_stats.values())[i]
                if baseline != 0:
                    normalized.append(feature / baseline)
                else:
                    normalized.append(feature)
            else:
                normalized.append(feature)
        
        return normalized
    
    def _calculate_entropy(self, values: List) -> float:
        """Calculate entropy of a list of values"""
        if not values:
            return 0.0
        
        # Count occurrences
        counts = defaultdict(int)
        for value in values:
            counts[value] += 1
        
        # Calculate entropy
        total = len(values)
        entropy = 0.0
        
        for count in counts.values():
            if count > 0:
                p = count / total
                entropy -= p * np.log2(p)
        
        return entropy
    
    def _create_empty_feature_vector(self) -> FeatureVector:
        """Create an empty feature vector"""
        return FeatureVector(
            timestamp=time.time(),
            packet_size_mean=0.0,
            packet_size_std=0.0,
            flow_rate=0.0,
            syn_ack_ratio=0.0,
            protocol_distribution={'TCP': 0.0, 'UDP': 0.0, 'ICMP': 0.0, 'OTHER': 0.0},
            ttl_mean=0.0,
            ttl_std=0.0,
            payload_length_mean=0.0,
            payload_length_std=0.0,
            unique_sources=0,
            unique_destinations=0,
            port_entropy=0.0,
            ip_entropy=0.0
        )
    
    def get_baseline_stats(self) -> Dict:
        """Get current baseline statistics"""
        return self.baseline_stats.copy()
    
    def reset_baseline(self) -> None:
        """Reset baseline statistics"""
        self.baseline_stats = {}
        self.baseline_initialized = False
        self.logger.info("Baseline statistics reset")
    
    def get_feature_names(self) -> List[str]:
        """Get list of feature names"""
        return [
            'packet_size_mean', 'packet_size_std', 'flow_rate', 'syn_ack_ratio',
            'tcp_ratio', 'udp_ratio', 'ttl_mean', 'ttl_std', 'payload_length_mean',
            'payload_length_std', 'unique_sources', 'unique_destinations',
            'port_entropy', 'ip_entropy'
        ] 