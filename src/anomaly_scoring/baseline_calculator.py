"""
Baseline Calculator Module for AI-ADMS

This module provides functionality to calculate baseline statistics for network traffic
to establish normal behavior patterns for anomaly detection.
"""

import numpy as np
import pandas as pd
from typing import Dict, List, Tuple, Optional
import logging

logger = logging.getLogger(__name__)


class BaselineCalculator:
    """
    Calculates baseline statistics for network traffic features.
    
    This class computes statistical baselines (mean, std, percentiles) for various
    network traffic features to establish normal behavior patterns.
    """
    
    def __init__(self, confidence_level: float = 0.95):
        """
        Initialize the baseline calculator.
        
        Args:
            confidence_level: Confidence level for anomaly thresholds (default: 0.95)
        """
        self.confidence_level = confidence_level
        self.baselines = {}
        self.is_fitted = False
        
    def fit(self, data: pd.DataFrame, feature_columns: List[str]) -> 'BaselineCalculator':
        """
        Calculate baseline statistics from training data.
        
        Args:
            data: Training data DataFrame
            feature_columns: List of feature column names to calculate baselines for
            
        Returns:
            self: Fitted BaselineCalculator instance
        """
        logger.info(f"Calculating baselines for {len(feature_columns)} features")
        
        for col in feature_columns:
            if col not in data.columns:
                logger.warning(f"Column {col} not found in data, skipping")
                continue
                
            col_data = data[col].dropna()
            if len(col_data) == 0:
                logger.warning(f"No valid data for column {col}, skipping")
                continue
                
            # Calculate baseline statistics
            self.baselines[col] = {
                'mean': float(col_data.mean()),
                'std': float(col_data.std()),
                'min': float(col_data.min()),
                'max': float(col_data.max()),
                'q25': float(col_data.quantile(0.25)),
                'q50': float(col_data.quantile(0.50)),
                'q75': float(col_data.quantile(0.75)),
                'q95': float(col_data.quantile(0.95)),
                'q99': float(col_data.quantile(0.99))
            }
            
        self.is_fitted = True
        logger.info(f"Successfully calculated baselines for {len(self.baselines)} features")
        return self
    
    def get_anomaly_thresholds(self, feature_name: str) -> Dict[str, float]:
        """
        Get anomaly detection thresholds for a specific feature.
        
        Args:
            feature_name: Name of the feature
            
        Returns:
            Dictionary containing upper and lower thresholds
        """
        if not self.is_fitted or feature_name not in self.baselines:
            raise ValueError(f"Baseline not calculated for feature: {feature_name}")
            
        baseline = self.baselines[feature_name]
        
        # Use 95th percentile as upper threshold and 5th percentile as lower threshold
        upper_threshold = baseline['q95'] + 2 * baseline['std']
        lower_threshold = max(0, baseline['q5'] - 2 * baseline['std']) if 'q5' in baseline else 0
        
        return {
            'upper_threshold': upper_threshold,
            'lower_threshold': lower_threshold,
            'mean': baseline['mean'],
            'std': baseline['std']
        }
    
    def calculate_anomaly_score(self, value: float, feature_name: str) -> float:
        """
        Calculate anomaly score for a single value based on baseline statistics.
        
        Args:
            value: The value to score
            feature_name: Name of the feature
            
        Returns:
            Anomaly score (0 = normal, >1 = anomalous)
        """
        if not self.is_fitted or feature_name not in self.baselines:
            return 0.0
            
        baseline = self.baselines[feature_name]
        mean = baseline['mean']
        std = baseline['std']
        
        if std == 0:
            return 0.0
            
        # Calculate z-score
        z_score = abs(value - mean) / std
        
        # Convert to anomaly score (values beyond 3 std deviations are highly anomalous)
        anomaly_score = max(0, (z_score - 2) / 1)  # Scale so >3 std = score >1
        
        return anomaly_score
    
    def get_baseline_summary(self) -> Dict[str, Dict]:
        """
        Get summary of all calculated baselines.
        
        Returns:
            Dictionary containing baseline statistics for all features
        """
        return self.baselines.copy()
    
    def save_baselines(self, filepath: str) -> None:
        """
        Save baseline statistics to a file.
        
        Args:
            filepath: Path to save the baselines
        """
        import json
        with open(filepath, 'w') as f:
            json.dump(self.baselines, f, indent=2)
        logger.info(f"Baselines saved to {filepath}")
    
    def load_baselines(self, filepath: str) -> None:
        """
        Load baseline statistics from a file.
        
        Args:
            filepath: Path to load the baselines from
        """
        import json
        with open(filepath, 'r') as f:
            self.baselines = json.load(f)
        self.is_fitted = True
        logger.info(f"Baselines loaded from {filepath}")
