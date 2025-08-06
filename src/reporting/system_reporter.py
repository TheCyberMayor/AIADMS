"""
System Reporter Module for AI-ADMS

This module handles logging, reporting, and data collection for the
AI-ADMS system.
"""

import csv
import json
import time
import threading
from typing import Dict, List, Optional, Any
import logging
from datetime import datetime
from pathlib import Path
import os

from ..traffic_capture.feature_extractor import FeatureVector
from ..ai_classifier.ddos_classifier import ClassificationResult
from ..anomaly_scoring.anomaly_detector import AnomalyScore
from ..rl_mitigation.q_learning_agent import MitigationResult


class SystemReporter:
    """
    System reporter for logging and data collection
    
    This class handles logging of system activities, performance metrics,
    and analysis results for the AI-ADMS system.
    """
    
    def __init__(self, 
                 log_file: str = "logs/ai_adms.log",
                 csv_log: str = "logs/traffic_analysis.csv",
                 dashboard_config: Dict = None):
        """
        Initialize the system reporter
        
        Args:
            log_file: Path to log file
            csv_log: Path to CSV log file
            dashboard_config: Dashboard configuration
        """
        self.log_file = log_file
        self.csv_log = csv_log
        self.dashboard_config = dashboard_config or {}
        
        # Create log directories
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        os.makedirs(os.path.dirname(csv_log), exist_ok=True)
        
        # CSV file setup
        self.csv_file = None
        self.csv_writer = None
        
        # Performance tracking
        self.analysis_results = []
        self.mitigation_results = []
        self.system_events = []
        
        # Threading
        self.is_running = False
        self.reporting_thread = None
        
        # Logging - initialize logger first
        self.logger = logging.getLogger(__name__)
        if not self.logger.handlers:
    
    def _setup_csv_logging(self) -> None:
        """Setup CSV logging for analysis results"""
        try:
            # Create CSV file with headers
            csv_headers = [
                'timestamp', 'packet_size_mean', 'packet_size_std', 'flow_rate',
                'syn_ack_ratio', 'tcp_ratio', 'udp_ratio', 'ttl_mean', 'ttl_std',
                'payload_length_mean', 'payload_length_std', 'unique_sources',
                'unique_destinations', 'port_entropy', 'ip_entropy',
                'predicted_class', 'confidence', 'is_attack', 'attack_type',
                'anomaly_score', 'is_anomalous', 'severity_level',
                'classification_valid', 'response_time'
            ]
            
            # Check if file exists
            file_exists = os.path.exists(self.csv_log)
            
            self.csv_file = open(self.csv_log, 'a', newline='', encoding='utf-8')
            self.csv_writer = csv.DictWriter(self.csv_file, fieldnames=csv_headers)
            
            # Write headers if file is new
            if not file_exists:
                self.csv_writer.writeheader()
                self.csv_file.flush()
            
            self.logger.info(f"CSV logging setup complete: {self.csv_log}")
            
        except Exception as e:
            self.logger.error(f"Error setting up CSV logging: {e}")
    
    def start(self) -> None:
        """Start the reporting system"""
        if self.is_running:
            return
        
        self.is_running = True
        
        # Start reporting thread
        self.reporting_thread = threading.Thread(target=self._reporting_loop, daemon=True)
        self.reporting_thread.start()
        
        self.logger.info("System reporter started")
    
    def stop(self) -> None:
        """Stop the reporting system"""
        self.is_running = False
        
        # Close CSV file
        if self.csv_file:
            self.csv_file.close()
        
        self.logger.info("System reporter stopped")
    
    def log_analysis_result(self, 
                           features: FeatureVector,
                           classification_result: ClassificationResult,
                           anomaly_result: AnomalyScore,
                           is_valid: bool) -> None:
        """
        Log analysis result
        
        Args:
            features: Feature vector
            classification_result: AI classification result
            anomaly_result: Anomaly detection result
            is_valid: Whether classification is valid
        """
        try:
            # Create log entry
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'packet_size_mean': features.packet_size_mean,
                'packet_size_std': features.packet_size_std,
                'flow_rate': features.flow_rate,
                'syn_ack_ratio': features.syn_ack_ratio,
                'tcp_ratio': features.protocol_distribution.get('TCP', 0.0),
                'udp_ratio': features.protocol_distribution.get('UDP', 0.0),
                'ttl_mean': features.ttl_mean,
                'ttl_std': features.ttl_std,
                'payload_length_mean': features.payload_length_mean,
                'payload_length_std': features.payload_length_std,
                'unique_sources': features.unique_sources,
                'unique_destinations': features.unique_destinations,
                'port_entropy': features.port_entropy,
                'ip_entropy': features.ip_entropy,
                'predicted_class': classification_result.predicted_class,
                'confidence': classification_result.confidence,
                'is_attack': classification_result.is_attack,
                'attack_type': classification_result.attack_type or 'none',
                'anomaly_score': anomaly_result.overall_score,
                'is_anomalous': anomaly_result.is_anomalous,
                'severity_level': anomaly_result.severity_level,
                'classification_valid': is_valid,
                'response_time': time.time() - features.timestamp
            }
            
            # Write to CSV
            if self.csv_writer:
                self.csv_writer.writerow(log_entry)
                self.csv_file.flush()
            
            # Store in memory
            self.analysis_results.append(log_entry)
            
            # Update statistics
            self._update_analysis_stats(classification_result, anomaly_result, is_valid)
            
            # Log to file
            self.logger.info(
                f"Analysis: {classification_result.predicted_class} "
                f"(conf: {classification_result.confidence:.3f}, "
                f"anomaly: {anomaly_result.overall_score:.3f}, "
                f"valid: {is_valid})"
            )
            
        except Exception as e:
            self.logger.error(f"Error logging analysis result: {e}")
    
    def log_mitigation_result(self, mitigation_result: MitigationResult) -> None:
        """
        Log mitigation result
        
        Args:
            mitigation_result: Result of mitigation action
        """
        try:
            # Create log entry
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'action': mitigation_result.action_taken.value,
                'state': mitigation_result.state,
                'reward': mitigation_result.reward,
                'effectiveness': mitigation_result.effectiveness,
                'response_time': mitigation_result.response_time,
                'success': mitigation_result.success
            }
            
            # Store in memory
            self.mitigation_results.append(log_entry)
            
            # Update statistics
            self._update_mitigation_stats(mitigation_result)
            
            # Log to file
            self.logger.info(
                f"Mitigation: {mitigation_result.action_taken.value} "
                f"(effectiveness: {mitigation_result.effectiveness:.3f}, "
                f"reward: {mitigation_result.reward:.3f}, "
                f"success: {mitigation_result.success})"
            )
            
        except Exception as e:
            self.logger.error(f"Error logging mitigation result: {e}")
    
    def log_system_event(self, event_type: str, message: str, data: Dict = None) -> None:
        """
        Log system event
        
        Args:
            event_type: Type of event
            message: Event message
            data: Additional event data
        """
        try:
            event = {
                'timestamp': datetime.now().isoformat(),
                'event_type': event_type,
                'message': message,
                'data': data or {}
            }
            
            self.system_events.append(event)
            
            # Log to file
            if event_type == 'ERROR':
                self.logger.error(message)
            elif event_type == 'WARNING':
                self.logger.warning(message)
            else:
                self.logger.info(message)
                
        except Exception as e:
            self.logger.error(f"Error logging system event: {e}")
    
    def _update_analysis_stats(self, 
                              classification_result: ClassificationResult,
                              anomaly_result: AnomalyScore,
                              is_valid: bool) -> None:
        """Update analysis statistics"""
        self.stats['total_analyses'] += 1
        
        if classification_result.is_attack:
            self.stats['attack_detections'] += 1
        
        if not is_valid:
            if classification_result.is_attack:
                self.stats['false_positives'] += 1
            else:
                self.stats['false_negatives'] += 1
        
        # Update average confidence
        if self.stats['total_analyses'] == 1:
            self.stats['avg_confidence'] = classification_result.confidence
        else:
            self.stats['avg_confidence'] = (
                (self.stats['avg_confidence'] * (self.stats['total_analyses'] - 1) + 
                 classification_result.confidence) / self.stats['total_analyses']
            )
    
    def _update_mitigation_stats(self, mitigation_result: MitigationResult) -> None:
        """Update mitigation statistics"""
        self.stats['total_mitigations'] += 1
        
        # Update average response time
        if self.stats['total_mitigations'] == 1:
            self.stats['avg_response_time'] = mitigation_result.response_time
        else:
            self.stats['avg_response_time'] = (
                (self.stats['avg_response_time'] * (self.stats['total_mitigations'] - 1) + 
                 mitigation_result.response_time) / self.stats['total_mitigations']
            )
    
    def _reporting_loop(self) -> None:
        """Main reporting loop"""
        while self.is_running:
            try:
                # Generate periodic reports
                self._generate_periodic_report()
                
                # Clean up old data
                self._cleanup_old_data()
                
                time.sleep(60)  # Report every minute
                
            except Exception as e:
                self.logger.error(f"Error in reporting loop: {e}")
                time.sleep(60)
    
    def _generate_periodic_report(self) -> None:
        """Generate periodic performance report"""
        try:
            # Calculate additional statistics
            if self.stats['total_analyses'] > 0:
                false_positive_rate = self.stats['false_positives'] / self.stats['total_analyses']
                false_negative_rate = self.stats['false_negatives'] / self.stats['total_analyses']
                detection_rate = self.stats['attack_detections'] / self.stats['total_analyses']
            else:
                false_positive_rate = 0.0
                false_negative_rate = 0.0
                detection_rate = 0.0
            
            # Create report
            report = {
                'timestamp': datetime.now().isoformat(),
                'total_analyses': self.stats['total_analyses'],
                'total_mitigations': self.stats['total_mitigations'],
                'attack_detections': self.stats['attack_detections'],
                'detection_rate': detection_rate,
                'false_positive_rate': false_positive_rate,
                'false_negative_rate': false_negative_rate,
                'avg_confidence': self.stats['avg_confidence'],
                'avg_response_time': self.stats['avg_response_time']
            }
            
            # Log report
            self.logger.info(
                f"Periodic Report: "
                f"Analyses: {report['total_analyses']}, "
                f"Detections: {report['attack_detections']}, "
                f"Detection Rate: {detection_rate:.3f}, "
                f"FPR: {false_positive_rate:.3f}, "
                f"Avg Confidence: {report['avg_confidence']:.3f}"
            )
            
        except Exception as e:
            self.logger.error(f"Error generating periodic report: {e}")
    
    def _cleanup_old_data(self) -> None:
        """Clean up old data from memory"""
        try:
            current_time = time.time()
            cutoff_time = current_time - 3600  # Keep last hour
            
            # Clean up analysis results
            self.analysis_results = [
                result for result in self.analysis_results
                if time.mktime(datetime.fromisoformat(result['timestamp']).timetuple()) > cutoff_time
            ]
            
            # Clean up mitigation results
            self.mitigation_results = [
                result for result in self.mitigation_results
                if time.mktime(datetime.fromisoformat(result['timestamp']).timetuple()) > cutoff_time
            ]
            
            # Clean up system events
            self.system_events = [
                event for event in self.system_events
                if time.mktime(datetime.fromisoformat(event['timestamp']).timetuple()) > cutoff_time
            ]
            
        except Exception as e:
            self.logger.error(f"Error cleaning up old data: {e}")
    
    def get_performance_stats(self) -> Dict:
        """Get current performance statistics"""
        return self.stats.copy()
    
    def get_recent_analysis_results(self, limit: int = 100) -> List[Dict]:
        """Get recent analysis results"""
        return self.analysis_results[-limit:]
    
    def get_recent_mitigation_results(self, limit: int = 100) -> List[Dict]:
        """Get recent mitigation results"""
        return self.mitigation_results[-limit:]
    
    def get_recent_system_events(self, limit: int = 100) -> List[Dict]:
        """Get recent system events"""
        return self.system_events[-limit:]
    
    def export_data(self, filepath: str, data_type: str = 'all') -> None:
        """
        Export data to JSON file
        
        Args:
            filepath: Output file path
            data_type: Type of data to export ('analysis', 'mitigation', 'events', 'all')
        """
        try:
            export_data = {}
            
            if data_type in ['analysis', 'all']:
                export_data['analysis_results'] = self.analysis_results
            
            if data_type in ['mitigation', 'all']:
                export_data['mitigation_results'] = self.mitigation_results
            
            if data_type in ['events', 'all']:
                export_data['system_events'] = self.system_events
            
            if data_type in ['stats', 'all']:
                export_data['statistics'] = self.stats
            
            with open(filepath, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            self.logger.info(f"Data exported to {filepath}")
            
        except Exception as e:
            self.logger.error(f"Error exporting data: {e}")
    
    def generate_summary_report(self) -> Dict:
        """Generate a comprehensive summary report"""
        try:
            # Calculate additional metrics
            total_analyses = self.stats['total_analyses']
            total_mitigations = self.stats['total_mitigations']
            
            if total_analyses > 0:
                accuracy = 1.0 - (self.stats['false_positives'] + self.stats['false_negatives']) / total_analyses
                precision = self.stats['attack_detections'] / max(1, self.stats['attack_detections'] + self.stats['false_positives'])
                recall = self.stats['attack_detections'] / max(1, self.stats['attack_detections'] + self.stats['false_negatives'])
            else:
                accuracy = precision = recall = 0.0
            
            # Create summary report
            summary = {
                'timestamp': datetime.now().isoformat(),
                'performance_metrics': {
                    'total_analyses': total_analyses,
                    'total_mitigations': total_mitigations,
                    'attack_detections': self.stats['attack_detections'],
                    'accuracy': accuracy,
                    'precision': precision,
                    'recall': recall,
                    'false_positive_rate': self.stats['false_positives'] / max(1, total_analyses),
                    'false_negative_rate': self.stats['false_negatives'] / max(1, total_analyses),
                    'avg_confidence': self.stats['avg_confidence'],
                    'avg_response_time': self.stats['avg_response_time']
                },
                'system_health': {
                    'csv_log_size': os.path.getsize(self.csv_log) if os.path.exists(self.csv_log) else 0,
                    'memory_usage': len(self.analysis_results) + len(self.mitigation_results) + len(self.system_events)
                }
            }
            
            return summary
            
        except Exception as e:
            self.logger.error(f"Error generating summary report: {e}")
            return {} 