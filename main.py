#!/usr/bin/env python3
"""
AI-Driven Adaptive DDoS Mitigation System (AI-ADMS)

Main entry point for the AI-ADMS system that orchestrates all components
including traffic capture, AI classification, anomaly detection, and
reinforcement learning-based mitigation.
"""

import os
import sys
import time
import signal
import logging
import argparse
import yaml
import threading
from typing import Dict, Optional
from pathlib import Path

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from src.traffic_capture import PacketCapture, FeatureExtractor
from src.ai_classifier import DDoSClassifier
from src.anomaly_scoring import AnomalyDetector
from src.rl_mitigation import QLearningAgent, MitigationActions
from src.reporting import SystemReporter


class AIADMSSystem:
    """
    Main orchestrator for the AI-ADMS system
    
    This class coordinates all system components and manages the overall
    DDoS detection and mitigation workflow.
    """
    
    def __init__(self, config_path: str = "config/config.yaml"):
        """
        Initialize the AI-ADMS system
        
        Args:
            config_path: Path to configuration file
        """
        self.config_path = config_path
        self.config = self._load_config()
        
        # Setup logging
        self._setup_logging()
        self.logger = logging.getLogger(__name__)
        
        # System components
        self.packet_capture = None
        self.feature_extractor = None
        self.ai_classifier = None
        self.anomaly_detector = None
        self.rl_agent = None
        self.mitigation_actions = None
        self.reporter = None
        
        # System state
        self.is_running = False
        self.start_time = None
        
        # Performance tracking
        self.total_packets_processed = 0
        self.total_attacks_detected = 0
        self.total_mitigations_performed = 0
        
        # Threading
        self.analysis_thread = None
        self.mitigation_thread = None
        
        self.logger.info("AI-ADMS System initialized")
    
    def _load_config(self) -> Dict:
        """Load configuration from YAML file"""
        try:
            with open(self.config_path, 'r') as f:
                config = yaml.safe_load(f)
            return config
        except Exception as e:
            print(f"Error loading config: {e}")
            return {}
    
    def _setup_logging(self) -> None:
        """Setup logging configuration"""
        log_config = self.config.get('reporting', {})
        log_file = log_config.get('log_file', 'logs/ai_adms.log')
        
        # Create logs directory
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
    
    def initialize_components(self) -> bool:
        """Initialize all system components"""
        try:
            self.logger.info("Initializing system components...")
            
            # Traffic capture
            capture_config = self.config.get('traffic_capture', {})
            self.packet_capture = PacketCapture(
                interface=capture_config.get('interface', 'eth0'),
                packet_count=capture_config.get('packet_count', 1000),
                timeout=capture_config.get('timeout', 30),
                filter_str=capture_config.get('filter', ''),
                buffer_size=10000
            )
            
            # Feature extractor
            anomaly_config = self.config.get('anomaly_scoring', {})
            self.feature_extractor = FeatureExtractor(
                window_size=anomaly_config.get('baseline_window', 1000),
                update_interval=1.0,
                feature_weights=anomaly_config.get('feature_weights')
            )
            
            # AI classifier
            ai_config = self.config.get('ai_classifier', {})
            self.ai_classifier = DDoSClassifier(
                model_path=ai_config.get('model_path', 'data/models/ddos_classifier.h5'),
                scaler_path=ai_config.get('scaler_path', 'data/models/feature_scaler.pkl'),
                input_dim=ai_config.get('input_dim', 14),
                hidden_layers=ai_config.get('hidden_layers', [64, 32, 16]),
                output_classes=ai_config.get('output_classes', 4),
                learning_rate=ai_config.get('learning_rate', 0.001),
                confidence_threshold=ai_config.get('confidence_threshold', 0.8)
            )
            
            # Anomaly detector
            self.anomaly_detector = AnomalyDetector(
                baseline_window=anomaly_config.get('baseline_window', 1000),
                update_frequency=anomaly_config.get('update_frequency', 100),
                anomaly_threshold=anomaly_config.get('anomaly_threshold', 0.7),
                high_anomaly_threshold=anomaly_config.get('high_anomaly_threshold', 0.9),
                feature_weights=anomaly_config.get('feature_weights')
            )
            
            # Reinforcement learning agent
            rl_config = self.config.get('rl_mitigation', {})
            self.rl_agent = QLearningAgent(
                learning_rate=rl_config.get('learning_rate', 0.1),
                discount_factor=rl_config.get('discount_factor', 0.9),
                epsilon=rl_config.get('epsilon', 0.1),
                q_table_path=rl_config.get('q_table_path', 'data/models/q_table.pkl')
            )
            
            # Mitigation actions
            self.mitigation_actions = MitigationActions(
                rate_limit_threshold=rl_config.get('rate_limit_threshold', 1000),
                blacklist_duration=rl_config.get('blacklist_duration', 300),
                syn_cookie_threshold=rl_config.get('syn_cookie_threshold', 0.8),
                max_blacklist_entries=1000
            )
            
            # Reporter
            reporting_config = self.config.get('reporting', {})
            self.reporter = SystemReporter(
                log_file=reporting_config.get('log_file', 'logs/ai_adms.log'),
                csv_log=reporting_config.get('csv_log', 'logs/traffic_analysis.csv'),
                dashboard_config=reporting_config.get('dashboard', {})
            )
            
            self.logger.info("All components initialized successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Error initializing components: {e}")
            return False
    
    def start_system(self) -> bool:
        """Start the AI-ADMS system"""
        if self.is_running:
            self.logger.warning("System is already running")
            return False
        
        if not self.initialize_components():
            return False
        
        try:
            self.logger.info("Starting AI-ADMS system...")
            
            # Start packet capture
            if not self.packet_capture.start_capture(callback=self._packet_callback):
                self.logger.error("Failed to start packet capture")
                return False
            
            # Start analysis thread
            self.analysis_thread = threading.Thread(target=self._analysis_loop, daemon=True)
            self.analysis_thread.start()
            
            # Start mitigation thread
            self.mitigation_thread = threading.Thread(target=self._mitigation_loop, daemon=True)
            self.mitigation_thread.start()
            
            # Start reporter
            self.reporter.start()
            
            self.is_running = True
            self.start_time = time.time()
            
            self.logger.info("AI-ADMS system started successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Error starting system: {e}")
            return False
    
    def stop_system(self) -> None:
        """Stop the AI-ADMS system"""
        if not self.is_running:
            return
        
        self.logger.info("Stopping AI-ADMS system...")
        
        # Stop packet capture
        if self.packet_capture:
            self.packet_capture.stop_capture()
        
        # Stop threads
        self.is_running = False
        
        # Wait for threads to finish
        if self.analysis_thread and self.analysis_thread.is_alive():
            self.analysis_thread.join(timeout=5)
        
        if self.mitigation_thread and self.mitigation_thread.is_alive():
            self.mitigation_thread.join(timeout=5)
        
        # Stop reporter
        if self.reporter:
            self.reporter.stop()
        
        # Save Q-table
        if self.rl_agent:
            self.rl_agent.save_q_table()
        
        self.logger.info("AI-ADMS system stopped")
    
    def _packet_callback(self, packet_info) -> None:
        """Callback for each captured packet"""
        try:
            # Add packet to feature extractor
            self.feature_extractor.add_packet(packet_info)
            
            # Add to anomaly detector
            self.anomaly_detector.add_feature_vector(
                self.feature_extractor.get_current_features()
            )
            
            self.total_packets_processed += 1
            
        except Exception as e:
            self.logger.error(f"Error in packet callback: {e}")
    
    def _analysis_loop(self) -> None:
        """Main analysis loop"""
        while self.is_running:
            try:
                # Get current features
                features = self.feature_extractor.get_current_features()
                
                if features:
                    # AI classification
                    classification_result = self.ai_classifier.predict(features)
                    
                    # Anomaly detection
                    anomaly_result = self.anomaly_detector.detect_anomaly(features)
                    
                    # Validate classification
                    is_valid = self.anomaly_detector.validate_classification(
                        classification_result.is_attack,
                        anomaly_result.overall_score
                    )
                    
                    # Log results
                    self.reporter.log_analysis_result(
                        features, classification_result, anomaly_result, is_valid
                    )
                    
                    # Update attack count
                    if classification_result.is_attack:
                        self.total_attacks_detected += 1
                
                time.sleep(1)  # Analysis interval
                
            except Exception as e:
                self.logger.error(f"Error in analysis loop: {e}")
                time.sleep(1)
    
    def _mitigation_loop(self) -> None:
        """Main mitigation loop"""
        while self.is_running:
            try:
                # Get current features
                features = self.feature_extractor.get_current_features()
                
                if features:
                    # Get anomaly score
                    anomaly_result = self.anomaly_detector.detect_anomaly(features)
                    
                    # Get mitigation strategy
                    state, action = self.rl_agent.get_mitigation_strategy(
                        features, anomaly_result.overall_score
                    )
                    
                    # Execute mitigation action
                    if action != "no_action":
                        mitigation_result = self.mitigation_actions.execute_action(
                            action, target_ip="192.168.1.1"  # Example target
                        )
                        
                        # Update RL agent
                        self.rl_agent.update_from_result(state, action, mitigation_result)
                        
                        # Log mitigation
                        self.reporter.log_mitigation_result(mitigation_result)
                        
                        self.total_mitigations_performed += 1
                
                time.sleep(5)  # Mitigation interval
                
            except Exception as e:
                self.logger.error(f"Error in mitigation loop: {e}")
                time.sleep(5)
    
    def get_system_stats(self) -> Dict:
        """Get current system statistics"""
        uptime = time.time() - self.start_time if self.start_time else 0
        
        stats = {
            'system_status': 'running' if self.is_running else 'stopped',
            'uptime_seconds': uptime,
            'total_packets_processed': self.total_packets_processed,
            'total_attacks_detected': self.total_attacks_detected,
            'total_mitigations_performed': self.total_mitigations_performed,
            'packets_per_second': self.total_packets_processed / max(1, uptime),
            'attack_detection_rate': self.total_attacks_detected / max(1, self.total_packets_processed),
            'mitigation_rate': self.total_mitigations_performed / max(1, self.total_attacks_detected)
        }
        
        # Add component stats
        if self.packet_capture:
            stats['packet_capture'] = self.packet_capture.get_packet_stats()
        
        if self.ai_classifier:
            stats['ai_classifier'] = self.ai_classifier.get_performance_stats()
        
        if self.anomaly_detector:
            stats['anomaly_detector'] = self.anomaly_detector.get_performance_stats()
        
        if self.rl_agent:
            stats['rl_agent'] = self.rl_agent.get_performance_stats()
        
        if self.mitigation_actions:
            stats['mitigation_actions'] = self.mitigation_actions.get_performance_stats()
        
        return stats


def signal_handler(signum, frame):
    """Handle system signals for graceful shutdown"""
    print("\nReceived signal to stop. Shutting down gracefully...")
    if hasattr(signal_handler, 'system'):
        signal_handler.system.stop_system()
    sys.exit(0)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='AI-ADMS DDoS Mitigation System')
    parser.add_argument('--config', default='config/config.yaml', 
                       help='Path to configuration file')
    parser.add_argument('--train', action='store_true',
                       help='Train the AI model before starting')
    parser.add_argument('--simulate', action='store_true',
                       help='Run in simulation mode')
    
    args = parser.parse_args()
    
    # Create system instance
    system = AIADMSSystem(args.config)
    
    # Store reference for signal handler
    signal_handler.system = system
    
    # Setup signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        # Train model if requested
        if args.train:
            print("Training AI model...")
            # TODO: Implement model training
            print("Model training completed")
        
        # Start system
        if system.start_system():
            print("AI-ADMS system is running. Press Ctrl+C to stop.")
            
            # Keep main thread alive
            while system.is_running:
                time.sleep(1)
        else:
            print("Failed to start AI-ADMS system")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\nShutting down...")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
    finally:
        system.stop_system()


if __name__ == "__main__":
    main() 