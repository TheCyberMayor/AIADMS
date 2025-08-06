#!/usr/bin/env python3
"""
System Test Script for AI-ADMS

This script tests the various components of the AI-ADMS system
to ensure they are working correctly.
"""

import os
import sys
import time
import logging
from pathlib import Path

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from src.traffic_capture import FeatureExtractor
from src.ai_classifier import DDoSClassifier
from src.anomaly_scoring import AnomalyDetector
from src.rl_mitigation import QLearningAgent, MitigationActions


def setup_logging():
    """Setup logging configuration"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('logs/test.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )


def test_feature_extractor():
    """Test feature extractor"""
    print("Testing Feature Extractor...")
    
    try:
        extractor = FeatureExtractor()
        
        # Test with empty packet list
        features = extractor.extract_features([])
        assert features is not None
        print("  ✓ Empty packet list handling")
        
        # Test feature normalization
        normalized = extractor.normalize_features(features)
        assert normalized.shape[0] == 14  # Expected feature count
        print("  ✓ Feature normalization")
        
        print("  ✓ Feature extractor test passed")
        return True
        
    except Exception as e:
        print(f"  ✗ Feature extractor test failed: {e}")
        return False


def test_ai_classifier():
    """Test AI classifier"""
    print("Testing AI Classifier...")
    
    try:
        classifier = DDoSClassifier()
        
        # Test model creation
        assert classifier.model is not None
        print("  ✓ Model initialization")
        
        # Test with dummy features
        dummy_features = [0.0] * 14
        result = classifier.predict(dummy_features)
        assert result is not None
        assert hasattr(result, 'predicted_class')
        assert hasattr(result, 'confidence')
        print("  ✓ Prediction with dummy features")
        
        print("  ✓ AI classifier test passed")
        return True
        
    except Exception as e:
        print(f"  ✗ AI classifier test failed: {e}")
        return False


def test_anomaly_detector():
    """Test anomaly detector"""
    print("Testing Anomaly Detector...")
    
    try:
        detector = AnomalyDetector()
        
        # Test with empty feature vector
        from src.traffic_capture.feature_extractor import FeatureVector
        
        empty_features = FeatureVector(
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
        
        result = detector.detect_anomaly(empty_features)
        assert result is not None
        assert hasattr(result, 'overall_score')
        assert hasattr(result, 'is_anomalous')
        print("  ✓ Anomaly detection with empty features")
        
        print("  ✓ Anomaly detector test passed")
        return True
        
    except Exception as e:
        print(f"  ✗ Anomaly detector test failed: {e}")
        return False


def test_rl_agent():
    """Test reinforcement learning agent"""
    print("Testing RL Agent...")
    
    try:
        agent = QLearningAgent()
        
        # Test state determination
        from src.traffic_capture.feature_extractor import FeatureVector
        
        test_features = FeatureVector(
            timestamp=time.time(),
            packet_size_mean=1000.0,
            packet_size_std=100.0,
            flow_rate=50.0,
            syn_ack_ratio=0.1,
            protocol_distribution={'TCP': 0.8, 'UDP': 0.1, 'ICMP': 0.05, 'OTHER': 0.05},
            ttl_mean=64.0,
            ttl_std=2.0,
            payload_length_mean=800.0,
            payload_length_std=150.0,
            unique_sources=5,
            unique_destinations=3,
            port_entropy=2.5,
            ip_entropy=2.0
        )
        
        state = agent.get_state(test_features, 0.5)
        assert state in ['normal', 'low_attack', 'medium_attack', 'high_attack']
        print("  ✓ State determination")
        
        # Test action selection
        action = agent.select_action(state, training=True)
        assert action in ['no_action', 'rate_limiting', 'blacklisting', 'syn_cookies', 'deep_packet_inspection']
        print("  ✓ Action selection")
        
        print("  ✓ RL agent test passed")
        return True
        
    except Exception as e:
        print(f"  ✗ RL agent test failed: {e}")
        return False


def test_mitigation_actions():
    """Test mitigation actions"""
    print("Testing Mitigation Actions...")
    
    try:
        actions = MitigationActions()
        
        # Test rate limiting
        result = actions.execute_action('rate_limiting', target_ip='192.168.1.100')
        assert result is not None
        assert hasattr(result, 'success')
        print("  ✓ Rate limiting action")
        
        # Test blacklisting
        result = actions.execute_action('blacklisting', target_ip='192.168.1.101')
        assert result is not None
        assert hasattr(result, 'success')
        print("  ✓ Blacklisting action")
        
        # Test blacklist checking
        is_blacklisted = actions.is_blacklisted('192.168.1.101')
        assert isinstance(is_blacklisted, bool)
        print("  ✓ Blacklist checking")
        
        print("  ✓ Mitigation actions test passed")
        return True
        
    except Exception as e:
        print(f"  ✗ Mitigation actions test failed: {e}")
        return False


def main():
    """Main test function"""
    print("AI-ADMS System Tests")
    print("=" * 50)
    
    # Setup logging
    setup_logging()
    
    # Run tests
    tests = [
        test_feature_extractor,
        test_ai_classifier,
        test_anomaly_detector,
        test_rl_agent,
        test_mitigation_actions
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
        print()
    
    # Summary
    print("Test Summary")
    print("=" * 50)
    print(f"Passed: {passed}/{total}")
    print(f"Success Rate: {(passed/total)*100:.1f}%")
    
    if passed == total:
        print("✓ All tests passed! System is ready to use.")
        return True
    else:
        print("✗ Some tests failed. Please check the errors above.")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 