"""
Q-Learning Agent for DDoS Mitigation

This module implements a Q-learning agent that learns optimal mitigation
strategies for different types of DDoS attacks.
"""

import numpy as np
import pandas as pd
from typing import List, Dict, Tuple, Optional, Union
import logging
import time
import os
import pickle
from dataclasses import dataclass
from enum import Enum

from ..traffic_capture.feature_extractor import FeatureVector


class AttackState(Enum):
    """Enumeration of attack states"""
    NORMAL = "normal"
    LOW_ATTACK = "low_attack"
    MEDIUM_ATTACK = "medium_attack"
    HIGH_ATTACK = "high_attack"


class MitigationAction(Enum):
    """Enumeration of mitigation actions"""
    NO_ACTION = "no_action"
    RATE_LIMITING = "rate_limiting"
    BLACKLISTING = "blacklisting"
    SYN_COOKIES = "syn_cookies"
    DEEP_PACKET_INSPECTION = "deep_packet_inspection"


@dataclass
class MitigationResult:
    """Data class for mitigation action results"""
    timestamp: float
    action_taken: MitigationAction
    state: AttackState
    reward: float
    effectiveness: float
    response_time: float
    success: bool


class QLearningAgent:
    """
    Q-Learning agent for adaptive DDoS mitigation
    
    This class implements a Q-learning algorithm that learns optimal
    mitigation strategies based on the current attack state and
    historical effectiveness of different actions.
    """
    
    def __init__(self, 
                 learning_rate: float = 0.1,
                 discount_factor: float = 0.9,
                 epsilon: float = 0.1,
                 q_table_path: str = "data/models/q_table.pkl",
                 states: List[str] = None,
                 actions: List[str] = None):
        """
        Initialize the Q-learning agent
        
        Args:
            learning_rate: Learning rate (alpha)
            discount_factor: Discount factor (gamma)
            epsilon: Exploration rate
            q_table_path: Path to save/load Q-table
            states: List of possible states
            actions: List of possible actions
        """
        self.learning_rate = learning_rate
        self.discount_factor = discount_factor
        self.epsilon = epsilon
        
        # State and action spaces
        self.states = states or [state.value for state in AttackState]
        self.actions = actions or [action.value for action in MitigationAction]
        
        # Q-table initialization
        self.q_table = {}
        self._initialize_q_table()
        
        # Performance tracking
        self.total_actions = 0
        self.successful_actions = 0
        self.avg_reward = 0.0
        self.learning_history = []
        
        # Logging
        self.logger = logging.getLogger(__name__)
        
        # Load existing Q-table if available
        self._load_q_table(q_table_path)
    
    def _initialize_q_table(self) -> None:
        """Initialize Q-table with zero values"""
        for state in self.states:
            self.q_table[state] = {}
            for action in self.actions:
                self.q_table[state][action] = 0.0
    
    def _load_q_table(self, q_table_path: str) -> None:
        """Load Q-table from file"""
        try:
            if os.path.exists(q_table_path):
                with open(q_table_path, 'rb') as f:
                    loaded_q_table = pickle.load(f)
                    self.q_table.update(loaded_q_table)
                self.logger.info(f"Loaded Q-table from {q_table_path}")
        except Exception as e:
            self.logger.warning(f"Could not load Q-table: {e}")
    
    def save_q_table(self, q_table_path: str = None) -> None:
        """Save Q-table to file"""
        if q_table_path is None:
            q_table_path = "data/models/q_table.pkl"
        
        try:
            os.makedirs(os.path.dirname(q_table_path), exist_ok=True)
            with open(q_table_path, 'wb') as f:
                pickle.dump(self.q_table, f)
            self.logger.info(f"Q-table saved to {q_table_path}")
        except Exception as e:
            self.logger.error(f"Error saving Q-table: {e}")
    
    def get_state(self, feature_vector: FeatureVector, anomaly_score: float) -> str:
        """
        Determine the current state based on features and anomaly score
        
        Args:
            feature_vector: Current feature vector
            anomaly_score: Current anomaly score
            
        Returns:
            str: Current state
        """
        # Determine attack intensity based on multiple factors
        attack_intensity = 0.0
        
        # Factor 1: Anomaly score
        attack_intensity += anomaly_score * 0.4
        
        # Factor 2: Flow rate (normalized)
        flow_rate_factor = min(1.0, feature_vector.flow_rate / 1000.0)
        attack_intensity += flow_rate_factor * 0.3
        
        # Factor 3: SYN/ACK ratio
        syn_factor = min(1.0, feature_vector.syn_ack_ratio)
        attack_intensity += syn_factor * 0.2
        
        # Factor 4: Protocol distribution (UDP flood indicator)
        udp_factor = feature_vector.protocol_distribution.get('UDP', 0.0)
        attack_intensity += udp_factor * 0.1
        
        # Determine state based on intensity
        if attack_intensity < 0.3:
            return AttackState.NORMAL.value
        elif attack_intensity < 0.6:
            return AttackState.LOW_ATTACK.value
        elif attack_intensity < 0.8:
            return AttackState.MEDIUM_ATTACK.value
        else:
            return AttackState.HIGH_ATTACK.value
    
    def select_action(self, state: str, training: bool = True) -> str:
        """
        Select action using epsilon-greedy policy
        
        Args:
            state: Current state
            training: Whether in training mode
            
        Returns:
            str: Selected action
        """
        if training and np.random.random() < self.epsilon:
            # Exploration: random action
            return np.random.choice(self.actions)
        else:
            # Exploitation: best action
            return self._get_best_action(state)
    
    def _get_best_action(self, state: str) -> str:
        """Get the best action for a given state"""
        if state not in self.q_table:
            return np.random.choice(self.actions)
        
        state_q_values = self.q_table[state]
        max_q_value = max(state_q_values.values())
        
        # Get all actions with maximum Q-value
        best_actions = [
            action for action, q_value in state_q_values.items()
            if q_value == max_q_value
        ]
        
        return np.random.choice(best_actions)
    
    def update_q_value(self, 
                      state: str, 
                      action: str, 
                      reward: float, 
                      next_state: str) -> None:
        """
        Update Q-value using Q-learning update rule
        
        Args:
            state: Current state
            action: Action taken
            reward: Reward received
            next_state: Next state
        """
        if state not in self.q_table or action not in self.q_table[state]:
            return
        
        # Get current Q-value
        current_q = self.q_table[state][action]
        
        # Get maximum Q-value for next state
        if next_state in self.q_table:
            max_next_q = max(self.q_table[next_state].values())
        else:
            max_next_q = 0.0
        
        # Q-learning update rule
        new_q = current_q + self.learning_rate * (
            reward + self.discount_factor * max_next_q - current_q
        )
        
        # Update Q-table
        self.q_table[state][action] = new_q
        
        # Track learning
        self.learning_history.append({
            'timestamp': time.time(),
            'state': state,
            'action': action,
            'reward': reward,
            'next_state': next_state,
            'q_value_change': new_q - current_q
        })
    
    def calculate_reward(self, 
                        action: str, 
                        effectiveness: float, 
                        response_time: float,
                        false_positive: bool = False) -> float:
        """
        Calculate reward for an action
        
        Args:
            action: Action taken
            effectiveness: Effectiveness of the action (0-1)
            response_time: Response time in seconds
            false_positive: Whether this was a false positive
            
        Returns:
            float: Calculated reward
        """
        # Base reward from effectiveness
        reward = effectiveness * 10.0
        
        # Penalty for response time
        time_penalty = max(0, (response_time - 1.0) * 2.0)
        reward -= time_penalty
        
        # Penalty for false positives
        if false_positive:
            reward -= 5.0
        
        # Action-specific rewards/penalties
        if action == MitigationAction.NO_ACTION.value:
            if effectiveness > 0.8:  # Good decision not to act
                reward += 2.0
            else:  # Should have acted
                reward -= 3.0
        
        elif action == MitigationAction.RATE_LIMITING.value:
            if effectiveness > 0.7:
                reward += 1.0
            else:
                reward -= 1.0
        
        elif action == MitigationAction.BLACKLISTING.value:
            if effectiveness > 0.8:
                reward += 2.0
            else:
                reward -= 2.0  # More aggressive action
        
        elif action == MitigationAction.SYN_COOKIES.value:
            if effectiveness > 0.6:
                reward += 1.5
            else:
                reward -= 1.5
        
        elif action == MitigationAction.DEEP_PACKET_INSPECTION.value:
            if effectiveness > 0.9:
                reward += 3.0
            else:
                reward -= 2.0  # Resource-intensive action
        
        return reward
    
    def get_mitigation_strategy(self, 
                               feature_vector: FeatureVector,
                               anomaly_score: float,
                               training: bool = True) -> Tuple[str, str]:
        """
        Get mitigation strategy for current situation
        
        Args:
            feature_vector: Current feature vector
            anomaly_score: Current anomaly score
            training: Whether in training mode
            
        Returns:
            Tuple[str, str]: (state, action)
        """
        # Determine current state
        state = self.get_state(feature_vector, anomaly_score)
        
        # Select action
        action = self.select_action(state, training)
        
        return state, action
    
    def update_from_result(self, 
                          state: str, 
                          action: str, 
                          result: MitigationResult) -> None:
        """
        Update Q-table based on mitigation result
        
        Args:
            state: State when action was taken
            action: Action that was taken
            result: Result of the action
        """
        # Calculate reward
        reward = self.calculate_reward(
            action, 
            result.effectiveness, 
            result.response_time,
            not result.success
        )
        
        # Determine next state (simplified - could be more sophisticated)
        next_state = self._determine_next_state(state, result)
        
        # Update Q-value
        self.update_q_value(state, action, reward, next_state)
        
        # Update performance metrics
        self._update_performance_metrics(result)
    
    def _determine_next_state(self, 
                             current_state: str, 
                             result: MitigationResult) -> str:
        """Determine next state based on mitigation result"""
        # Simplified state transition logic
        if result.success and result.effectiveness > 0.8:
            # Successful mitigation - move to lower attack state
            if current_state == AttackState.HIGH_ATTACK.value:
                return AttackState.MEDIUM_ATTACK.value
            elif current_state == AttackState.MEDIUM_ATTACK.value:
                return AttackState.LOW_ATTACK.value
            elif current_state == AttackState.LOW_ATTACK.value:
                return AttackState.NORMAL.value
            else:
                return AttackState.NORMAL.value
        else:
            # Unsuccessful mitigation - stay in current state or worsen
            if result.effectiveness < 0.3:
                # Very ineffective - attack might be getting worse
                if current_state == AttackState.LOW_ATTACK.value:
                    return AttackState.MEDIUM_ATTACK.value
                elif current_state == AttackState.MEDIUM_ATTACK.value:
                    return AttackState.HIGH_ATTACK.value
                else:
                    return current_state
            else:
                return current_state
    
    def _update_performance_metrics(self, result: MitigationResult) -> None:
        """Update performance tracking metrics"""
        self.total_actions += 1
        
        if result.success:
            self.successful_actions += 1
        
        # Update average reward
        if self.total_actions == 1:
            self.avg_reward = result.reward
        else:
            self.avg_reward = (
                (self.avg_reward * (self.total_actions - 1) + result.reward) / 
                self.total_actions
            )
    
    def get_performance_stats(self) -> Dict:
        """Get current performance statistics"""
        return {
            'total_actions': self.total_actions,
            'successful_actions': self.successful_actions,
            'success_rate': self.successful_actions / max(1, self.total_actions),
            'average_reward': self.avg_reward,
            'learning_rate': self.learning_rate,
            'discount_factor': self.discount_factor,
            'epsilon': self.epsilon,
            'q_table_size': len(self.q_table)
        }
    
    def get_q_table_summary(self) -> Dict:
        """Get summary of Q-table"""
        summary = {}
        
        for state in self.states:
            if state in self.q_table:
                state_q_values = self.q_table[state]
                best_action = max(state_q_values, key=state_q_values.get)
                best_value = state_q_values[best_action]
                
                summary[state] = {
                    'best_action': best_action,
                    'best_value': best_value,
                    'action_count': len(state_q_values)
                }
        
        return summary
    
    def decay_epsilon(self, decay_rate: float = 0.99) -> None:
        """Decay exploration rate"""
        self.epsilon *= decay_rate
        self.epsilon = max(0.01, self.epsilon)  # Minimum epsilon
    
    def reset_learning_history(self) -> None:
        """Reset learning history"""
        self.learning_history = []
        self.logger.info("Learning history reset")
    
    def export_learning_data(self, filepath: str) -> None:
        """Export learning history to CSV"""
        try:
            df = pd.DataFrame(self.learning_history)
            df.to_csv(filepath, index=False)
            self.logger.info(f"Learning data exported to {filepath}")
        except Exception as e:
            self.logger.error(f"Error exporting learning data: {e}") 