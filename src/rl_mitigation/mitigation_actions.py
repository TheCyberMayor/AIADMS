"""
Mitigation Actions Module for AI-ADMS

This module implements various DDoS mitigation strategies including
rate limiting, blacklisting, SYN cookies, and deep packet inspection.
"""

import time
import threading
from typing import List, Dict, Tuple, Optional, Set
import logging
from dataclasses import dataclass
from collections import defaultdict, deque
import ipaddress

from .q_learning_agent import MitigationAction, MitigationResult


@dataclass
class RateLimitRule:
    """Data class for rate limiting rules"""
    source_ip: str
    max_packets_per_second: int
    current_packets: int
    window_start: float
    is_active: bool


@dataclass
class BlacklistEntry:
    """Data class for blacklist entries"""
    ip_address: str
    timestamp: float
    reason: str
    duration: float  # Duration in seconds, 0 for permanent
    is_active: bool


class MitigationActions:
    """
    Implementation of various DDoS mitigation strategies
    
    This class provides concrete implementations of mitigation actions
    that can be executed by the reinforcement learning agent.
    """
    
    def __init__(self, 
                 rate_limit_threshold: int = 1000,
                 blacklist_duration: float = 300.0,
                 syn_cookie_threshold: float = 0.8,
                 max_blacklist_entries: int = 1000):
        """
        Initialize mitigation actions
        
        Args:
            rate_limit_threshold: Default packets per second threshold
            blacklist_duration: Default blacklist duration in seconds
            syn_cookie_threshold: Threshold for SYN cookie activation
            max_blacklist_entries: Maximum number of blacklist entries
        """
        self.rate_limit_threshold = rate_limit_threshold
        self.blacklist_duration = blacklist_duration
        self.syn_cookie_threshold = syn_cookie_threshold
        self.max_blacklist_entries = max_blacklist_entries
        
        # Rate limiting
        self.rate_limit_rules: Dict[str, RateLimitRule] = {}
        self.rate_limit_lock = threading.Lock()
        
        # Blacklisting
        self.blacklist: Dict[str, BlacklistEntry] = {}
        self.blacklist_lock = threading.Lock()
        
        # SYN cookies
        self.syn_cookies_enabled = False
        self.syn_cookie_stats = {
            'total_requests': 0,
            'challenge_responses': 0,
            'successful_connections': 0
        }
        
        # Deep packet inspection
        self.dpi_enabled = False
        self.dpi_patterns = {
            'http_flood': [b'GET', b'POST', b'HTTP/1.1'],
            'slowloris': [b'X-a:', b'X-b:', b'X-c:'],
            'udp_flood': [b'\x00' * 100]  # Large UDP packets
        }
        
        # Performance tracking
        self.action_count = 0
        self.successful_actions = 0
        self.avg_response_time = 0.0
        
        # Logging
        self.logger = logging.getLogger(__name__)
        
        # Start cleanup thread
        self._start_cleanup_thread()
    
    def execute_action(self, 
                      action: MitigationAction, 
                      target_ip: str = None,
                      parameters: Dict = None) -> MitigationResult:
        """
        Execute a mitigation action
        
        Args:
            action: Action to execute
            target_ip: Target IP address (if applicable)
            parameters: Additional parameters for the action
            
        Returns:
            MitigationResult: Result of the action
        """
        start_time = time.time()
        
        try:
            if action == MitigationAction.NO_ACTION:
                result = self._no_action()
            elif action == MitigationAction.RATE_LIMITING:
                result = self._rate_limiting(target_ip, parameters)
            elif action == MitigationAction.BLACKLISTING:
                result = self._blacklisting(target_ip, parameters)
            elif action == MitigationAction.SYN_COOKIES:
                result = self._syn_cookies(parameters)
            elif action == MitigationAction.DEEP_PACKET_INSPECTION:
                result = self._deep_packet_inspection(parameters)
            else:
                result = MitigationResult(
                    timestamp=time.time(),
                    action_taken=action,
                    state="unknown",
                    reward=-1.0,
                    effectiveness=0.0,
                    response_time=time.time() - start_time,
                    success=False
                )
            
            # Update performance metrics
            self._update_performance_metrics(result)
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error executing action {action}: {e}")
            return MitigationResult(
                timestamp=time.time(),
                action_taken=action,
                state="error",
                reward=-5.0,
                effectiveness=0.0,
                response_time=time.time() - start_time,
                success=False
            )
    
    def _no_action(self) -> MitigationResult:
        """Execute no action (monitoring only)"""
        return MitigationResult(
            timestamp=time.time(),
            action_taken=MitigationAction.NO_ACTION,
            state="normal",
            reward=0.0,
            effectiveness=1.0,  # No action is 100% effective when no action is needed
            response_time=0.001,
            success=True
        )
    
    def _rate_limiting(self, target_ip: str, parameters: Dict = None) -> MitigationResult:
        """Implement rate limiting for a specific IP"""
        if not target_ip:
            return MitigationResult(
                timestamp=time.time(),
                action_taken=MitigationAction.RATE_LIMITING,
                state="error",
                reward=-1.0,
                effectiveness=0.0,
                response_time=0.001,
                success=False
            )
        
        # Get parameters
        threshold = parameters.get('threshold', self.rate_limit_threshold) if parameters else self.rate_limit_threshold
        
        with self.rate_limit_lock:
            current_time = time.time()
            
            # Check if rule exists
            if target_ip in self.rate_limit_rules:
                rule = self.rate_limit_rules[target_ip]
                
                # Reset window if needed
                if current_time - rule.window_start >= 1.0:
                    rule.current_packets = 0
                    rule.window_start = current_time
                
                # Increment packet count
                rule.current_packets += 1
                
                # Check if rate limit exceeded
                if rule.current_packets > threshold:
                    rule.is_active = True
                    effectiveness = 0.8  # Rate limiting is moderately effective
                else:
                    rule.is_active = False
                    effectiveness = 0.9  # Rate limiting working well
            else:
                # Create new rule
                rule = RateLimitRule(
                    source_ip=target_ip,
                    max_packets_per_second=threshold,
                    current_packets=1,
                    window_start=current_time,
                    is_active=False
                )
                self.rate_limit_rules[target_ip] = rule
                effectiveness = 0.7  # New rule created
        
        return MitigationResult(
            timestamp=time.time(),
            action_taken=MitigationAction.RATE_LIMITING,
            state="rate_limited" if rule.is_active else "normal",
            reward=effectiveness * 2.0,
            effectiveness=effectiveness,
            response_time=0.005,
            success=True
        )
    
    def _blacklisting(self, target_ip: str, parameters: Dict = None) -> MitigationResult:
        """Implement IP blacklisting"""
        if not target_ip:
            return MitigationResult(
                timestamp=time.time(),
                action_taken=MitigationAction.BLACKLISTING,
                state="error",
                reward=-1.0,
                effectiveness=0.0,
                response_time=0.001,
                success=False
            )
        
        # Get parameters
        duration = parameters.get('duration', self.blacklist_duration) if parameters else self.blacklist_duration
        reason = parameters.get('reason', 'DDoS attack detected') if parameters else 'DDoS attack detected'
        
        with self.blacklist_lock:
            current_time = time.time()
            
            # Check if already blacklisted
            if target_ip in self.blacklist:
                entry = self.blacklist[target_ip]
                if entry.is_active:
                    effectiveness = 0.9  # Already blacklisted
                else:
                    # Reactivate blacklist
                    entry.timestamp = current_time
                    entry.duration = duration
                    entry.is_active = True
                    effectiveness = 0.8  # Reactivated
            else:
                # Add to blacklist
                if len(self.blacklist) >= self.max_blacklist_entries:
                    # Remove oldest entry
                    oldest_ip = min(self.blacklist.keys(), 
                                  key=lambda ip: self.blacklist[ip].timestamp)
                    del self.blacklist[oldest_ip]
                
                entry = BlacklistEntry(
                    ip_address=target_ip,
                    timestamp=current_time,
                    reason=reason,
                    duration=duration,
                    is_active=True
                )
                self.blacklist[target_ip] = entry
                effectiveness = 0.95  # New blacklist entry
        
        return MitigationResult(
            timestamp=time.time(),
            action_taken=MitigationAction.BLACKLISTING,
            state="blacklisted",
            reward=effectiveness * 3.0,
            effectiveness=effectiveness,
            response_time=0.01,
            success=True
        )
    
    def _syn_cookies(self, parameters: Dict = None) -> MitigationResult:
        """Implement SYN cookie protection"""
        current_time = time.time()
        
        # Enable SYN cookies
        if not self.syn_cookies_enabled:
            self.syn_cookies_enabled = True
            self.logger.info("SYN cookies enabled")
        
        # Update statistics
        self.syn_cookie_stats['total_requests'] += 1
        
        # Simulate SYN cookie effectiveness
        # In a real implementation, this would involve actual TCP handling
        if parameters and 'syn_ratio' in parameters:
            syn_ratio = parameters['syn_ratio']
            if syn_ratio > self.syn_cookie_threshold:
                effectiveness = 0.85  # SYN cookies very effective against SYN floods
                self.syn_cookie_stats['challenge_responses'] += 1
            else:
                effectiveness = 0.6  # Less effective when SYN ratio is low
        else:
            effectiveness = 0.7  # Default effectiveness
        
        return MitigationResult(
            timestamp=current_time,
            action_taken=MitigationAction.SYN_COOKIES,
            state="syn_cookies_active",
            reward=effectiveness * 2.5,
            effectiveness=effectiveness,
            response_time=0.02,
            success=True
        )
    
    def _deep_packet_inspection(self, parameters: Dict = None) -> MitigationResult:
        """Implement deep packet inspection"""
        current_time = time.time()
        
        # Enable DPI
        if not self.dpi_enabled:
            self.dpi_enabled = True
            self.logger.info("Deep packet inspection enabled")
        
        # Simulate DPI effectiveness based on attack patterns
        effectiveness = 0.6  # Base effectiveness
        
        if parameters and 'attack_type' in parameters:
            attack_type = parameters['attack_type']
            if attack_type in self.dpi_patterns:
                effectiveness = 0.9  # DPI very effective against known patterns
            else:
                effectiveness = 0.7  # Moderate effectiveness for unknown patterns
        
        # DPI is resource-intensive but very effective
        return MitigationResult(
            timestamp=current_time,
            action_taken=MitigationAction.DEEP_PACKET_INSPECTION,
            state="dpi_active",
            reward=effectiveness * 3.0 - 1.0,  # High reward but resource cost
            effectiveness=effectiveness,
            response_time=0.05,  # Slower response time due to inspection
            success=True
        )
    
    def check_rate_limit(self, source_ip: str) -> bool:
        """Check if an IP is currently rate limited"""
        with self.rate_limit_lock:
            if source_ip in self.rate_limit_rules:
                rule = self.rate_limit_rules[source_ip]
                return rule.is_active
        return False
    
    def is_blacklisted(self, ip_address: str) -> bool:
        """Check if an IP is blacklisted"""
        with self.blacklist_lock:
            if ip_address in self.blacklist:
                entry = self.blacklist[ip_address]
                # Check if blacklist entry is still active
                if entry.duration > 0:
                    if time.time() - entry.timestamp > entry.duration:
                        entry.is_active = False
                        return False
                return entry.is_active
        return False
    
    def remove_from_blacklist(self, ip_address: str) -> bool:
        """Remove an IP from blacklist"""
        with self.blacklist_lock:
            if ip_address in self.blacklist:
                del self.blacklist[ip_address]
                self.logger.info(f"Removed {ip_address} from blacklist")
                return True
        return False
    
    def get_blacklist_summary(self) -> Dict:
        """Get summary of blacklist entries"""
        with self.blacklist_lock:
            active_count = sum(1 for entry in self.blacklist.values() if entry.is_active)
            return {
                'total_entries': len(self.blacklist),
                'active_entries': active_count,
                'max_entries': self.max_blacklist_entries
            }
    
    def get_rate_limit_summary(self) -> Dict:
        """Get summary of rate limiting rules"""
        with self.rate_limit_lock:
            active_count = sum(1 for rule in self.rate_limit_rules.values() if rule.is_active)
            return {
                'total_rules': len(self.rate_limit_rules),
                'active_rules': active_count
            }
    
    def _update_performance_metrics(self, result: MitigationResult) -> None:
        """Update performance tracking metrics"""
        self.action_count += 1
        
        if result.success:
            self.successful_actions += 1
        
        # Update average response time
        if self.action_count == 1:
            self.avg_response_time = result.response_time
        else:
            self.avg_response_time = (
                (self.avg_response_time * (self.action_count - 1) + result.response_time) / 
                self.action_count
            )
    
    def _start_cleanup_thread(self) -> None:
        """Start background thread for cleanup tasks"""
        def cleanup_worker():
            while True:
                try:
                    time.sleep(60)  # Run every minute
                    self._cleanup_expired_entries()
                except Exception as e:
                    self.logger.error(f"Error in cleanup thread: {e}")
        
        cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
        cleanup_thread.start()
    
    def _cleanup_expired_entries(self) -> None:
        """Clean up expired blacklist entries and rate limit rules"""
        current_time = time.time()
        
        # Clean up expired blacklist entries
        with self.blacklist_lock:
            expired_ips = []
            for ip, entry in self.blacklist.items():
                if entry.duration > 0 and current_time - entry.timestamp > entry.duration:
                    expired_ips.append(ip)
            
            for ip in expired_ips:
                del self.blacklist[ip]
        
        # Clean up old rate limit rules (older than 1 hour)
        with self.rate_limit_lock:
            expired_rules = []
            for ip, rule in self.rate_limit_rules.items():
                if current_time - rule.window_start > 3600:  # 1 hour
                    expired_rules.append(ip)
            
            for ip in expired_rules:
                del self.rate_limit_rules[ip]
        
        if expired_ips or expired_rules:
            self.logger.info(f"Cleaned up {len(expired_ips)} blacklist entries and {len(expired_rules)} rate limit rules")
    
    def get_performance_stats(self) -> Dict:
        """Get current performance statistics"""
        return {
            'total_actions': self.action_count,
            'successful_actions': self.successful_actions,
            'success_rate': self.successful_actions / max(1, self.action_count),
            'average_response_time': self.avg_response_time,
            'syn_cookies_enabled': self.syn_cookies_enabled,
            'dpi_enabled': self.dpi_enabled,
            'blacklist_summary': self.get_blacklist_summary(),
            'rate_limit_summary': self.get_rate_limit_summary()
        }
    
    def reset_mitigation_state(self) -> None:
        """Reset all mitigation state"""
        with self.rate_limit_lock:
            self.rate_limit_rules.clear()
        
        with self.blacklist_lock:
            self.blacklist.clear()
        
        self.syn_cookies_enabled = False
        self.dpi_enabled = False
        
        self.logger.info("Mitigation state reset") 