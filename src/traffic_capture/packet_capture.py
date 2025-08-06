"""
Packet Capture Module for AI-ADMS

This module provides real-time network packet capture functionality using Scapy.
It captures packets from specified network interfaces and provides them for analysis.
"""

import time
import threading
from collections import deque
from typing import List, Dict, Optional, Callable
import logging

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    from scapy.layers.inet import IP
except ImportError:
    print("Warning: Scapy not available. Install with: pip install scapy")
    IP = TCP = UDP = ICMP = None

import psutil
import numpy as np
from dataclasses import dataclass
from datetime import datetime


@dataclass
class PacketInfo:
    """Data class to store packet information"""
    timestamp: float
    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    protocol: str
    packet_size: int
    ttl: int
    flags: str
    payload_length: int


class PacketCapture:
    """
    Real-time packet capture and analysis class
    
    This class provides functionality to capture network packets from a specified
    interface, extract relevant features, and maintain a rolling buffer of recent
    packets for analysis.
    """
    
    def __init__(self, 
                 interface: str = "eth0",
                 packet_count: int = 1000,
                 timeout: int = 30,
                 filter_str: str = "",
                 buffer_size: int = 10000):
        """
        Initialize the packet capture system
        
        Args:
            interface: Network interface to capture from
            packet_count: Number of packets to capture per batch
            timeout: Capture timeout in seconds
            filter_str: BPF filter string
            buffer_size: Size of packet buffer
        """
        self.interface = interface
        self.packet_count = packet_count
        self.timeout = timeout
        self.filter_str = filter_str
        self.buffer_size = buffer_size
        
        # Packet storage
        self.packet_buffer = deque(maxlen=buffer_size)
        self.packet_stats = {
            'total_packets': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'icmp_packets': 0,
            'other_packets': 0,
            'bytes_captured': 0
        }
        
        # Threading
        self.capture_thread = None
        self.is_capturing = False
        self.callback = None
        
        # Logging
        self.logger = logging.getLogger(__name__)
        
        # Performance tracking
        self.start_time = None
        self.capture_rate = 0.0
        
    def start_capture(self, callback: Optional[Callable] = None) -> bool:
        """
        Start packet capture in a separate thread
        
        Args:
            callback: Optional callback function for each packet
            
        Returns:
            bool: True if capture started successfully
        """
        if self.is_capturing:
            self.logger.warning("Packet capture already running")
            return False
            
        if not self._check_interface():
            self.logger.error(f"Interface {self.interface} not available")
            return False
            
        self.callback = callback
        self.is_capturing = True
        self.start_time = time.time()
        
        self.capture_thread = threading.Thread(
            target=self._capture_loop,
            daemon=True
        )
        self.capture_thread.start()
        
        self.logger.info(f"Started packet capture on interface {self.interface}")
        return True
    
    def stop_capture(self) -> None:
        """Stop packet capture"""
        self.is_capturing = False
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=5)
        self.logger.info("Stopped packet capture")
    
    def _capture_loop(self) -> None:
        """Main capture loop"""
        try:
            while self.is_capturing:
                # Capture packets using Scapy
                packets = sniff(
                    iface=self.interface,
                    count=self.packet_count,
                    timeout=self.timeout,
                    filter=self.filter_str,
                    store=False,
                    prn=self._process_packet
                )
                
                # Update capture rate
                if self.start_time:
                    elapsed = time.time() - self.start_time
                    self.capture_rate = self.packet_stats['total_packets'] / elapsed
                    
        except Exception as e:
            self.logger.error(f"Error in capture loop: {e}")
            self.is_capturing = False
    
    def _process_packet(self, packet) -> None:
        """Process individual packet and extract features"""
        try:
            packet_info = self._extract_packet_info(packet)
            if packet_info:
                self.packet_buffer.append(packet_info)
                self._update_stats(packet_info)
                
                # Call callback if provided
                if self.callback:
                    self.callback(packet_info)
                    
        except Exception as e:
            self.logger.error(f"Error processing packet: {e}")
    
    def _extract_packet_info(self, packet) -> Optional[PacketInfo]:
        """Extract relevant information from a packet"""
        try:
            # Basic packet info
            timestamp = time.time()
            packet_size = len(packet)
            
            # IP layer
            if IP in packet:
                ip_layer = packet[IP]
                source_ip = ip_layer.src
                dest_ip = ip_layer.dst
                ttl = ip_layer.ttl
                protocol = ip_layer.proto
                
                # TCP layer
                if TCP in packet:
                    tcp_layer = packet[TCP]
                    source_port = tcp_layer.sport
                    dest_port = tcp_layer.dport
                    flags = str(tcp_layer.flags)
                    protocol_name = "TCP"
                    
                # UDP layer
                elif UDP in packet:
                    udp_layer = packet[UDP]
                    source_port = udp_layer.sport
                    dest_port = udp_layer.dport
                    flags = ""
                    protocol_name = "UDP"
                    
                # ICMP layer
                elif ICMP in packet:
                    source_port = 0
                    dest_port = 0
                    flags = ""
                    protocol_name = "ICMP"
                    
                else:
                    source_port = 0
                    dest_port = 0
                    flags = ""
                    protocol_name = "OTHER"
                
                # Payload length
                payload_length = len(packet.payload) if hasattr(packet, 'payload') else 0
                
                return PacketInfo(
                    timestamp=timestamp,
                    source_ip=source_ip,
                    dest_ip=dest_ip,
                    source_port=source_port,
                    dest_port=dest_port,
                    protocol=protocol_name,
                    packet_size=packet_size,
                    ttl=ttl,
                    flags=flags,
                    payload_length=payload_length
                )
                
        except Exception as e:
            self.logger.error(f"Error extracting packet info: {e}")
            return None
    
    def _update_stats(self, packet_info: PacketInfo) -> None:
        """Update packet statistics"""
        self.packet_stats['total_packets'] += 1
        self.packet_stats['bytes_captured'] += packet_info.packet_size
        
        if packet_info.protocol == "TCP":
            self.packet_stats['tcp_packets'] += 1
        elif packet_info.protocol == "UDP":
            self.packet_stats['udp_packets'] += 1
        elif packet_info.protocol == "ICMP":
            self.packet_stats['icmp_packets'] += 1
        else:
            self.packet_stats['other_packets'] += 1
    
    def _check_interface(self) -> bool:
        """Check if the specified interface exists"""
        try:
            interfaces = psutil.net_if_addrs()
            return self.interface in interfaces
        except Exception:
            return False
    
    def get_recent_packets(self, count: int = 100) -> List[PacketInfo]:
        """Get the most recent packets from buffer"""
        return list(self.packet_buffer)[-count:]
    
    def get_packet_stats(self) -> Dict:
        """Get current packet statistics"""
        stats = self.packet_stats.copy()
        stats['capture_rate'] = self.capture_rate
        stats['buffer_size'] = len(self.packet_buffer)
        stats['uptime'] = time.time() - self.start_time if self.start_time else 0
        return stats
    
    def clear_buffer(self) -> None:
        """Clear the packet buffer"""
        self.packet_buffer.clear()
        self.logger.info("Packet buffer cleared")
    
    def get_flow_statistics(self, window_seconds: int = 60) -> Dict:
        """Calculate flow statistics for the specified time window"""
        current_time = time.time()
        window_start = current_time - window_seconds
        
        # Filter packets in time window
        recent_packets = [
            p for p in self.packet_buffer 
            if p.timestamp >= window_start
        ]
        
        if not recent_packets:
            return {}
        
        # Calculate flow statistics
        flow_stats = {
            'total_flows': len(set((p.source_ip, p.dest_ip, p.source_port, p.dest_port) 
                                 for p in recent_packets)),
            'packets_per_second': len(recent_packets) / window_seconds,
            'bytes_per_second': sum(p.packet_size for p in recent_packets) / window_seconds,
            'avg_packet_size': np.mean([p.packet_size for p in recent_packets]),
            'protocol_distribution': {}
        }
        
        # Protocol distribution
        protocols = [p.protocol for p in recent_packets]
        for protocol in set(protocols):
            flow_stats['protocol_distribution'][protocol] = protocols.count(protocol)
        
        return flow_stats 