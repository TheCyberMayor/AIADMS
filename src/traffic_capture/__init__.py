"""
Traffic Capture Module for AI-ADMS

This module handles packet capture and feature extraction from network traffic.
"""

from .packet_capture import PacketCapture
from .feature_extractor import FeatureExtractor

__all__ = ['PacketCapture', 'FeatureExtractor'] 