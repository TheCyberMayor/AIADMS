"""
AI Classifier Module for AI-ADMS

This module provides AI-based DDoS attack detection and classification using
deep learning models.
"""

from .ddos_classifier import DDoSClassifier
from .model_trainer import ModelTrainer

__all__ = ['DDoSClassifier', 'ModelTrainer'] 