#!/usr/bin/env python3
"""
Model Training Script for AI-ADMS

This script trains the DDoS classifier model using synthetic data
and saves the trained model for use in the main system.
"""

import os
import sys
import logging
from pathlib import Path

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from src.ai_classifier import ModelTrainer, DDoSClassifier


def setup_logging():
    """Setup logging configuration"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('logs/training.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )


def main():
    """Main training function"""
    print("AI-ADMS Model Training")
    print("=" * 50)
    
    # Setup logging
    setup_logging()
    logger = logging.getLogger(__name__)
    
    try:
        # Create trainer
        trainer = ModelTrainer(
            data_dir="data/training",
            model_dir="data/models",
            test_size=0.2,
            random_state=42
        )
        
        print("1. Generating synthetic training data...")
        features, labels = trainer.generate_synthetic_data(
            num_samples=10000,
            attack_ratio=0.3
        )
        
        print(f"   Generated {len(features)} samples")
        print(f"   Features shape: {features.shape}")
        print(f"   Label distribution: {dict(zip(*np.unique(labels, return_counts=True)))}")
        
        # Save training data
        print("2. Saving training data...")
        trainer.save_training_data(features, labels, "training_data.csv")
        
        # Train model
        print("3. Training AI model...")
        classifier = trainer.train_model(features, labels)
        
        # Evaluate model
        print("4. Evaluating model...")
        X_train, X_test, y_train, y_test = train_test_split(
            features, labels, test_size=0.2, random_state=42, stratify=labels
        )
        
        metrics = classifier.evaluate(X_test, y_test)
        
        print("5. Training Results:")
        print(f"   Test Accuracy: {metrics['accuracy']:.4f}")
        print(f"   Classification Report:")
        print(metrics['classification_report'])
        
        # Save training plots
        print("6. Saving training plots...")
        history = classifier.get_performance_stats()
        trainer.plot_training_history(history, "logs/training_history.png")
        trainer.plot_confusion_matrix(
            y_test, metrics['predictions'], "logs/confusion_matrix.png"
        )
        
        print("7. Model training completed successfully!")
        print(f"   Model saved to: {classifier.model_path}")
        print(f"   Scaler saved to: {classifier.scaler_path}")
        
    except Exception as e:
        logger.error(f"Training failed: {e}")
        print(f"Error: {e}")
        return False
    
    return True


if __name__ == "__main__":
    import numpy as np
    from sklearn.model_selection import train_test_split
    
    success = main()
    sys.exit(0 if success else 1) 