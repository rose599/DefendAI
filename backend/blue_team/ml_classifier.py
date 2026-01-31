import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import pickle
import time
from typing import Dict, List, Tuple
from .feature_engineering import FeatureEngineer

class MLClassifier:
    """Machine Learning based intrusion detection system"""
    
    def __init__(self):
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            n_jobs=-1
        )
        self.feature_engineer = FeatureEngineer()
        self.is_trained = False
        self.metrics = {}
        
    def train(self, logs: List[Dict]) -> Dict:
        """Train the ML model on labeled logs"""
        if len(logs) < 10:
            return {'error': 'Insufficient training data. Need at least 10 logs.'}
        
        X = self.feature_engineer.extract_features(logs)
        y = self.feature_engineer.extract_labels(logs)
        
        if len(X) == 0 or len(y) == 0:
            return {'error': 'Failed to extract features or labels'}
        
        if len(np.unique(y)) < 2:
            return {'error': 'Need both normal and malicious samples for training'}
        
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        start_time = time.time()
        self.model.fit(X_train, y_train)
        training_time = time.time() - start_time
        
        y_pred = self.model.predict(X_test)
        
        self.metrics = {
            'accuracy': float(accuracy_score(y_test, y_pred)),
            'precision': float(precision_score(y_test, y_pred, zero_division=0)),
            'recall': float(recall_score(y_test, y_pred, zero_division=0)),
            'f1_score': float(f1_score(y_test, y_pred, zero_division=0)),
            'training_time': training_time,
            'training_samples': len(X_train),
            'test_samples': len(X_test)
        }
        
        self.is_trained = True
        
        return self.metrics
    
    def predict(self, logs: List[Dict]) -> Tuple[List[int], List[float], float]:
        """Predict whether logs are malicious"""
        if not self.is_trained:
            raise ValueError('Model is not trained yet')
        
        X = self.feature_engineer.extract_features(logs)
        
        if len(X) == 0:
            return [], [], 0.0
        
        start_time = time.time()
        predictions = self.model.predict(X)
        probabilities = self.model.predict_proba(X)[:, 1]
        detection_latency = (time.time() - start_time) / len(X)
        
        return predictions.tolist(), probabilities.tolist(), detection_latency
    
    def get_metrics(self) -> Dict:
        """Get current model metrics"""
        return self.metrics if self.is_trained else {'error': 'Model not trained'}
    
    def save_model(self, filepath: str):
        """Save trained model to file"""
        with open(filepath, 'wb') as f:
            pickle.dump(self.model, f)
    
    def load_model(self, filepath: str):
        """Load trained model from file"""
        with open(filepath, 'rb') as f:
            self.model = pickle.load(f)
        self.is_trained = True
