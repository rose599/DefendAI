import numpy as np
import pandas as pd
from typing import List, Dict

class FeatureEngineer:
    """Extract and engineer features from network logs"""
    
    FEATURE_COLUMNS = [
        'packet_size',
        'login_attempts',
        'flow_duration',
        'packets_per_second',
        'protocol_TCP',
        'protocol_UDP',
        'protocol_ICMP',
        'protocol_HTTP',
        'protocol_HTTPS',
        'port_22',
        'port_80',
        'port_443',
        'port_other'
    ]
    
    def extract_features(self, logs: List[Dict]) -> pd.DataFrame:
        """Extract features from logs for ML model"""
        df = pd.DataFrame(logs)
        
        if df.empty:
            return pd.DataFrame(columns=self.FEATURE_COLUMNS)
        
        features = pd.DataFrame()
        
        features['packet_size'] = df['packet_size']
        features['login_attempts'] = df['login_attempts']
        features['flow_duration'] = df['flow_duration']
        features['packets_per_second'] = df['packets_per_second']
        
        features['protocol_TCP'] = (df['protocol'] == 'TCP').astype(int)
        features['protocol_UDP'] = (df['protocol'] == 'UDP').astype(int)
        features['protocol_ICMP'] = (df['protocol'] == 'ICMP').astype(int)
        features['protocol_HTTP'] = (df['protocol'] == 'HTTP').astype(int)
        features['protocol_HTTPS'] = (df['protocol'] == 'HTTPS').astype(int)
        
        features['port_22'] = (df['port'] == 22).astype(int)
        features['port_80'] = (df['port'] == 80).astype(int)
        features['port_443'] = (df['port'] == 443).astype(int)
        features['port_other'] = (~df['port'].isin([22, 80, 443])).astype(int)
        
        return features
    
    def extract_labels(self, logs: List[Dict]) -> np.ndarray:
        """Extract labels from logs"""
        df = pd.DataFrame(logs)
        if df.empty or 'label' not in df.columns:
            return np.array([])
        return (df['label'] == 'malicious').astype(int).values
