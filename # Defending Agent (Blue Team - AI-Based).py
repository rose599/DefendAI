# Defending Agent (Blue Team - AI-Based)
# This code implements a supervised ML model to classify network traffic as normal (0) or malicious (1).
# It uses Random Forest by default (as it's interpretable and fast), but can be swapped for XGBoost or Neural Networks.
# Requirements: Train on labeled data, evaluate with accuracy, precision, recall, and detection latency.
# Assumes synthetic data from the Attack Simulation step; replace with real datasets like CICIDS-2017 if needed.

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, classification_report
from sklearn.preprocessing import LabelEncoder
import time
import joblib  # For saving/loading the model

# Optional: Uncomment for XGBoost
# from xgboost import XGBClassifier

# Optional: Uncomment for Neural Network (requires TensorFlow)
# from tensorflow.keras.models import Sequential
# from tensorflow.keras.layers import Dense
# from tensorflow.keras.utils import to_categorical

def load_or_generate_data(filepath='synthetic_network_logs.csv'):
    """
    Load data from CSV or generate synthetic if not exists.
    Assumes CSV has columns: packet_count, port, protocol, label, attack_type
    """
    try:
        df = pd.read_csv(filepath)
        print(f"Loaded data from {filepath}")
    except FileNotFoundError:
        print("Data file not found. Generating synthetic data...")
        # Reuse synthetic generation from Attack Simulation
        def generate_synthetic_logs(num_samples=5000):
            data = []
            for _ in range(num_samples):
                if np.random.rand() > 0.3:  # 70% normal
                    label = 0
                    packet_count = np.random.randint(1, 50)
                    port = np.random.choice([80, 443, 22])
                    protocol = 'TCP'
                    attack_type = 'normal'
                else:  # 30% attacks
                    attack_type = np.random.choice(['DoS', 'PortScan', 'BruteForce', 'Malware'])
                    label = 1
                    if attack_type == 'DoS':
                        packet_count = np.random.randint(1000, 10000)
                        port = np.random.randint(1, 65535)
                        protocol = 'UDP'
                    elif attack_type == 'PortScan':
                        packet_count = np.random.randint(100, 500)
                        port = np.random.randint(1, 1024)
                        protocol = 'TCP'
                    elif attack_type == 'BruteForce':
                        packet_count = np.random.randint(50, 200)
                        port = 22
                        protocol = 'TCP'
                    else:  # Malware
                        packet_count = np.random.randint(10, 100)
                        port = np.random.randint(1, 65535)
                        protocol = 'TCP'
                data.append({
                    'packet_count': packet_count,
                    'port': port,
                    'protocol': protocol,
                    'label': label,
                    'attack_type': attack_type
                })
            return pd.DataFrame(data)
        
        df = generate_synthetic_logs()
        df.to_csv(filepath, index=False)
        print(f"Synthetic data generated and saved to {filepath}")
    
    return df

def preprocess_data(df):
    """
    Preprocess data: Encode categorical features, select features.
    """
    # Encode protocol
    le = LabelEncoder()
    df['protocol_encoded'] = le.fit_transform(df['protocol'])
    
    # Features: packet_count, port, protocol_encoded
    X = df[['packet_count', 'port', 'protocol_encoded']]
    y = df['label']
    
    return X, y, le

def train_model(X_train, y_train, model_type='random_forest'):
    """
    Train the ML model.
    Options: 'random_forest', 'xgboost', 'neural_network'
    """
    if model_type == 'random_forest':
        model = RandomForestClassifier(n_estimators=100, random_state=42)
    elif model_type == 'xgboost':
        model = XGBClassifier(n_estimators=100, random_state=42)
    elif model_type == 'neural_network':
        # Simple NN: Input -> Hidden -> Output
        model = Sequential([
            Dense(64, activation='relu', input_shape=(X_train.shape[1],)),
            Dense(32, activation='relu'),
            Dense(1, activation='sigmoid')  # Binary classification
        ])
        model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
        # Note: For NN, y_train needs to be categorical if multi-class, but here it's binary
        model.fit(X_train, y_train, epochs=10, batch_size=32, verbose=0)
        return model  # NN doesn't use joblib, so handle separately
    else:
        raise ValueError("Invalid model_type")
    
    model.fit(X_train, y_train)
    return model

def evaluate_model(model, X_test, y_test, model_type='random_forest'):
    """
    Evaluate model and return metrics.
    """
    if model_type == 'neural_network':
        loss, accuracy = model.evaluate(X_test, y_test, verbose=0)
        y_pred = (model.predict(X_test) > 0.5).astype(int).flatten()
    else:
        y_pred = model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
    
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    
    # Detection latency: Average time for 100 predictions
    start_time = time.time()
    for _ in range(100):
        if model_type == 'neural_network':
            model.predict(X_test.iloc[:1] if hasattr(X_test, 'iloc') else X_test[:1])
        else:
            model.predict(X_test.iloc[:1])
    latency = (time.time() - start_time) / 100 * 1000  # in milliseconds
    
    return {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'latency_ms': latency,
        'classification_report': classification_report(y_test, y_pred)
    }

def predict_traffic(model, new_data, le, model_type='random_forest'):
    """
    Predict on new traffic data.
    new_data: dict or DataFrame with 'packet_count', 'port', 'protocol'
    Returns: 0 (normal) or 1 (attack), with latency.
    """
    if isinstance(new_data, dict):
        df = pd.DataFrame([new_data])
    else:
        df = new_data
    
    df['protocol_encoded'] = le.transform(df['protocol'])
    X = df[['packet_count', 'port', 'protocol_encoded']]
    
    start_time = time.time()
    if model_type == 'neural_network':
        pred = (model.predict(X) > 0.5).astype(int).flatten()[0]
    else:
        pred = model.predict(X)[0]
    latency = (time.time() - start_time) * 1000  # ms
    
    return pred, latency

# Main execution
if __name__ == "__main__":
    # Step 1: Load/Generate Data
    df = load_or_generate_data()
    
    # Step 2: Preprocess
    X, y, le = preprocess_data(df)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Step 3: Train Model (Change model_type as needed)
    model_type = 'random_forest'  # Options: 'random_forest', 'xgboost', 'neural_network'
    model = train_model(X_train, y_train, model_type)
    
    # Save model (except for NN, which uses HDF5 or SavedModel)
    if model_type != 'neural_network':
        joblib.dump(model, 'defense_model.pkl')
        print("Model saved to defense_model.pkl")
    
    # Step 4: Evaluate
    metrics = evaluate_model(model, X_test, y_test, model_type)
    print("Model Evaluation:")
    print(f"Accuracy: {metrics['accuracy']:.2f}")
    print(f"Precision: {metrics['precision']:.2f}")
    print(f"Recall: {metrics['recall']:.2f}")
    print(f"Detection Latency: {metrics['latency_ms']:.2f} ms")
    print("Classification Report:")
    print(metrics['classification_report'])
    
    # Step 5: Example Prediction
    new_traffic = {'packet_count': 1500, 'port': 80, 'protocol': 'TCP'}  # Example: Likely DoS
    pred, lat = predict_traffic(model, new_traffic, le, model_type)
    print(f"Prediction for new traffic: {'Attack' if pred == 1 else 'Normal'} (Latency: {lat:.2f} ms)")
    
    # To load and use later:
    # loaded_model = joblib.load('defense_model.pkl')
    # pred, lat = predict_traffic(loaded_model, new_traffic, le, model_type)