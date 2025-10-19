import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, precision_recall_curve
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.feature_selection import SelectKBest, f_classif
import joblib
import os
import sys
import asyncio
import time
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Any
import xgboost as xgb
from lightgbm import LGBMClassifier
from catboost import CatBoostClassifier
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from kafka import KafkaConsumer, KafkaProducer
import json
import threading
import logging
import warnings
import hashlib
import redis
import psycopg2
from psycopg2.extras import RealDictCursor
import yaml
from pathlib import Path
import matplotlib.pyplot as plt
import seaborn as sns
from scipy import stats
from collections import deque, defaultdict
import pickle
import tensorflow as tf
from tensorflow.keras.models import Sequential, load_model
from tensorflow.keras.layers import Dense, Dropout, LSTM, BatchNormalization
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import Dataset, DataLoader
from transformers import AutoTokenizer, AutoModel
import networkx as nx
from sklearn.cluster import DBSCAN
from sklearn.decomposition import PCA
import plotly.graph_objects as go
import plotly.express as px
from dataclasses import dataclass, asdict
from enum import Enum
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import requests

warnings.filterwarnings('ignore')

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('fraud_detection.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class FraudType(Enum):
    """Types of fraud detection categories"""
    IDENTITY_THEFT = "identity_theft"
    SYNTHETIC_IDENTITY = "synthetic_identity"
    ACCOUNT_TAKEOVER = "account_takeover"
    DOCUMENT_FRAUD = "document_fraud"
    BEHAVIORAL_ANOMALY = "behavioral_anomaly"
    TRANSACTION_FRAUD = "transaction_fraud"
    APPLICATION_FRAUD = "application_fraud"
    BIOMETRIC_SPOOFING = "biometric_spoofing"

class RiskLevel(Enum):
    """Risk assessment levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class FraudAlert:
    """Fraud detection alert structure"""
    alert_id: str
    fraud_type: FraudType
    risk_level: RiskLevel
    confidence_score: float
    user_id: str
    event_id: str
    timestamp: datetime
    features: Dict[str, Any]
    evidence: List[str]
    recommended_actions: List[str]

def publish_fraud_event(redis_client, alert: FraudAlert):
    """Publish fraud detection event to Redis"""
    event = {
        "type": "fraud_detected",
        "data": {
            "alert_id": alert.alert_id,
            "fraud_type": alert.fraud_type.value,
            "risk_level": alert.risk_level.value,
            "confidence_score": alert.confidence_score,
            "user_id": alert.user_id,
            "timestamp": alert.timestamp.isoformat()
        }
    }
    redis_client.publish("id-system-events", json.dumps(event))

def anonymize_data(data: pd.DataFrame) -> pd.DataFrame:
    """Apply differential privacy and anonymization"""
    # Add noise to sensitive features
    sensitive_cols = ['income', 'balance', 'transaction_amount']
    for col in sensitive_cols:
        if col in data.columns:
            noise = np.random.laplace(0, 1, size=len(data))
            data[col] = data[col] + noise
    # Hash identifiers
    if 'user_id' in data.columns:
        data['user_id'] = data['user_id'].apply(lambda x: hashlib.sha256(str(x).encode()).hexdigest())
    return data
    false_positive_likelihood: float

@dataclass
class ModelMetrics:
    """Model performance metrics"""
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    auc_score: float
    false_positive_rate: float
    false_negative_rate: float
    training_time: float
    inference_time: float

class FraudDetectionConfig:
    """Configuration management for fraud detection system"""
    
    def __init__(self, config_path: str = "fraud_config.yaml"):
        self.config_path = config_path
        self.config = self._load_config()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        default_config = {
            'database': {
                'host': 'localhost',
                'port': 5432,
                'database': 'fraud_detection',
                'user': 'postgres',
                'password': 'password'
            },
            'redis': {
                'host': 'localhost',
                'port': 6379,
                'db': 0
            },
            'kafka': {
                'bootstrap_servers': ['localhost:9092'],
                'consumer_group': 'fraud-detection',
                'topics': ['audit-events', 'user-activities', 'transactions']
            },
            'models': {
                'ensemble_weights': {
                    'xgboost': 0.3,
                    'lightgbm': 0.25,
                    'catboost': 0.2,
                    'neural_network': 0.15,
                    'isolation_forest': 0.1
                },
                'retrain_threshold': 0.05,
                'min_samples_retrain': 1000
            },
            'thresholds': {
                'low_risk': 0.3,
                'medium_risk': 0.6,
                'high_risk': 0.8,
                'critical_risk': 0.95
            },
            'features': {
                'time_window_hours': 24,
                'behavioral_lookback_days': 30,
                'graph_analysis_depth': 3
            },
            'alerts': {
                'enable_email': True,
                'enable_slack': True,
                'enable_webhook': True,
                'batch_size': 100,
                'delay_seconds': 300
            }
        }
        
        try:
            if Path(self.config_path).exists():
                with open(self.config_path, 'r') as f:
                    config = yaml.safe_load(f)
                    # Merge with defaults
                    return {**default_config, **config}
            else:
                # Save default config
                with open(self.config_path, 'w') as f:
                    yaml.dump(default_config, f, default_flow_style=False)
                return default_config
        except Exception as e:
            logger.warning(f"Could not load config: {e}. Using defaults.")
            return default_config

class AdvancedFraudDetector:
    """Advanced fraud detection system with multiple ML algorithms and real-time processing"""
    
    def __init__(self, config_path: str = "fraud_config.yaml"):
        self.config = FraudDetectionConfig(config_path).config
        self.models = {}
        self.scalers = {}
        self.feature_selector = None
        self.model_metrics = {}
        self.audit_data = deque(maxlen=10000)  # In-memory audit data buffer
        self.alert_queue = deque(maxlen=1000)
        self.redis_client = self._init_redis()
        self.db_connection = self._init_database()
        self.kafka_producer = self._init_kafka_producer()
        self.feature_importance = {}
        self.graph_analyzer = GraphAnalyzer()
        self.behavioral_analyzer = BehavioralAnalyzer()
        self.document_analyzer = DocumentAnalyzer()
        self.biometric_analyzer = BiometricAnalyzer()
        self.running = False

        # Subscribe to government data events
        self._start_event_subscription()
        
        logger.info("Advanced Fraud Detection System initialized")
    
    def _start_event_subscription(self):
        """Start subscription to government data events"""
        def event_listener():
            pubsub = self.redis_client.pubsub()
            pubsub.subscribe("id-system-events")
            for message in pubsub.listen():
                if message['type'] == 'message':
                    try:
                        event = json.loads(message['data'])
                        if event.get('type') == 'connector_data_received':
                            # Use government data for fraud analysis
                            logger.info(f"Received government data for fraud analysis: {event}")
                            # Could update models or trigger analysis
                    except json.JSONDecodeError:
                        pass
        
        threading.Thread(target=event_listener, daemon=True).start()
    
    def _init_redis(self) -> Optional[redis.Redis]:
        """Initialize Redis connection"""
        try:
            client = redis.Redis(
                host=self.config['redis']['host'],
                port=self.config['redis']['port'],
                db=self.config['redis']['db'],
                decode_responses=True
            )
            client.ping()
            return client
        except Exception as e:
            logger.warning(f"Redis connection failed: {e}")
            return None
    
    def _init_database(self) -> Optional[psycopg2.connection]:
        """Initialize PostgreSQL connection"""
        try:
            conn = psycopg2.connect(
                host=self.config['database']['host'],
                port=self.config['database']['port'],
                database=self.config['database']['database'],
                user=self.config['database']['user'],
                password=self.config['database']['password']
            )
            return conn
        except Exception as e:
            logger.warning(f"Database connection failed: {e}")
            return None
    
    def _init_kafka_producer(self) -> Optional[KafkaProducer]:
        """Initialize Kafka producer for alerts"""
        try:
            return KafkaProducer(
                bootstrap_servers=self.config['kafka']['bootstrap_servers'],
                value_serializer=lambda x: json.dumps(x).encode('utf-8')
            )
        except Exception as e:
            logger.warning(f"Kafka producer initialization failed: {e}")
            return None

    def train_ensemble_models(self, data_path: str) -> Dict[str, ModelMetrics]:
        """Train multiple ML models and create ensemble"""
        try:
            logger.info(f"Loading training data from {data_path}")
            df = pd.read_csv(data_path)
            
            # Feature engineering
            df = self._engineer_features(df)
            
            # Prepare features and labels
            features = df.drop('label', axis=1)
            labels = df['label']
            
            # Feature selection
            self.feature_selector = SelectKBest(f_classif, k=min(50, features.shape[1]))
            features_selected = self.feature_selector.fit_transform(features, labels)
            
            # Scale features
            scaler = StandardScaler()
            features_scaled = scaler.fit_transform(features_selected)
            self.scalers['main'] = scaler
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                features_scaled, labels, test_size=0.2, random_state=42, stratify=labels
            )
            
            # Train multiple models
            models_to_train = {
                'xgboost': xgb.XGBClassifier(
                    n_estimators=200, max_depth=8, learning_rate=0.1, 
                    n_jobs=-1, random_state=42, eval_metric='logloss'
                ),
                'lightgbm': LGBMClassifier(
                    n_estimators=200, max_depth=8, learning_rate=0.1,
                    n_jobs=-1, random_state=42, verbose=-1
                ),
                'catboost': CatBoostClassifier(
                    iterations=200, depth=8, learning_rate=0.1,
                    thread_count=-1, random_state=42, verbose=False
                ),
                'random_forest': RandomForestClassifier(
                    n_estimators=200, max_depth=8, n_jobs=-1, random_state=42
                ),
                'isolation_forest': IsolationForest(
                    n_estimators=200, contamination=0.1, n_jobs=-1, random_state=42
                )
            }
            
            metrics = {}
            
            for model_name, model in models_to_train.items():
                logger.info(f"Training {model_name}...")
                start_time = time.time()
                
                if model_name == 'isolation_forest':
                    # Unsupervised model
                    model.fit(X_train)
                    predictions = model.predict(X_test)
                    # Convert to binary classification (-1 -> 1, 1 -> 0)
                    predictions = np.where(predictions == -1, 1, 0)
                else:
                    # Supervised models
                    model.fit(X_train, y_train)
                    predictions = model.predict(X_test)
                
                training_time = time.time() - start_time
                
                # Calculate metrics
                metrics[model_name] = self._calculate_metrics(y_test, predictions, training_time)
                self.models[model_name] = model
                
                logger.info(f"{model_name} trained - AUC: {metrics[model_name].auc_score:.4f}")
            
            # Train neural network
            nn_metrics = self._train_neural_network(X_train, X_test, y_train, y_test)
            metrics['neural_network'] = nn_metrics
            
            # Save models
            self._save_models()
            
            self.model_metrics = metrics
            logger.info("Ensemble training completed")
            
            return metrics
            
        except Exception as e:
            logger.error(f"Error training ensemble models: {e}")
            raise
    
    def _engineer_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Advanced feature engineering for fraud detection"""
        logger.info("Engineering features...")
        
        # Time-based features
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            df['hour'] = df['timestamp'].dt.hour
            df['day_of_week'] = df['timestamp'].dt.dayofweek
            df['is_weekend'] = df['day_of_week'].isin([5, 6]).astype(int)
            df['is_night'] = ((df['hour'] >= 22) | (df['hour'] <= 6)).astype(int)
        
        # Velocity features (if user_id exists)
        if 'user_id' in df.columns:
            df = df.sort_values(['user_id', 'timestamp'])
            df['time_since_last'] = df.groupby('user_id')['timestamp'].diff().dt.total_seconds()
            df['events_per_hour'] = df.groupby(['user_id', df['timestamp'].dt.floor('H')]).cumcount() + 1
            df['unique_ips_per_day'] = df.groupby(['user_id', df['timestamp'].dt.date])['ip_address'].nunique()
        
        # Location-based features
        if 'ip_address' in df.columns:
            df['ip_risk_score'] = df['ip_address'].apply(self._calculate_ip_risk)
        
        # Amount-based features (for transactions)
        if 'amount' in df.columns:
            df['amount_log'] = np.log1p(df['amount'])
            df['amount_zscore'] = stats.zscore(df['amount'])
            df['is_round_amount'] = (df['amount'] % 10 == 0).astype(int)
        
        # Device fingerprinting features
        if 'user_agent' in df.columns:
            df['browser_risk'] = df['user_agent'].apply(self._extract_browser_risk)
            df['device_risk'] = df['user_agent'].apply(self._extract_device_risk)
        
        return df
    
    def _calculate_ip_risk(self, ip_address: str) -> float:
        """Calculate risk score for IP address"""
        # Simplified IP risk calculation
        # In production, use threat intelligence feeds
        risk_ranges = [
            ('10.', 0.1),  # Internal network
            ('192.168.', 0.1),  # Private network
            ('172.16.', 0.1),  # Private network
        ]
        
        for prefix, risk in risk_ranges:
            if ip_address.startswith(prefix):
                return risk
        
        return 0.5  # Default risk for public IPs
    
    def _extract_browser_risk(self, user_agent: str) -> float:
        """Extract browser risk from user agent"""
        high_risk_patterns = ['bot', 'crawler', 'script', 'automation']
        for pattern in high_risk_patterns:
            if pattern.lower() in user_agent.lower():
                return 0.9
        return 0.2
    
    def _extract_device_risk(self, user_agent: str) -> float:
        """Extract device risk from user agent"""
        mobile_patterns = ['mobile', 'android', 'iphone']
        for pattern in mobile_patterns:
            if pattern.lower() in user_agent.lower():
                return 0.3  # Mobile devices have lower risk
        return 0.5
    
    def _calculate_metrics(self, y_true: np.ndarray, y_pred: np.ndarray, training_time: float) -> ModelMetrics:
        """Calculate comprehensive model metrics"""
        start_time = time.time()
        
        # Basic metrics
        accuracy = (y_true == y_pred).mean()
        
        # Confusion matrix
        tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
        
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        # Rates
        false_positive_rate = fp / (fp + tn) if (fp + tn) > 0 else 0
        false_negative_rate = fn / (fn + tp) if (fn + tp) > 0 else 0
        
        # AUC (if probabilities available)
        try:
            auc_score = roc_auc_score(y_true, y_pred)
        except:
            auc_score = 0.5
        
        inference_time = time.time() - start_time
        
        return ModelMetrics(
            accuracy=accuracy,
            precision=precision,
            recall=recall,
            f1_score=f1_score,
            auc_score=auc_score,
            false_positive_rate=false_positive_rate,
            false_negative_rate=false_negative_rate,
            training_time=training_time,
            inference_time=inference_time
        )
    
    def _train_neural_network(self, X_train: np.ndarray, X_test: np.ndarray, 
                            y_train: np.ndarray, y_test: np.ndarray) -> ModelMetrics:
        """Train deep learning model for fraud detection"""
        logger.info("Training neural network...")
        
        start_time = time.time()
        
        # Build model
        model = Sequential([
            Dense(128, activation='relu', input_shape=(X_train.shape[1],)),
            BatchNormalization(),
            Dropout(0.3),
            Dense(64, activation='relu'),
            BatchNormalization(),
            Dropout(0.3),
            Dense(32, activation='relu'),
            Dropout(0.2),
            Dense(1, activation='sigmoid')
        ])
        
        model.compile(
            optimizer=Adam(learning_rate=0.001),
            loss='binary_crossentropy',
            metrics=['accuracy', 'precision', 'recall']
        )
        
        # Callbacks
        callbacks = [
            EarlyStopping(patience=10, restore_best_weights=True),
            ModelCheckpoint('best_nn_model.h5', save_best_only=True)
        ]
        
        # Train
        history = model.fit(
            X_train, y_train,
            validation_data=(X_test, y_test),
            epochs=100,
            batch_size=32,
            callbacks=callbacks,
            verbose=0
        )
        
        training_time = time.time() - start_time
        
        # Predictions
        predictions = (model.predict(X_test) > 0.5).astype(int).flatten()
        
        # Save model
        model.save('fraud_neural_network.h5')
        self.models['neural_network'] = model
        
        return self._calculate_metrics(y_test, predictions, training_time)
    
    def _save_models(self):
        """Save all trained models"""
        models_dir = Path('models')
        models_dir.mkdir(exist_ok=True)
        
        for name, model in self.models.items():
            if name != 'neural_network':  # NN saved separately
                model_path = models_dir / f'{name}_model.pkl'
                joblib.dump(model, model_path)
        
        # Save scalers and feature selector
        if self.scalers:
            joblib.dump(self.scalers, models_dir / 'scalers.pkl')
        if self.feature_selector:
            joblib.dump(self.feature_selector, models_dir / 'feature_selector.pkl')
        
        logger.info("Models saved successfully")

    def analyze_transaction(self, transaction_data: Dict[str, Any]) -> Optional[FraudAlert]:
        """Analyze a single transaction for fraud"""
        # Feature extraction
        features = self._extract_features(pd.DataFrame([transaction_data]))
        features_scaled = self.scalers['main'].transform(features)
        features_selected = self.feature_selector.transform(features_scaled)
        
        # Ensemble prediction
        predictions = {}
        for model_name, model in self.models.items():
            if model_name == 'isolation_forest':
                pred = model.predict(features_selected)
                predictions[model_name] = 1 if pred[0] == -1 else 0
            else:
                pred = model.predict_proba(features_selected)[0][1]
                predictions[model_name] = pred
        
        # Weighted ensemble
        weights = self.config['models']['ensemble_weights']
        final_score = sum(predictions[model] * weight for model, weight in weights.items())
        
        # Determine risk level
        thresholds = self.config['thresholds']
        if final_score >= thresholds['critical_risk']:
            risk_level = RiskLevel.CRITICAL
        elif final_score >= thresholds['high_risk']:
            risk_level = RiskLevel.HIGH
        elif final_score >= thresholds['medium_risk']:
            risk_level = RiskLevel.MEDIUM
        else:
            risk_level = RiskLevel.LOW
        
        if risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            alert = FraudAlert(
                alert_id=f"alert_{datetime.now().timestamp()}",
                fraud_type=FraudType.TRANSACTION_FRAUD,
                risk_level=risk_level,
                confidence_score=final_score,
                user_id=transaction_data.get('user_id', 'unknown'),
                event_id=transaction_data.get('transaction_id', 'unknown'),
                timestamp=datetime.now(),
                features=transaction_data,
                evidence=[f"High risk score: {final_score}"],
                recommended_actions=["Block transaction", "Notify user", "Investigate"]
            )
            # Publish event
            publish_fraud_event(self.redis_client, alert)
            return alert
        
        return None


class GraphAnalyzer:
    """Graph-based fraud detection using network analysis"""
    
    def __init__(self):
        self.graph = nx.Graph()
        self.suspicious_patterns = []
    
    def build_user_network(self, transactions_df: pd.DataFrame) -> nx.Graph:
        """Build network graph from transaction data"""
        self.graph.clear()
        
        for _, transaction in transactions_df.iterrows():
            sender = transaction.get('sender_id')
            receiver = transaction.get('receiver_id')
            amount = transaction.get('amount', 0)
            timestamp = transaction.get('timestamp')
            
            if sender and receiver:
                if self.graph.has_edge(sender, receiver):
                    # Update edge weight
                    self.graph[sender][receiver]['weight'] += amount
                    self.graph[sender][receiver]['count'] += 1
                else:
                    # Add new edge
                    self.graph.add_edge(sender, receiver, weight=amount, count=1, 
                                      first_seen=timestamp)
        
        return self.graph
    
    def detect_suspicious_patterns(self) -> List[Dict[str, Any]]:
        """Detect suspicious patterns in the network"""
        patterns = []
        
        # Detect money laundering rings (cycles)
        cycles = list(nx.simple_cycles(self.graph.to_directed()))
        for cycle in cycles:
            if len(cycle) >= 3:  # Ring of 3 or more users
                total_amount = sum(self.graph[cycle[i]][cycle[(i+1) % len(cycle)]]['weight'] 
                                 for i in range(len(cycle)))
                patterns.append({
                    'type': 'money_laundering_ring',
                    'users': cycle,
                    'total_amount': total_amount,
                    'risk_score': min(total_amount / 10000, 1.0)  # Normalize
                })
        
        # Detect hub accounts (unusual centrality)
        centrality = nx.degree_centrality(self.graph)
        high_centrality = {node: score for node, score in centrality.items() if score > 0.1}
        
        for node, score in high_centrality.items():
            patterns.append({
                'type': 'hub_account',
                'user': node,
                'centrality_score': score,
                'risk_score': min(score * 2, 1.0)
            })
        
        return patterns


class BehavioralAnalyzer:
    """Behavioral analysis for detecting anomalous user patterns"""
    
    def __init__(self):
        self.user_profiles = {}
        self.behavioral_models = {}
    
    def build_user_profile(self, user_id: str, activities_df: pd.DataFrame) -> Dict[str, Any]:
        """Build behavioral profile for a user"""
        user_activities = activities_df[activities_df['user_id'] == user_id]
        
        if user_activities.empty:
            return {}
        
        # Time patterns
        hours = pd.to_datetime(user_activities['timestamp']).dt.hour
        days = pd.to_datetime(user_activities['timestamp']).dt.dayofweek
        
        profile = {
            'total_activities': len(user_activities),
            'avg_daily_activities': len(user_activities) / max(1, user_activities['timestamp'].nunique()),
            'peak_hour': hours.mode().iloc[0] if not hours.mode().empty else 12,
            'activity_hours_std': hours.std(),
            'weekend_activity_ratio': (days >= 5).mean(),
            'night_activity_ratio': ((hours >= 22) | (hours <= 6)).mean(),
            
            # Location patterns
            'unique_locations': user_activities['location'].nunique() if 'location' in user_activities.columns else 0,
            'location_entropy': self._calculate_entropy(user_activities.get('location', [])),
            
            # Device patterns
            'unique_devices': user_activities['device_id'].nunique() if 'device_id' in user_activities.columns else 0,
            'device_switches_per_day': 0,  # Calculate if needed
            
            # Activity types
            'activity_type_distribution': user_activities['activity_type'].value_counts().to_dict() if 'activity_type' in user_activities.columns else {},
        }
        
        self.user_profiles[user_id] = profile
        return profile
    
    def _calculate_entropy(self, values: pd.Series) -> float:
        """Calculate Shannon entropy for a series of values"""
        if len(values) == 0:
            return 0
        
        value_counts = values.value_counts(normalize=True)
        return -sum(p * np.log2(p) for p in value_counts if p > 0)
    
    def detect_behavioral_anomalies(self, user_id: str, recent_activities: pd.DataFrame) -> List[Dict[str, Any]]:
        """Detect behavioral anomalies for a user"""
        profile = self.user_profiles.get(user_id, {})
        if not profile:
            return []
        
        anomalies = []
        
        # Check for time-based anomalies
        if not recent_activities.empty:
            recent_hours = pd.to_datetime(recent_activities['timestamp']).dt.hour
            
            # Unusual time activity
            peak_hour = profile.get('peak_hour', 12)
            hour_deviation = min(abs(recent_hours.mean() - peak_hour), 
                               24 - abs(recent_hours.mean() - peak_hour))
            
            if hour_deviation > 6:  # More than 6 hours from normal
                anomalies.append({
                    'type': 'unusual_time_activity',
                    'severity': min(hour_deviation / 12, 1.0),
                    'details': f'Activity at unusual time: {recent_hours.mean():.1f} vs normal {peak_hour}'
                })
            
            # High frequency activity
            activities_per_hour = len(recent_activities) / max(1, 
                (recent_activities['timestamp'].max() - recent_activities['timestamp'].min()).total_seconds() / 3600)
            
            normal_rate = profile.get('avg_daily_activities', 10) / 24
            
            if activities_per_hour > normal_rate * 5:  # 5x normal rate
                anomalies.append({
                    'type': 'high_frequency_activity',
                    'severity': min(activities_per_hour / (normal_rate * 10), 1.0),
                    'details': f'Activity rate: {activities_per_hour:.2f}/hour vs normal {normal_rate:.2f}/hour'
                })
        
        return anomalies


class DocumentAnalyzer:
    """Document fraud detection using image analysis and OCR"""
    
    def __init__(self):
        self.document_templates = {}
        self.suspicious_patterns = []
    
    def analyze_document(self, document_path: str, document_type: str) -> Dict[str, Any]:
        """Analyze document for fraud indicators"""
        # Placeholder for document analysis
        # In production, this would use computer vision and OCR
        
        analysis = {
            'document_type': document_type,
            'authenticity_score': np.random.uniform(0.7, 0.95),  # Simulated
            'quality_score': np.random.uniform(0.8, 1.0),
            'tampering_indicators': [],
            'extracted_data': {},
            'risk_factors': []
        }
        
        # Simulate some checks
        if np.random.random() < 0.1:  # 10% chance of detecting issues
            analysis['risk_factors'].append('Low image quality')
            analysis['authenticity_score'] *= 0.8
        
        if np.random.random() < 0.05:  # 5% chance of tampering
            analysis['tampering_indicators'].append('Digital alteration detected')
            analysis['authenticity_score'] *= 0.5
        
        return analysis
    
    def verify_document_consistency(self, documents: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Verify consistency across multiple documents"""
        consistency_checks = {
            'name_consistency': True,
            'date_consistency': True,
            'photo_consistency': True,
            'inconsistencies': []
        }
        
        # Simulate consistency checks
        if len(documents) > 1 and np.random.random() < 0.1:
            consistency_checks['name_consistency'] = False
            consistency_checks['inconsistencies'].append('Name mismatch across documents')
        
        return consistency_checks


class BiometricAnalyzer:
    """Biometric fraud detection and liveness detection"""
    
    def __init__(self):
        self.biometric_templates = {}
        self.liveness_models = {}
    
    def analyze_biometric(self, biometric_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze biometric data for spoofing and authenticity"""
        analysis = {
            'liveness_score': np.random.uniform(0.8, 0.98),  # Simulated
            'quality_score': np.random.uniform(0.7, 0.95),
            'spoofing_indicators': [],
            'match_confidence': np.random.uniform(0.85, 0.99),
            'risk_assessment': 'low'
        }
        
        # Simulate liveness detection
        if analysis['liveness_score'] < 0.85:
            analysis['spoofing_indicators'].append('Low liveness score')
            analysis['risk_assessment'] = 'high'
        
        if analysis['quality_score'] < 0.8:
            analysis['spoofing_indicators'].append('Poor biometric quality')
            analysis['risk_assessment'] = 'medium'
        
        return analysis


# Continue with main detection and real-time processing methods
    def _extract_features_from_event(self, event_data: Dict[str, Any]) -> Optional[np.ndarray]:
        """Extract features from real-time event data"""
        try:
            features = []
            
            # Basic event features
            features.append(event_data.get('severity_score', 0.5))
            features.append(1 if event_data.get('outcome') == 'failure' else 0)
            features.append(len(event_data.get('details', {})))
            
            # Time-based features
            timestamp = pd.to_datetime(event_data.get('timestamp', datetime.now()))
            features.extend([
                timestamp.hour,
                timestamp.dayofweek,
                1 if timestamp.hour >= 22 or timestamp.hour <= 6 else 0,  # Night activity
                1 if timestamp.dayofweek >= 5 else 0  # Weekend
            ])
            
            # User behavior features
            user_id = event_data.get('user_id')
            if user_id and self.redis_client:
                # Get recent user activity from Redis
                recent_activity_key = f"user_activity:{user_id}"
                recent_count = self.redis_client.get(recent_activity_key) or 0
                features.append(float(recent_count))
                
                # Update activity counter
                self.redis_client.incr(recent_activity_key)
                self.redis_client.expire(recent_activity_key, 3600)  # 1 hour TTL
            else:
                features.append(0)
            
            # IP and location features
            ip_address = event_data.get('ip_address', '')
            features.append(self._calculate_ip_risk(ip_address))
            
            # Device features
            user_agent = event_data.get('user_agent', '')
            features.extend([
                self._extract_browser_risk(user_agent),
                self._extract_device_risk(user_agent)
            ])
            
            # Transaction features (if applicable)
            if 'amount' in event_data:
                amount = float(event_data['amount'])
                features.extend([
                    np.log1p(amount),
                    1 if amount % 10 == 0 else 0,  # Round amount
                    min(amount / 10000, 1.0)  # Normalized amount
                ])
            else:
                features.extend([0, 0, 0])
            
            return np.array(features).reshape(1, -1)
            
        except Exception as e:
            logger.error(f"Error extracting features: {e}")
            return None
    
    def _get_ensemble_prediction(self, features: np.ndarray) -> float:
        """Get ensemble prediction from all models"""
        if not self.models:
            return 0.5  # Default score if no models
        
        predictions = {}
        weights = self.config['models']['ensemble_weights']
        
        try:
            # Preprocess features
            if self.feature_selector and features.shape[1] > len(self.feature_selector.get_support()):
                # Pad features if needed
                features = np.pad(features, ((0, 0), (0, max(0, len(self.feature_selector.get_support()) - features.shape[1]))), 'constant')
            
            if self.feature_selector:
                features = self.feature_selector.transform(features)
            
            if 'main' in self.scalers:
                features = self.scalers['main'].transform(features)
            
            # Get predictions from each model
            for model_name, model in self.models.items():
                try:
                    if model_name == 'isolation_forest':
                        # Isolation forest returns -1 for anomalies, 1 for normal
                        pred = model.decision_function(features)[0]
                        # Convert to probability (higher = more anomalous)
                        predictions[model_name] = 1 / (1 + np.exp(pred))  # Sigmoid
                    elif model_name == 'neural_network':
                        # Neural network returns probability
                        predictions[model_name] = float(model.predict(features)[0][0])
                    else:
                        # Scikit-learn classifiers
                        predictions[model_name] = model.predict_proba(features)[0][1]
                except Exception as e:
                    logger.warning(f"Error getting prediction from {model_name}: {e}")
                    predictions[model_name] = 0.5
            
            # Calculate weighted ensemble score
            total_weight = 0
            weighted_sum = 0
            
            for model_name, pred in predictions.items():
                weight = weights.get(model_name, 0.2)  # Default weight
                weighted_sum += pred * weight
                total_weight += weight
            
            ensemble_score = weighted_sum / total_weight if total_weight > 0 else 0.5
            
            return min(max(ensemble_score, 0.0), 1.0)  # Clamp to [0, 1]
            
        except Exception as e:
            logger.error(f"Error in ensemble prediction: {e}")
            return 0.5
    
    def _determine_risk_level(self, fraud_score: float) -> RiskLevel:
        """Determine risk level based on fraud score"""
        thresholds = self.config['thresholds']
        
        if fraud_score >= thresholds['critical_risk']:
            return RiskLevel.CRITICAL
        elif fraud_score >= thresholds['high_risk']:
            return RiskLevel.HIGH
        elif fraud_score >= thresholds['medium_risk']:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    def _generate_fraud_alert(self, event_data: Dict[str, Any], fraud_score: float, 
                            risk_level: RiskLevel, features: np.ndarray) -> FraudAlert:
        """Generate comprehensive fraud alert"""
        
        # Determine fraud type based on event characteristics
        fraud_type = self._classify_fraud_type(event_data, features)
        
        # Generate evidence
        evidence = self._generate_evidence(event_data, fraud_score, features)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(fraud_type, risk_level, event_data)
        
        # Calculate false positive likelihood
        fp_likelihood = self._calculate_false_positive_likelihood(fraud_score, fraud_type, event_data)
        
        alert = FraudAlert(
            alert_id=hashlib.md5(f"{event_data.get('user_id', '')}{datetime.now()}".encode()).hexdigest(),
            fraud_type=fraud_type,
            risk_level=risk_level,
            confidence_score=fraud_score,
            user_id=event_data.get('user_id', 'unknown'),
            event_id=event_data.get('event_id', 'unknown'),
            timestamp=datetime.now(),
            features={
                'ip_address': event_data.get('ip_address'),
                'user_agent': event_data.get('user_agent'),
                'location': event_data.get('location'),
                'device_id': event_data.get('device_id'),
                'activity_type': event_data.get('activity_type')
            },
            evidence=evidence,
            recommended_actions=recommendations,
            false_positive_likelihood=fp_likelihood
        )
        
        return alert
    
    def _classify_fraud_type(self, event_data: Dict[str, Any], features: np.ndarray) -> FraudType:
        """Classify the type of fraud based on event characteristics"""
        
        # Simple rule-based classification (could be enhanced with ML)
        activity_type = event_data.get('activity_type', '').lower()
        
        if 'login' in activity_type or 'authentication' in activity_type:
            return FraudType.ACCOUNT_TAKEOVER
        elif 'document' in activity_type or 'verification' in activity_type:
            return FraudType.DOCUMENT_FRAUD
        elif 'biometric' in activity_type:
            return FraudType.BIOMETRIC_SPOOFING
        elif 'transaction' in activity_type or 'payment' in activity_type:
            return FraudType.TRANSACTION_FRAUD
        elif 'registration' in activity_type or 'application' in activity_type:
            return FraudType.APPLICATION_FRAUD
        else:
            return FraudType.BEHAVIORAL_ANOMALY
    
    def _generate_evidence(self, event_data: Dict[str, Any], fraud_score: float, 
                         features: np.ndarray) -> List[str]:
        """Generate evidence list for fraud detection"""
        evidence = []
        
        if fraud_score > 0.8:
            evidence.append(f"High fraud probability: {fraud_score:.3f}")
        
        # IP-based evidence
        ip_address = event_data.get('ip_address', '')
        if self._calculate_ip_risk(ip_address) > 0.7:
            evidence.append(f"High-risk IP address: {ip_address}")
        
        # Time-based evidence
        timestamp = pd.to_datetime(event_data.get('timestamp', datetime.now()))
        if timestamp.hour >= 22 or timestamp.hour <= 6:
            evidence.append(f"Unusual time activity: {timestamp.strftime('%H:%M')}")
        
        # Device-based evidence
        user_agent = event_data.get('user_agent', '')
        if self._extract_browser_risk(user_agent) > 0.7:
            evidence.append("Suspicious user agent detected")
        
        # Velocity evidence
        user_id = event_data.get('user_id')
        if user_id and self.redis_client:
            recent_count = self.redis_client.get(f"user_activity:{user_id}") or 0
            if int(recent_count) > 50:  # More than 50 activities in last hour
                evidence.append(f"High activity velocity: {recent_count} events/hour")
        
        return evidence
    
    def _generate_recommendations(self, fraud_type: FraudType, risk_level: RiskLevel, 
                                event_data: Dict[str, Any]) -> List[str]:
        """Generate recommended actions based on fraud type and risk level"""
        recommendations = []
        
        if risk_level == RiskLevel.CRITICAL:
            recommendations.extend([
                "Immediately suspend user account",
                "Trigger manual review process",
                "Notify security team",
                "Log detailed forensic information"
            ])
        elif risk_level == RiskLevel.HIGH:
            recommendations.extend([
                "Flag account for enhanced monitoring",
                "Require additional authentication",
                "Review recent account activity"
            ])
        elif risk_level == RiskLevel.MEDIUM:
            recommendations.extend([
                "Monitor subsequent user activities",
                "Consider step-up authentication",
                "Log event for pattern analysis"
            ])
        
        # Fraud-type specific recommendations
        if fraud_type == FraudType.ACCOUNT_TAKEOVER:
            recommendations.append("Force password reset")
            recommendations.append("Check for credential stuffing patterns")
        elif fraud_type == FraudType.DOCUMENT_FRAUD:
            recommendations.append("Request additional document verification")
            recommendations.append("Schedule manual document review")
        elif fraud_type == FraudType.BIOMETRIC_SPOOFING:
            recommendations.append("Require liveness detection")
            recommendations.append("Use alternative verification method")
        
        return recommendations
    
    def _calculate_false_positive_likelihood(self, fraud_score: float, fraud_type: FraudType, 
                                           event_data: Dict[str, Any]) -> float:
        """Calculate likelihood of false positive"""
        
        # Base false positive rate by fraud type
        base_fp_rates = {
            FraudType.IDENTITY_THEFT: 0.05,
            FraudType.ACCOUNT_TAKEOVER: 0.08,
            FraudType.DOCUMENT_FRAUD: 0.03,
            FraudType.BEHAVIORAL_ANOMALY: 0.15,
            FraudType.TRANSACTION_FRAUD: 0.07,
            FraudType.APPLICATION_FRAUD: 0.10,
            FraudType.BIOMETRIC_SPOOFING: 0.02,
            FraudType.SYNTHETIC_IDENTITY: 0.04
        }
        
        base_fp = base_fp_rates.get(fraud_type, 0.1)
        
        # Adjust based on fraud score confidence
        if fraud_score > 0.9:
            fp_likelihood = base_fp * 0.5  # High confidence = lower FP likelihood
        elif fraud_score > 0.7:
            fp_likelihood = base_fp
        else:
            fp_likelihood = base_fp * 1.5  # Lower confidence = higher FP likelihood
        
        return min(fp_likelihood, 0.5)  # Cap at 50%
    
    def _send_immediate_alert(self, alert: FraudAlert):
        """Send immediate alert for critical fraud cases"""
        try:
            if self.kafka_producer:
                alert_message = {
                    'alert_id': alert.alert_id,
                    'type': 'critical_fraud_alert',
                    'user_id': alert.user_id,
                    'fraud_type': alert.fraud_type.value,
                    'risk_level': alert.risk_level.value,
                    'confidence_score': alert.confidence_score,
                    'timestamp': alert.timestamp.isoformat(),
                    'evidence': alert.evidence,
                    'recommendations': alert.recommended_actions
                }
                
                self.kafka_producer.send('fraud-alerts', alert_message)
                logger.info(f"Critical fraud alert sent: {alert.alert_id}")
        
        except Exception as e:
            logger.error(f"Error sending immediate alert: {e}")
    
    def _alert_processor_worker(self):
        """Background worker to process fraud alerts"""
        while self.running:
            try:
                if self.alert_queue:
                    # Process alerts in batches
                    batch_size = self.config['alerts']['batch_size']
                    alerts_to_process = []
                    
                    for _ in range(min(batch_size, len(self.alert_queue))):
                        if self.alert_queue:
                            alerts_to_process.append(self.alert_queue.popleft())
                    
                    if alerts_to_process:
                        self._process_alert_batch(alerts_to_process)
                
                time.sleep(self.config['alerts']['delay_seconds'])
                
            except Exception as e:
                logger.error(f"Error in alert processor: {e}")
                time.sleep(5)
    
    def _process_alert_batch(self, alerts: List[FraudAlert]):
        """Process a batch of fraud alerts"""
        try:
            # Save alerts to database
            if self.db_connection:
                self._save_alerts_to_db(alerts)
            
            # Send notifications
            for alert in alerts:
                if alert.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
                    self._send_alert_notification(alert)
            
            logger.info(f"Processed {len(alerts)} fraud alerts")
            
        except Exception as e:
            logger.error(f"Error processing alert batch: {e}")
    
    def _save_alerts_to_db(self, alerts: List[FraudAlert]):
        """Save fraud alerts to database"""
        try:
            cursor = self.db_connection.cursor()
            
            for alert in alerts:
                cursor.execute("""
                    INSERT INTO fraud_alerts 
                    (alert_id, fraud_type, risk_level, confidence_score, user_id, event_id, 
                     timestamp, features, evidence, recommendations, false_positive_likelihood)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    alert.alert_id, alert.fraud_type.value, alert.risk_level.value,
                    alert.confidence_score, alert.user_id, alert.event_id,
                    alert.timestamp, json.dumps(alert.features), json.dumps(alert.evidence),
                    json.dumps(alert.recommended_actions), alert.false_positive_likelihood
                ))
            
            self.db_connection.commit()
            
        except Exception as e:
            logger.error(f"Error saving alerts to database: {e}")
            if self.db_connection:
                self.db_connection.rollback()
    
    def _send_alert_notification(self, alert: FraudAlert):
        """Send alert notification via configured channels"""
        # Placeholder for notification logic
        # In production, integrate with email, Slack, webhooks, etc.
        logger.info(f"Alert notification sent for {alert.alert_id}")

    def detect_fraud_realtime(self, event_data: Dict[str, Any]) -> Optional[FraudAlert]:
        """Real-time fraud detection for incoming events"""
        try:
            # Store event
            self.audit_data.append(event_data)
            
            # Feature extraction
            features = self._extract_features_from_event(event_data)
            
            if features is None:
                return None
            
            # Get ensemble prediction
            fraud_score = self._get_ensemble_prediction(features)
            
            # Determine risk level
            risk_level = self._determine_risk_level(fraud_score)
            
            if risk_level != RiskLevel.LOW:
                # Generate alert
                alert = self._generate_fraud_alert(event_data, fraud_score, risk_level, features)
                
                # Queue alert for processing
                self.alert_queue.append(alert)
                
                # Send immediate notification for critical risks
                if risk_level == RiskLevel.CRITICAL:
                    self._send_immediate_alert(alert)
                
                return alert
            
            return None
            
        except Exception as e:
            logger.error(f"Error in real-time fraud detection: {e}")
            return None

    def start_realtime_monitoring(self):
        """Start real-time fraud monitoring"""
        logger.info("Starting real-time fraud monitoring...")
        self.running = True
        
        # Start Kafka consumer thread
        consumer_thread = threading.Thread(target=self._kafka_consumer_worker)
        consumer_thread.daemon = True
        consumer_thread.start()
        
        # Start alert processing thread
        alert_thread = threading.Thread(target=self._alert_processor_worker)
        alert_thread.daemon = True  
        alert_thread.start()
        
        logger.info("Real-time monitoring started")

    def _kafka_consumer_worker(self):
        """Kafka consumer worker thread"""
        try:
            consumer = KafkaConsumer(
                *self.config['kafka']['topics'],
                bootstrap_servers=self.config['kafka']['bootstrap_servers'],
                auto_offset_reset='latest',
                enable_auto_commit=True,
                group_id=self.config['kafka']['consumer_group'],
                value_deserializer=lambda x: json.loads(x.decode('utf-8'))
            )
            
            logger.info("Kafka consumer started")
            
            while self.running:
                try:
                    message_batch = consumer.poll(timeout_ms=1000)
                    
                    for topic_partition, messages in message_batch.items():
                        for message in messages:
                            event_data = message.value
                            
                            # Process event for fraud detection
                            alert = self.detect_fraud_realtime(event_data)
                            
                            if alert:
                                logger.info(f"Fraud alert generated: {alert.alert_id}")
                    
                except Exception as e:
                    logger.error(f"Error processing Kafka messages: {e}")
                    time.sleep(1)
                    
        except Exception as e:
            logger.error(f"Kafka consumer error: {e}")

# Example usage and main execution
def main():
    """Main execution function"""
    try:
        # Initialize fraud detector
        detector = AdvancedFraudDetector()
        
        # Load and train models if training data exists
        training_data_path = "fraud_training_data.csv"
        if Path(training_data_path).exists():
            logger.info("Training fraud detection models...")
            metrics = detector.train_ensemble_models(training_data_path)
            
            # Print model performance
            for model_name, metric in metrics.items():
                logger.info(f"{model_name}: AUC={metric.auc_score:.4f}, "
                          f"Precision={metric.precision:.4f}, Recall={metric.recall:.4f}")
        else:
            logger.warning("No training data found. Running with pre-trained models if available.")
        
        # Start real-time monitoring
        detector.start_realtime_monitoring()
        
        # Keep running
        logger.info("Fraud detection system running. Press Ctrl+C to stop.")
        try:
            while True:
                time.sleep(60)
                logger.info(f"System status: {len(detector.audit_data)} events processed, "
                          f"{len(detector.alert_queue)} alerts queued")
        except KeyboardInterrupt:
            logger.info("Shutting down fraud detection system...")
            detector.running = False
            
    except Exception as e:
        logger.error(f"Fatal error in fraud detection system: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()