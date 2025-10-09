# � Advanced Fraud Analytics System

Comprehensive AI-powered fraud detection system for the UK Digital Identity Platform with real-time processing, advanced machine learning, and production-ready monitoring capabilities.

## 🎯 Features

### Enterprise ML Stack
- **Advanced Algorithms**: XGBoost, LightGBM, CatBoost ensemble with TensorFlow/PyTorch deep learning
- **Real-time Processing**: Kafka consumer with Redis caching and PostgreSQL audit logging
- **Deep Learning**: LSTM networks for sequence analysis, Transformers for document processing
- **Production ML**: A/B testing framework, automated model training, hyperparameter optimization

### 8 Fraud Detection Categories
- **Identity Theft**: Stolen identity usage with behavioral pattern analysis
- **Synthetic Identity**: AI-generated fake identity detection using graph analytics  
- **Account Takeover**: Unauthorized access detection with session analysis
- **Document Fraud**: Computer vision analysis for altered/fake documents
- **Behavioral Anomaly**: Time-series analysis for unusual user patterns
- **Transaction Fraud**: Financial pattern recognition with ensemble models
- **Application Fraud**: Form analysis with NLP and statistical validation
- **Biometric Spoofing**: Liveness detection and anti-spoofing algorithms

### Production Analytics Platform
- **Streamlit Dashboard**: Real-time visualization with interactive charts using Plotly/Seaborn
- **Graph Analytics**: NetworkX relationship analysis, DBSCAN clustering for fraud rings  
- **Model Performance**: Comprehensive metrics tracking, A/B testing, drift detection
- **Multi-channel Alerts**: Email (SMTP), Slack, database notifications with severity levels
- **Computer Vision**: OpenCV + Pillow for document analysis, NLTK for text processing
- **Concurrent Processing**: ThreadPoolExecutor + ProcessPoolExecutor for parallel ML inference
- **Enterprise Integration**: PostgreSQL audit, Redis caching, Kafka streaming, YAML configuration

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│ Kafka Topics    │───▶│ Python Consumer  │───▶│ XGBoost Model   │
│ (audit-logs)    │    │ (Fraud Engine)   │    │ (Classification)│
└─────────────────┘    └──────────────────┘    └─────────────────┘
         ▲                        │
         │                        ▼
┌─────────────────┐    ┌──────────────────┐
│ Go Gateway      │    │ Fraud Alerts     │
│ (Audit Events)  │    │ (Notifications)  │
└─────────────────┘    └──────────────────┘
```

## Core Components

### Machine Learning Pipeline
- **Data Preprocessing**: Feature extraction from audit events
- **Model Training**: XGBoost with parallel processing (n_jobs=-1)
- **Real-time Inference**: Live fraud scoring on incoming events
- **Model Evaluation**: Classification reports and accuracy metrics

### Kafka Integration
- **Consumer Group**: `fraud-detector` for scalable processing
- **Topic Subscription**: `audit-logs` for transaction monitoring
- **Message Processing**: JSON deserialization and fraud analysis
- **Error Handling**: Graceful degradation on message failures

## Fraud Detection Models

### XGBoost Classifier
```python
model = xgb.XGBClassifier(
    n_estimators=100,      # 100 decision trees
    max_depth=6,           # Prevent overfitting  
    learning_rate=0.1,     # Conservative learning
    n_jobs=-1              # Parallel processing
)
```

### Features Used
- Transaction frequency patterns
- Geographic location anomalies  
- Time-based behavior analysis
- Credential usage patterns
- Login attempt sequences

## Real-time Processing

### Kafka Consumer
```python
consumer = KafkaConsumer(
    'audit-logs',
    bootstrap_servers=['localhost:9092'],
    group_id='fraud-detector',
    value_deserializer=lambda x: json.loads(x.decode('utf-8'))
)
```

### Live Fraud Detection
```python
def detect_fraud_live(model, audit_event):
    features = extract_features(audit_event)
    prediction = model.predict([features])[0]
    probability = model.predict_proba([features])[0][1]
    return prediction, probability
```

## Performance Optimizations

- **Parallel Training**: Multi-core CPU utilization with n_jobs=-1
- **Batch Processing**: Process multiple events simultaneously
- **Model Caching**: In-memory model storage for fast inference
- **Async Processing**: Non-blocking Kafka message consumption
- **Feature Caching**: Reuse computed features across predictions

## Data Flow

1. **Audit Events**: Go gateway publishes user actions to Kafka
2. **Consumer**: Python service consumes events in real-time  
3. **Feature Extraction**: Convert events to ML feature vectors
4. **Fraud Scoring**: XGBoost model predicts fraud probability
5. **Alerting**: High-risk events trigger notifications
6. **Model Updates**: Periodic retraining with new fraud patterns

## Model Training

### Dataset Requirements
```python
# Expected CSV format:
# feature1, feature2, feature3, ..., label
# 0.1,      0.5,      0.8,      ..., 0     (normal)
# 0.9,      0.2,      0.1,      ..., 1     (fraud)
```

### Training Process
```python
# Load and split data
df = pd.read_csv('fraud_training_data.csv')
X_train, X_test, y_train, y_test = train_test_split(
    features, labels, test_size=0.2, random_state=42
)

# Train XGBoost model
model = xgb.XGBClassifier(n_estimators=100, n_jobs=-1)
model.fit(X_train, y_train)

# Evaluate performance
predictions = model.predict(X_test)
print(classification_report(y_test, predictions))
```

## Error Handling & Logging

### Comprehensive Logging
```python
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)
```

### Error Recovery
- **Kafka Reconnection**: Automatic reconnection on broker failures
- **Model Fallback**: Use cached model if loading fails
- **Message Skipping**: Continue processing on individual message errors
- **Exception Logging**: Detailed error context for debugging

## Usage Examples

### Training a Model
```python
from detect_fraud import train_model

# Train new model from CSV data
model = train_model('training_data.csv', 'fraud_model.pkl')
```

### Real-time Detection
```python
from detect_fraud import start_kafka_consumer, detect_fraud

# Start consuming Kafka events
start_kafka_consumer()

# Load model and run detection
detect_fraud('training_data.csv', 'fraud_model.pkl')
```

## Integration Points

### Kafka Events from Go Gateway
```json
{
  "event_type": "user_registration",
  "user_id": "12345",
  "timestamp": "2025-10-09T10:30:00Z",
  "ip_address": "192.168.1.100",
  "user_agent": "Mozilla/5.0...",
  "features": {
    "login_frequency": 5,
    "geo_location": "London",
    "device_fingerprint": "abc123"
  }
}
```

### Fraud Alert Output
```python
{
  "fraud_probability": 0.85,
  "prediction": 1,  # 1 = fraud, 0 = normal
  "risk_level": "HIGH",
  "user_id": "12345",
  "timestamp": "2025-10-09T10:30:05Z"
}
```

## Dependencies

- **pandas**: Data manipulation and analysis
- **scikit-learn**: Machine learning utilities and evaluation
- **xgboost**: Gradient boosting classifier
- **kafka-python**: Kafka client for real-time streaming
- **joblib**: Model serialization and persistence
- **numpy**: Numerical computing operations

## Building & Running

```bash
pip install -r requirements.txt    # Install dependencies
python detect_fraud.py            # Start fraud detection service
```

## Monitoring

- **Model Performance**: Precision, recall, F1-score tracking
- **Processing Latency**: Kafka message processing time
- **Fraud Rate**: Percentage of transactions flagged as fraudulent
- **Model Drift**: Accuracy degradation over time
- **System Health**: Consumer lag and error rates