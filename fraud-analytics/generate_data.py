#!/usr/bin/env python3
"""
Synthetic Fraud Data Generator
Generates realistic synthetic data for training and testing fraud detection models
"""

import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random
from faker import Faker
import json
from typing import Dict, List, Any, Tuple
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

fake = Faker()

class SyntheticFraudDataGenerator:
    """Generate synthetic fraud detection training data"""
    
    def __init__(self, seed: int = 42):
        np.random.seed(seed)
        random.seed(seed)
        Faker.seed(seed)
        
        # Define fraud patterns and rules
        self.fraud_patterns = {
            'identity_theft': {
                'probability': 0.15,
                'indicators': ['unusual_location', 'new_device', 'multiple_failed_logins']
            },
            'account_takeover': {
                'probability': 0.20,
                'indicators': ['password_change', 'email_change', 'unusual_activity_time']
            },
            'document_fraud': {
                'probability': 0.10,
                'indicators': ['poor_image_quality', 'digital_alteration', 'template_mismatch']
            },
            'behavioral_anomaly': {
                'probability': 0.25,
                'indicators': ['velocity_anomaly', 'location_anomaly', 'device_anomaly']
            },
            'transaction_fraud': {
                'probability': 0.20,
                'indicators': ['unusual_amount', 'merchant_risk', 'velocity_check']
            },
            'synthetic_identity': {
                'probability': 0.10,
                'indicators': ['thin_file', 'inconsistent_data', 'manufactured_identity']
            }
        }
        
        self.ip_ranges = {
            'low_risk': ['192.168.', '10.0.', '172.16.'],
            'medium_risk': ['203.0.113.', '198.51.100.'],
            'high_risk': ['185.220.', '45.129.', '89.248.']
        }
        
        self.user_agents = {
            'normal': [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
                'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
            ],
            'suspicious': [
                'Bot/1.0',
                'Python-requests/2.28.1',
                'curl/7.68.0',
                'Scrapy/2.5.0'
            ]
        }
    
    def generate_user_data(self, num_users: int = 10000) -> pd.DataFrame:
        """Generate synthetic user data"""
        logger.info(f"Generating {num_users} synthetic users...")
        
        users = []
        for i in range(num_users):
            user = {
                'user_id': fake.uuid4(),
                'email': fake.email(),
                'first_name': fake.first_name(),
                'last_name': fake.last_name(),
                'date_of_birth': fake.date_of_birth(minimum_age=18, maximum_age=80),
                'phone': fake.phone_number(),
                'address': fake.address().replace('\n', ', '),
                'city': fake.city(),
                'country': fake.country(),
                'registration_date': fake.date_between(start_date='-2y', end_date='today'),
                'account_status': random.choices(['active', 'suspended', 'closed'], weights=[0.9, 0.08, 0.02])[0],
                'risk_score': np.random.beta(2, 5),  # Skewed towards lower risk
                'is_verified': random.choices([True, False], weights=[0.85, 0.15])[0]
            }
            users.append(user)
        
        return pd.DataFrame(users)
    
    def generate_activity_data(self, users_df: pd.DataFrame, num_activities: int = 100000) -> pd.DataFrame:
        """Generate synthetic user activity data"""
        logger.info(f"Generating {num_activities} synthetic activities...")
        
        activities = []
        user_ids = users_df['user_id'].tolist()
        
        for i in range(num_activities):
            user_id = random.choice(user_ids)
            user_info = users_df[users_df['user_id'] == user_id].iloc[0]
            
            # Determine if this should be a fraudulent activity
            is_fraud = np.random.random() < 0.1  # 10% fraud rate
            
            activity = self._generate_single_activity(user_id, user_info, is_fraud)
            activities.append(activity)
        
        return pd.DataFrame(activities)
    
    def _generate_single_activity(self, user_id: str, user_info: Dict, is_fraud: bool) -> Dict[str, Any]:
        """Generate a single activity record"""
        
        # Base activity
        timestamp = fake.date_time_between(start_date='-30d', end_date='now')
        
        activity = {
            'event_id': fake.uuid4(),
            'user_id': user_id,
            'timestamp': timestamp,
            'activity_type': random.choice(['login', 'logout', 'password_change', 'email_change', 
                                         'document_upload', 'verification_request', 'transaction',
                                         'profile_update', 'settings_change']),
            'outcome': 'success',
            'session_id': fake.uuid4(),
            'request_id': fake.uuid4(),
        }
        
        # Add location and device info
        activity.update(self._generate_location_device_info(is_fraud))
        
        # Add fraud-specific features
        if is_fraud:
            activity.update(self._add_fraud_indicators(activity, user_info))
            activity['label'] = 1  # Fraud label
        else:
            activity['label'] = 0  # Normal label
        
        # Add derived features
        activity.update(self._calculate_derived_features(activity, timestamp))
        
        return activity
    
    def _generate_location_device_info(self, is_fraud: bool) -> Dict[str, Any]:
        """Generate location and device information"""
        
        # IP address
        if is_fraud and np.random.random() < 0.6:
            # High-risk IP for fraud
            ip_prefix = random.choice(self.ip_ranges['high_risk'])
            ip_address = ip_prefix + '.'.join([str(random.randint(1, 254)) for _ in range(4 - ip_prefix.count('.'))])
        else:
            # Normal IP
            ip_prefix = random.choice(self.ip_ranges['low_risk'])
            ip_address = ip_prefix + '.'.join([str(random.randint(1, 254)) for _ in range(4 - ip_prefix.count('.'))])
        
        # User agent
        if is_fraud and np.random.random() < 0.4:
            user_agent = random.choice(self.user_agents['suspicious'])
        else:
            user_agent = random.choice(self.user_agents['normal'])
        
        # Location
        latitude = fake.latitude()
        longitude = fake.longitude()
        
        return {
            'ip_address': ip_address,
            'user_agent': user_agent,
            'latitude': float(latitude),
            'longitude': float(longitude),
            'city': fake.city(),
            'country': fake.country(),
            'device_id': fake.uuid4(),
            'browser': random.choice(['Chrome', 'Firefox', 'Safari', 'Edge']),
            'os': random.choice(['Windows', 'macOS', 'Linux', 'iOS', 'Android'])
        }
    
    def _add_fraud_indicators(self, activity: Dict[str, Any], user_info: Dict) -> Dict[str, Any]:
        """Add fraud-specific indicators to activity"""
        
        fraud_indicators = {}
        
        # Choose fraud type
        fraud_type = np.random.choice(list(self.fraud_patterns.keys()), 
                                    p=[self.fraud_patterns[ft]['probability'] 
                                       for ft in self.fraud_patterns.keys()])
        
        fraud_indicators['fraud_type'] = fraud_type
        
        # Add specific indicators based on fraud type
        if fraud_type == 'identity_theft':
            fraud_indicators['multiple_devices'] = True
            fraud_indicators['location_mismatch'] = True
            fraud_indicators['failed_attempts'] = random.randint(3, 10)
            
        elif fraud_type == 'account_takeover':
            fraud_indicators['password_attempts'] = random.randint(5, 20)
            fraud_indicators['new_location'] = True
            fraud_indicators['unusual_time'] = True
            activity['outcome'] = random.choices(['success', 'failure'], weights=[0.3, 0.7])[0]
            
        elif fraud_type == 'document_fraud':
            fraud_indicators['image_quality_score'] = np.random.uniform(0.1, 0.4)  # Poor quality
            fraud_indicators['tampering_detected'] = True
            fraud_indicators['template_match_score'] = np.random.uniform(0.2, 0.6)
            
        elif fraud_type == 'behavioral_anomaly':
            fraud_indicators['activity_velocity'] = np.random.uniform(5.0, 20.0)  # High velocity
            fraud_indicators['unusual_pattern'] = True
            fraud_indicators['time_deviation'] = np.random.uniform(8.0, 15.0)  # Hours from normal
            
        elif fraud_type == 'transaction_fraud':
            fraud_indicators['transaction_amount'] = np.random.uniform(5000, 50000)  # Large amount
            fraud_indicators['merchant_risk_score'] = np.random.uniform(0.7, 1.0)
            fraud_indicators['velocity_risk'] = True
            
        elif fraud_type == 'synthetic_identity':
            fraud_indicators['credit_history_length'] = random.randint(0, 6)  # Short history
            fraud_indicators['data_inconsistency'] = True
            fraud_indicators['velocity_anomaly'] = True
        
        return fraud_indicators
    
    def _calculate_derived_features(self, activity: Dict[str, Any], timestamp: datetime) -> Dict[str, Any]:
        """Calculate derived features for the activity"""
        
        features = {}
        
        # Time-based features
        features['hour'] = timestamp.hour
        features['day_of_week'] = timestamp.weekday()
        features['is_weekend'] = timestamp.weekday() >= 5
        features['is_night'] = timestamp.hour < 6 or timestamp.hour >= 22
        features['is_business_hours'] = 9 <= timestamp.hour <= 17
        
        # IP risk score
        ip = activity['ip_address']
        if any(ip.startswith(prefix) for prefix in self.ip_ranges['high_risk']):
            features['ip_risk_score'] = np.random.uniform(0.7, 1.0)
        elif any(ip.startswith(prefix) for prefix in self.ip_ranges['medium_risk']):
            features['ip_risk_score'] = np.random.uniform(0.3, 0.7)
        else:
            features['ip_risk_score'] = np.random.uniform(0.0, 0.3)
        
        # Device risk features
        user_agent = activity['user_agent']
        if any(bot in user_agent for bot in ['Bot', 'requests', 'curl', 'Scrapy']):
            features['device_risk_score'] = np.random.uniform(0.8, 1.0)
        else:
            features['device_risk_score'] = np.random.uniform(0.0, 0.2)
        
        # Geographic features
        features['location_risk'] = np.random.uniform(0.0, 1.0)
        features['travel_velocity'] = np.random.uniform(0, 1000)  # km/h if applicable
        
        # Behavioral features
        features['session_duration'] = random.randint(60, 7200)  # seconds
        features['page_views'] = random.randint(1, 50)
        features['click_rate'] = np.random.uniform(0.1, 2.0)
        
        return features
    
    def generate_transaction_data(self, users_df: pd.DataFrame, num_transactions: int = 50000) -> pd.DataFrame:
        """Generate synthetic transaction data"""
        logger.info(f"Generating {num_transactions} synthetic transactions...")
        
        transactions = []
        user_ids = users_df['user_id'].tolist()
        
        for i in range(num_transactions):
            sender_id = random.choice(user_ids)
            receiver_id = random.choice(user_ids) if random.random() < 0.3 else None  # P2P transaction
            
            is_fraud = np.random.random() < 0.08  # 8% fraud rate for transactions
            
            transaction = {
                'transaction_id': fake.uuid4(),
                'sender_id': sender_id,
                'receiver_id': receiver_id,
                'amount': self._generate_transaction_amount(is_fraud),
                'currency': random.choices(['GBP', 'EUR', 'USD'], weights=[0.7, 0.2, 0.1])[0],
                'timestamp': fake.date_time_between(start_date='-30d', end_date='now'),
                'merchant_id': fake.uuid4() if receiver_id is None else None,
                'merchant_category': random.choice(['grocery', 'gas', 'restaurant', 'retail', 'online', 'atm']) if receiver_id is None else None,
                'payment_method': random.choice(['card', 'bank_transfer', 'digital_wallet']),
                'status': random.choices(['completed', 'pending', 'failed'], weights=[0.9, 0.05, 0.05])[0],
                'label': 1 if is_fraud else 0
            }
            
            # Add fraud indicators for fraudulent transactions
            if is_fraud:
                transaction.update(self._add_transaction_fraud_indicators(transaction))
            
            transactions.append(transaction)
        
        return pd.DataFrame(transactions)
    
    def _generate_transaction_amount(self, is_fraud: bool) -> float:
        """Generate transaction amount based on fraud status"""
        if is_fraud:
            # Fraudulent transactions: either very small (testing) or very large
            if random.random() < 0.3:
                return round(random.uniform(0.01, 5.0), 2)  # Small test amounts
            else:
                return round(random.uniform(1000, 25000), 2)  # Large amounts
        else:
            # Normal transactions: log-normal distribution
            return round(np.random.lognormal(mean=3.0, sigma=1.5), 2)
    
    def _add_transaction_fraud_indicators(self, transaction: Dict[str, Any]) -> Dict[str, Any]:
        """Add fraud indicators to transaction"""
        indicators = {}
        
        # Unusual amounts
        if transaction['amount'] > 5000:
            indicators['large_amount_flag'] = True
            
        if transaction['amount'] < 1:
            indicators['micro_transaction_flag'] = True
        
        # Round amounts (common in fraud)
        if transaction['amount'] % 10 == 0:
            indicators['round_amount'] = True
        
        # Velocity indicators
        indicators['transaction_velocity'] = np.random.uniform(5, 50)  # transactions per hour
        indicators['amount_velocity'] = np.random.uniform(10000, 100000)  # amount per hour
        
        # Risk indicators
        indicators['merchant_risk_score'] = np.random.uniform(0.7, 1.0)
        indicators['card_present'] = False  # Card not present transactions are riskier
        indicators['international_transaction'] = random.choice([True, False])
        
        return indicators
    
    def generate_training_dataset(self, num_users: int = 5000, num_activities: int = 50000, 
                                num_transactions: int = 25000) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
        """Generate complete training dataset"""
        logger.info("Generating complete synthetic fraud detection dataset...")
        
        # Generate users
        users_df = self.generate_user_data(num_users)
        
        # Generate activities
        activities_df = self.generate_activity_data(users_df, num_activities)
        
        # Generate transactions
        transactions_df = self.generate_transaction_data(users_df, num_transactions)
        
        logger.info("Dataset generation completed!")
        logger.info(f"Users: {len(users_df)}, Activities: {len(activities_df)}, Transactions: {len(transactions_df)}")
        logger.info(f"Fraud rate - Activities: {activities_df['label'].mean():.2%}, Transactions: {transactions_df['label'].mean():.2%}")
        
        return users_df, activities_df, transactions_df
    
    def save_datasets(self, users_df: pd.DataFrame, activities_df: pd.DataFrame, 
                     transactions_df: pd.DataFrame, output_dir: str = "."):
        """Save generated datasets to CSV files"""
        import os
        
        os.makedirs(output_dir, exist_ok=True)
        
        users_df.to_csv(f"{output_dir}/synthetic_users.csv", index=False)
        activities_df.to_csv(f"{output_dir}/synthetic_activities.csv", index=False)
        transactions_df.to_csv(f"{output_dir}/synthetic_transactions.csv", index=False)
        
        # Create combined training dataset for ML models
        ml_features = self._prepare_ml_features(activities_df, transactions_df)
        ml_features.to_csv(f"{output_dir}/fraud_training_data.csv", index=False)
        
        logger.info(f"Datasets saved to {output_dir}/")
    
    def _prepare_ml_features(self, activities_df: pd.DataFrame, transactions_df: pd.DataFrame) -> pd.DataFrame:
        """Prepare features for ML training"""
        
        # Select relevant columns for ML training
        activity_features = [
            'hour', 'day_of_week', 'is_weekend', 'is_night', 'is_business_hours',
            'ip_risk_score', 'device_risk_score', 'location_risk', 'session_duration',
            'page_views', 'click_rate', 'label'
        ]
        
        transaction_features = [
            'amount', 'label'
        ]
        
        # Filter and prepare activity features
        activities_ml = activities_df[activity_features].copy()
        activities_ml['data_type'] = 'activity'
        
        # Prepare transaction features (simplified)
        if not transactions_df.empty:
            transactions_ml = transactions_df[['amount', 'label']].copy()
            
            # Add dummy features to match activity schema
            for col in activity_features[:-1]:  # Exclude 'label'
                if col not in transactions_ml.columns:
                    if col == 'amount':
                        continue  # Already have amount
                    elif 'risk' in col:
                        transactions_ml[col] = np.random.uniform(0, 1, len(transactions_ml))
                    else:
                        transactions_ml[col] = 0
            
            transactions_ml['data_type'] = 'transaction'
            
            # Combine datasets
            combined_ml = pd.concat([activities_ml, transactions_ml], ignore_index=True)
        else:
            combined_ml = activities_ml
        
        return combined_ml


def main():
    """Main execution function"""
    print("🔧 Synthetic Fraud Data Generator")
    print("=" * 50)
    
    # Initialize generator
    generator = SyntheticFraudDataGenerator(seed=42)
    
    # Generate datasets
    users_df, activities_df, transactions_df = generator.generate_training_dataset(
        num_users=5000,
        num_activities=50000,
        num_transactions=25000
    )
    
    # Save datasets
    generator.save_datasets(users_df, activities_df, transactions_df)
    
    # Display summary statistics
    print("\n📊 Dataset Summary:")
    print(f"Total Users: {len(users_df):,}")
    print(f"Total Activities: {len(activities_df):,}")
    print(f"Total Transactions: {len(transactions_df):,}")
    print(f"Activity Fraud Rate: {activities_df['label'].mean():.2%}")
    print(f"Transaction Fraud Rate: {transactions_df['label'].mean():.2%}")
    
    print("\n✅ Data generation completed successfully!")
    print("Files created:")
    print("  - synthetic_users.csv")
    print("  - synthetic_activities.csv") 
    print("  - synthetic_transactions.csv")
    print("  - fraud_training_data.csv")


if __name__ == "__main__":
    main()