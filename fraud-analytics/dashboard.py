#!/usr/bin/env python3
"""
Advanced Fraud Analytics Dashboard
Provides real-time visualization and analytics for fraud detection system
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import psycopg2
from psycopg2.extras import RealDictCursor
import redis
import json
from datetime import datetime, timedelta
import logging
from typing import Dict, List, Any, Optional
import yaml
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class FraudAnalyticsDashboard:
    """Real-time fraud analytics dashboard"""
    
    def __init__(self, config_path: str = "fraud_config.yaml"):
        self.config = self._load_config(config_path)
        self.db_connection = self._init_database()
        self.redis_client = self._init_redis()
    
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Error loading config: {e}")
            return {}
    
    def _init_database(self) -> Optional[psycopg2.connection]:
        """Initialize PostgreSQL connection"""
        try:
            db_config = self.config.get('database', {})
            conn = psycopg2.connect(
                host=db_config.get('host', 'localhost'),
                port=db_config.get('port', 5432),
                database=db_config.get('database', 'fraud_detection'),
                user=db_config.get('user', 'postgres'),
                password=db_config.get('password', 'password')
            )
            return conn
        except Exception as e:
            logger.warning(f"Database connection failed: {e}")
            return None
    
    def _init_redis(self) -> Optional[redis.Redis]:
        """Initialize Redis connection"""
        try:
            redis_config = self.config.get('redis', {})
            client = redis.Redis(
                host=redis_config.get('host', 'localhost'),
                port=redis_config.get('port', 6379),
                db=redis_config.get('db', 0),
                decode_responses=True
            )
            client.ping()
            return client
        except Exception as e:
            logger.warning(f"Redis connection failed: {e}")
            return None
    
    def get_fraud_alerts_data(self, hours: int = 24) -> pd.DataFrame:
        """Get fraud alerts from the last N hours"""
        if not self.db_connection:
            return pd.DataFrame()
        
        try:
            cursor = self.db_connection.cursor(cursor_factory=RealDictCursor)
            cursor.execute("""
                SELECT alert_id, fraud_type, risk_level, confidence_score, user_id, 
                       timestamp, evidence, recommendations
                FROM fraud_alerts 
                WHERE timestamp >= %s 
                ORDER BY timestamp DESC
            """, (datetime.now() - timedelta(hours=hours),))
            
            data = cursor.fetchall()
            return pd.DataFrame(data)
        except Exception as e:
            logger.error(f"Error fetching fraud alerts: {e}")
            return pd.DataFrame()
    
    def get_model_performance_metrics(self) -> Dict[str, Any]:
        """Get current model performance metrics"""
        if not self.redis_client:
            return {}
        
        try:
            metrics = {}
            models = ['xgboost', 'lightgbm', 'catboost', 'neural_network', 'isolation_forest']
            
            for model in models:
                model_metrics = self.redis_client.hgetall(f"model_metrics:{model}")
                if model_metrics:
                    metrics[model] = {k: float(v) for k, v in model_metrics.items()}
            
            return metrics
        except Exception as e:
            logger.error(f"Error fetching model metrics: {e}")
            return {}
    
    def get_real_time_stats(self) -> Dict[str, Any]:
        """Get real-time system statistics"""
        stats = {
            'total_alerts_24h': 0,
            'high_risk_alerts': 0,
            'critical_alerts': 0,
            'false_positive_rate': 0.0,
            'system_load': 0.0,
            'processing_rate': 0.0
        }
        
        # Get from database
        if self.db_connection:
            try:
                cursor = self.db_connection.cursor()
                
                # Total alerts in last 24 hours
                cursor.execute("""
                    SELECT COUNT(*) FROM fraud_alerts 
                    WHERE timestamp >= %s
                """, (datetime.now() - timedelta(hours=24),))
                stats['total_alerts_24h'] = cursor.fetchone()[0]
                
                # High risk alerts
                cursor.execute("""
                    SELECT COUNT(*) FROM fraud_alerts 
                    WHERE risk_level = 'high' AND timestamp >= %s
                """, (datetime.now() - timedelta(hours=24),))
                stats['high_risk_alerts'] = cursor.fetchone()[0]
                
                # Critical alerts
                cursor.execute("""
                    SELECT COUNT(*) FROM fraud_alerts 
                    WHERE risk_level = 'critical' AND timestamp >= %s
                """, (datetime.now() - timedelta(hours=24),))
                stats['critical_alerts'] = cursor.fetchone()[0]
                
            except Exception as e:
                logger.error(f"Error fetching stats: {e}")
        
        # Get from Redis
        if self.redis_client:
            try:
                fp_rate = self.redis_client.get("system_metrics:false_positive_rate")
                if fp_rate:
                    stats['false_positive_rate'] = float(fp_rate)
                
                processing_rate = self.redis_client.get("system_metrics:processing_rate")
                if processing_rate:
                    stats['processing_rate'] = float(processing_rate)
                
            except Exception as e:
                logger.error(f"Error fetching Redis stats: {e}")
        
        return stats
    
    def create_alerts_timeline_chart(self, df: pd.DataFrame) -> go.Figure:
        """Create timeline chart of fraud alerts"""
        if df.empty:
            return go.Figure().add_annotation(text="No data available", 
                                            xref="paper", yref="paper", 
                                            x=0.5, y=0.5, showarrow=False)
        
        # Aggregate by hour and risk level
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df['hour'] = df['timestamp'].dt.floor('H')
        
        hourly_counts = df.groupby(['hour', 'risk_level']).size().reset_index(name='count')
        
        fig = px.line(hourly_counts, x='hour', y='count', color='risk_level',
                     title='Fraud Alerts Timeline (Last 24 Hours)')
        
        fig.update_layout(
            xaxis_title="Time",
            yaxis_title="Number of Alerts",
            hovermode='x unified'
        )
        
        return fig
    
    def create_risk_distribution_chart(self, df: pd.DataFrame) -> go.Figure:
        """Create risk level distribution pie chart"""
        if df.empty:
            return go.Figure()
        
        risk_counts = df['risk_level'].value_counts()
        
        colors = {
            'low': '#28a745',
            'medium': '#ffc107', 
            'high': '#fd7e14',
            'critical': '#dc3545'
        }
        
        fig = go.Figure(data=[go.Pie(
            labels=risk_counts.index,
            values=risk_counts.values,
            marker_colors=[colors.get(level, '#6c757d') for level in risk_counts.index]
        )])
        
        fig.update_layout(title="Alert Risk Level Distribution")
        return fig
    
    def create_fraud_type_chart(self, df: pd.DataFrame) -> go.Figure:
        """Create fraud type distribution chart"""
        if df.empty:
            return go.Figure()
        
        fraud_type_counts = df['fraud_type'].value_counts()
        
        fig = go.Figure(data=[go.Bar(
            x=fraud_type_counts.values,
            y=fraud_type_counts.index,
            orientation='h'
        )])
        
        fig.update_layout(
            title="Fraud Type Distribution",
            xaxis_title="Number of Alerts",
            yaxis_title="Fraud Type"
        )
        
        return fig
    
    def create_confidence_score_distribution(self, df: pd.DataFrame) -> go.Figure:
        """Create confidence score distribution histogram"""
        if df.empty:
            return go.Figure()
        
        fig = go.Figure(data=[go.Histogram(
            x=df['confidence_score'],
            nbinsx=20,
            opacity=0.7
        )])
        
        fig.update_layout(
            title="Fraud Confidence Score Distribution",
            xaxis_title="Confidence Score",
            yaxis_title="Frequency"
        )
        
        return fig
    
    def create_model_performance_chart(self, metrics: Dict[str, Any]) -> go.Figure:
        """Create model performance comparison chart"""
        if not metrics:
            return go.Figure()
        
        models = list(metrics.keys())
        auc_scores = [metrics[model].get('auc_score', 0) for model in models]
        precision_scores = [metrics[model].get('precision', 0) for model in models]
        recall_scores = [metrics[model].get('recall', 0) for model in models]
        
        fig = go.Figure()
        
        fig.add_trace(go.Bar(
            name='AUC Score',
            x=models,
            y=auc_scores,
            yaxis='y',
            offsetgroup=1
        ))
        
        fig.add_trace(go.Bar(
            name='Precision',
            x=models,
            y=precision_scores,
            yaxis='y',
            offsetgroup=2
        ))
        
        fig.add_trace(go.Bar(
            name='Recall',
            x=models,
            y=recall_scores,
            yaxis='y',
            offsetgroup=3
        ))
        
        fig.update_layout(
            title="Model Performance Comparison",
            xaxis_title="Models",
            yaxis_title="Score",
            barmode='group'
        )
        
        return fig

def main():
    """Main Streamlit dashboard application"""
    st.set_page_config(
        page_title="Fraud Analytics Dashboard",
        page_icon="🛡️",
        layout="wide"
    )
    
    st.title("🛡️ Advanced Fraud Analytics Dashboard")
    st.markdown("Real-time fraud detection monitoring and analytics")
    
    # Initialize dashboard
    dashboard = FraudAnalyticsDashboard()
    
    # Sidebar controls
    st.sidebar.header("Dashboard Controls")
    
    # Time range selector
    time_range = st.sidebar.selectbox(
        "Time Range",
        options=[1, 6, 12, 24, 48, 168],  # hours
        format_func=lambda x: f"Last {x} hours" if x < 24 else f"Last {x//24} days",
        index=3  # Default to 24 hours
    )
    
    # Auto-refresh
    auto_refresh = st.sidebar.checkbox("Auto Refresh (30s)", value=True)
    if auto_refresh:
        st.rerun()
    
    # Refresh button
    if st.sidebar.button("🔄 Refresh Data"):
        st.rerun()
    
    # Main dashboard content
    col1, col2, col3, col4 = st.columns(4)
    
    # Get real-time stats
    stats = dashboard.get_real_time_stats()
    
    with col1:
        st.metric(
            label="Total Alerts (24h)",
            value=stats['total_alerts_24h'],
            delta=None
        )
    
    with col2:
        st.metric(
            label="High Risk Alerts",
            value=stats['high_risk_alerts'],
            delta=None
        )
    
    with col3:
        st.metric(
            label="Critical Alerts",
            value=stats['critical_alerts'],
            delta=None
        )
    
    with col4:
        st.metric(
            label="False Positive Rate",
            value=f"{stats['false_positive_rate']:.2%}",
            delta=None
        )
    
    st.divider()
    
    # Get fraud alerts data
    alerts_df = dashboard.get_fraud_alerts_data(hours=time_range)
    
    # Charts row 1
    col1, col2 = st.columns(2)
    
    with col1:
        timeline_chart = dashboard.create_alerts_timeline_chart(alerts_df)
        st.plotly_chart(timeline_chart, use_container_width=True)
    
    with col2:
        risk_chart = dashboard.create_risk_distribution_chart(alerts_df)
        st.plotly_chart(risk_chart, use_container_width=True)
    
    # Charts row 2
    col1, col2 = st.columns(2)
    
    with col1:
        fraud_type_chart = dashboard.create_fraud_type_chart(alerts_df)
        st.plotly_chart(fraud_type_chart, use_container_width=True)
    
    with col2:
        confidence_chart = dashboard.create_confidence_score_distribution(alerts_df)
        st.plotly_chart(confidence_chart, use_container_width=True)
    
    # Model performance
    st.subheader("🤖 Model Performance")
    model_metrics = dashboard.get_model_performance_metrics()
    
    if model_metrics:
        performance_chart = dashboard.create_model_performance_chart(model_metrics)
        st.plotly_chart(performance_chart, use_container_width=True)
    else:
        st.info("Model performance metrics not available")
    
    # Recent alerts table
    st.subheader("🚨 Recent Fraud Alerts")
    
    if not alerts_df.empty:
        # Display recent alerts
        recent_alerts = alerts_df.head(20)[['timestamp', 'fraud_type', 'risk_level', 
                                         'confidence_score', 'user_id']]
        recent_alerts['timestamp'] = recent_alerts['timestamp'].dt.strftime('%Y-%m-%d %H:%M:%S')
        
        st.dataframe(
            recent_alerts,
            use_container_width=True,
            column_config={
                "confidence_score": st.column_config.ProgressColumn(
                    "Confidence Score",
                    help="Fraud confidence score",
                    min_value=0,
                    max_value=1,
                ),
                "risk_level": st.column_config.TextColumn(
                    "Risk Level",
                    help="Alert risk level"
                )
            }
        )
    else:
        st.info("No recent fraud alerts found")
    
    # Footer
    st.divider()
    st.markdown("*Dashboard updates every 30 seconds in auto-refresh mode*")

if __name__ == "__main__":
    main()