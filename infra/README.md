# 🐳 Infrastructure (Docker & Kubernetes)

Enterprise-grade infrastructure platform for the UK Digital Identity Platform with comprehensive containerization, orchestration, monitoring, and security features.

## 🎯 Features

- **Multi-Service Docker Compose**: 15+ containerized services with encrypted bridge networks
- **Production Kubernetes**: Multi-namespace deployment with HPA auto-scaling and admission controllers  
- **Event-Driven Sync**: Redis pub/sub integration for cross-service synchronization with secure routing
- **Enterprise Data Stack**: PostgreSQL HA cluster, Redis cluster, Kafka streaming, HashiCorp Vault secrets
- **Complete Observability**: Prometheus metrics, Grafana dashboards, Jaeger distributed tracing, ELK stack logging
- **Security-First**: mTLS between services, Network Policies for traffic control, secret management, vulnerability scanning
- **CI/CD Integration**: Automated deployments with Helm charts, GitOps workflows, blue-green deployments

## 🏗️ Production Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                Production Kubernetes Cluster                │
│                                                             │
│ ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐│
│ │  Application    │  │   Monitoring    │  │    System       ││
│ │   Namespace     │  │   Namespace     │  │   Namespace     ││
│ │                 │  │                 │  │                 ││
│ │ • Rust Core     │  │ • Prometheus    │  │ • Vault         ││
│ │ • Go Services   │  │ • Grafana       │  │ • Consul        ││
│ │ • Kotlin APIs   │  │ • Jaeger        │  │ • Nginx LB      ││
│ │ • React Portals │  │ • ELK Stack     │  │ • Cert Manager  ││
│ │ • Python ML     │  │ • AlertManager  │  │ • External DNS  ││
│ └─────────────────┘  └─────────────────┘  └─────────────────┘│
│          │                    │                    │         │
│ ┌────────▼────────────────────▼────────────────────▼───────┐ │
│ │               Data & Messaging Layer                   │ │
│ │                                                        │ │
│ │ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐   │ │
│ │ │PostgreSQL│ │  Redis   │ │  Kafka   │ │MinIO/S3  │   │ │
│ │ │ HA Cluster│ │ Cluster  │ │Streaming │ │ Storage  │   │ │
│ │ │ (Sync)    │ │ (Pub/Sub)│ │(Events)  │ │ (Secure) │   │ │
│ │ └──────────┘ └──────────┘ └──────────┘ └──────────┘   │ │
│ └────────────────────────────────────────────────────────┘ │
│                           │                                 │
│ ┌─────────────────────────▼─────────────────────────────────┐ │
│ │            Network Policies & Security Layer             │ │
│ │                                                          │ │
│ │ • Service Mesh (mTLS) • Network Policies • Event Routing │ │
│ │ • Encrypted Networks  • Traffic Control  • Secure Sync   │ │
│ └──────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

## 📦 Infrastructure Components

| Category | Service | Purpose | Scaling | Ports |
|----------|---------|---------|---------|-------|
| **Application** | rust-core | Crypto engine | 3-10 pods | 3000 |
| | digital-id-gateway | API gateway | 3-10 pods | 8081 |
| | gov-connectors | Government APIs | 3 pods | 8070 |
| | fraud-analytics | ML processing | 2-5 pods | 8090 |
| | citizen-portal | Web interface | 2-8 pods | 3002 |
| | admin-dashboard | Admin interface | 2-4 pods | 3001 |
| **Data** | postgresql | Primary database | HA cluster | 5432 |
| | redis | Cache/sessions | 3-node cluster | 6379 |
| | kafka | Event streaming | 3 brokers | 9092 |
| | minio | Object storage | 4-node cluster | 9000 |
| **Monitoring** | prometheus | Metrics collection | HA pair | 9090 |
| | grafana | Visualization | 2 pods | 3003 |
| | jaeger | Distributed tracing | Cluster | 14268 |
| | elasticsearch | Log storage | 3-node cluster | 9200 |
| **Security** | vault | Secret management | HA cluster | 8200 |
| | consul | Service discovery | 3 nodes | 8500 |

## 🔄 Sync Capabilities

- **Redis Pub/Sub Integration**: Event-driven synchronization across all services
- **HPA Auto-Scaling**: Horizontal Pod Autoscaling based on CPU/memory and custom metrics
- **Network Policies**: Kubernetes Network Policies for secure inter-service communication
- **Event Routing**: Secure routing of government feed events through encrypted channels
- **Service Mesh**: Istio or Linkerd integration for advanced traffic management

## Services Configuration

### Docker Compose Services

#### Application Services
- **go-gateway** (Port 8080): API gateway with Rust FFI integration
- **kotlin-connectors** (Port 8081): Government API integrations  
- **nextjs-portal** (Port 3001): Web interface for citizens
- **rust-core** (Port 3000): Cryptographic engine (if standalone)

#### Infrastructure Services
- **postgres** (Port 5432): Primary database with persistent storage
- **kafka** (Port 9092): Message streaming for audit events
- **zookeeper** (Port 2181): Kafka coordination service
- **prometheus** (Port 9090): Metrics collection and monitoring
- **grafana** (Port 3002): Visualization dashboards

### Environment Configuration

#### Secrets Management (.env)
```bash
# Database
DB_PASSWORD=secure_database_password_change_in_prod

# Authentication  
JWT_SECRET=your-very-secure-jwt-secret-key-minimum-32-chars

# External APIs
HMRC_API_KEY=government_api_key_from_hmrc
DVLA_API_KEY=government_api_key_from_dvla

# Monitoring
PROMETHEUS_PASSWORD=monitoring_dashboard_password
```

#### Database Connection
```yaml
DATABASE_URL: "host=postgres user=user password=${DB_PASSWORD} dbname=digital_id port=5432 sslmode=disable TimeZone=UTC"
```

## Kubernetes Deployment

### Service Definitions
```yaml
apiVersion: v1
kind: Service
metadata:
  name: go-gateway-service
spec:
  selector:
    app: go-gateway
  ports:
    - port: 8080
      targetPort: 8080
  type: LoadBalancer
```

### Deployment Configuration
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: go-gateway-deployment
spec:
  replicas: 3
  selector:
    matchLabels:
      app: go-gateway
  template:
    metadata:
      labels:
        app: go-gateway
    spec:
      containers:
      - name: go-gateway
        image: digital-id/go-gateway:latest
        ports:
        - containerPort: 8080
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: db-secret
              key: url
```

## Database Configuration

### PostgreSQL Setup
```yaml
postgres:
  image: postgres:15
  environment:
    POSTGRES_DB: digital_id
    POSTGRES_USER: user  
    POSTGRES_PASSWORD: ${DB_PASSWORD}
  ports:
    - "5432:5432"
  volumes:
    - postgres_data:/var/lib/postgresql/data
    - ./init-db.sql:/docker-entrypoint-initdb.d/init-db.sql
```

### Database Schema
- **Users Table**: Authentication and profile information
- **Credentials Table**: Digital identity credentials with signatures
- **Audit Logs Table**: Transaction history and compliance records
- **Sessions Table**: Active user sessions and tokens

## Message Streaming

### Kafka Configuration
```yaml
kafka:
  image: confluentinc/cp-kafka:7.4.0
  environment:
    KAFKA_ZOOKEEPER_CONNECT: zookeeper:2181
    KAFKA_ADVERTISED_LISTENERS: PLAINTEXT://kafka:29092,PLAINTEXT_HOST://localhost:9092
    KAFKA_LISTENER_SECURITY_PROTOCOL_MAP: PLAINTEXT:PLAINTEXT,PLAINTEXT_HOST:PLAINTEXT
    KAFKA_INTER_BROKER_LISTENER_NAME: PLAINTEXT
```

### Topics
- **audit-logs**: User registration, login, credential issuance events
- **fraud-alerts**: High-risk transaction notifications
- **system-metrics**: Service health and performance data

## Monitoring & Observability

### Prometheus Configuration
```yaml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'go-gateway'
    static_configs:
      - targets: ['go-gateway:8080']
  
  - job_name: 'kotlin-connectors'
    static_configs:
      - targets: ['kotlin-connectors:8080']
  
  - job_name: 'postgres-exporter'
    static_configs:
      - targets: ['postgres-exporter:9187']
```

### Grafana Dashboards
- **Service Health**: Uptime, response times, error rates
- **Database Metrics**: Connection pools, query performance, storage usage
- **Kafka Metrics**: Message throughput, consumer lag, partition distribution
- **Business Metrics**: User registrations, credential issuance, fraud detection

## Security Configuration

### SSL/TLS Setup
```yaml
volumes:
  - ./ssl:/etc/ssl/certs  # Mount SSL certificates
environment:
  - TLS_CERT_PATH=/etc/ssl/certs/server.crt
  - TLS_KEY_PATH=/etc/ssl/certs/server.key
```

### Network Security
- **Internal Networks**: Isolated communication between services
- **Ingress Controllers**: External traffic routing and SSL termination
- **Network Policies**: Kubernetes pod-to-pod communication restrictions
- **Secrets Management**: Encrypted storage of sensitive configuration

## Deployment Commands

### Local Development
```bash
# Start all services
docker-compose --env-file .env up --build

# Start specific services
docker-compose up postgres kafka zookeeper

# View service logs  
docker-compose logs -f go-gateway

# Scale services
docker-compose up --scale go-gateway=3
```

### Production Deployment
```bash
# Apply Kubernetes manifests
kubectl apply -f k8s/

# Check deployment status
kubectl get pods -n digital-id

# View service logs
kubectl logs -f deployment/go-gateway-deployment

# Scale deployments
kubectl scale deployment go-gateway-deployment --replicas=5
```

## Health Checks

### Service Health Endpoints
- **Go Gateway**: `GET /health` - API gateway health status
- **Kotlin Connectors**: `GET /actuator/health` - Spring Boot health check
- **Database**: Connection pool status and query responsiveness
- **Kafka**: Broker health and topic availability

### Kubernetes Probes
```yaml
livenessProbe:
  httpGet:
    path: /health
    port: 8080
  initialDelaySeconds: 30
  periodSeconds: 10

readinessProbe:
  httpGet:
    path: /health
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 5
```

## Backup & Recovery

### Database Backups
```bash
# Automated PostgreSQL backups
docker exec postgres pg_dump -U user digital_id > backup-$(date +%Y%m%d).sql

# Restore from backup
docker exec -i postgres psql -U user digital_id < backup-20251009.sql
```

### Disaster Recovery
- **Multi-Region Deployment**: Geographic distribution for availability
- **Data Replication**: PostgreSQL streaming replication
- **Backup Strategy**: Daily full backups with point-in-time recovery
- **Failover Procedures**: Automated service failover with health checks

## Performance Tuning

### Resource Limits
```yaml
resources:
  requests:
    memory: "256Mi"
    cpu: "250m"
  limits:
    memory: "512Mi"  
    cpu: "500m"
```

### Database Optimization
- **Connection Pooling**: PgBouncer for connection management
- **Query Optimization**: Indexed columns for frequent lookups
- **Memory Configuration**: Tuned PostgreSQL memory settings
- **Storage**: SSD storage for improved I/O performance

## Maintenance

### Updates & Patches
```bash
# Rolling updates in Kubernetes
kubectl set image deployment/go-gateway-deployment go-gateway=digital-id/go-gateway:v1.2.0

# Docker Compose updates
docker-compose pull
docker-compose up -d --no-deps go-gateway
```

### Monitoring Maintenance
- **Log Rotation**: Automated log cleanup and archival
- **Metric Retention**: Prometheus data retention policies  
- **Alert Management**: Notification rules for critical issues
- **Capacity Planning**: Resource usage trend analysis