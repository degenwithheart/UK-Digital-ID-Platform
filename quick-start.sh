#!/bin/bash

# 🚀 UK Digital Identity Platform - Quick Start Script
# Simplified initialization for development

set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log() { echo -e "${BLUE}🔄 $1${NC}"; }
success() { echo -e "${GREEN}✅ $1${NC}"; }
warning() { echo -e "${YELLOW}⚠️  $1${NC}"; }
error() { echo -e "${RED}❌ $1${NC}"; }

echo -e "${BLUE}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║             🇬🇧 UK Digital Identity Platform                 ║"
echo "║                     Quick Start                              ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check if required files exist
if [ ! -f "./initialize-platform.sh" ]; then
    error "Full initialization script not found!"
    echo "Please ensure initialize-platform.sh is in the same directory."
    exit 1
fi

if [ ! -f "./.env.template" ]; then
    error "Environment template not found!"
    echo "Please ensure .env.template is in the project root."
    exit 1
fi

# Process environment template if .env doesn't exist
if [ ! -f "./.env" ]; then
    log "Processing environment template..."
    source ./initialize-platform.sh
    process_environment_template
fi

echo ""
echo "Choose initialization method:"
echo ""
echo "1. 🚀 Full System Initialization (All 7 components)"
echo "   - Complete setup with all services"
echo "   - Recommended for development/production"
echo ""
echo "2. 🐳 Infrastructure Only (Docker services)"
echo "   - Database, Redis, Kafka, Monitoring"
echo "   - Quick setup for testing individual components"
echo ""
echo "3. 🔧 Development Mode (Core services only)"
echo "   - Infrastructure + Go Gateway + Kotlin Connectors"
echo "   - Fast setup for API development"
echo ""
echo "4. 📊 Analytics Setup (Infrastructure + Python)"
echo "   - Infrastructure + Fraud Analytics"
echo "   - For ML model development"
echo ""

read -p "Select option (1-4): " choice

case $choice in
    1)
        log "Starting full system initialization..."
        ./initialize-platform.sh
        ;;
    2)
        log "Starting infrastructure only..."
        cd infra
        
        # Create basic .env if it doesn't exist
        if [ ! -f ".env" ]; then
            log "Creating basic environment configuration..."
            cat > .env << 'EOF'
POSTGRES_DB=digital_identity
POSTGRES_USER=digital_user
POSTGRES_PASSWORD=secure_digital_password_2025
REDIS_PASSWORD=secure_redis_password_2025
GRAFANA_ADMIN_PASSWORD=admin_secure_2025
EOF
        fi
        
        log "Starting infrastructure services..."
        docker-compose up -d postgres redis kafka zookeeper prometheus grafana
        
        echo ""
        success "Infrastructure services started!"
        echo ""
        echo "Available services:"
        echo "  📊 Prometheus:  http://localhost:9090"
        echo "  📈 Grafana:     http://localhost:3002 (admin/admin_secure_2025)"
        echo "  🐘 PostgreSQL:  localhost:5432"
        echo "  📦 Redis:       localhost:6379"
        echo "  📊 Kafka:       localhost:9092"
        ;;
    3)
        log "Starting development mode..."
        
        # Start infrastructure first
        cd infra
        if [ ! -f ".env" ]; then
            cat > .env << 'EOF'
POSTGRES_DB=digital_identity
POSTGRES_USER=digital_user
POSTGRES_PASSWORD=secure_digital_password_2025
REDIS_PASSWORD=secure_redis_password_2025
EOF
        fi
        
        docker-compose up -d postgres redis kafka zookeeper
        cd ..
        
        # Quick build and start Go gateway
        log "Starting Go API Gateway..."
        cd digital-id-services
        
        if [ ! -f ".env" ]; then
            cat > .env << 'EOF'
PORT=8080
DATABASE_URL=postgresql://digital_user:secure_digital_password_2025@localhost:5432/digital_identity
REDIS_URL=redis://:secure_redis_password_2025@localhost:6379
JWT_SECRET=dev_jwt_secret_key
LOG_LEVEL=info
EOF
        fi
        
        # Start Go service in background
        nohup go run gateway/main.go > ../logs/go-gateway-quick.log 2>&1 &
        echo $! > ../logs/go-gateway.pid
        cd ..
        
        # Quick start Kotlin connectors
        log "Starting Kotlin Government Connectors..."
        cd gov-connectors
        
        mkdir -p src/main/resources
        if [ ! -f "src/main/resources/application-dev.yml" ]; then
            cat > src/main/resources/application-dev.yml << 'EOF'
server:
  port: 8081
spring:
  datasource:
    url: jdbc:postgresql://localhost:5432/digital_identity
    username: digital_user
    password: secure_digital_password_2025
logging:
  level:
    root: INFO
EOF
        fi
        
        # Start Kotlin service in background
        nohup ./gradlew bootRun --args='--spring.profiles.active=dev' > ../logs/kotlin-connectors-quick.log 2>&1 &
        echo $! > ../logs/kotlin-connectors.pid
        cd ..
        
        success "Development environment started!"
        echo ""
        echo "Available services:"
        echo "  🚀 API Gateway:      http://localhost:8080"
        echo "  ☕ Gov Connectors:   http://localhost:8081"
        echo "  📊 Database:         localhost:5432"
        echo ""
        echo "Test with: curl http://localhost:8080/health"
        ;;
    4)
        log "Starting analytics setup..."
        
        # Start infrastructure
        cd infra
        if [ ! -f ".env" ]; then
            cat > .env << 'EOF'
POSTGRES_DB=digital_identity
POSTGRES_USER=digital_user
POSTGRES_PASSWORD=secure_digital_password_2025
REDIS_PASSWORD=secure_redis_password_2025
EOF
        fi
        
        docker-compose up -d postgres redis kafka zookeeper
        cd ..
        
        # Start Python analytics
        log "Starting Python Fraud Analytics..."
        cd fraud-analytics
        
        # Create virtual environment if needed
        if [ ! -d "venv" ]; then
            python3 -m venv venv
        fi
        
        source venv/bin/activate
        
        if [ ! -f ".env" ]; then
            cat > .env << 'EOF'
DATABASE_URL=postgresql://digital_user:secure_digital_password_2025@localhost:5432/digital_identity
REDIS_URL=redis://:secure_redis_password_2025@localhost:6379
KAFKA_BOOTSTRAP_SERVERS=localhost:9092
STREAMLIT_SERVER_PORT=8083
EOF
        fi
        
        # Install basic dependencies if requirements.txt doesn't exist
        if [ ! -f "requirements.txt" ]; then
            pip install streamlit pandas numpy scikit-learn
        else
            pip install -r requirements.txt
        fi
        
        # Start Streamlit dashboard
        nohup streamlit run dashboard.py --server.port 8083 > ../logs/analytics-quick.log 2>&1 &
        echo $! > ../logs/analytics.pid
        cd ..
        
        success "Analytics environment started!"
        echo ""
        echo "Available services:"
        echo "  🐍 Analytics Dashboard: http://localhost:8083"
        echo "  📊 Database:           localhost:5432"
        echo "  📦 Redis:              localhost:6379"
        echo "  📊 Kafka:              localhost:9092"
        ;;
    *)
        error "Invalid option selected"
        exit 1
        ;;
esac

# Create logs directory if it doesn't exist
mkdir -p logs

echo ""
success "Quick start completed!"
echo ""
echo "Additional commands:"
echo "  📊 Check status:  ./check-system-status.sh"
echo "  🔄 Sync services: ./sync-components.sh"
echo "  🚀 Full setup:    ./initialize-platform.sh"
echo "  📋 View logs:     tail -f logs/*.log"
echo ""
echo "To stop services:"
echo "  kill \$(cat logs/*.pid) 2>/dev/null || true"
echo "  docker-compose -f infra/docker-compose.yml down"