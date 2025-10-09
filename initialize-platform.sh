#!/bin/bash

# 🚀 UK Digital Identity Platform - Comprehensive Initialization Script
# Systematically initializes all 7 components with dependency management

set -e

# Script metadata
SCRIPT_VERSION="1.0.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${SCRIPT_DIR}"
LOG_DIR="${PROJECT_ROOT}/logs"
CONFIG_DIR="${PROJECT_ROOT}/.init-config"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Logging functions
log() { echo -e "${BLUE}[$(date '+%H:%M:%S')] 🔄 $1${NC}"; }
success() { echo -e "${GREEN}[$(date '+%H:%M:%S')] ✅ $1${NC}"; }
warning() { echo -e "${YELLOW}[$(date '+%H:%M:%S')] ⚠️  $1${NC}"; }
error() { echo -e "${RED}[$(date '+%H:%M:%S')] ❌ $1${NC}"; }
info() { echo -e "${PURPLE}[$(date '+%H:%M:%S')] ℹ️  $1${NC}"; }
header() { echo -e "${CYAN}[$(date '+%H:%M:%S')] 🎯 $1${NC}"; }

# Environment template path
ENV_TEMPLATE="${PROJECT_ROOT}/.env.template"
ENV_FILE="${PROJECT_ROOT}/.env"

# Component configuration
declare -A COMPONENTS=(
    ["infrastructure"]="infra"
    ["core-engine"]="core-id-engine"
    ["digital-services"]="digital-id-services"
    ["gov-connectors"]="gov-connectors"
    ["fraud-analytics"]="fraud-analytics"
    ["web-portal"]="web-portal"
    ["mobile-wallet"]="mobile-wallet"
)

declare -A COMPONENT_LANGUAGES=(
    ["infrastructure"]="docker"
    ["core-engine"]="rust"
    ["digital-services"]="go"
    ["gov-connectors"]="kotlin"
    ["fraud-analytics"]="python"
    ["web-portal"]="typescript"
    ["mobile-wallet"]="flutter"
)

declare -A COMPONENT_PORTS=(
    ["infrastructure"]="5432,6379,9092,9090,3002"
    ["core-engine"]="FFI"
    ["digital-services"]="8080"
    ["gov-connectors"]="8081"
    ["fraud-analytics"]="8083"
    ["web-portal"]="3001"
    ["mobile-wallet"]="simulator"
)

declare -A STARTUP_ORDER=(
    [1]="infrastructure"
    [2]="core-engine"
    [3]="digital-services"
    [4]="gov-connectors"
    [5]="fraud-analytics"
    [6]="web-portal"
    [7]="mobile-wallet"
)

# Global status tracking
declare -A COMPONENT_STATUS=()
TOTAL_STEPS=0
CURRENT_STEP=0

# Initialization phases
PHASE_INJECT="inject"
PHASE_INSTALL="install"
PHASE_BUILD="build"
PHASE_START="start"
PHASE_VERIFY="verify"

# Configuration templates
create_directories() {
    log "Creating initialization directories..."
    mkdir -p "${LOG_DIR}" "${CONFIG_DIR}"
    success "Directories created"
}

save_log() {
    local component="$1"
    local phase="$2"
    local message="$3"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[${timestamp}] [${component}] [${phase}] ${message}" >> "${LOG_DIR}/init-$(date '+%Y%m%d').log"
}

print_banner() {
    clear
    echo -e "${CYAN}"
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║                🇬🇧 UK Digital Identity Platform                ║"
    echo "║                  System Initialization Script                  ║"
    echo "║                                                                ║"
    echo "║  Version: ${SCRIPT_VERSION}                                            ║"
    echo "║  Components: 7                                                 ║"
    echo "║  Languages: 6                                                  ║"
    echo "║  Government APIs: 25                                           ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

check_prerequisites() {
    header "Phase 0: Prerequisites Check"
    
    local missing_tools=()
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        missing_tools+=("docker")
    fi
    
    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        missing_tools+=("docker-compose")
    fi
    
    # Check programming languages
    if ! command -v cargo &> /dev/null; then
        missing_tools+=("rust/cargo")
    fi
    
    if ! command -v go &> /dev/null; then
        missing_tools+=("go")
    fi
    
    if ! command -v java &> /dev/null; then
        missing_tools+=("java/kotlin")
    fi
    
    if ! command -v node &> /dev/null; then
        missing_tools+=("node.js")
    fi
    
    if ! command -v python3 &> /dev/null; then
        missing_tools+=("python3")
    fi
    
    if ! command -v flutter &> /dev/null; then
        missing_tools+=("flutter")
    fi
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        error "Missing prerequisites: ${missing_tools[*]}"
        echo ""
        echo "Please install the missing tools:"
        echo "  - Docker: https://docs.docker.com/get-docker/"
        echo "  - Docker Compose: https://docs.docker.com/compose/install/"
        echo "  - Rust: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
        echo "  - Go: https://golang.org/doc/install"
        echo "  - Java/Kotlin: https://adoptopenjdk.net/"
        echo "  - Node.js: https://nodejs.org/"
        echo "  - Python: https://www.python.org/downloads/"
        echo "  - Flutter: https://flutter.dev/docs/get-started/install"
        exit 1
    fi
    
    success "All prerequisites satisfied"
}

# Generate secure random secrets
generate_secret() {
    local length=${1:-32}
    openssl rand -hex $length 2>/dev/null || head -c $length /dev/urandom | xxd -p -c $length
}

generate_password() {
    local length=${1:-16}
    openssl rand -base64 $length 2>/dev/null | tr -d "=+/" | cut -c1-$length || head -c $length /dev/urandom | base64 | tr -d "=+/" | cut -c1-$length
}

generate_jwt_secret() {
    generate_secret 32
}

generate_aes_key() {
    generate_secret 32
}

generate_ed25519_keypair() {
    local private_key=$(openssl genpkey -algorithm Ed25519 2>/dev/null | openssl pkey -text -noout | grep -A 5 "priv:" | tail -n +2 | tr -d '[:space:]:' || generate_secret 32)
    local public_key=$(echo $private_key | xxd -r -p | openssl pkey -pubout 2>/dev/null | openssl pkey -pubin -text -noout | grep -A 3 "pub:" | tail -n +2 | tr -d '[:space:]:' || generate_secret 32)
    echo "$private_key:$public_key"
}

# Process environment template and generate .env file
process_environment_template() {
    header "Processing Environment Template"
    
    if [ ! -f "$ENV_TEMPLATE" ]; then
        error "Environment template not found: $ENV_TEMPLATE"
        exit 1
    fi
    
    log "Loading environment template..."
    cp "$ENV_TEMPLATE" "$ENV_FILE"
    
    # Generate secrets
    log "Generating cryptographic secrets..."
    local postgres_password=$(generate_password 24)
    local redis_password=$(generate_password 20)
    local jwt_secret=$(generate_jwt_secret)
    local aes_key=$(generate_aes_key)
    local api_secret=$(generate_secret 24)
    local webhook_secret=$(generate_secret 16)
    local rate_limit_secret=$(generate_secret 12)
    local nextauth_secret=$(generate_secret 16)
    local grafana_password=$(generate_password 16)
    local grafana_secret=$(generate_secret 8)
    
    # Generate Ed25519 keypair
    local keypair=$(generate_ed25519_keypair)
    local ed25519_private=$(echo "$keypair" | cut -d':' -f1)
    local ed25519_public=$(echo "$keypair" | cut -d':' -f2)
    
    # Replace placeholders in .env file
    log "Injecting generated secrets..."
    sed -i.bak \
        -e "s/POSTGRES_PASSWORD=\"\"/POSTGRES_PASSWORD=\"$postgres_password\"/" \
        -e "s/REDIS_PASSWORD=\"\"/REDIS_PASSWORD=\"$redis_password\"/" \
        -e "s/JWT_SECRET=\"\"/JWT_SECRET=\"$jwt_secret\"/" \
        -e "s/AES_ENCRYPTION_KEY=\"\"/AES_ENCRYPTION_KEY=\"$aes_key\"/" \
        -e "s/ED25519_PRIVATE_KEY=\"\"/ED25519_PRIVATE_KEY=\"$ed25519_private\"/" \
        -e "s/ED25519_PUBLIC_KEY=\"\"/ED25519_PUBLIC_KEY=\"$ed25519_public\"/" \
        -e "s/API_SECRET_KEY=\"\"/API_SECRET_KEY=\"$api_secret\"/" \
        -e "s/WEBHOOK_SECRET=\"\"/WEBHOOK_SECRET=\"$webhook_secret\"/" \
        -e "s/RATE_LIMIT_SECRET=\"\"/RATE_LIMIT_SECRET=\"$rate_limit_secret\"/" \
        -e "s/NEXTAUTH_SECRET=\"\"/NEXTAUTH_SECRET=\"$nextauth_secret\"/" \
        -e "s/GRAFANA_ADMIN_PASSWORD=\"\"/GRAFANA_ADMIN_PASSWORD=\"$grafana_password\"/" \
        -e "s/GRAFANA_SECRET_KEY=\"\"/GRAFANA_SECRET_KEY=\"$grafana_secret\"/" \
        "$ENV_FILE"
    
    # Clean up backup file
    rm -f "$ENV_FILE.bak"
    
    success "Environment configuration generated: $ENV_FILE"
    info "✨ All secrets have been generated automatically"
    info "📝 Review $ENV_FILE to customize API keys and government credentials"
}

# Helper function to extract value from .env file
get_env_value() {
    local key="$1"
    local env_file="${2:-$ENV_FILE}"
    
    if [ -f "$env_file" ]; then
        grep "^$key=" "$env_file" | cut -d'=' -f2- | sed 's/^["'"'"']//;s/["'"'"']$//' | head -1
    else
        echo ""
    fi
}

inject_configuration() {
    local component="$1"
    local component_dir="${PROJECT_ROOT}/${COMPONENTS[$component]}"
    
    log "[$component] Injecting configuration..."
    save_log "$component" "$PHASE_INJECT" "Starting configuration injection"
    
    case "${COMPONENT_LANGUAGES[$component]}" in
        "docker")
            inject_infrastructure_config "$component_dir"
            ;;
        "rust")
            inject_rust_config "$component_dir"
            ;;
        "go")
            inject_go_config "$component_dir"
            ;;
        "kotlin")
            inject_kotlin_config "$component_dir"
            ;;
        "python")
            inject_python_config "$component_dir"
            ;;
        "typescript")
            inject_typescript_config "$component_dir"
            ;;
        "flutter")
            inject_flutter_config "$component_dir"
            ;;
    esac
    
    success "[$component] Configuration injected"
    save_log "$component" "$PHASE_INJECT" "Configuration injection completed"
}

inject_infrastructure_config() {
    local infra_dir="$1"
    
    # Copy the main .env file to infrastructure directory
    if [ -f "$ENV_FILE" ]; then
        log "Using master environment configuration..."
        cp "$ENV_FILE" "${infra_dir}/.env"
        success "Infrastructure environment configured from template"
    else
        error "Master .env file not found. Run process_environment_template first."
        exit 1
    fi
    
    # Create Docker override for development
    if [ ! -f "${infra_dir}/docker-compose.override.yml" ]; then
        log "Creating Docker Compose override for development..."
        cat > "${infra_dir}/docker-compose.override.yml" << 'EOF'
version: '3.8'

services:
  postgres:
    ports:
      - "5432:5432"
    environment:
      POSTGRES_DB: ${POSTGRES_DB}
      POSTGRES_USER: ${POSTGRES_USER}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    ports:
      - "6379:6379"
    command: redis-server --requirepass ${REDIS_PASSWORD}

  prometheus:
    ports:
      - "9090:9090"

  grafana:
    ports:
      - "3002:3000"
    environment:
      GF_SECURITY_ADMIN_PASSWORD: ${GRAFANA_ADMIN_PASSWORD}

volumes:
  postgres_data:
EOF
    fi
}

inject_rust_config() {
    local rust_dir="$1"
    
    # Extract values from master .env
    local database_url=$(get_env_value "DATABASE_URL")
    local redis_url=$(get_env_value "REDIS_URL")
    local rust_log=$(get_env_value "RUST_LOG")
    local aes_key=$(get_env_value "AES_ENCRYPTION_KEY")
    local ed25519_private=$(get_env_value "ED25519_PRIVATE_KEY")
    local ed25519_public=$(get_env_value "ED25519_PUBLIC_KEY")
    
    # Create environment file for Rust
    log "Creating Rust-specific configuration..."
    cat > "${rust_dir}/.env" << EOF
# Rust Core Engine Configuration (Generated from template)
DATABASE_URL=${database_url}
REDIS_URL=${redis_url}
RUST_LOG=${rust_log}
RUST_BACKTRACE=1

# Cryptographic Configuration
AES_ENCRYPTION_KEY=${aes_key}
ED25519_PRIVATE_KEY=${ed25519_private}
ED25519_PUBLIC_KEY=${ed25519_public}

# FFI Configuration
FFI_LIBRARY_PATH=./target/release/
CRYPTO_PROVIDER=ring

# Performance Tuning
TOKIO_WORKER_THREADS=4
RUST_MIN_STACK=8388608
EOF
    
    # Create keys directory and store keys
    mkdir -p "${rust_dir}/keys"
    
    if [ ! -z "$ed25519_private" ]; then
        echo "$ed25519_private" > "${rust_dir}/keys/private.key"
        echo "$ed25519_public" > "${rust_dir}/keys/public.key"
        chmod 600 "${rust_dir}/keys/private.key"
        chmod 644 "${rust_dir}/keys/public.key"
    fi
}

inject_go_config() {
    local go_dir="$1"
    
    # Extract values from master .env
    local database_url=$(get_env_value "DATABASE_URL")
    local redis_url=$(get_env_value "REDIS_URL")
    local kafka_brokers=$(get_env_value "KAFKA_BROKERS")
    local jwt_secret=$(get_env_value "JWT_SECRET")
    local go_gateway_port=$(get_env_value "GO_GATEWAY_PORT")
    local kotlin_port=$(get_env_value "KOTLIN_CONNECTORS_PORT")
    local go_env=$(get_env_value "GO_ENV")
    local gin_mode=$(get_env_value "GIN_MODE")
    
    # Create configuration for Go services
    log "Creating Go microservices configuration..."
    cat > "${go_dir}/.env" << EOF
# Go Digital Services Configuration (Generated from template)
PORT=${go_gateway_port}
GO_ENV=${go_env}
GIN_MODE=${gin_mode}

# Database & Cache
DATABASE_URL=${database_url}
REDIS_URL=${redis_url}
KAFKA_BROKERS=${kafka_brokers}

# Security
JWT_SECRET=${jwt_secret}
JWT_EXPIRY=24h

# Service Integration
RUST_FFI_LIB_PATH=../core-id-engine/target/release/libcore_id_engine.dylib
KOTLIN_CONNECTORS_URL=http://localhost:${kotlin_port}

# Performance
HTTP_READ_TIMEOUT=30s
HTTP_WRITE_TIMEOUT=30s
HTTP_IDLE_TIMEOUT=60s
MAX_GOROUTINES=10000

# Rate Limiting
RATE_LIMIT_PER_MINUTE=100
RATE_LIMIT_BURST=50

# Monitoring
LOG_LEVEL=info
STRUCTURED_LOGGING=true
EOF
}

inject_kotlin_config() {
    local kotlin_dir="$1"
    
    # Extract values from master .env
    local postgres_host=$(get_env_value "POSTGRES_HOST")
    local postgres_port=$(get_env_value "POSTGRES_PORT")
    local postgres_db=$(get_env_value "POSTGRES_DB")
    local postgres_user=$(get_env_value "POSTGRES_USER")
    local postgres_password=$(get_env_value "POSTGRES_PASSWORD")
    local redis_host=$(get_env_value "REDIS_HOST")
    local redis_port=$(get_env_value "REDIS_PORT")
    local redis_password=$(get_env_value "REDIS_PASSWORD")
    local kafka_brokers=$(get_env_value "KAFKA_BROKERS")
    local kotlin_port=$(get_env_value "KOTLIN_CONNECTORS_PORT")
    local spring_profile=$(get_env_value "SPRING_PROFILES_ACTIVE")
    
    # Government API credentials
    local hmrc_key=$(get_env_value "HMRC_CLIENT_ID")
    local hmrc_secret=$(get_env_value "HMRC_CLIENT_SECRET")
    local hmrc_url=$(get_env_value "HMRC_BASE_URL")
    local nhs_key=$(get_env_value "NHS_CLIENT_ID")
    local nhs_url=$(get_env_value "NHS_BASE_URL")
    local dvla_key=$(get_env_value "DVLA_API_KEY")
    local dvla_url=$(get_env_value "DVLA_BASE_URL")
    
    # Create application.yml for Spring Boot
    mkdir -p "${kotlin_dir}/src/main/resources"
    log "Creating Kotlin Spring Boot configuration..."
    cat > "${kotlin_dir}/src/main/resources/application-dev.yml" << EOF
server:
  port: ${kotlin_port}

spring:
  profiles:
    active: ${spring_profile}
    
  datasource:
    url: jdbc:postgresql://${postgres_host}:${postgres_port}/${postgres_db}
    username: ${postgres_user}
    password: ${postgres_password}
    driver-class-name: org.postgresql.Driver
    hikari:
      maximum-pool-size: 20
      connection-timeout: 30000
  
  redis:
    host: ${redis_host}
    port: ${redis_port}
    password: ${redis_password}
    timeout: 5000ms
  
  kafka:
    bootstrap-servers: ${kafka_brokers}
    consumer:
      group-id: gov-connectors
      key-deserializer: org.apache.kafka.common.serialization.StringDeserializer
      value-deserializer: org.apache.kafka.common.serialization.StringDeserializer

government:
  apis:
    hmrc:
      base-url: ${hmrc_url}
      client-id: ${hmrc_key}
      client-secret: ${hmrc_secret}
    nhs:
      base-url: ${nhs_url}
      client-id: ${nhs_key}
    dvla:
      base-url: ${dvla_url}
      api-key: ${dvla_key}

logging:
  level:
    uk.gov.digitalidentity: DEBUG
    org.springframework: INFO
    org.springframework.security: DEBUG

management:
  endpoints:
    web:
      exposure:
        include: health,info,metrics,prometheus
  endpoint:
    health:
      show-details: always
EOF

    # Also create .env file for Kotlin component
    cat > "${kotlin_dir}/.env" << EOF
# Kotlin Government Connectors Configuration (Generated from template)
SPRING_PROFILES_ACTIVE=${spring_profile}
SERVER_PORT=${kotlin_port}
POSTGRES_URL=jdbc:postgresql://${postgres_host}:${postgres_port}/${postgres_db}
POSTGRES_USERNAME=${postgres_user}
POSTGRES_PASSWORD=${postgres_password}
REDIS_HOST=${redis_host}
REDIS_PORT=${redis_port}
REDIS_PASSWORD=${redis_password}
KAFKA_BROKERS=${kafka_brokers}
EOF
}

inject_python_config() {
    local python_dir="$1"
    
    # Create Python environment configuration
    if [ ! -f "${python_dir}/.env" ]; then
        cat > "${python_dir}/.env" << 'EOF'
# Python Fraud Analytics Configuration
DATABASE_URL=postgresql://digital_user:secure_digital_password_2025@localhost:5432/digital_identity
REDIS_URL=redis://:secure_redis_password_2025@localhost:6379
KAFKA_BOOTSTRAP_SERVERS=localhost:9092
ML_MODEL_PATH=./models/
STREAMLIT_SERVER_PORT=8083
LOG_LEVEL=INFO
PYTHONPATH=.
EOF
    fi
    
    # Create models directory
    mkdir -p "${python_dir}/models"
}

inject_typescript_config() {
    local ts_dir="$1"
    
    # Create environment files for both portals
    for portal in "citizen-portal" "admin-dashboard"; do
        if [ -d "${ts_dir}/${portal}" ] && [ ! -f "${ts_dir}/${portal}/.env.local" ]; then
            cat > "${ts_dir}/${portal}/.env.local" << 'EOF'
# TypeScript Web Portal Configuration
NEXT_PUBLIC_API_BASE_URL=http://localhost:8080
NEXT_PUBLIC_WS_URL=ws://localhost:8080/ws
NEXTAUTH_URL=http://localhost:3001
NEXTAUTH_SECRET=uk_digital_identity_nextauth_secret_2025
DATABASE_URL=postgresql://digital_user:secure_digital_password_2025@localhost:5432/digital_identity
REDIS_URL=redis://:secure_redis_password_2025@localhost:6379
EOF
        fi
    done
}

inject_flutter_config() {
    local flutter_dir="$1"
    
    # Create Flutter configuration
    if [ ! -f "${flutter_dir}/.env" ]; then
        cat > "${flutter_dir}/.env" << 'EOF'
# Flutter Mobile Wallet Configuration
API_BASE_URL=http://localhost:8080
WS_URL=ws://localhost:8080/ws
APP_ENV=development
LOG_LEVEL=debug
EOF
    fi
    
    # Create config file for Flutter
    mkdir -p "${flutter_dir}/lib/core/config"
    if [ ! -f "${flutter_dir}/lib/core/config/env_config.dart" ]; then
        cat > "${flutter_dir}/lib/core/config/env_config.dart" << 'EOF'
class EnvConfig {
  static const String apiBaseUrl = String.fromEnvironment(
    'API_BASE_URL',
    defaultValue: 'http://localhost:8080',
  );
  
  static const String wsUrl = String.fromEnvironment(
    'WS_URL',
    defaultValue: 'ws://localhost:8080/ws',
  );
  
  static const String appEnv = String.fromEnvironment(
    'APP_ENV',
    defaultValue: 'development',
  );
}
EOF
    fi
}

install_dependencies() {
    local component="$1"
    local component_dir="${PROJECT_ROOT}/${COMPONENTS[$component]}"
    
    log "[$component] Installing dependencies..."
    save_log "$component" "$PHASE_INSTALL" "Starting dependency installation"
    
    cd "$component_dir"
    
    case "${COMPONENT_LANGUAGES[$component]}" in
        "docker")
            install_docker_dependencies
            ;;
        "rust")
            install_rust_dependencies
            ;;
        "go")
            install_go_dependencies
            ;;
        "kotlin")
            install_kotlin_dependencies
            ;;
        "python")
            install_python_dependencies
            ;;
        "typescript")
            install_typescript_dependencies "$component_dir"
            ;;
        "flutter")
            install_flutter_dependencies
            ;;
    esac
    
    success "[$component] Dependencies installed"
    save_log "$component" "$PHASE_INSTALL" "Dependencies installation completed"
}

install_docker_dependencies() {
    log "Pulling Docker images..."
    docker-compose pull || warning "Some images may need to be built locally"
}

install_rust_dependencies() {
    log "Installing Rust dependencies..."
    if [ -f "Cargo.toml" ]; then
        cargo fetch
        rustup component add clippy rustfmt
    else
        warning "No Cargo.toml found, skipping Rust dependencies"
    fi
}

install_go_dependencies() {
    log "Installing Go dependencies..."
    if [ -f "go.mod" ]; then
        go mod download
        go mod tidy
    else
        warning "No go.mod found, skipping Go dependencies"
    fi
}

install_kotlin_dependencies() {
    log "Installing Kotlin dependencies..."
    if [ -f "build.gradle.kts" ] || [ -f "build.gradle" ]; then
        ./gradlew dependencies --refresh-dependencies || {
            warning "Gradle wrapper not found, trying system gradle"
            gradle dependencies --refresh-dependencies || warning "Could not install Kotlin dependencies"
        }
    else
        warning "No Gradle build file found, skipping Kotlin dependencies"
    fi
}

install_python_dependencies() {
    log "Installing Python dependencies..."
    
    # Create virtual environment if it doesn't exist
    if [ ! -d "venv" ]; then
        python3 -m venv venv
    fi
    
    # Activate virtual environment and install dependencies
    source venv/bin/activate
    
    if [ -f "requirements.txt" ]; then
        pip install --upgrade pip
        pip install -r requirements.txt
    else
        warning "No requirements.txt found, installing basic dependencies"
        pip install pandas numpy scikit-learn streamlit kafka-python redis psycopg2-binary
    fi
}

install_typescript_dependencies() {
    local base_dir="$1"
    
    for portal in "citizen-portal" "admin-dashboard"; do
        if [ -d "${portal}" ] && [ -f "${portal}/package.json" ]; then
            log "Installing dependencies for ${portal}..."
            cd "${portal}"
            
            # Use yarn if available, otherwise npm
            if command -v yarn &> /dev/null; then
                yarn install
            else
                npm install
            fi
            
            cd ..
        fi
    done
}

install_flutter_dependencies() {
    log "Installing Flutter dependencies..."
    if [ -f "pubspec.yaml" ]; then
        flutter clean
        flutter pub get
        flutter pub deps
    else
        warning "No pubspec.yaml found, skipping Flutter dependencies"
    fi
}

build_component() {
    local component="$1"
    local component_dir="${PROJECT_ROOT}/${COMPONENTS[$component]}"
    
    log "[$component] Building..."
    save_log "$component" "$PHASE_BUILD" "Starting build"
    
    cd "$component_dir"
    
    case "${COMPONENT_LANGUAGES[$component]}" in
        "docker")
            build_docker_services
            ;;
        "rust")
            build_rust_component
            ;;
        "go")
            build_go_component
            ;;
        "kotlin")
            build_kotlin_component
            ;;
        "python")
            build_python_component
            ;;
        "typescript")
            build_typescript_component "$component_dir"
            ;;
        "flutter")
            build_flutter_component
            ;;
    esac
    
    success "[$component] Build completed"
    save_log "$component" "$PHASE_BUILD" "Build completed successfully"
}

build_docker_services() {
    log "Building Docker services..."
    docker-compose build --parallel
}

build_rust_component() {
    log "Building Rust component..."
    cargo build --release
    
    # Create FFI library
    if grep -q "crate-type.*cdylib" Cargo.toml; then
        log "Building FFI library..."
        cargo build --release --lib
    fi
}

build_go_component() {
    log "Building Go services..."
    
    # Build all Go services
    for service in gateway registration verification credential audit; do
        if [ -d "$service" ] && [ -f "${service}/main.go" ]; then
            log "Building Go service: $service"
            cd "$service"
            go build -o "../bin/${service}" .
            cd ..
        fi
    done
    
    # If no services found, try building main
    if [ -f "main.go" ] || [ -f "gateway/main.go" ]; then
        go build -o bin/gateway ./gateway/ 2>/dev/null || go build -o bin/main . 2>/dev/null || true
    fi
}

build_kotlin_component() {
    log "Building Kotlin component..."
    if [ -f "build.gradle.kts" ] || [ -f "build.gradle" ]; then
        ./gradlew clean build -x test || {
            warning "Gradle wrapper not found, trying system gradle"
            gradle clean build -x test || warning "Kotlin build failed"
        }
    fi
}

build_python_component() {
    log "Building Python component..."
    
    # Activate virtual environment
    if [ -d "venv" ]; then
        source venv/bin/activate
    fi
    
    # Run any setup if needed
    if [ -f "setup.py" ]; then
        pip install -e .
    fi
    
    # Compile Python files
    python3 -m compileall . || warning "Python compilation warnings"
}

build_typescript_component() {
    local base_dir="$1"
    
    for portal in "citizen-portal" "admin-dashboard"; do
        if [ -d "${portal}" ] && [ -f "${portal}/package.json" ]; then
            log "Building ${portal}..."
            cd "${portal}"
            
            # Build the project
            if command -v yarn &> /dev/null; then
                yarn build
            else
                npm run build
            fi
            
            cd ..
        fi
    done
}

build_flutter_component() {
    log "Building Flutter component..."
    if [ -f "pubspec.yaml" ]; then
        flutter clean
        flutter pub get
        
        # Build for different platforms based on what's available
        if command -v flutter &> /dev/null; then
            flutter build apk --debug || warning "Android build failed"
            if [[ "$OSTYPE" == "darwin"* ]]; then
                flutter build ios --debug --no-codesign || warning "iOS build failed"
            fi
        fi
    fi
}

start_component() {
    local component="$1"
    local component_dir="${PROJECT_ROOT}/${COMPONENTS[$component]}"
    
    log "[$component] Starting..."
    save_log "$component" "$PHASE_START" "Starting component"
    
    cd "$component_dir"
    
    case "${COMPONENT_LANGUAGES[$component]}" in
        "docker")
            start_infrastructure
            ;;
        "rust")
            start_rust_component
            ;;
        "go")
            start_go_component
            ;;
        "kotlin")
            start_kotlin_component
            ;;
        "python")
            start_python_component
            ;;
        "typescript")
            start_typescript_component "$component_dir"
            ;;
        "flutter")
            start_flutter_component
            ;;
    esac
    
    success "[$component] Started"
    save_log "$component" "$PHASE_START" "Component started successfully"
}

start_infrastructure() {
    log "Starting infrastructure services..."
    
    # Start core infrastructure first
    docker-compose up -d postgres redis kafka zookeeper
    
    # Wait for services to be ready
    log "Waiting for infrastructure services to be ready..."
    sleep 10
    
    # Start monitoring
    docker-compose up -d prometheus grafana
    
    success "Infrastructure services started"
}

start_rust_component() {
    log "Starting Rust core engine..."
    
    # Rust core engine runs as FFI library, so just verify it's built
    if [ -f "target/release/libcore_id_engine.dylib" ] || [ -f "target/release/libcore_id_engine.so" ]; then
        success "Rust FFI library ready"
    else
        warning "Rust FFI library not found, may need rebuild"
    fi
}

start_go_component() {
    log "Starting Go services..."
    
    # Load environment
    set -a
    source .env 2>/dev/null || true
    set +a
    
    # Start main gateway service in background
    if [ -f "bin/gateway" ]; then
        nohup ./bin/gateway > "${LOG_DIR}/go-gateway.log" 2>&1 &
        echo $! > "${CONFIG_DIR}/go-gateway.pid"
    elif [ -f "gateway/main.go" ]; then
        nohup go run gateway/main.go > "${LOG_DIR}/go-gateway.log" 2>&1 &
        echo $! > "${CONFIG_DIR}/go-gateway.pid"
    fi
    
    success "Go services started"
}

start_kotlin_component() {
    log "Starting Kotlin services..."
    
    # Start Spring Boot application
    if [ -f "build/libs/"*.jar ]; then
        nohup java -jar build/libs/*.jar --spring.profiles.active=dev > "${LOG_DIR}/kotlin-connectors.log" 2>&1 &
        echo $! > "${CONFIG_DIR}/kotlin-connectors.pid"
    else
        # Try with Gradle
        nohup ./gradlew bootRun --args='--spring.profiles.active=dev' > "${LOG_DIR}/kotlin-connectors.log" 2>&1 &
        echo $! > "${CONFIG_DIR}/kotlin-connectors.pid"
    fi
    
    success "Kotlin services started"
}

start_python_component() {
    log "Starting Python services..."
    
    # Activate virtual environment
    if [ -d "venv" ]; then
        source venv/bin/activate
    fi
    
    # Load environment
    set -a
    source .env 2>/dev/null || true
    set +a
    
    # Start Streamlit dashboard
    if [ -f "dashboard.py" ]; then
        nohup streamlit run dashboard.py --server.port 8083 > "${LOG_DIR}/python-analytics.log" 2>&1 &
        echo $! > "${CONFIG_DIR}/python-analytics.pid"
    fi
    
    # Start fraud detection service if available
    if [ -f "detect_fraud.py" ]; then
        nohup python detect_fraud.py > "${LOG_DIR}/fraud-detection.log" 2>&1 &
        echo $! > "${CONFIG_DIR}/fraud-detection.pid"
    fi
    
    success "Python services started"
}

start_typescript_component() {
    local base_dir="$1"
    
    for portal in "citizen-portal" "admin-dashboard"; do
        if [ -d "${portal}" ] && [ -f "${portal}/package.json" ]; then
            log "Starting ${portal}..."
            cd "${portal}"
            
            # Determine port
            local port=3001
            if [ "$portal" = "admin-dashboard" ]; then
                port=3000
            fi
            
            # Start in development mode
            if command -v yarn &> /dev/null; then
                nohup yarn dev -p $port > "${LOG_DIR}/${portal}.log" 2>&1 &
            else
                nohup npm run dev -- -p $port > "${LOG_DIR}/${portal}.log" 2>&1 &
            fi
            
            echo $! > "${CONFIG_DIR}/${portal}.pid"
            cd ..
        fi
    done
    
    success "TypeScript services started"
}

start_flutter_component() {
    log "Flutter mobile app built and ready for simulator/device"
    info "To run Flutter app: cd mobile-wallet && flutter run"
    success "Flutter component ready"
}

verify_component() {
    local component="$1"
    
    log "[$component] Verifying..."
    save_log "$component" "$PHASE_VERIFY" "Starting verification"
    
    case "$component" in
        "infrastructure")
            verify_infrastructure
            ;;
        "core-engine")
            verify_rust_component
            ;;
        "digital-services")
            verify_go_component
            ;;
        "gov-connectors")
            verify_kotlin_component
            ;;
        "fraud-analytics")
            verify_python_component
            ;;
        "web-portal")
            verify_typescript_component
            ;;
        "mobile-wallet")
            verify_flutter_component
            ;;
    esac
    
    success "[$component] Verification completed"
    save_log "$component" "$PHASE_VERIFY" "Verification completed successfully"
}

verify_infrastructure() {
    local all_healthy=true
    
    # Check PostgreSQL
    if docker-compose exec -T postgres pg_isready -U digital_user &>/dev/null; then
        success "PostgreSQL is ready"
    else
        error "PostgreSQL is not responding"
        all_healthy=false
    fi
    
    # Check Redis
    if docker-compose exec -T redis redis-cli ping | grep -q PONG; then
        success "Redis is ready"
    else
        error "Redis is not responding"
        all_healthy=false
    fi
    
    # Check Kafka
    if docker-compose ps kafka | grep -q "Up"; then
        success "Kafka is running"
    else
        error "Kafka is not running"
        all_healthy=false
    fi
    
    COMPONENT_STATUS["infrastructure"]=$all_healthy
}

verify_go_component() {
    if curl -s http://localhost:8080/health &>/dev/null; then
        success "Go API Gateway is responding"
        COMPONENT_STATUS["digital-services"]=true
    else
        error "Go API Gateway is not responding on port 8080"
        COMPONENT_STATUS["digital-services"]=false
    fi
}

verify_kotlin_component() {
    if curl -s http://localhost:8081/actuator/health &>/dev/null; then
        success "Kotlin Gov Connectors responding"
        COMPONENT_STATUS["gov-connectors"]=true
    else
        error "Kotlin Gov Connectors not responding on port 8081"
        COMPONENT_STATUS["gov-connectors"]=false
    fi
}

verify_python_component() {
    if curl -s http://localhost:8083 &>/dev/null; then
        success "Python Analytics Dashboard responding"
        COMPONENT_STATUS["fraud-analytics"]=true
    else
        error "Python Analytics not responding on port 8083"
        COMPONENT_STATUS["fraud-analytics"]=false
    fi
}

verify_typescript_component() {
    local all_healthy=true
    
    if curl -s http://localhost:3001 &>/dev/null; then
        success "Citizen Portal responding on port 3001"
    else
        error "Citizen Portal not responding"
        all_healthy=false
    fi
    
    if curl -s http://localhost:3000 &>/dev/null; then
        success "Admin Dashboard responding on port 3000"
    else
        error "Admin Dashboard not responding"
        all_healthy=false
    fi
    
    COMPONENT_STATUS["web-portal"]=$all_healthy
}

verify_rust_component() {
    local lib_path="${PROJECT_ROOT}/core-id-engine/target/release"
    if [ -f "${lib_path}/libcore_id_engine.dylib" ] || [ -f "${lib_path}/libcore_id_engine.so" ]; then
        success "Rust FFI library available"
        COMPONENT_STATUS["core-engine"]=true
    else
        error "Rust FFI library not found"
        COMPONENT_STATUS["core-engine"]=false
    fi
}

verify_flutter_component() {
    if [ -f "${PROJECT_ROOT}/mobile-wallet/pubspec.yaml" ] && command -v flutter &>/dev/null; then
        success "Flutter environment ready"
        COMPONENT_STATUS["mobile-wallet"]=true
    else
        error "Flutter not properly configured"
        COMPONENT_STATUS["mobile-wallet"]=false
    fi
}

cleanup_on_exit() {
    echo ""
    warning "Initialization interrupted. Cleaning up..."
    
    # Kill background processes
    for pid_file in "${CONFIG_DIR}"/*.pid; do
        if [ -f "$pid_file" ]; then
            local pid=$(cat "$pid_file")
            kill "$pid" 2>/dev/null || true
            rm "$pid_file"
        fi
    done
    
    info "Cleanup completed"
    exit 1
}

show_final_status() {
    header "🎯 Final System Status"
    echo ""
    
    local total_components=${#COMPONENTS[@]}
    local healthy_components=0
    
    for component in "${!COMPONENT_STATUS[@]}"; do
        if [ "${COMPONENT_STATUS[$component]}" = "true" ]; then
            success "[$component] Healthy"
            ((healthy_components++))
        else
            error "[$component] Unhealthy"
        fi
    done
    
    echo ""
    info "System Health: $healthy_components/$total_components components healthy"
    
    if [ $healthy_components -eq $total_components ]; then
        success "🎉 UK Digital Identity Platform fully initialized!"
        echo ""
        echo "Service URLs:"
        echo "  🚀 API Gateway:      http://localhost:8080"
        echo "  ☕ Gov Connectors:   http://localhost:8081"
        echo "  🐍 Analytics:        http://localhost:8083"
        echo "  🌐 Citizen Portal:   http://localhost:3001"
        echo "  👥 Admin Dashboard:  http://localhost:3000"
        echo "  📊 Prometheus:       http://localhost:9090"
        echo "  📈 Grafana:          http://localhost:3002"
        echo ""
        echo "Next steps:"
        echo "  1. Run: ./check-system-status.sh"
        echo "  2. Run: ./sync-components.sh"
        echo "  3. Open http://localhost:3001 for citizen portal"
        echo "  4. For Flutter: cd mobile-wallet && flutter run"
    else
        warning "System partially initialized. Check logs in ./logs/"
    fi
}

print_progress() {
    local current=$1
    local total=$2
    local component=$3
    local phase=$4
    
    local percent=$((current * 100 / total))
    local filled=$((percent / 5))
    local empty=$((20 - filled))
    
    printf "\r${BLUE}Progress: ["
    printf "%${filled}s" | tr ' ' '█'
    printf "%${empty}s" | tr ' ' '░'
    printf "] %d%% - %s (%s)${NC}" "$percent" "$component" "$phase"
}

# Main initialization function
main() {
    # Set up signal handlers
    trap cleanup_on_exit INT TERM
    
    print_banner
    create_directories
    check_prerequisites
    
    # Process environment template first
    process_environment_template
    
    # Calculate total steps
    TOTAL_STEPS=$((${#COMPONENTS[@]} * 5)) # 5 phases per component
    CURRENT_STEP=0
    
    echo ""
    header "🚀 Starting Systematic Initialization"
    echo ""
    
    # Initialize each component in dependency order
    for order in $(seq 1 ${#STARTUP_ORDER[@]}); do
        local component="${STARTUP_ORDER[$order]}"
        
        header "Initializing Component $order/${#STARTUP_ORDER[@]}: $component"
        
        # Phase 1: Inject Configuration
        ((CURRENT_STEP++))
        print_progress $CURRENT_STEP $TOTAL_STEPS "$component" "inject"
        inject_configuration "$component"
        
        # Phase 2: Install Dependencies
        ((CURRENT_STEP++))
        print_progress $CURRENT_STEP $TOTAL_STEPS "$component" "install"
        install_dependencies "$component"
        
        # Phase 3: Build
        ((CURRENT_STEP++))
        print_progress $CURRENT_STEP $TOTAL_STEPS "$component" "build"
        build_component "$component"
        
        # Phase 4: Start
        ((CURRENT_STEP++))
        print_progress $CURRENT_STEP $TOTAL_STEPS "$component" "start"
        start_component "$component"
        
        # Brief pause for services to stabilize
        sleep 2
        
        # Phase 5: Verify
        ((CURRENT_STEP++))
        print_progress $CURRENT_STEP $TOTAL_STEPS "$component" "verify"
        verify_component "$component"
        
        echo "" # New line after progress bar
    done
    
    echo ""
    show_final_status
}

# Script execution options
case "${1:-}" in
    "--help"|"-h")
        echo "UK Digital Identity Platform - Initialization Script"
        echo ""
        echo "Usage: $0 [options]"
        echo ""
        echo "Options:"
        echo "  --help, -h     Show this help message"
        echo "  --version, -v  Show script version"
        echo "  --dry-run      Show what would be done without executing"
        echo ""
        echo "This script systematically initializes all 7 components:"
        echo "  1. Infrastructure (Docker/K8s)"
        echo "  2. Core Engine (Rust)"
        echo "  3. Digital Services (Go)"
        echo "  4. Government Connectors (Kotlin)"
        echo "  5. Fraud Analytics (Python)"
        echo "  6. Web Portal (TypeScript)"
        echo "  7. Mobile Wallet (Flutter)"
        ;;
    "--version"|"-v")
        echo "UK Digital Identity Platform Initialization Script v${SCRIPT_VERSION}"
        ;;
    "--dry-run")
        echo "DRY RUN: Would initialize all components systematically"
        echo "This would execute: inject -> install -> build -> start -> verify"
        echo "for each of the 7 components in dependency order."
        ;;
    *)
        main "$@"
        ;;
esac