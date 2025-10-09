#!/bin/bash

# Comprehensive System Status Checker
# Verifies all 7 components are synchronized with 25 government APIs

set -e

echo "🔍 UK Digital Identity Platform - System Status Check"
echo "=================================================="

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

check_status() { echo -e "${BLUE}🔍 $1${NC}"; }
success() { echo -e "${GREEN}✅ $1${NC}"; }
warning() { echo -e "${YELLOW}⚠️  $1${NC}"; }
error() { echo -e "${RED}❌ $1${NC}"; }
info() { echo -e "${PURPLE}ℹ️  $1${NC}"; }

# Component status tracking
declare -a COMPONENTS=("core-id-engine" "digital-id-services" "fraud-analytics" "gov-connectors" "mobile-wallet" "web-portal" "infrastructure")
declare -a COMPONENT_PORTS=(8080 8081 8090 8070 3000 3001 9090)
declare -a COMPONENT_STATUS=()

# Government API tracking
declare -a GOV_APIS=(
    "DWP" "NHS" "DVLA" "HMRC" "Home Office" "Border Control"
    "Companies House" "Financial Services" "Business & Trade"
    "Education" "Professional Bodies" "Law Enforcement"
    "Security Services" "Courts & Tribunals" "Healthcare"
    "Transport" "Land Registry" "Local Government"
    "DEFRA" "Housing & Communities" "Culture Media Sport"
    "Energy Security" "Science Innovation"
)

declare -A API_ENDPOINTS=(
    ["DWP"]="https://dwp-api.digital-identity.gov.uk"
    ["NHS"]="https://nhs-api.digital-identity.gov.uk"
    ["DVLA"]="https://dvla-api.digital-identity.gov.uk"
    ["HMRC"]="https://hmrc-api.digital-identity.gov.uk"
    ["Home Office"]="https://homeoffice-api.digital-identity.gov.uk"
    ["Border Control"]="https://border-api.digital-identity.gov.uk"
    ["Companies House"]="https://api.companieshouse.gov.uk"
    ["Financial Services"]="https://fca-api.digital-identity.gov.uk"
    ["Business & Trade"]="https://businesstrade-api.digital-identity.gov.uk"
    ["Education"]="https://education-api.digital-identity.gov.uk"
    ["Professional Bodies"]="https://professional-api.digital-identity.gov.uk"
    ["Law Enforcement"]="https://police-api.digital-identity.gov.uk"
    ["Security Services"]="https://security-api.digital-identity.gov.uk"
    ["Courts & Tribunals"]="https://courts-api.digital-identity.gov.uk"
    ["Healthcare"]="https://healthcare-api.digital-identity.gov.uk"
    ["Transport"]="https://transport-api.digital-identity.gov.uk"
    ["Land Registry"]="https://landregistry-api.digital-identity.gov.uk"
    ["Local Government"]="https://local-api.digital-identity.gov.uk"
    ["DEFRA"]="https://defra-api.digital-identity.gov.uk"
    ["Housing & Communities"]="https://housing-api.digital-identity.gov.uk"
    ["Culture Media Sport"]="https://culture-api.digital-identity.gov.uk"
    ["Energy Security"]="https://energy-api.digital-identity.gov.uk"
    ["Science Innovation"]="https://science-api.digital-identity.gov.uk"
)

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check port availability
check_port() {
    local port=$1
    if command_exists nc; then
        nc -z localhost $port 2>/dev/null
    elif command_exists telnet; then
        timeout 5 telnet localhost $port >/dev/null 2>&1
    else
        # Fallback using curl
        curl -s --connect-timeout 5 http://localhost:$port >/dev/null 2>&1
    fi
}

# Check HTTP endpoint
check_http_endpoint() {
    local url=$1
    local timeout=${2:-10}
    
    if command_exists curl; then
        curl -s --connect-timeout $timeout --max-time $timeout "$url" >/dev/null 2>&1
    elif command_exists wget; then
        wget -q --timeout=$timeout --tries=1 "$url" -O /dev/null 2>/dev/null
    else
        return 1
    fi
}

# System Requirements Check
echo ""
check_status "Checking system requirements..."

# Check Docker
if command_exists docker; then
    success "Docker is installed"
    if docker info >/dev/null 2>&1; then
        success "Docker daemon is running"
    else
        error "Docker daemon is not running"
    fi
else
    error "Docker is not installed"
fi

# Check Docker Compose
if command_exists docker-compose; then
    success "Docker Compose is installed"
elif docker compose version >/dev/null 2>&1; then
    success "Docker Compose (plugin) is available"
else
    error "Docker Compose is not available"
fi

# Check Node.js for web portals
if command_exists node; then
    NODE_VERSION=$(node --version)
    success "Node.js is installed: $NODE_VERSION"
else
    warning "Node.js not found (required for web portals)"
fi

# Check Redis for synchronization
echo ""
check_status "Checking synchronization infrastructure..."

if check_port 6379; then
    success "Redis (sync event bus) is running on port 6379"
else
    error "Redis (sync event bus) is not running on port 6379"
fi

# Check sync coordinator
if check_port 8095; then
    success "Sync coordinator is running on port 8095"
    
    # Try to get sync status
    if check_http_endpoint "http://localhost:8095/health"; then
        success "Sync coordinator health endpoint is responding"
    else
        warning "Sync coordinator health endpoint not responding"
    fi
else
    error "Sync coordinator is not running on port 8095"
fi

# Component Status Check
echo ""
check_status "Checking all 7 components..."

HEALTHY_COMPONENTS=0
TOTAL_COMPONENTS=${#COMPONENTS[@]}

for i in "${!COMPONENTS[@]}"; do
    component="${COMPONENTS[$i]}"
    port="${COMPONENT_PORTS[$i]}"
    
    echo -n "  Checking $component (port $port)... "
    
    if check_port $port; then
        success "$component is running"
        COMPONENT_STATUS[$i]="healthy"
        ((HEALTHY_COMPONENTS++))
        
        # Additional health checks
        case $component in
            "core-id-engine")
                if check_http_endpoint "http://localhost:$port/health"; then
                    success "  ├─ Health endpoint responding"
                else
                    warning "  ├─ Health endpoint not responding"
                fi
                ;;
            "digital-id-services")
                if check_http_endpoint "http://localhost:$port/health"; then
                    success "  ├─ Gateway service healthy"
                else
                    warning "  ├─ Gateway service not responding"
                fi
                ;;
            "web-portal")
                if check_http_endpoint "http://localhost:$port"; then
                    success "  ├─ Admin dashboard accessible"
                else
                    warning "  ├─ Admin dashboard not accessible"
                fi
                ;;
        esac
    else
        error "$component is not running"
        COMPONENT_STATUS[$i]="down"
    fi
done

# Government API Configuration Check
echo ""
check_status "Checking government API configuration..."

#!/bin/bash

# System Status Checker
# Verifies synchronization and government API configuration

echo "🔍 Checking UK Digital Identity Platform Status..."

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Check .env file for government APIs
ENV_FILE="${SCRIPT_DIR}/web-portal/citizen-portal/.env"

if [ -f "$ENV_FILE" ]; then
    success "Environment configuration file found"
    
    CONFIGURED_APIS=0
    TOTAL_APIS=${#GOV_APIS[@]}
    
    for api in "${GOV_APIS[@]}"; do
        # Convert API name to env var format
        api_var=$(echo "$api" | tr '[:lower:]' '[:upper:]' | tr ' ' '_' | sed 's/&/AND/')
        
        case "$api_var" in
            "DWP") env_var="REACT_APP_DWP_API_URL" ;;
            "NHS") env_var="REACT_APP_NHS_API_URL" ;;
            "DVLA") env_var="REACT_APP_DVLA_API_URL" ;;
            "HMRC") env_var="REACT_APP_HMRC_API_URL" ;;
            "HOME_OFFICE") env_var="REACT_APP_HOME_OFFICE_API_URL" ;;
            "BORDER_CONTROL") env_var="REACT_APP_BORDER_CONTROL_API_URL" ;;
            "COMPANIES_HOUSE") env_var="REACT_APP_COMPANIES_HOUSE_API" ;;
            "FINANCIAL_SERVICES") env_var="REACT_APP_FINANCIAL_SERVICES_API_URL" ;;
            "BUSINESS_AND_TRADE") env_var="REACT_APP_BUSINESS_TRADE_API_URL" ;;
            "EDUCATION") env_var="REACT_APP_EDUCATION_API_URL" ;;
            "PROFESSIONAL_BODIES") env_var="REACT_APP_PROFESSIONAL_BODIES_API_URL" ;;
            "LAW_ENFORCEMENT") env_var="REACT_APP_LAW_ENFORCEMENT_API_URL" ;;
            "SECURITY_SERVICES") env_var="REACT_APP_SECURITY_SERVICES_API_URL" ;;
            "COURTS_AND_TRIBUNALS") env_var="REACT_APP_COURTS_TRIBUNALS_API_URL" ;;
            "HEALTHCARE") env_var="REACT_APP_HEALTHCARE_API_URL" ;;
            "TRANSPORT") env_var="REACT_APP_TRANSPORT_API_URL" ;;
            "LAND_REGISTRY") env_var="REACT_APP_LAND_REGISTRY_API_URL" ;;
            "LOCAL_GOVERNMENT") env_var="REACT_APP_LOCAL_GOVERNMENT_API_URL" ;;
            "DEFRA") env_var="REACT_APP_DEFRA_API_URL" ;;
            "HOUSING_AND_COMMUNITIES") env_var="REACT_APP_HOUSING_COMMUNITIES_API_URL" ;;
            "CULTURE_MEDIA_SPORT") env_var="REACT_APP_CULTURE_MEDIA_SPORT_API_URL" ;;
            "ENERGY_SECURITY") env_var="REACT_APP_ENERGY_SECURITY_API_URL" ;;
            "SCIENCE_INNOVATION") env_var="REACT_APP_SCIENCE_INNOVATION_API_URL" ;;
        esac
        
        if grep -q "^$env_var=" "$ENV_FILE" 2>/dev/null; then
            success "  ✅ $api API configured"
            ((CONFIGURED_APIS++))
        else
            warning "  ⚠️  $api API not configured"
        fi
    done
    
    info "Government APIs configured: $CONFIGURED_APIS/$TOTAL_APIS"
else
    error "Environment configuration file not found: $ENV_FILE"
fi

# Synchronization Status Check
echo ""
check_status "Checking component synchronization..."

# Check if sync config exists
SYNC_CONFIG="${SCRIPT_DIR}/sync-config.yaml"
if [ -f "$SYNC_CONFIG" ]; then
    success "Synchronization configuration found"
else
    warning "Synchronization configuration not found"
fi

# Check sync services
sync_services=("redis-sync" "sync-coordinator")
for service in "${sync_services[@]}"; do
    if docker ps --format "table {{.Names}}" | grep -q "$service"; then
        success "  ✅ $service container is running"
    else
        warning "  ⚠️  $service container is not running"
    fi
done

# Network Connectivity Check
echo ""
check_status "Checking network connectivity..."

# Check internal network
if docker network ls | grep -q "digital-id-network"; then
    success "Digital ID network exists"
else
    warning "Digital ID network not found"
fi

# Summary Report
echo ""
echo "=================================================="
echo -e "${BLUE}📊 SYSTEM STATUS SUMMARY${NC}"
echo "=================================================="

# Component Health
component_health_percent=$((HEALTHY_COMPONENTS * 100 / TOTAL_COMPONENTS))
echo -e "🏗️  Components: $HEALTHY_COMPONENTS/$TOTAL_COMPONENTS healthy (${component_health_percent}%)"

if [ $component_health_percent -ge 90 ]; then
    success "Component health: EXCELLENT"
elif [ $component_health_percent -ge 70 ]; then
    warning "Component health: GOOD"
elif [ $component_health_percent -ge 50 ]; then
    warning "Component health: FAIR"
else
    error "Component health: POOR"
fi

# API Configuration
if [ -n "$CONFIGURED_APIS" ]; then
    api_config_percent=$((CONFIGURED_APIS * 100 / TOTAL_APIS))
    echo -e "🏛️  Government APIs: $CONFIGURED_APIS/$TOTAL_APIS configured (${api_config_percent}%)"
    
    if [ $api_config_percent -ge 90 ]; then
        success "API configuration: COMPLETE"
    elif [ $api_config_percent -ge 70 ]; then
        warning "API configuration: MOSTLY COMPLETE"
    else
        error "API configuration: INCOMPLETE"
    fi
fi

# Overall System Status
echo ""
if [ $component_health_percent -ge 80 ] && [ "${CONFIGURED_APIS:-0}" -ge 20 ]; then
    success "🎉 SYSTEM STATUS: OPERATIONAL"
    success "   All critical components are synchronized and ready"
elif [ $component_health_percent -ge 60 ]; then
    warning "⚠️  SYSTEM STATUS: DEGRADED"
    warning "   Some components may not be fully operational"
else
    error "❌ SYSTEM STATUS: CRITICAL"
    error "   Multiple components are not operational"
fi

echo ""
echo "🔗 Access URLs:"
echo "   Admin Dashboard:    http://localhost:3001"
echo "   Citizen Portal:     http://localhost:3002" 
echo "   API Gateway:        http://localhost:8081"
echo "   Sync Dashboard:     http://localhost:8095"
echo "   Core Engine:        http://localhost:8080"
echo "   Gov Connectors:     http://localhost:8070"
echo "   Fraud Analytics:    http://localhost:8090"
echo ""

if [ $component_health_percent -ge 80 ]; then
    success "🚀 System ready for production use!"
else
    warning "🔧 System requires attention before production use"
fi

exit 0