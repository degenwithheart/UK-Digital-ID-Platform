#!/bin/bash

# 🛑 UK Digital Identity Platform - Stop/Cleanup Script
# Gracefully stops all components and cleans up resources

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

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="${SCRIPT_DIR}/logs"
CONFIG_DIR="${SCRIPT_DIR}/.init-config"

echo -e "${BLUE}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║             🇬🇧 UK Digital Identity Platform                 ║"
echo "║                   Stop & Cleanup                             ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

stop_background_processes() {
    log "Stopping background processes..."
    
    local stopped_count=0
    
    if [ -d "$CONFIG_DIR" ]; then
        for pid_file in "$CONFIG_DIR"/*.pid; do
            if [ -f "$pid_file" ]; then
                local service=$(basename "$pid_file" .pid)
                local pid=$(cat "$pid_file")
                
                if kill -0 "$pid" 2>/dev/null; then
                    log "Stopping $service (PID: $pid)"
                    kill -TERM "$pid" 2>/dev/null || true
                    
                    # Wait for graceful shutdown
                    local count=0
                    while kill -0 "$pid" 2>/dev/null && [ $count -lt 10 ]; do
                        sleep 1
                        ((count++))
                    done
                    
                    # Force kill if still running
                    if kill -0 "$pid" 2>/dev/null; then
                        warning "Force killing $service"
                        kill -KILL "$pid" 2>/dev/null || true
                    fi
                    
                    success "Stopped $service"
                    ((stopped_count++))
                else
                    warning "$service was not running"
                fi
                
                rm -f "$pid_file"
            fi
        done
    fi
    
    if [ $stopped_count -gt 0 ]; then
        success "Stopped $stopped_count background processes"
    else
        info "No background processes found"
    fi
}

stop_docker_services() {
    log "Stopping Docker services..."
    
    cd "$SCRIPT_DIR/infra" 2>/dev/null || {
        warning "Infrastructure directory not found, skipping Docker cleanup"
        return
    }
    
    if [ -f "docker-compose.yml" ]; then
        # Stop services gracefully
        docker-compose stop
        
        # Remove containers
        docker-compose down
        
        success "Docker services stopped"
    else
        warning "Docker Compose file not found"
    fi
}

cleanup_processes_by_port() {
    log "Cleaning up processes by known ports..."
    
    local ports=(8080 8081 8083 3000 3001 5432 6379 9092 9090 3002)
    local killed_count=0
    
    for port in "${ports[@]}"; do
        local pid=$(lsof -ti:$port 2>/dev/null || true)
        if [ -n "$pid" ]; then
            log "Killing process on port $port (PID: $pid)"
            kill -TERM "$pid" 2>/dev/null || true
            ((killed_count++))
        fi
    done
    
    if [ $killed_count -gt 0 ]; then
        success "Cleaned up $killed_count port-based processes"
        sleep 2  # Give processes time to terminate
    fi
}

cleanup_node_processes() {
    log "Cleaning up Node.js processes..."
    
    local node_pids=$(pgrep -f "node.*digital.*identity\|next.*dev\|yarn.*dev\|npm.*dev" 2>/dev/null || true)
    
    if [ -n "$node_pids" ]; then
        echo "$node_pids" | while read -r pid; do
            if [ -n "$pid" ]; then
                log "Stopping Node.js process (PID: $pid)"
                kill -TERM "$pid" 2>/dev/null || true
            fi
        done
        success "Node.js processes cleaned up"
    fi
}

cleanup_java_processes() {
    log "Cleaning up Java/Kotlin processes..."
    
    local java_pids=$(pgrep -f "java.*gov.*connectors\|gradle.*bootRun" 2>/dev/null || true)
    
    if [ -n "$java_pids" ]; then
        echo "$java_pids" | while read -r pid; do
            if [ -n "$pid" ]; then
                log "Stopping Java process (PID: $pid)"
                kill -TERM "$pid" 2>/dev/null || true
            fi
        done
        success "Java processes cleaned up"
    fi
}

cleanup_python_processes() {
    log "Cleaning up Python processes..."
    
    local python_pids=$(pgrep -f "python.*streamlit\|streamlit.*run\|python.*detect_fraud" 2>/dev/null || true)
    
    if [ -n "$python_pids" ]; then
        echo "$python_pids" | while read -r pid; do
            if [ -n "$pid" ]; then
                log "Stopping Python process (PID: $pid)"
                kill -TERM "$pid" 2>/dev/null || true
            fi
        done
        success "Python processes cleaned up"
    fi
}

cleanup_go_processes() {
    log "Cleaning up Go processes..."
    
    local go_pids=$(pgrep -f "go.*run.*gateway\|.*digital.*services" 2>/dev/null || true)
    
    if [ -n "$go_pids" ]; then
        echo "$go_pids" | while read -r pid; do
            if [ -n "$pid" ]; then
                log "Stopping Go process (PID: $pid)"
                kill -TERM "$pid" 2>/dev/null || true
            fi
        done
        success "Go processes cleaned up"
    fi
}

cleanup_temp_files() {
    log "Cleaning up temporary files..."
    
    # Remove PID files
    rm -rf "$CONFIG_DIR" 2>/dev/null || true
    
    # Clean up logs older than 7 days
    if [ -d "$LOG_DIR" ]; then
        find "$LOG_DIR" -name "*.log" -mtime +7 -delete 2>/dev/null || true
    fi
    
    # Clean up any temporary build artifacts
    find "$SCRIPT_DIR" -name "*.tmp" -delete 2>/dev/null || true
    find "$SCRIPT_DIR" -name "nohup.out" -delete 2>/dev/null || true
    
    success "Temporary files cleaned up"
}

reset_environment() {
    log "Resetting environment configuration..."
    
    # Remove generated .env files (keep .env.example files)
    find "$SCRIPT_DIR" -name ".env" ! -name "*.example" -delete 2>/dev/null || true
    
    # Reset Docker volumes (optional, ask user)
    if [ "$1" = "--reset-data" ]; then
        warning "Resetting all data (including databases)..."
        cd "$SCRIPT_DIR/infra" 2>/dev/null || return
        docker-compose down -v 2>/dev/null || true
        docker volume prune -f 2>/dev/null || true
    fi
    
    success "Environment reset completed"
}

show_cleanup_summary() {
    echo ""
    success "🧹 Cleanup Summary"
    echo ""
    
    # Check if any processes are still running on our ports
    local still_running=()
    local ports=(8080 8081 8083 3000 3001 5432 6379 9092 9090 3002)
    
    for port in "${ports[@]}"; do
        if lsof -ti:$port >/dev/null 2>&1; then
            still_running+=("$port")
        fi
    done
    
    if [ ${#still_running[@]} -eq 0 ]; then
        success "✅ All platform services stopped"
        success "✅ All ports cleared"
        success "✅ Temporary files cleaned"
    else
        warning "Some processes still running on ports: ${still_running[*]}"
        echo "You may need to manually kill these processes:"
        for port in "${still_running[@]}"; do
            local pid=$(lsof -ti:$port 2>/dev/null || true)
            if [ -n "$pid" ]; then
                echo "  Port $port: kill $pid"
            fi
        done
    fi
    
    echo ""
    echo "Platform Status:"
    echo "  🛑 All services stopped"
    echo "  🧹 Temporary files cleaned"
    echo "  📁 Source code preserved"
    echo "  📊 Logs preserved in ./logs/"
    echo ""
    echo "To restart:"
    echo "  🚀 Full setup:    ./initialize-platform.sh"
    echo "  ⚡ Quick start:   ./quick-start.sh"
}

# Main cleanup function
main() {
    local reset_data=false
    
    # Parse command line arguments
    case "${1:-}" in
        "--help"|"-h")
            echo "UK Digital Identity Platform - Stop & Cleanup Script"
            echo ""
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  --help, -h         Show this help message"
            echo "  --reset-data       Also reset all data (databases, volumes)"
            echo "  --force            Force stop all processes without confirmation"
            echo ""
            echo "This script stops all platform services and cleans up:"
            echo "  • Background processes (Go, Kotlin, Python, Node.js)"
            echo "  • Docker services (PostgreSQL, Redis, Kafka, etc.)"
            echo "  • Temporary files and logs"
            echo "  • PID files and configuration"
            exit 0
            ;;
        "--reset-data")
            reset_data=true
            ;;
        "--force")
            # Skip confirmation
            ;;
        *)
            # Ask for confirmation
            echo ""
            read -p "This will stop all UK Digital Identity Platform services. Continue? (y/N): " -n 1 -r
            echo ""
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                echo "Operation cancelled."
                exit 0
            fi
            ;;
    esac
    
    echo ""
    log "Starting platform cleanup..."
    
    # Stop services in reverse dependency order
    stop_background_processes
    cleanup_go_processes
    cleanup_java_processes
    cleanup_python_processes
    cleanup_node_processes
    cleanup_processes_by_port
    stop_docker_services
    cleanup_temp_files
    
    if [ "$reset_data" = true ]; then
        reset_environment --reset-data
    fi
    
    show_cleanup_summary
}

# Execute main function with all arguments
main "$@"