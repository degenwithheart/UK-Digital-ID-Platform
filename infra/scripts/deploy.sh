#!/bin/bash

# Enhanced Infrastructure Deployment Script
# Digital Identity Platform

set -euo pipefail

# Configuration
NAMESPACE="digital-identity"
MONITORING_NAMESPACE="digital-identity-monitoring"
HELM_CHART_NAME="digital-identity"
KUBECONFIG_FILE="${KUBECONFIG:-~/.kube/config}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check kubectl
    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl is not installed or not in PATH"
        exit 1
    fi
    
    # Check helm
    if ! command -v helm &> /dev/null; then
        log_error "helm is not installed or not in PATH"
        exit 1
    fi
    
    # Check docker
    if ! command -v docker &> /dev/null; then
        log_error "docker is not installed or not in PATH"
        exit 1
    fi
    
    # Verify kubectl connection
    if ! kubectl cluster-info &> /dev/null; then
        log_error "Cannot connect to Kubernetes cluster"
        exit 1
    fi
    
    log_success "Prerequisites check passed"
}

# Create namespaces
create_namespaces() {
    log_info "Creating namespaces..."
    
    kubectl apply -f k8s/namespace.yaml
    
    log_success "Namespaces created successfully"
}

# Deploy secrets
deploy_secrets() {
    log_info "Deploying secrets..."
    
    # Check if secrets file exists
    if [[ ! -f "k8s/secrets.yaml" ]]; then
        log_warning "Secrets file not found. Creating from template..."
        if [[ -f "k8s/secrets.yaml.template" ]]; then
            cp k8s/secrets.yaml.template k8s/secrets.yaml
            log_warning "Please update k8s/secrets.yaml with actual values before proceeding"
            exit 1
        else
            log_error "No secrets template found"
            exit 1
        fi
    fi
    
    kubectl apply -f k8s/secrets.yaml
    
    log_success "Secrets deployed successfully"
}

# Deploy configuration
deploy_config() {
    log_info "Deploying configuration..."
    
    kubectl apply -f k8s/configmaps.yaml
    
    log_success "Configuration deployed successfully"
}

# Deploy data services
deploy_data_services() {
    log_info "Deploying data services..."
    
    kubectl apply -f k8s/data-services.yaml
    
    # Wait for data services to be ready
    log_info "Waiting for data services to be ready..."
    kubectl wait --for=condition=ready pod -l component=database -n $NAMESPACE --timeout=300s
    kubectl wait --for=condition=ready pod -l component=cache -n $NAMESPACE --timeout=300s
    kubectl wait --for=condition=ready pod -l component=messaging -n $NAMESPACE --timeout=300s
    
    log_success "Data services deployed and ready"
}

# Deploy core services
deploy_core_services() {
    log_info "Deploying core services..."
    
    kubectl apply -f k8s/core-services.yaml
    
    # Wait for core services to be ready
    log_info "Waiting for core services to be ready..."
    kubectl wait --for=condition=ready pod -l component=core-engine -n $NAMESPACE --timeout=600s
    kubectl wait --for=condition=ready pod -l component=api-gateway -n $NAMESPACE --timeout=600s
    
    log_success "Core services deployed and ready"
}

# Deploy application services
deploy_app_services() {
    log_info "Deploying application services..."
    
    kubectl apply -f k8s/app-services.yaml
    
    # Wait for application services to be ready
    log_info "Waiting for application services to be ready..."
    kubectl wait --for=condition=ready pod -l component=government-connectors -n $NAMESPACE --timeout=600s
    kubectl wait --for=condition=ready pod -l component=fraud-detection -n $NAMESPACE --timeout=600s
    kubectl wait --for=condition=ready pod -l component=citizen-portal -n $NAMESPACE --timeout=600s
    
    log_success "Application services deployed and ready"
}

# Deploy monitoring services
deploy_monitoring() {
    log_info "Deploying monitoring services..."
    
    kubectl apply -f k8s/monitoring-services.yaml
    
    # Wait for monitoring services to be ready
    log_info "Waiting for monitoring services to be ready..."
    kubectl wait --for=condition=ready pod -l component=metrics -n $MONITORING_NAMESPACE --timeout=600s
    kubectl wait --for=condition=ready pod -l component=logging -n $MONITORING_NAMESPACE --timeout=600s
    
    log_success "Monitoring services deployed and ready"
}

# Deploy scaling policies
deploy_scaling() {
    log_info "Deploying scaling policies..."
    
    kubectl apply -f k8s/scaling-policies.yaml
    
    log_success "Scaling policies deployed successfully"
}

# Verify deployment
verify_deployment() {
    log_info "Verifying deployment..."
    
    # Check pod status
    log_info "Checking pod status..."
    kubectl get pods -n $NAMESPACE
    kubectl get pods -n $MONITORING_NAMESPACE
    
    # Check services
    log_info "Checking services..."
    kubectl get services -n $NAMESPACE
    
    # Check ingress
    log_info "Checking ingress..."
    kubectl get ingress -n $NAMESPACE 2>/dev/null || log_warning "No ingress resources found"
    
    # Check HPA
    log_info "Checking horizontal pod autoscalers..."
    kubectl get hpa -n $NAMESPACE
    
    # Basic health check
    log_info "Running basic health checks..."
    
    # Check if nginx service is accessible
    if kubectl get service nginx-service -n $NAMESPACE &> /dev/null; then
        kubectl port-forward service/nginx-service 8080:80 -n $NAMESPACE &
        sleep 5
        if curl -f http://localhost:8080/health &> /dev/null; then
            log_success "Health check passed"
        else
            log_warning "Health check failed - service may still be starting"
        fi
        pkill -f "kubectl port-forward" || true
    fi
    
    log_success "Deployment verification completed"
}

# Helm deployment
deploy_with_helm() {
    log_info "Deploying with Helm..."
    
    # Check if helm chart exists
    if [[ ! -f "helm/digital-identity/Chart.yaml" ]]; then
        log_error "Helm chart not found"
        exit 1
    fi
    
    cd helm/digital-identity
    
    # Update dependencies
    log_info "Updating Helm dependencies..."
    helm dependency update
    
    # Install or upgrade
    if helm list -n $NAMESPACE | grep -q $HELM_CHART_NAME; then
        log_info "Upgrading existing Helm release..."
        helm upgrade $HELM_CHART_NAME . \
            --namespace $NAMESPACE \
            --values values.yaml \
            --wait --timeout=20m
    else
        log_info "Installing new Helm release..."
        helm install $HELM_CHART_NAME . \
            --namespace $NAMESPACE \
            --create-namespace \
            --values values.yaml \
            --wait --timeout=20m
    fi
    
    cd ../..
    
    log_success "Helm deployment completed"
}

# Cleanup deployment
cleanup() {
    log_warning "Cleaning up deployment..."
    
    # Delete applications first
    kubectl delete -f k8s/scaling-policies.yaml --ignore-not-found=true
    kubectl delete -f k8s/app-services.yaml --ignore-not-found=true
    kubectl delete -f k8s/core-services.yaml --ignore-not-found=true
    kubectl delete -f k8s/monitoring-services.yaml --ignore-not-found=true
    kubectl delete -f k8s/data-services.yaml --ignore-not-found=true
    kubectl delete -f k8s/configmaps.yaml --ignore-not-found=true
    kubectl delete -f k8s/secrets.yaml --ignore-not-found=true
    
    # Delete namespaces (this will clean up everything)
    kubectl delete namespace $NAMESPACE --ignore-not-found=true
    kubectl delete namespace $MONITORING_NAMESPACE --ignore-not-found=true
    
    log_success "Cleanup completed"
}

# Show usage
show_usage() {
    echo "Usage: $0 [COMMAND] [OPTIONS]"
    echo ""
    echo "Commands:"
    echo "  deploy          Deploy the full platform"
    echo "  deploy-helm     Deploy using Helm chart"
    echo "  verify          Verify existing deployment"
    echo "  cleanup         Remove all deployed resources"
    echo "  help            Show this help message"
    echo ""
    echo "Options:"
    echo "  --namespace     Kubernetes namespace (default: digital-identity)"
    echo "  --kubeconfig    Path to kubeconfig file (default: ~/.kube/config)"
    echo ""
    echo "Examples:"
    echo "  $0 deploy                    # Deploy full platform"
    echo "  $0 deploy-helm              # Deploy with Helm"
    echo "  $0 verify                   # Verify deployment"
    echo "  $0 cleanup                  # Clean up resources"
}

# Main function
main() {
    local command="${1:-help}"
    
    case $command in
        "deploy")
            check_prerequisites
            create_namespaces
            deploy_secrets
            deploy_config
            deploy_data_services
            deploy_core_services
            deploy_app_services
            deploy_monitoring
            deploy_scaling
            verify_deployment
            log_success "Full deployment completed successfully!"
            ;;
        "deploy-helm")
            check_prerequisites
            deploy_with_helm
            verify_deployment
            log_success "Helm deployment completed successfully!"
            ;;
        "verify")
            verify_deployment
            ;;
        "cleanup")
            cleanup
            ;;
        "help"|"-h"|"--help")
            show_usage
            ;;
        *)
            log_error "Unknown command: $command"
            show_usage
            exit 1
            ;;
    esac
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --namespace)
            NAMESPACE="$2"
            MONITORING_NAMESPACE="$2-monitoring"
            shift 2
            ;;
        --kubeconfig)
            KUBECONFIG_FILE="$2"
            export KUBECONFIG="$KUBECONFIG_FILE"
            shift 2
            ;;
        *)
            break
            ;;
    esac
done

# Run main function with remaining arguments
main "$@"