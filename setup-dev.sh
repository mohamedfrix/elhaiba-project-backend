#!/bin/bash

# =============================================================================
# ELHAIBA BACKEND - DEVELOPMENT SETUP SCRIPT
# =============================================================================
# This script starts all required infrastructure services for development
# and performs basic health checks to ensure everything is working correctly.
# =============================================================================

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to wait for a service to be ready
wait_for_service() {
    local service_name="$1"
    local check_command="$2"
    local max_attempts=30
    local attempt=1

    print_status "Waiting for $service_name to be ready..."
    
    while [ $attempt -le $max_attempts ]; do
        if eval "$check_command" >/dev/null 2>&1; then
            print_success "$service_name is ready!"
            return 0
        fi
        
        echo -n "."
        sleep 2
        attempt=$((attempt + 1))
    done
    
    print_error "$service_name failed to start within $(($max_attempts * 2)) seconds"
    return 1
}

# Main setup function
main() {
    print_status "Starting Elhaiba Backend Development Environment..."
    
    # Check prerequisites
    print_status "Checking prerequisites..."
    
    if ! command_exists docker; then
        print_error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    if ! command_exists docker-compose; then
        print_error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi
    
    # Check if Docker daemon is running
    if ! docker info >/dev/null 2>&1; then
        print_error "Docker daemon is not running. Please start Docker first."
        exit 1
    fi
    
    print_success "Prerequisites check passed"
    
    # Load environment variables
    if [ -f .env ]; then
        print_status "Loading environment variables from .env file..."
        export $(grep -v '^#' .env | grep -v '^$' | xargs)
        print_success "Environment variables loaded"
    else
        print_warning ".env file not found. Using default values."
    fi
    
    # Ensure volume directories exist and have proper permissions
    print_status "Setting up volume directories..."
    mkdir -p volumes/minio volumes/redis
    
    # Set proper permissions for volume directories
    # MinIO needs specific permissions for data directory
    chmod 755 volumes/minio volumes/redis
    
    # Ensure the current user owns the volume directories
    if [ "$(id -u)" != "0" ]; then
        # Not running as root, ensure user ownership
        if [ -w volumes/ ]; then
            chown -R $(id -u):$(id -g) volumes/ 2>/dev/null || true
        fi
    fi
    
    print_success "Volume directories prepared"
    
    # Stop any existing services
    print_status "Stopping any existing services..."
    docker-compose down >/dev/null 2>&1 || true
    
    # Start services
    print_status "Starting infrastructure services..."
    docker-compose up -d
    
    if [ $? -eq 0 ]; then
        print_success "Services started successfully"
    else
        print_error "Failed to start services"
        exit 1
    fi
    
    # Wait for services to be ready
    print_status "Performing health checks..."
    
    # Wait for MinIO
    if ! wait_for_service "MinIO" "curl -f http://localhost:9000/minio/health/live"; then
        print_error "MinIO health check failed"
        docker-compose logs minio
        exit 1
    fi
    
    # Wait for Redis
    if ! wait_for_service "Redis" "docker-compose exec -T redis redis-cli ping"; then
        print_error "Redis health check failed"
        docker-compose logs redis
        exit 1
    fi
    
    # Wait for Redis Commander (optional)
    if ! wait_for_service "Redis Commander" "curl -f http://localhost:8081"; then
        print_warning "Redis Commander health check failed (this is optional)"
    fi
    
    # Show service status
    print_status "Service Status:"
    docker-compose ps
    
    # Show access information
    echo ""
    print_success "🎉 All services are ready!"
    echo ""
    echo "📋 Service Access Information:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "🗄️  MinIO Object Storage:"
    echo "   • API Endpoint:    http://localhost:9000"
    echo "   • Web Console:     http://localhost:9001"
    echo "   • Access Key:      minioadmin"
    echo "   • Secret Key:      minioadmin"
    echo "   • Default Bucket:  elhaiba-bucket"
    echo "   • Test Bucket:     test-bucket"
    echo ""
    echo "🔴 Redis Cache Service:"
    echo "   • Host:           localhost"
    echo "   • Port:           6379"
    echo "   • Database:       0 (default), 1 (testing)"
    echo "   • Authentication: None (development mode)"
    echo ""
    echo "🌐 Redis Commander (Web UI):"
    echo "   • URL:            http://localhost:8081"
    echo "   • Username:       admin"
    echo "   • Password:       admin"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "🧪 Running Tests:"
    echo "   • Unit Tests:           cargo test"
    echo "   • Integration Tests:    cargo test -- --ignored"
    echo "   • MinIO Tests:          cargo test --test minio_tests -- --ignored"
    echo "   • Redis Tests:          cargo test --test redis_tests -- --ignored"
    echo ""
    echo "🛑 Stopping Services:"
    echo "   • Stop all:             docker-compose down"
    echo "   • Stop and clean data:  rm -rf volumes/minio/* volumes/redis/*"
    echo ""
    echo "📖 For more information, see docker/README.md"
}

# Handle script arguments
case "${1:-}" in
    --help|-h)
        echo "Usage: $0 [OPTIONS]"
        echo ""
        echo "Options:"
        echo "  --help, -h     Show this help message"
        echo "  --status, -s   Show service status"
        echo "  --stop         Stop all services"
        echo "  --restart      Restart all services"
        echo "  --logs         Show service logs"
        echo ""
        echo "This script starts all infrastructure services required for the"
        echo "Elhaiba backend development environment."
        exit 0
        ;;
    --status|-s)
        print_status "Service Status:"
        docker-compose ps
        exit 0
        ;;
    --stop)
        print_status "Stopping all services..."
        docker-compose down
        print_success "All services stopped"
        exit 0
        ;;
    --restart)
        print_status "Restarting all services..."
        docker-compose down
        exec "$0"
        ;;
    --logs)
        print_status "Showing service logs (Ctrl+C to exit)..."
        docker-compose logs -f
        exit 0
        ;;
    "")
        # No arguments, run main setup
        main
        ;;
    *)
        print_error "Unknown option: $1"
        print_status "Use '$0 --help' for usage information"
        exit 1
        ;;
esac
