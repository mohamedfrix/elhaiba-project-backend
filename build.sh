#!/bin/bash

# Elhaiba Backend Build and Deploy Script

set -e

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

# Default values
ENVIRONMENT="prod"
BUILD_ONLY=false
PUSH_IMAGE=false
IMAGE_NAME="elhaiba-backend"
IMAGE_TAG="latest"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -e|--env)
            ENVIRONMENT="$2"
            shift 2
            ;;
        -b|--build-only)
            BUILD_ONLY=true
            shift
            ;;
        -p|--push)
            PUSH_IMAGE=true
            shift
            ;;
        -t|--tag)
            IMAGE_TAG="$2"
            shift 2
            ;;
        -n|--name)
            IMAGE_NAME="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo "Options:"
            echo "  -e, --env ENV        Environment (prod/dev) [default: prod]"
            echo "  -b, --build-only     Only build the image, don't run"
            echo "  -p, --push          Push image to registry"
            echo "  -t, --tag TAG       Image tag [default: latest]"
            echo "  -n, --name NAME     Image name [default: elhaiba-backend]"
            echo "  -h, --help          Show this help message"
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

print_status "Starting Elhaiba Backend build process..."
print_status "Environment: $ENVIRONMENT"
print_status "Image: $IMAGE_NAME:$IMAGE_TAG"

# Check if Docker is running
if ! docker info >/dev/null 2>&1; then
    print_error "Docker is not running. Please start Docker and try again."
    exit 1
fi

# Check if environment file exists
ENV_FILE=".env.$ENVIRONMENT"
if [ ! -f "$ENV_FILE" ]; then
    if [ -f ".env.$ENVIRONMENT.example" ]; then
        print_warning "Environment file $ENV_FILE not found."
        print_status "Copying from example file..."
        cp ".env.$ENVIRONMENT.example" "$ENV_FILE"
        print_warning "Please edit $ENV_FILE with your actual values before running again."
        exit 1
    else
        print_error "Environment file $ENV_FILE not found and no example available."
        exit 1
    fi
fi

# Build the Docker image
print_status "Building Docker image..."
if docker build -t "$IMAGE_NAME:$IMAGE_TAG" .; then
    print_success "Docker image built successfully!"
else
    print_error "Failed to build Docker image"
    exit 1
fi

# Push image if requested
if [ "$PUSH_IMAGE" = true ]; then
    print_status "Pushing image to registry..."
    if docker push "$IMAGE_NAME:$IMAGE_TAG"; then
        print_success "Image pushed successfully!"
    else
        print_error "Failed to push image"
        exit 1
    fi
fi

# Exit if build-only mode
if [ "$BUILD_ONLY" = true ]; then
    print_success "Build completed. Use the following command to run:"
    echo "docker-compose --env-file $ENV_FILE -f docker-compose.prod.yml up -d"
    exit 0
fi

# Stop existing containers
print_status "Stopping existing containers..."
docker-compose --env-file "$ENV_FILE" -f docker-compose.prod.yml down

# Start the application
print_status "Starting application..."
if docker-compose --env-file "$ENV_FILE" -f docker-compose.prod.yml up -d; then
    print_success "Application started successfully!"
    print_status "Services are starting up..."
    
    # Wait a moment for services to initialize
    sleep 5
    
    # Show running containers
    print_status "Running containers:"
    docker-compose --env-file "$ENV_FILE" -f docker-compose.prod.yml ps
    
    print_success "Deployment completed!"
    print_status "Application should be available at: http://localhost:4000"
    print_status "MinIO Console: http://localhost:9001"
    print_status ""
    print_status "To view logs: docker-compose --env-file $ENV_FILE -f docker-compose.prod.yml logs -f"
    print_status "To stop: docker-compose --env-file $ENV_FILE -f docker-compose.prod.yml down"
else
    print_error "Failed to start application"
    exit 1
fi
