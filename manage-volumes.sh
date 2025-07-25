#!/bin/bash

# =============================================================================
# ELHAIBA BACKEND - VOLUME MANAGEMENT SCRIPT
# =============================================================================
# This script provides utilities for managing local project volumes
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

# Function to check if volumes directory exists
check_volumes_dir() {
    if [ ! -d "volumes" ]; then
        print_error "volumes directory not found. Run this script from the project root."
        exit 1
    fi
}

# Function to show volume sizes
show_sizes() {
    check_volumes_dir
    print_status "Volume directory sizes:"
    echo ""
    
    if [ -d "volumes/minio" ]; then
        minio_size=$(du -sh volumes/minio 2>/dev/null | cut -f1 || echo "0B")
        echo "📦 MinIO:  $minio_size"
    else
        echo "📦 MinIO:  Directory not found"
    fi
    
    if [ -d "volumes/redis" ]; then
        redis_size=$(du -sh volumes/redis 2>/dev/null | cut -f1 || echo "0B")
        echo "🔴 Redis:  $redis_size"
    else
        echo "🔴 Redis:  Directory not found"
    fi
    
    total_size=$(du -sh volumes 2>/dev/null | cut -f1 || echo "0B")
    echo "📊 Total: $total_size"
}

# Function to list volume contents
list_contents() {
    check_volumes_dir
    local service="$1"
    
    case "$service" in
        minio|MinIO)
            print_status "MinIO volume contents:"
            if [ -d "volumes/minio" ]; then
                ls -la volumes/minio/ 2>/dev/null || print_warning "MinIO volume is empty"
            else
                print_error "MinIO volume directory not found"
            fi
            ;;
        redis|Redis)
            print_status "Redis volume contents:"
            if [ -d "volumes/redis" ]; then
                ls -la volumes/redis/ 2>/dev/null || print_warning "Redis volume is empty"
            else
                print_error "Redis volume directory not found"
            fi
            ;;
        all|"")
            print_status "All volume contents:"
            echo ""
            echo "📦 MinIO volume:"
            if [ -d "volumes/minio" ]; then
                ls -la volumes/minio/ 2>/dev/null || echo "  (empty)"
            else
                echo "  (directory not found)"
            fi
            echo ""
            echo "🔴 Redis volume:"
            if [ -d "volumes/redis" ]; then
                ls -la volumes/redis/ 2>/dev/null || echo "  (empty)"
            else
                echo "  (directory not found)"
            fi
            ;;
        *)
            print_error "Unknown service: $service"
            print_status "Available services: minio, redis, all"
            exit 1
            ;;
    esac
}

# Function to backup volumes
backup_volumes() {
    check_volumes_dir
    local service="$1"
    local timestamp=$(date +%Y%m%d-%H%M%S)
    
    case "$service" in
        minio|MinIO)
            if [ -d "volumes/minio" ]; then
                local backup_file="backup-minio-${timestamp}.tar.gz"
                print_status "Creating MinIO backup: $backup_file"
                tar -czf "$backup_file" volumes/minio/
                print_success "MinIO backup created: $backup_file"
            else
                print_error "MinIO volume directory not found"
                exit 1
            fi
            ;;
        redis|Redis)
            if [ -d "volumes/redis" ]; then
                local backup_file="backup-redis-${timestamp}.tar.gz"
                print_status "Creating Redis backup: $backup_file"
                tar -czf "$backup_file" volumes/redis/
                print_success "Redis backup created: $backup_file"
            else
                print_error "Redis volume directory not found"
                exit 1
            fi
            ;;
        all|"")
            local backup_file="backup-all-volumes-${timestamp}.tar.gz"
            print_status "Creating full backup: $backup_file"
            tar -czf "$backup_file" volumes/
            print_success "Full backup created: $backup_file"
            ;;
        *)
            print_error "Unknown service: $service"
            print_status "Available services: minio, redis, all"
            exit 1
            ;;
    esac
}

# Function to restore volumes
restore_volumes() {
    local backup_file="$1"
    
    if [ -z "$backup_file" ]; then
        print_error "Please specify a backup file to restore from"
        exit 1
    fi
    
    if [ ! -f "$backup_file" ]; then
        print_error "Backup file not found: $backup_file"
        exit 1
    fi
    
    print_warning "This will overwrite existing volume data!"
    read -p "Are you sure you want to continue? (y/N): " -n 1 -r
    echo
    
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_status "Restore cancelled"
        exit 0
    fi
    
    print_status "Restoring from backup: $backup_file"
    tar -xzf "$backup_file"
    print_success "Backup restored successfully"
}

# Function to clean volumes
clean_volumes() {
    local service="$1"
    
    print_warning "This will permanently delete volume data!"
    read -p "Are you sure you want to continue? (y/N): " -n 1 -r
    echo
    
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_status "Clean cancelled"
        exit 0
    fi
    
    case "$service" in
        minio|MinIO)
            if [ -d "volumes/minio" ]; then
                print_status "Cleaning MinIO volume..."
                rm -rf volumes/minio/*
                # Recreate .gitkeep
                echo "# This file ensures the minio volume directory is tracked in git" > volumes/minio/.gitkeep
                echo "# The actual MinIO data files will be ignored via .gitignore" >> volumes/minio/.gitkeep
                print_success "MinIO volume cleaned"
            else
                print_warning "MinIO volume directory not found"
            fi
            ;;
        redis|Redis)
            if [ -d "volumes/redis" ]; then
                print_status "Cleaning Redis volume..."
                rm -rf volumes/redis/*
                # Recreate .gitkeep
                echo "# This file ensures the redis volume directory is tracked in git" > volumes/redis/.gitkeep
                echo "# The actual Redis data files will be ignored via .gitignore" >> volumes/redis/.gitkeep
                print_success "Redis volume cleaned"
            else
                print_warning "Redis volume directory not found"
            fi
            ;;
        all|"")
            print_status "Cleaning all volumes..."
            if [ -d "volumes" ]; then
                rm -rf volumes/minio/* volumes/redis/* 2>/dev/null || true
                # Recreate .gitkeep files
                echo "# This file ensures the minio volume directory is tracked in git" > volumes/minio/.gitkeep
                echo "# The actual MinIO data files will be ignored via .gitignore" >> volumes/minio/.gitkeep
                echo "# This file ensures the redis volume directory is tracked in git" > volumes/redis/.gitkeep
                echo "# The actual Redis data files will be ignored via .gitignore" >> volumes/redis/.gitkeep
                print_success "All volumes cleaned"
            else
                print_warning "Volumes directory not found"
            fi
            ;;
        *)
            print_error "Unknown service: $service"
            print_status "Available services: minio, redis, all"
            exit 1
            ;;
    esac
}

# Function to initialize volumes
init_volumes() {
    print_status "Initializing volume directories..."
    
    # Create directories if they don't exist
    mkdir -p volumes/minio volumes/redis
    
    # Set proper permissions
    chmod 755 volumes/minio volumes/redis
    
    # Create .gitkeep files if they don't exist
    if [ ! -f "volumes/minio/.gitkeep" ]; then
        echo "# This file ensures the minio volume directory is tracked in git" > volumes/minio/.gitkeep
        echo "# The actual MinIO data files will be ignored via .gitignore" >> volumes/minio/.gitkeep
    fi
    
    if [ ! -f "volumes/redis/.gitkeep" ]; then
        echo "# This file ensures the redis volume directory is tracked in git" > volumes/redis/.gitkeep
        echo "# The actual Redis data files will be ignored via .gitignore" >> volumes/redis/.gitkeep
    fi
    
    # Ensure proper ownership
    if [ "$(id -u)" != "0" ] && [ -w volumes/ ]; then
        chown -R $(id -u):$(id -g) volumes/ 2>/dev/null || true
    fi
    
    print_success "Volume directories initialized"
}

# Function to show help
show_help() {
    echo "Usage: $0 <command> [options]"
    echo ""
    echo "Commands:"
    echo "  size                    Show volume directory sizes"
    echo "  list [service]          List volume contents (minio, redis, all)"
    echo "  backup [service]        Create backup (minio, redis, all)"
    echo "  restore <backup_file>   Restore from backup file"
    echo "  clean [service]         Clean volume data (minio, redis, all)"
    echo "  init                    Initialize volume directories"
    echo "  help                    Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 size                      # Show all volume sizes"
    echo "  $0 list minio                # List MinIO volume contents"
    echo "  $0 backup redis              # Backup Redis volume"
    echo "  $0 restore backup-all-*.tar.gz  # Restore from backup"
    echo "  $0 clean all                 # Clean all volumes"
    echo "  $0 init                      # Initialize volume directories"
}

# Main script logic
case "${1:-}" in
    size)
        show_sizes
        ;;
    list)
        list_contents "$2"
        ;;
    backup)
        backup_volumes "$2"
        ;;
    restore)
        restore_volumes "$2"
        ;;
    clean)
        clean_volumes "$2"
        ;;
    init)
        init_volumes
        ;;
    help|--help|-h)
        show_help
        ;;
    "")
        print_error "No command specified"
        show_help
        exit 1
        ;;
    *)
        print_error "Unknown command: $1"
        show_help
        exit 1
        ;;
esac
