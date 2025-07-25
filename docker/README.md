# Docker Setup for Elhaiba Backend

This directory contains Docker configuration files for running the infrastructure services required by the Elhaiba backend application.

## Services Included

### MinIO (Object Storage)
- **API Port**: 9000
- **Console Port**: 9001 (Web UI)
- **Default Credentials**: minioadmin / minioadmin
- **Console URL**: http://localhost:9001

### Redis (Cache Service)
- **Port**: 6379
- **Databases**: 16 (0-15)
- **Memory Limit**: 256MB (development)
- **Persistence**: AOF + RDB snapshots

### Redis Commander (Optional Web UI)
- **Port**: 8081
- **Credentials**: admin / admin
- **URL**: http://localhost:8081

## Quick Start

### Start All Services
```bash
# Start all services in the background
docker-compose up -d

# View logs
docker-compose logs -f

# Check service status
docker-compose ps
```

### Stop All Services
```bash
# Stop all services
docker-compose down

# Stop and remove all data (WARNING: This deletes all data!)
docker-compose down -v
```

### Individual Service Management
```bash
# Start only MinIO
docker-compose up -d minio

# Start only Redis
docker-compose up -d redis

# Restart a service
docker-compose restart redis

# View logs for a specific service
docker-compose logs -f minio
```

## Service Access

### MinIO
- **API Endpoint**: http://localhost:9000
- **Web Console**: http://localhost:9001
- **Access Key**: minioadmin
- **Secret Key**: minioadmin
- **Default Bucket**: elhaiba-bucket
- **Test Bucket**: test-bucket

### Redis
- **Host**: localhost
- **Port**: 6379
- **Database**: 0 (default), 1 (testing)
- **No authentication** (development only)

### Redis Commander
- **URL**: http://localhost:8081
- **Username**: admin
- **Password**: admin

## Configuration Files

### `docker-compose.yml`
Main Docker Compose configuration with all services.

### `redis/redis.conf`
Custom Redis configuration optimized for development:
- Memory limit: 256MB
- Persistence: AOF + RDB snapshots
- Eviction policy: allkeys-lru
- Keyspace notifications for expired events

## Environment Variables

The following environment variables are used (defined in `.env`):

### MinIO
- `MINIO_ENDPOINT=localhost:9000`
- `MINIO_ACCESS_KEY=minioadmin`
- `MINIO_SECRET_KEY=minioadmin`
- `MINIO_BUCKET_NAME=elhaiba-bucket`
- `MINIO_REGION=us-east-1`
- `MINIO_SECURE=false`

### Redis
- `REDIS_HOST=localhost`
- `REDIS_PORT=6379`
- `REDIS_DATABASE=0`
- `REDIS_POOL_MAX_SIZE=20`
- `REDIS_CONNECTION_TIMEOUT=5`
- `REDIS_COMMAND_TIMEOUT=10`
- `REDIS_USE_TLS=false`

### Container Names
- `MINIO_CONTAINER_NAME=elhaiba-minio`
- `REDIS_CONTAINER_NAME=elhaiba-redis`

## Data Persistence

### Local Volumes
The project uses bind mounts to local directories for data persistence:

- `./volumes/minio/`: MinIO object storage data
- `./volumes/redis/`: Redis database files

This approach provides several benefits:
- **Easy backup**: Simply copy the `volumes/` directory
- **Direct access**: Inspect data files directly on the host system
- **Version control**: Volume directories are tracked in git (but data files are ignored)
- **Portability**: Data moves with the project

### Backup and Restore
```bash
# Backup all data
tar -czf backup-$(date +%Y%m%d-%H%M%S).tar.gz volumes/

# Restore from backup
tar -xzf backup-20240115-143022.tar.gz

# Backup individual services
tar -czf minio-backup.tar.gz volumes/minio/
tar -czf redis-backup.tar.gz volumes/redis/
```

## Testing

### Running Integration Tests
```bash
# Start services
docker-compose up -d

# Wait for services to be ready
sleep 10

# Run tests that require MinIO and Redis
cargo test --test minio_tests -- --ignored
cargo test --test redis_tests -- --ignored

# Run all integration tests
cargo test -- --ignored
```

### Health Checks
```bash
# Check MinIO health
curl -f http://localhost:9000/minio/health/live

# Check Redis health
docker-compose exec redis redis-cli ping

# Check all service health
docker-compose ps
```

## Troubleshooting

### Common Issues

#### Services not starting
```bash
# Check logs
docker-compose logs

# Check specific service logs
docker-compose logs minio
docker-compose logs redis
```

#### Port conflicts
```bash
# Check what's using the ports
lsof -i :9000
lsof -i :9001
lsof -i :6379
lsof -i :8081

# Change ports in docker-compose.yml if needed
```

#### Permission issues
```bash
# Fix volume permissions
sudo chown -R $USER:$USER ./data
```

#### MinIO bucket creation fails
```bash
# Manually create buckets
docker-compose exec minio mc mb minio/elhaiba-bucket
docker-compose exec minio mc mb minio/test-bucket
```

### Cleanup
```bash
# Remove all containers and networks
docker-compose down

# Remove all data (WARNING: Deletes all data!)
rm -rf volumes/minio/* volumes/redis/*

# Or remove entire volumes directory (will need to recreate .gitkeep files)
rm -rf volumes/

# Remove all images
docker-compose down --rmi all

# Clean up Docker system
docker system prune -a
```

## Production Considerations

When deploying to production, consider:

1. **Security**:
   - Change default passwords
   - Enable TLS/SSL
   - Use secrets management
   - Configure proper network security

2. **Performance**:
   - Increase memory limits
   - Tune Redis configuration
   - Use persistent storage
   - Monitor resource usage

3. **High Availability**:
   - Use Redis Cluster or Sentinel
   - Set up MinIO in distributed mode
   - Implement proper backup strategies
   - Configure health checks and monitoring

4. **Configuration**:
   - Use separate configuration files for production
   - Set proper resource limits
   - Configure logging and monitoring
   - Use environment-specific settings
