# Volumes Directory

This directory contains the persistent data for all Docker services used by the Elhaiba backend project.

## Structure

```
volumes/
├── minio/          # MinIO object storage data
│   └── .gitkeep    # Ensures directory is tracked in git
├── redis/          # Redis database files
│   └── .gitkeep    # Ensures directory is tracked in git
└── README.md       # This file
```

## Services

### MinIO (`./minio/`)
- **Purpose**: Object storage data and metadata
- **Contains**: Buckets, objects, and MinIO configuration
- **Default Buckets**: `elhaiba-bucket`, `test-bucket`
- **Access**: Files stored through MinIO API

### Redis (`./redis/`)
- **Purpose**: Redis database persistence files
- **Contains**: RDB snapshots, AOF logs, and temporary files
- **Persistence**: Both RDB and AOF enabled
- **Database**: 16 databases (0-15)

## Data Management

### Using the Volume Manager Script
```bash
# Show volume sizes
./manage-volumes.sh size

# List contents
./manage-volumes.sh list all
./manage-volumes.sh list minio
./manage-volumes.sh list redis

# Create backups
./manage-volumes.sh backup all
./manage-volumes.sh backup minio
./manage-volumes.sh backup redis

# Restore from backup
./manage-volumes.sh restore backup-all-20240115-143022.tar.gz

# Clean volumes (WARNING: Deletes data!)
./manage-volumes.sh clean all
./manage-volumes.sh clean minio
./manage-volumes.sh clean redis

# Initialize directories
./manage-volumes.sh init
```

### Manual Management
```bash
# View sizes
du -sh volumes/*

# Backup manually
tar -czf backup-$(date +%Y%m%d-%H%M%S).tar.gz volumes/

# Clean manually (WARNING: Deletes all data!)
rm -rf volumes/minio/* volumes/redis/*
```

## Git Integration

- **Tracked**: Directory structure and `.gitkeep` files
- **Ignored**: Actual data files (see `.gitignore`)
- **Benefits**: 
  - Volume directories are preserved in version control
  - Data files don't bloat the repository
  - Easy setup for new developers

## Permissions

The volume directories need proper permissions for Docker containers:
- **Owner**: Current user (for development)
- **Permissions**: 755 (rwxr-xr-x)
- **Setup**: Automatically configured by `setup-dev.sh`

## Backup Strategy

### Development
- Use the volume manager script for quick backups
- Backup before major changes or updates
- Keep recent backups locally

### Production
- Implement automated daily backups
- Store backups in separate storage systems
- Test restore procedures regularly
- Consider using volume snapshots

## Troubleshooting

### Permission Issues
```bash
# Fix ownership
sudo chown -R $USER:$USER volumes/

# Fix permissions
chmod -R 755 volumes/
```

### Data Corruption
```bash
# Stop services
docker-compose down

# Check data integrity
./manage-volumes.sh list all

# Restore from backup if needed
./manage-volumes.sh restore backup-file.tar.gz

# Restart services
docker-compose up -d
```

### Space Issues
```bash
# Check sizes
./manage-volumes.sh size

# Clean old data
./manage-volumes.sh clean [service]

# Or manually remove specific files
rm -rf volumes/redis/dump.rdb
```

## Security Considerations

1. **Sensitive Data**: Volume data may contain sensitive information
2. **Backup Security**: Encrypt backups containing sensitive data
3. **Access Control**: Restrict access to volume directories in production
4. **Data Retention**: Implement proper data retention policies
5. **Audit Trail**: Log access to volume data in production environments

## Performance Notes

- **SSD Recommended**: Use SSD storage for better I/O performance
- **Space Monitoring**: Monitor disk space usage regularly
- **Cleanup**: Implement regular cleanup of old data
- **Optimization**: Redis AOF files can grow large; monitor and optimize
