# MySQL Setup Research Report for Huginn

## Executive Summary

This report provides a comprehensive analysis of MySQL as an alternative database option for Huginn, comparing it with PostgreSQL and providing detailed setup instructions for macOS development environments.

## Current Huginn Database Configuration

### Default Database Support
- **Primary Database**: MySQL (mysql2 adapter)
- **Alternative Database**: PostgreSQL (pg adapter)
- **Configuration**: Environment variable `DATABASE_ADAPTER` controls which database is used
- **Default Behavior**: MySQL is the default unless running on Heroku (which defaults to PostgreSQL)

### Existing MySQL Integration
Huginn is already well-configured for MySQL with:
- `mysql2` gem (~> 0.5, >= 0.5.6) in Gemfile
- MySQL-specific database.yml configuration
- Docker support with MySQL 5.7 containers
- Production deployment guides for MySQL

## MySQL Installation & Configuration

### 1. Installation Options

#### macOS (Recommended: Homebrew)
```bash
# Install MySQL via Homebrew
brew install mysql

# Start MySQL service
brew services start mysql

# Secure installation (set root password, remove test databases)
mysql_secure_installation

# Connect to MySQL
mysql -u root -p
```

#### Linux (Ubuntu/Debian)
```bash
# Install MySQL server and client
sudo apt-get install -y mysql-server mysql-client libmysqlclient-dev

# For newer distributions (Debian BullsEye)
sudo apt-get install -y default-mysql-server default-mysql-client default-libmysqlclient-dev

# Secure installation
sudo mysql_secure_installation
```

#### Docker (Development)
```yaml
# Use existing docker/single-process/docker-compose.yml
version: '2'
services:
  mysql:
    image: mysql:5.7
    restart: always
    env_file:
      - ../mysql.env
    volumes_from:
      - mysqldata
```

### 2. MySQL Version Compatibility

#### Rails 7.0.1 Requirements
- **Supported MySQL Versions**: 5.7 and 8.0
- **Recommended Version**: MySQL 5.7 for Rails applications (based on performance analysis)
- **Minimum Requirements**: MySQL >= 5.5.3 for utf8mb4 support
- **Ruby Requirements**: Ruby >= 2.7.0 for Rails 7.0.1

#### Version-Specific Considerations
- **MySQL 5.7**: Stable, well-tested with Rails applications
- **MySQL 8.0**: Newer features but performance regressions in Rails environments (up to 36% slower)
- **MySQL 8.4.3/9.1.0 (2024)**: Recent improvements, but still evaluating stability

### 3. Huginn Database Setup

#### Create Database and User
```sql
# Connect as root
mysql -u root -p

# Create Huginn user
CREATE USER 'huginn'@'localhost' IDENTIFIED BY 'your_secure_password';

# Set InnoDB as default engine
SET default_storage_engine=INNODB;

# Grant permissions for development
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, INDEX, ALTER, LOCK TABLES ON `huginn_development`.* TO 'huginn'@'localhost';
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, INDEX, ALTER, LOCK TABLES ON `huginn_test`.* TO 'huginn'@'localhost';

# For production
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, INDEX, ALTER, LOCK TABLES ON `huginn_production`.* TO 'huginn'@'localhost';

# Apply changes
FLUSH PRIVILEGES;

# Exit MySQL
\q
```

#### Environment Configuration (.env)
```bash
# Database Configuration
DATABASE_ADAPTER=mysql2
DATABASE_ENCODING=utf8mb4  # For full UTF-8 support including emoji
DATABASE_RECONNECT=true
DATABASE_NAME=huginn_development
DATABASE_POOL=20
DATABASE_USERNAME=huginn
DATABASE_PASSWORD=your_secure_password
DATABASE_HOST=localhost
DATABASE_PORT=3306
# DATABASE_SOCKET=/tmp/mysql.sock  # If using socket connection
```

#### Huginn-Specific MySQL Configuration
The `mysqlpls.rb` initializer handles MySQL-specific optimizations:
- Limits varchar default to 191 characters for utf8mb4 compatibility
- Circumvents InnoDB index prefix byte limitations
- Only applied when not on Heroku

## Performance & Feature Comparison

### MySQL vs PostgreSQL for Rails Applications

#### MySQL Advantages
- **Default Database**: Huginn's primary and well-tested database
- **Mature Integration**: All Huginn features tested with MySQL
- **Docker Support**: Ready-to-use Docker configurations
- **Wide Adoption**: More familiar to many developers
- **Performance**: Better for read-heavy workloads

#### PostgreSQL Advantages
- **Advanced Features**: JSON columns, full-text search, arrays
- **ACID Compliance**: Stronger consistency guarantees
- **Extensibility**: PostGIS for geographic data, other extensions
- **Performance**: Better for complex queries and analytics
- **Modern Features**: Window functions, CTEs, advanced indexing

#### Performance Analysis (2024)
- **MySQL 5.7**: Stable performance, recommended for Rails applications
- **MySQL 8.0**: Performance regressions in Rails environments (6min vs 19min test suite)
- **Rails-Specific Impact**: MySQL 8.0 shows significant slowdowns for INSERT-heavy workloads
- **Recommendation**: Stay with MySQL 5.7 for production Rails applications

### Huginn-Specific Considerations
- **Agent Data**: Mostly JSON storage in text fields, no specific database feature requirements
- **Event Processing**: High INSERT/UPDATE volume, benefits from MySQL's write performance
- **Background Jobs**: Simple queue processing, no complex query requirements
- **Web Interface**: Standard Rails CRUD operations

## Development Setup Process

### Complete Installation and Configuration

#### 1. Install MySQL
```bash
# macOS with Homebrew
brew install mysql
brew services start mysql
mysql_secure_installation
```

#### 2. Create Databases
```sql
mysql -u root -p
CREATE USER 'huginn'@'localhost' IDENTIFIED BY 'huginn_dev_password';
SET default_storage_engine=INNODB;
GRANT ALL PRIVILEGES ON `huginn_%`.* TO 'huginn'@'localhost';
FLUSH PRIVILEGES;
\q
```

#### 3. Configure Huginn Environment
```bash
# Copy and edit .env file
cp .env.example .env

# Update database configuration
sed -i '' 's/DATABASE_ADAPTER=mysql2/DATABASE_ADAPTER=mysql2/' .env
sed -i '' 's/DATABASE_USERNAME=root/DATABASE_USERNAME=huginn/' .env
sed -i '' 's/DATABASE_PASSWORD=""/DATABASE_PASSWORD=huginn_dev_password/' .env
sed -i '' 's/DATABASE_ENCODING=utf8/DATABASE_ENCODING=utf8mb4/' .env
```

#### 4. Install Dependencies and Setup Database
```bash
# Install Ruby dependencies
bundle install

# Create and migrate databases
bin/rails db:create
bin/rails db:migrate
bin/rails db:seed

# Start Huginn
foreman start
```

#### 5. Connection Testing
```bash
# Test database connection
bin/rails runner "puts ActiveRecord::Base.connection.adapter_name"
# Should output: Mysql2

# Test basic operations
bin/rails console
> User.count
> Agent.count
```

## Migration Considerations

### From PostgreSQL to MySQL
- **Schema Differences**: JSON columns become TEXT, array columns need restructuring
- **Data Migration**: Use Rails migration tools or database export/import
- **Feature Compatibility**: Huginn doesn't use PostgreSQL-specific features extensively

### From MySQL 5.7 to 8.0
- **Performance Testing**: Mandatory before production deployment
- **Configuration Updates**: May need optimization for Rails workloads
- **Feature Validation**: Test all Huginn features after upgrade

### Database Schema Considerations
- **InnoDB Engine**: Required for transactions and foreign keys
- **utf8mb4 Encoding**: Essential for full Unicode support including emoji
- **Index Limitations**: Handled by Huginn's mysqlpls.rb initializer
- **Connection Pooling**: Configure appropriate pool size for concurrent agents

## Production-Ready Configuration

### MySQL Server Configuration
```ini
# /etc/mysql/mysql.conf.d/mysqld.cnf

[mysqld]
# Basic settings
default_storage_engine = InnoDB
character_set_server = utf8mb4
collation_server = utf8mb4_unicode_ci

# Performance tuning
innodb_buffer_pool_size = 1G  # Adjust based on available RAM
innodb_log_file_size = 256M
max_connections = 200

# Huginn-specific optimizations
innodb_large_prefix = 1
innodb_file_format = Barracuda
innodb_file_per_table = 1

# Security
bind_address = 127.0.0.1
```

### Backup Strategy
```bash
# Database backup
mysqldump -u huginn -p huginn_production > huginn_backup_$(date +%Y%m%d).sql

# Restore from backup
mysql -u huginn -p huginn_production < huginn_backup_20241203.sql
```

### Security Configuration
```sql
# Create production user with limited privileges
CREATE USER 'huginn_prod'@'localhost' IDENTIFIED BY 'strong_random_password';
GRANT SELECT, INSERT, UPDATE, DELETE ON huginn_production.* TO 'huginn_prod'@'localhost';
FLUSH PRIVILEGES;
```

## Recommendations

### For Development
1. **Use MySQL 5.7** for optimal Rails compatibility
2. **Install via Homebrew** on macOS for easy management
3. **Enable utf8mb4** encoding for full Unicode support
4. **Use InnoDB engine** for all tables

### For Production
1. **Stick with MySQL 5.7** until 8.0 performance issues are resolved
2. **Implement proper backup strategy** with regular automated backups
3. **Configure connection pooling** based on expected load
4. **Monitor performance** after any MySQL version changes

### Migration Strategy
1. **Test thoroughly** in development environment
2. **Benchmark performance** with your specific Huginn usage patterns
3. **Have rollback plan** ready for production migrations
4. **Consider staying with PostgreSQL** if already using it successfully

## Conclusion

MySQL remains an excellent choice for Huginn, being the default and well-supported database option. The existing integration is mature and battle-tested. For new installations, MySQL 5.7 is recommended due to performance considerations with Rails applications. The setup process is straightforward, especially on macOS with Homebrew, and the configuration is well-documented in Huginn's existing files.

While PostgreSQL offers more advanced features, MySQL's simplicity and Huginn's existing optimization make it the pragmatic choice for most users. The decision between MySQL and PostgreSQL should be based on your specific requirements, existing infrastructure, and team expertise rather than technical limitations of either option.