# Huginn Documentation

Welcome to the comprehensive documentation for Huginn - the IFTTT-like platform for building agents that monitor and act on your behalf.

## 📖 Table of Contents

### Getting Started
- [Overview](getting-started/README.md) - Introduction to Huginn and its capabilities

### Installation & Setup
- [Manual Installation](installation/manual/) - Complete manual setup guide
  - [Installation Guide](installation/manual/installation.md)
  - [Requirements](installation/manual/requirements.md)  
  - [Capistrano Deployment](installation/manual/capistrano.md)
  - [Update Guide](installation/manual/update.md)
- [Heroku Installation](installation/heroku/) - Deploy to Heroku
  - [Installation Guide](installation/heroku/install.md)
  - [Update Guide](installation/heroku/update.md)
- [Docker Installation](installation/docker/) - Docker-based deployment
  - [Installation Guide](installation/docker/install.md)

### Docker Documentation
- [Docker Overview](docker/README.md) - Docker deployment overview
- [Multi-Process Setup](docker/multi-process-README.md) - Multi-process Docker configuration
- [Single-Process Setup](docker/single-process-README.md) - Single-process Docker configuration  
- [Testing Setup](docker/test-README.md) - Docker testing environment

### Deployment & Configuration
- [Backup Configuration](deployment/backup/) - Backup strategies and examples
- [Capistrano Setup](deployment/capistrano/) - Capistrano deployment configuration
- [Nginx Configuration](deployment/nginx/) - Web server configuration
- [Unicorn Configuration](deployment/unicorn/) - Application server setup

### Development
- [Development Overview](development/general.md) - General development guidelines
- [Development Guides](development/guides/) - Detailed development guides
  - [TaskManager API Guide](development/guides/taskmanager-api-guide.md)
  - [Setup Stop Hook](development/guides/setup-stop-hook.md)
  - [Setup Post Tool Hook](development/guides/setup-post-tool-hook.md)
  - [Lint Hook Integration](development/guides/Lint%20Hook%20INTEGRATION.md)
- [Development Modes](development/modes/) - Different development workflows
  - [Development Mode](development/modes/development.md)
  - [Debugging Mode](development/modes/debugging.md)
  - [Testing Mode](development/modes/testing.md)
  - [Security Mode](development/modes/security.md)
  - [Performance Mode](development/modes/performance.md)
  - [Monitoring Mode](development/modes/monitoring.md)
  - [Deployment Mode](development/modes/deployment.md)
  - [Refactoring Mode](development/modes/refactoring.md)
  - [Research Mode](development/modes/research.md)
  - [Reviewer Mode](development/modes/reviewer.md)
  - [Task Creation Mode](development/modes/task-creation.md)

### Resources
- [Screenshots & Diagrams](images/) - Visual documentation and screenshots
- [Changelog](CHANGES.md) - Version history and release notes

## 🚀 Quick Start

1. **Choose your installation method:**
   - For production: [Manual Installation](installation/manual/installation.md) 
   - For cloud deployment: [Heroku Installation](installation/heroku/install.md)
   - For containerized deployment: [Docker Installation](installation/docker/install.md)

2. **Follow the setup guide** for your chosen method

3. **Explore the development documentation** if you plan to contribute or customize Huginn

## 📝 Contributing

This documentation is part of the Huginn project. For contributing guidelines, please refer to the main project repository.

## 🔗 Additional Resources

- [Main Huginn Repository](https://github.com/huginn/huginn)
- [Huginn Wiki](https://github.com/huginn/huginn/wiki) (if available)
- [Community Forums and Support](https://github.com/huginn/huginn/discussions)

---

*This documentation structure was organized to provide clear navigation and comprehensive coverage of all Huginn documentation.*