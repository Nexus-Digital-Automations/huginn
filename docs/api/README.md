# Huginn API Documentation

This directory contains comprehensive API documentation for integrating external systems with Huginn.

## 📚 Documentation Files

### [Integration Guide](./integration-guide.md)
**The complete reference for Huginn API integration**
- Getting started with authentication and configuration
- Webhook integration patterns (sending data TO Huginn)  
- Data retrieval patterns (getting data FROM Huginn)
- Agent management and monitoring APIs
- Real-world integration examples in multiple languages
- Error handling, rate limiting, and performance optimization
- Troubleshooting and debugging tools

### [OpenAPI Specification](./openapi-spec.yaml)
**Machine-readable API specification**
- Complete API endpoint definitions
- Request/response schemas and examples
- Authentication requirements
- Compatible with OpenAPI 3.0 tools and generators

## 🚀 Quick Start

1. **Read the [Integration Guide](./integration-guide.md)** for comprehensive examples and best practices
2. **Use the [OpenAPI Spec](./openapi-spec.yaml)** to generate client libraries or documentation
3. **Start with WebhookAgent** to send data TO Huginn
4. **Use DataOutputAgent** to get data FROM Huginn

## 🔗 Key API Patterns

### Webhook Endpoints (Incoming Data)
```
POST https://huginn.example.com/users/{user_id}/web_requests/{agent_id}/{secret}
```

### Data Feed Endpoints (Outgoing Data)  
```
GET https://huginn.example.com/users/{user_id}/web_requests/{agent_id}/{secret}.json
GET https://huginn.example.com/users/{user_id}/web_requests/{agent_id}/{secret}.xml
```

### Required Information
- **Domain**: Your Huginn instance URL
- **User ID**: Found in agent URLs or account settings
- **Agent ID**: Unique identifier for each agent  
- **Secret**: Authentication token configured in the agent

## 🛠️ Integration Examples

The integration guide includes complete, production-ready examples for:

- **IoT Data Pipelines** - Sensor data collection and alerting
- **E-commerce Integration** - Order processing and inventory management
- **Social Media Monitoring** - Brand mention tracking and analysis
- **Health Monitoring** - System status and performance tracking

## 📖 Additional Resources

- [Huginn Wiki](https://github.com/huginn/huginn/wiki) - Official project documentation
- [Agent Documentation](https://github.com/huginn/huginn/tree/master/app/models/agents) - Individual agent references
- [Huginn GitHub](https://github.com/huginn/huginn) - Source code and issues

## 🤝 Contributing

Found an issue or have a suggestion for the API documentation? Please:

1. Check existing issues in the [Huginn repository](https://github.com/huginn/huginn/issues)
2. Submit documentation feedback or improvements
3. Share your integration patterns and examples

---

**Need help?** Start with the [Integration Guide](./integration-guide.md) for step-by-step examples and troubleshooting.