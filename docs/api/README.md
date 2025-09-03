# Huginn API Documentation

This directory contains comprehensive API documentation for the Huginn automation platform.

## Contents

- **`openapi.yaml`** - Complete OpenAPI 3.0 specification for all Huginn API endpoints
- **`integration-guide.md`** - Detailed integration guide with examples and best practices

## Quick Start

### 1. Authentication

Most API endpoints require session-based authentication through Devise. Login through the web interface first to establish a session, then use the session cookie in your API requests.

```bash
# Login first through web interface, then use the session cookie
curl -H "Cookie: _huginn_session=your-session-cookie" \
     https://your-huginn.com/agents
```

### 2. Webhooks (No Authentication Required)

Webhook endpoints use secret-based authentication and don't require sessions:

```bash
# Send webhook data to an agent
curl -X POST https://your-huginn.com/users/1/web_requests/123/your-secret \
     -H "Content-Type: application/json" \
     -d '{"event": "user_signup", "email": "user@example.com"}'
```

### 3. Common Operations

#### List Your Agents
```bash
GET /agents
```

#### Create a WebhookAgent
```bash
POST /agents
Content-Type: application/json

{
  "name": "My Webhook Agent",
  "type": "Agents::WebhookAgent",
  "options": {
    "secret": "my-secret-token",
    "expected_receive_period_in_days": 1,
    "payload_path": "."
  }
}
```

#### Get RSS Feed from DataOutputAgent
```bash
GET /users/1/web_requests/456/feed-secret?format=xml
```

## API Specification

The complete API specification is available in OpenAPI 3.0 format at `openapi.yaml`. You can:

1. **View in Swagger UI**: Import the YAML file into [Swagger Editor](https://editor.swagger.io/)
2. **Generate Client Libraries**: Use [OpenAPI Generator](https://openapi-generator.tech/) to create client libraries in your preferred language
3. **Import into Postman**: Import the OpenAPI spec directly into Postman for testing

## Key Features

### Webhook System
- **Multiple HTTP Verbs**: Support for GET, POST, PUT, DELETE
- **Secret Authentication**: Each agent uses a configurable secret token
- **Flexible Payloads**: JSON, form data, and multipart support
- **Custom Responses**: Agents can return custom content and HTTP status codes

### Agent Management
- **Full CRUD Operations**: Create, read, update, delete agents
- **Runtime Control**: Manually run agents, clear memory, re-emit events
- **Type Discovery**: Get agent type details and validation
- **Scenario Organization**: Group agents into scenarios

### Event Handling
- **Event Streams**: Monitor events across all agents
- **Re-emission**: Re-trigger events for downstream processing
- **Filtering**: Filter events by agent or time period

### Background Jobs
- **Job Monitoring**: View delayed job queue (admin only)
- **Job Control**: Retry, delete, or manually run jobs
- **System Status**: Monitor worker health and performance

## Security Considerations

1. **Secret Tokens**: Use strong, unique secrets for webhook agents
2. **HTTPS**: Always use HTTPS in production
3. **Rate Limiting**: Implement client-side rate limiting for API calls
4. **Validation**: Validate all webhook payloads in your agents
5. **Secrets Management**: Store API secrets securely, not in code

## Error Handling

The API uses standard HTTP status codes:

- **200/201**: Success
- **401**: Unauthorized (invalid session or secret)
- **403**: Forbidden (insufficient permissions)
- **404**: Not Found
- **422**: Validation Error
- **500**: Server Error

Error responses include descriptive messages in the response body.

## Examples

See `integration-guide.md` for detailed examples and integration patterns for common use cases including:

- Setting up webhook endpoints
- Creating data processing pipelines  
- Building RSS/JSON feeds
- Integrating with external services
- Monitoring and alerting

## Support

For questions and support:

- **Documentation**: [Huginn Wiki](https://github.com/huginn/huginn/wiki)
- **Issues**: [GitHub Issues](https://github.com/huginn/huginn/issues)
- **Community**: [Huginn Discussions](https://github.com/huginn/huginn/discussions)