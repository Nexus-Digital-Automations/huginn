# Huginn API Quick Reference

A concise reference for the most commonly used Huginn API endpoints.

## Authentication
```http
POST /users/sign_in - Login
DELETE /users/sign_out - Logout
```

## Agents
```http
GET    /agents           - List all agents
GET    /agents/{id}      - Get agent details
POST   /agents           - Create agent
PUT    /agents/{id}      - Update agent
DELETE /agents/{id}      - Delete agent
POST   /agents/{id}/run  - Run agent manually
```

## Events
```http
GET    /events            - List all events
GET    /events/{id}       - Get event details
GET    /agents/{id}/events - Get agent's events
DELETE /events/{id}       - Delete event
POST   /events/{id}/reemit - Re-emit event
```

## Scenarios
```http
GET    /scenarios                    - List scenarios
GET    /scenarios/{id}               - Get scenario details
POST   /scenarios                    - Create scenario
PUT    /scenarios/{id}               - Update scenario
DELETE /scenarios/{id}               - Delete scenario
GET    /scenarios/{id}/export        - Export scenario JSON
```

## External Webhooks (No Auth Required)
```http
POST /users/{user_id}/web_requests/{agent_id}/{secret}
```

Common webhook agents:
- **WebhookAgent** - Receive webhooks, create events
- **DataOutputAgent** - Output RSS/JSON feeds
- **UserLocationAgent** - Receive location updates

## System Status
```http
GET /worker_status - System health and job queue status
```

## Jobs (Admin Only)
```http
GET    /jobs                - List background jobs
DELETE /jobs/{id}           - Delete job
PUT    /jobs/{id}/run       - Force run job
POST   /jobs/retry_queued   - Retry failed jobs
DELETE /jobs/destroy_failed - Clear failed jobs
```

## Common Response Codes
- `200` - Success
- `201` - Created
- `401` - Unauthorized
- `403` - Forbidden/Invalid secret
- `404` - Not found
- `422` - Validation error

## Agent Types Reference

### WebhookAgent
**Purpose:** Receive external webhooks  
**Endpoint:** `POST /users/{user_id}/web_requests/{agent_id}/{secret}`  
**Key Options:** `secret`, `payload_path`, `verbs`, `response`

### DataOutputAgent  
**Purpose:** Export data as RSS/JSON feeds  
**Endpoint:** `GET /users/{user_id}/web_requests/{agent_id}/{secret}.{xml|json}`  
**Key Options:** `secrets[]`, `template`, `events_to_show`

### UserLocationAgent
**Purpose:** Track GPS location  
**Endpoint:** `POST /users/{user_id}/update_location/{secret}`  
**Key Options:** `secret`, `max_accuracy`, `min_distance`

### SchedulerAgent
**Purpose:** Trigger events on schedule  
**Key Options:** `action`, `schedule`

### WebsiteAgent  
**Purpose:** Scrape websites  
**Key Options:** `url`, `type`, `extract`

### EmailAgent
**Purpose:** Send emails  
**Key Options:** `recipients`, `subject`, `body`

### PostAgent
**Purpose:** Make HTTP requests  
**Key Options:** `url`, `method`, `payload`

## Quick Setup Examples

### Create Webhook Receiver
```bash
curl -X POST http://localhost:3000/agents \
  -H "Content-Type: application/json" \
  -d '{
    "agent": {
      "name": "My Webhook",
      "type": "Agents::WebhookAgent", 
      "options": {
        "secret": "my-secret-123",
        "payload_path": "."
      }
    }
  }'
```

### Send Webhook Data
```bash
curl -X POST http://localhost:3000/users/1/web_requests/1/my-secret-123 \
  -H "Content-Type: application/json" \
  -d '{"message": "Hello Huginn"}'
```

### Create RSS Feed
```bash
curl -X POST http://localhost:3000/agents \
  -H "Content-Type: application/json" \
  -d '{
    "agent": {
      "name": "My RSS Feed",
      "type": "Agents::DataOutputAgent",
      "options": {
        "secrets": ["feed-secret"],
        "template": {
          "title": "My Feed",
          "item": {
            "title": "{{title}}",
            "description": "{{description}}"
          }
        }
      }
    }
  }'
```

### Access RSS Feed
```bash
curl http://localhost:3000/users/1/web_requests/2/feed-secret.xml
```

## Troubleshooting

**401 Unauthorized**
- Check authentication session
- Verify secret tokens for webhooks

**403 Forbidden**  
- Admin endpoints require admin user
- Check agent ownership
- Verify secret token format

**422 Validation Error**
- Required fields missing (name, type, secret)
- Invalid agent options
- Check JSON format

**404 Not Found**
- Verify agent/user/event IDs
- Check URL paths
- Ensure resources exist

For complete details, see the [Full API Reference](reference.md) and [Data Schemas](schemas.md).