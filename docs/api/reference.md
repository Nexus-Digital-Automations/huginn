# Huginn API Reference

This document provides a comprehensive reference for all Huginn API endpoints, organized by functional areas. All APIs require authentication unless explicitly noted.

## Table of Contents

- [Authentication](#authentication)
- [Agent Management APIs](#agent-management-apis)
- [Event APIs](#event-apis)
- [Scenario Management APIs](#scenario-management-apis)
- [External Web Request APIs](#external-web-request-apis)
- [System & Job Management APIs](#system--job-management-apis)
- [Data Models](#data-models)
- [Error Handling](#error-handling)
- [Agent-Specific APIs](#agent-specific-apis)

## Authentication

Huginn uses session-based authentication via Devise. Most API endpoints require authentication except for external webhook endpoints and public scenario exports.

### Session Management
- `POST /users/sign_in` - User login
- `DELETE /users/sign_out` - User logout  
- `POST /users` - User registration (if enabled)

### Admin Authentication
Some endpoints require admin privileges and will return 403 if accessed by non-admin users.

## Agent Management APIs

### Core Agent Operations

#### List Agents
```http
GET /agents
Accept: application/json
```

**Query Parameters:**
- `page` - Page number for pagination
- Various sorting parameters via SortableTable concern

**Response:** Array of agent objects with basic information

#### Get Agent Details
```http
GET /agents/{id}
Accept: application/json
```

**Response:** Complete agent object including configuration and metadata

#### Create Agent
```http
POST /agents
Content-Type: application/json

{
  "agent": {
    "name": "My Agent",
    "type": "Agents::WebhookAgent",
    "options": {...},
    "schedule": "never",
    "scenario_ids": [1, 2]
  }
}
```

**Parameters:**
- `name` - Agent display name (required)
- `type` - Agent class name (required)
- `options` - Agent-specific configuration (required)
- `schedule` - Execution schedule (see SCHEDULES constant)
- `disabled` - Boolean, default false
- `keep_events_for` - Event retention period in seconds
- `source_ids` - Array of source agent IDs
- `receiver_ids` - Array of receiver agent IDs
- `scenario_ids` - Array of scenario IDs
- `controller_ids` - Array of controller agent IDs
- `control_target_ids` - Array of control target agent IDs
- `service_id` - Associated service ID
- `propagate_immediately` - Boolean for immediate event propagation
- `drop_pending_events` - Boolean for event handling

**Response:** Created agent object or validation errors

#### Update Agent
```http
PUT /agents/{id}
Content-Type: application/json

{
  "agent": {
    "name": "Updated Name",
    "options": {...}
  }
}
```

**Response:** Updated agent object or validation errors

#### Delete Agent
```http
DELETE /agents/{id}
```

**Response:** 204 No Content

### Agent Operations

#### Run Agent Manually
```http
POST /agents/{id}/run
```

Triggers immediate execution of the agent outside its normal schedule.

**Response:** 200 OK

#### Get Agent Type Details
```http
GET /agents/type_details?type=Agents::WebhookAgent
```

Returns metadata about agent type capabilities and default configuration.

**Response:**
```json
{
  "can_be_scheduled": true,
  "default_schedule": "never",
  "can_receive_events": true,
  "can_create_events": true,
  "can_control_other_agents": false,
  "can_dry_run": true,
  "options": {...},
  "description_html": "...",
  "oauthable": "...",
  "form_options": "..."
}
```

#### Get Event Descriptions
```http
GET /agents/event_descriptions?ids=1,2,3
```

Returns HTML description of events that specified agents can produce.

#### Validate Agent Option
```http
POST /agents/validate
Content-Type: application/json

{
  "agent": {...},
  "attribute": "option_name"
}
```

Validates a specific agent option value.

**Response:** "ok" or "error" with 403 status

#### Complete Agent Option
```http
POST /agents/complete
Content-Type: application/json

{
  "agent": {...},
  "attribute": "option_name"
}
```

Returns completion suggestions for agent option values.

#### Re-emit Events
```http
POST /agents/{id}/reemit_events?delete_old_events=1
```

Re-emits all events from an agent, optionally deleting old events.

#### Remove All Events
```http
DELETE /agents/{id}/remove_events
```

Deletes all events created by the agent.

#### Clear Agent Memory
```http
DELETE /agents/{id}/memory
```

Resets the agent's internal memory state.

#### Leave Scenario
```http
PUT /agents/{id}/leave_scenario?scenario_id=1
```

Removes agent from specified scenario.

### Bulk Operations

#### Toggle Visibility
```http
PUT /agents/toggle_visibility
```

Toggles between showing all agents or only enabled agents in the interface.

#### Propagate Events
```http
POST /agents/propagate
```

Manually triggers event propagation across all agents.

**Response:** 200 OK or 423 Locked if already running

#### Delete Undefined Agents
```http
DELETE /agents/undefined
```

Removes all agents with undefined/missing agent types.

## Event APIs

### Event Operations

#### List Events
```http
GET /events
Accept: application/json
```

**Query Parameters:**
- `page` - Page number
- `agent_id` - Filter by specific agent

**Response:** Paginated list of events

#### List Agent Events
```http
GET /agents/{agent_id}/events
Accept: application/json
```

**Response:** Events created by specific agent

#### Get Event Details  
```http
GET /events/{id}
Accept: application/json
```

**Response:** Complete event object with payload and metadata

#### Delete Event
```http
DELETE /events/{id}
```

**Response:** 204 No Content

#### Re-emit Event
```http
POST /events/{id}/reemit
```

Re-emits a specific event to trigger downstream processing.

## Scenario Management APIs

### Scenario Operations

#### List Scenarios
```http
GET /scenarios
Accept: application/json
```

**Response:** Array of scenario objects

#### Get Scenario Details
```http
GET /scenarios/{id}
Accept: application/json
```

**Response:** Complete scenario object with associated agents

#### Create Scenario
```http
POST /scenarios
Content-Type: application/json

{
  "scenario": {
    "name": "My Scenario",
    "description": "Description",
    "public": false,
    "tag_fg_color": "#ffffff",
    "tag_bg_color": "#000000",
    "icon": "fa-cog",
    "agent_ids": [1, 2, 3]
  }
}
```

#### Update Scenario
```http
PUT /scenarios/{id}
Content-Type: application/json

{
  "scenario": {
    "name": "Updated Name"
  }
}
```

#### Delete Scenario
```http
DELETE /scenarios/{id}?mode=delete_mode
```

**Query Parameters:**
- `mode` - Deletion mode for handling associated agents

#### Export Scenario
```http
GET /scenarios/{id}/export
```

Exports scenario configuration as JSON. Available for public scenarios or scenarios owned by authenticated user.

**Response:** JSON file download

#### Share Scenario
```http
GET /scenarios/{id}/share
```

Returns sharing interface and public URL for scenarios.

#### Enable/Disable All Agents
```http
PUT /scenarios/{id}/enable_or_disable_all_agents
Content-Type: application/json

{
  "scenario": {
    "disabled": "true"
  }
}
```

Bulk enable or disable all agents within a scenario.

### Scenario Import

#### Create Import Session
```http
POST /scenarios/scenario_imports
Content-Type: application/json

{
  "scenario_import": {
    "file": "base64_encoded_json"
  }
}
```

Initiates scenario import process from JSON file.

## External Web Request APIs

These endpoints are designed for external systems to send data to Huginn agents without authentication.

### Webhook Endpoint
```http
GET|POST|PUT|DELETE /users/{user_id}/web_requests/{agent_id}/{secret}
Content-Type: application/json
```

**Path Parameters:**
- `user_id` - User ID who owns the agent  
- `agent_id` - Target agent ID
- `secret` - Secret token for authentication

**Supported Agents:**
- WebhookAgent - Receives webhooks and creates events
- DataOutputAgent - Outputs RSS/JSON feeds  
- UserLocationAgent - Receives location data
- LiquidOutputAgent - Outputs templated data
- TwilioReceiveTextAgent - Receives SMS webhooks
- TwilioAgent - Receives communication webhooks

**Response:** Agent-specific response format

### Legacy Location Update
```http
POST /users/{user_id}/update_location/{secret}
Content-Type: application/x-www-form-urlencoded

latitude=37.123&longitude=-122.456
```

Legacy endpoint for location updates, primarily for iOS apps.

## System & Job Management APIs

### Worker Status
```http
GET /worker_status
Accept: application/json
```

Returns system health and job queue status.

**Response:**
```json
{
  "pending": 5,
  "awaiting_retry": 2,
  "recent_failures": 0,
  "event_count": 150,
  "max_id": 12345,
  "events_url": "/events?hl=12345",
  "compute_time": 0.045
}
```

### Job Management (Admin Only)

#### List Jobs
```http
GET /jobs
Accept: application/json
```

**Response:** Paginated list of background jobs

#### Delete Job
```http
DELETE /jobs/{id}
```

Deletes a specific job (cannot delete running jobs).

#### Run Job
```http
PUT /jobs/{id}/run
```

Forces immediate execution of a job.

#### Retry Failed Jobs
```http
POST /jobs/retry_queued
```

Retries all jobs awaiting retry.

#### Delete Failed Jobs
```http
DELETE /jobs/destroy_failed
```

Removes all failed jobs from queue.

#### Delete All Jobs
```http
DELETE /jobs/destroy_all
```

Removes all non-running jobs from queue.

### Admin User Management

#### List Users (Admin Only)
```http
GET /admin/users
Accept: application/json
```

#### Create User (Admin Only)
```http
POST /admin/users
Content-Type: application/json

{
  "user": {
    "username": "newuser",
    "email": "user@example.com",
    "password": "password"
  }
}
```

#### Update User (Admin Only)
```http
PUT /admin/users/{id}
```

#### Delete User (Admin Only)
```http
DELETE /admin/users/{id}
```

#### Deactivate User (Admin Only)
```http
PUT /admin/users/{id}/deactivate
```

#### Activate User (Admin Only)
```http
PUT /admin/users/{id}/activate
```

#### Switch to User (Admin Only)
```http
GET /admin/users/{id}/switch_to_user
```

#### Switch Back (Admin Only)
```http
GET /admin/users/switch_back
```

## Data Models

### Agent Model
```json
{
  "id": 1,
  "name": "My Agent",
  "type": "Agents::WebhookAgent",
  "options": {},
  "schedule": "never",
  "disabled": false,
  "memory": {},
  "last_check_at": "2023-01-01T00:00:00Z",
  "last_event_at": "2023-01-01T00:00:00Z",
  "last_receive_at": "2023-01-01T00:00:00Z",
  "last_web_request_at": "2023-01-01T00:00:00Z",
  "keep_events_for": 86400,
  "propagate_immediately": false,
  "drop_pending_events": false,
  "created_at": "2023-01-01T00:00:00Z",
  "updated_at": "2023-01-01T00:00:00Z",
  "user_id": 1,
  "service_id": null,
  "guid": "unique-identifier",
  "events_count": 150,
  "deactivated": false
}
```

### Event Model
```json
{
  "id": 1,
  "user_id": 1,
  "agent_id": 1,
  "lat": 37.123456,
  "lng": -122.123456,
  "payload": {},
  "created_at": "2023-01-01T00:00:00Z",
  "updated_at": "2023-01-01T00:00:00Z",
  "expires_at": "2023-01-02T00:00:00Z"
}
```

### Scenario Model
```json
{
  "id": 1,
  "name": "My Scenario",
  "description": "Scenario description",
  "user_id": 1,
  "public": false,
  "source_url": null,
  "guid": "scenario-guid",
  "tag_fg_color": "#ffffff",
  "tag_bg_color": "#000000",
  "icon": "fa-cog",
  "created_at": "2023-01-01T00:00:00Z",
  "updated_at": "2023-01-01T00:00:00Z"
}
```

## Error Handling

### Standard HTTP Status Codes

- **200 OK** - Successful request
- **201 Created** - Resource successfully created
- **204 No Content** - Successful request with no response body
- **400 Bad Request** - Invalid request parameters
- **401 Unauthorized** - Authentication required or invalid
- **403 Forbidden** - Access denied (admin required, invalid secret, etc.)
- **404 Not Found** - Resource not found
- **422 Unprocessable Entity** - Validation errors
- **423 Locked** - Resource temporarily locked (e.g., job already running)
- **500 Internal Server Error** - Server error

### Error Response Format

```json
{
  "errors": {
    "field_name": ["validation error message"],
    "base": ["general error message"]
  }
}
```

### Common Validation Errors

- Missing required fields (name, type, secret, etc.)
- Invalid agent type
- Invalid schedule values
- Invalid JSON in options
- Circular dependencies in agent connections
- Invalid secret tokens in external APIs

## Agent-Specific APIs

### WebhookAgent
**Endpoint:** `POST /users/{user_id}/web_requests/{agent_id}/{secret}`

**Options:**
- `secret` - Authentication token (required)
- `expected_receive_period_in_days` - Health check period
- `payload_path` - JSONPath for extracting payload data  
- `event_headers` - HTTP headers to include in events
- `event_headers_key` - Key name for header storage
- `verbs` - Allowed HTTP methods (comma-separated)
- `response` - Custom response message
- `response_headers` - Custom response headers object
- `code` - HTTP response code (default 201)
- `recaptcha_secret` - reCAPTCHA validation
- `score_threshold` - reCAPTCHA v3 score threshold

**Features:**
- Accepts GET, POST, PUT, DELETE requests (configurable)
- reCAPTCHA integration for spam protection
- Custom response codes and headers
- JSONPath payload extraction
- Multiple event creation from arrays

### DataOutputAgent
**Endpoint:** `GET /users/{user_id}/web_requests/{agent_id}/{secret}.{format}`

**Formats:** `xml` (RSS), `json`

**Options:**
- `secrets` - Array of valid authentication tokens
- `template` - Output template configuration
- `events_to_show` - Number of events to display (default 40)
- `ttl` - RSS TTL value (default 60)
- `push_hubs` - PubSubHubbub endpoints for notifications
- `ns_dc`, `ns_media`, `ns_itunes` - XML namespace options
- `rss_content_type` - RSS content type header
- `response_headers` - Custom response headers

**Features:**
- RSS and JSON feed generation
- Liquid templating for output formatting
- PubSubHubbub push notifications
- Custom XML namespaces
- Event ordering and pagination

### UserLocationAgent
**Endpoint:** `POST /users/{user_id}/update_location/{secret}`

**Options:**
- `secret` - Authentication token (required, >4 characters)
- `max_accuracy` - Maximum GPS accuracy in meters
- `min_distance` - Minimum distance for new location events
- `api_key` - Google Maps API key for visualization

**Input Format:**
```json
{
  "latitude": "37.123456",
  "longitude": "-122.123456", 
  "accuracy": "5.0",
  "timestamp": "1234567890.0",
  "altitude": "100.0",
  "speed": "1.5"
}
```

### Dry Run APIs

#### Run Dry Run Test
```http
POST /agents/{agent_id}/dry_runs
Content-Type: application/json

{
  "event": {
    "payload": {...}
  }
}
```

Tests agent execution with sample data without creating real events.

#### List Dry Run Results  
```http
GET /agents/{agent_id}/dry_runs
```

**Response:** Historical dry run execution results

## Advanced Features

### Batch Operations
Multiple agents can be operated on simultaneously using array parameters:
- `agent_ids[]` for bulk operations
- Scenario-level enable/disable affects all contained agents

### Event Propagation
- `propagate_immediately` option bypasses normal queuing
- Manual propagation via `POST /agents/propagate`
- Global propagation affects all agents

### Filtering and Queries
- SortableTable concern provides consistent sorting across resources
- Pagination via `page` parameter
- Date range filtering on events and logs
- Agent type filtering

### Security Features
- Secret token validation for external endpoints
- Admin-only endpoints for system management
- User isolation - users can only access their own resources
- reCAPTCHA integration for webhook protection
- CSRF protection for authenticated requests

### Integration Patterns

#### Webhook Integration
1. Create WebhookAgent with unique secret
2. Configure external system to POST to webhook URL
3. Events created automatically from incoming data
4. Connect to other agents for processing

#### Data Output Integration  
1. Create DataOutputAgent with RSS/JSON template
2. Connect source agents to provide events
3. External systems consume feed at public URL
4. Optional PubSubHubbub notifications

#### Location Tracking
1. Create UserLocationAgent with secret
2. Configure mobile apps to POST location data
3. Events created for location updates
4. Optional accuracy and distance filtering

This reference covers all major API endpoints and patterns in Huginn. For implementation details and examples, refer to the agent-specific documentation and the main Huginn documentation.