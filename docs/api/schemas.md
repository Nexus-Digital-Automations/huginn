# Huginn API Data Schemas

This document defines the data models and schemas used throughout the Huginn API.

## Core Models

### Agent Schema

```json
{
  "id": "integer",
  "name": "string (required, max: 255)",
  "type": "string (required, format: 'Agents::AgentClassName')",
  "options": "object (required, agent-specific configuration)",
  "schedule": "string (enum: SCHEDULES, default: 'never')",
  "disabled": "boolean (default: false)",
  "deactivated": "boolean (default: false)", 
  "memory": "object (default: {})",
  "last_check_at": "datetime (nullable)",
  "last_event_at": "datetime (nullable)",
  "last_receive_at": "datetime (nullable)",
  "last_web_request_at": "datetime (nullable)",
  "keep_events_for": "integer (seconds, default: 0 = forever)",
  "propagate_immediately": "boolean (default: false)",
  "drop_pending_events": "boolean (default: false)", 
  "events_count": "integer (computed)",
  "created_at": "datetime",
  "updated_at": "datetime",
  "user_id": "integer (foreign key)",
  "service_id": "integer (foreign key, nullable)",
  "guid": "string (unique identifier)",
  "source_ids": "array[integer] (connected source agents)",
  "receiver_ids": "array[integer] (connected receiver agents)",
  "controller_ids": "array[integer] (controlling agents)",
  "control_target_ids": "array[integer] (controlled agents)",
  "scenario_ids": "array[integer] (associated scenarios)"
}
```

**Schedule Values:**
```
every_1m, every_2m, every_5m, every_10m, every_30m
every_1h, every_2h, every_5h, every_12h
every_1d, every_2d, every_7d
midnight, 1am, 2am, 3am, 4am, 5am, 6am, 7am, 8am, 9am, 10am, 11am
noon, 1pm, 2pm, 3pm, 4pm, 5pm, 6pm, 7pm, 8pm, 9pm, 10pm, 11pm
never
```

**Event Retention Periods (keep_events_for):**
```
0 (forever), 3600 (1 hour), 21600 (6 hours), 86400 (1 day),
172800 (2 days), 259200 (3 days), 432000 (5 days), 604800 (1 week),
1209600 (2 weeks), 1814400 (3 weeks), 2592000 (30 days),
3888000 (45 days), 7776000 (90 days), 15552000 (180 days),
31536000 (365 days)
```

### Event Schema

```json
{
  "id": "integer",
  "user_id": "integer (foreign key)",
  "agent_id": "integer (foreign key, required)", 
  "lat": "decimal (nullable, GPS latitude)",
  "lng": "decimal (nullable, GPS longitude)",
  "payload": "object (required, event data)",
  "expires_at": "datetime (nullable, auto-expiration)",
  "created_at": "datetime",
  "updated_at": "datetime"
}
```

**Payload Structure:**
The payload is a flexible JSON object that can contain any structure. Common patterns:

```json
{
  "title": "string",
  "description": "string", 
  "url": "string",
  "date_published": "datetime",
  "tags": "array[string]",
  "metadata": "object",
  "headers": "object (HTTP headers for webhook events)",
  "_index_": "integer (for ordering)"
}
```

### Scenario Schema

```json
{
  "id": "integer",
  "name": "string (required, max: 255)",
  "description": "text (nullable)",
  "user_id": "integer (foreign key)",
  "public": "boolean (default: false)",
  "source_url": "string (nullable, import source)",
  "guid": "string (unique identifier)",
  "tag_fg_color": "string (hex color, default: '#ffffff')",
  "tag_bg_color": "string (hex color, default: '#5bc0de')",
  "icon": "string (FontAwesome icon class, default: 'fa-calendar')",
  "created_at": "datetime",
  "updated_at": "datetime",
  "agents": "array[Agent] (associated agents)"
}
```

### User Schema

```json
{
  "id": "integer",
  "username": "string (required, unique, max: 255)",
  "email": "string (required, unique, max: 255)",
  "admin": "boolean (default: false)",
  "failed_attempts": "integer (default: 0)",
  "unlock_token": "string (nullable)",
  "locked_at": "datetime (nullable)",
  "sign_in_count": "integer (default: 0)",
  "current_sign_in_at": "datetime (nullable)",
  "last_sign_in_at": "datetime (nullable)",
  "current_sign_in_ip": "string (nullable)",
  "last_sign_in_ip": "string (nullable)",
  "confirmation_token": "string (nullable)",
  "confirmed_at": "datetime (nullable)",
  "confirmation_sent_at": "datetime (nullable)",
  "unconfirmed_email": "string (nullable)",
  "invitation_code": "string (nullable)",
  "created_at": "datetime",
  "updated_at": "datetime",
  "deactivated_at": "datetime (nullable)"
}
```

### Job Schema (Delayed::Job)

```json
{
  "id": "integer",
  "priority": "integer (default: 0)",
  "attempts": "integer (default: 0)",
  "handler": "text (serialized job data)",
  "last_error": "text (nullable)",
  "run_at": "datetime",
  "locked_at": "datetime (nullable)",
  "failed_at": "datetime (nullable)",
  "locked_by": "string (nullable, worker identifier)",
  "queue": "string (nullable)",
  "created_at": "datetime",
  "updated_at": "datetime"
}
```

### Service Schema

```json
{
  "id": "integer",
  "user_id": "integer (foreign key)",
  "provider": "string (OAuth provider name)",
  "name": "string (service name)",
  "token": "text (encrypted OAuth token)",
  "secret": "text (encrypted OAuth secret, nullable)",
  "refresh_token": "text (encrypted refresh token, nullable)",
  "expires_at": "datetime (nullable)",
  "uid": "string (provider user ID)",
  "options": "object (additional service configuration)",
  "created_at": "datetime",
  "updated_at": "datetime"
}
```

### UserCredential Schema

```json
{
  "id": "integer",
  "user_id": "integer (foreign key)",
  "credential_name": "string (required, max: 255)",
  "credential_value": "text (encrypted credential data)",
  "mode": "string (enum: 'text', 'pairs', default: 'text')",
  "created_at": "datetime",
  "updated_at": "datetime"
}
```

## Agent-Specific Option Schemas

### WebhookAgent Options

```json
{
  "secret": "string (required, authentication token)",
  "expected_receive_period_in_days": "integer (default: 1)",
  "payload_path": "string (JSONPath, default: '.')",
  "event_headers": "string (comma-separated header names)",
  "event_headers_key": "string (default: 'headers')",
  "verbs": "string (comma-separated HTTP methods, default: 'post')",
  "response": "string (response message, default: 'Event Created')",
  "response_headers": "object (custom response headers)",
  "code": "integer (HTTP response code, default: 201)",
  "recaptcha_secret": "string (reCAPTCHA secret key, nullable)",
  "recaptcha_send_remote_addr": "boolean (default: false)",
  "score_threshold": "float (reCAPTCHA v3 threshold, default: 0.5)"
}
```

### DataOutputAgent Options

```json
{
  "secrets": "array[string] (authentication tokens, required)",
  "expected_receive_period_in_days": "integer (required)",
  "template": {
    "title": "string (feed title)",
    "description": "string (feed description)", 
    "link": "string (feed link)",
    "self": "string (feed self URL)",
    "icon": "string (feed icon URL)",
    "item": {
      "title": "string (Liquid template)",
      "description": "string (Liquid template)",
      "link": "string (Liquid template)",
      "pubDate": "string (Liquid template)",
      "guid": "string|object (Liquid template or XML attributes)",
      "enclosure": "object (XML attributes for media)"
    }
  },
  "events_to_show": "integer (default: 40)",
  "ttl": "integer (RSS TTL in minutes, default: 60)",
  "ns_dc": "boolean|string (Dublin Core namespace)",
  "ns_media": "boolean|string (Yahoo Media namespace)", 
  "ns_itunes": "boolean|string (iTunes namespace)",
  "rss_content_type": "string (default: 'application/rss+xml')",
  "response_headers": "object (custom response headers)",
  "push_hubs": "array[string] (PubSubHubbub endpoints)",
  "events_order": "array (event ordering rules)",
  "events_list_order": "array (output ordering rules)"
}
```

### UserLocationAgent Options

```json
{
  "secret": "string (required, min: 4 characters)",
  "max_accuracy": "integer (GPS accuracy threshold in meters)",
  "min_distance": "integer (minimum distance for new events in meters)",
  "accuracy_field": "string (accuracy field name, default: 'accuracy')",
  "api_key": "string (Google Maps API key for visualization)"
}
```

### WebsiteAgent Options

```json
{
  "url": "string (required, target URL)",
  "type": "string (enum: 'html', 'xml', 'json', 'text')",
  "mode": "string (enum: 'all', 'on_change', 'merge')",
  "extract": "object (extraction rules)",
  "headers": "object (HTTP headers)",
  "basic_auth": "string (username:password)",
  "user_agent": "string (custom User-Agent)",
  "expected_receive_period_in_days": "integer",
  "uniqueness_look_back": "integer (duplicate detection window)",
  "force_encoding": "string (character encoding)",
  "disable_redirect_follow": "boolean (default: false)",
  "disable_ssl_verification": "boolean (default: false)"
}
```

### EmailAgent Options  

```json
{
  "recipients": "array[string] (required, email addresses)",
  "subject": "string (required, Liquid template)",
  "body": "string (required, Liquid template)",
  "content_type": "string (default: 'text/plain')",
  "from": "string (sender email)",
  "reply_to": "string (reply-to email)",
  "attach_events": "boolean (attach events as JSON)",
  "expected_receive_period_in_days": "integer"
}
```

### PostAgent Options

```json
{
  "post_url": "string (required, target URL)",
  "method": "string (HTTP method, default: 'post')",
  "payload": "object (request payload)",
  "headers": "object (HTTP headers)",
  "basic_auth": "string (username:password)",
  "user_agent": "string (custom User-Agent)",
  "disable_redirect_follow": "boolean (default: false)",
  "disable_ssl_verification": "boolean (default: false)",
  "output_mode": "string (enum: 'clean', 'merge')",
  "no_merge": "boolean (disable payload merging)",
  "expected_receive_period_in_days": "integer"
}
```

## API Response Schemas

### Standard Success Response

```json
{
  "id": "integer",
  "...": "model fields"
}
```

### Paginated Response  

```json
{
  "data": "array[object] (page items)",
  "current_page": "integer",
  "per_page": "integer", 
  "total_entries": "integer",
  "total_pages": "integer"
}
```

### Error Response

```json
{
  "errors": {
    "field_name": ["array of error messages"],
    "base": ["array of general errors"]
  }
}
```

### Agent Type Details Response

```json
{
  "can_be_scheduled": "boolean",
  "default_schedule": "string",
  "can_receive_events": "boolean", 
  "can_create_events": "boolean",
  "can_control_other_agents": "boolean",
  "can_dry_run": "boolean",
  "options": "object (default options)",
  "description_html": "string (HTML description)",
  "oauthable": "string (OAuth UI partial)", 
  "form_options": "string (options form partial)"
}
```

### Worker Status Response

```json
{
  "pending": "integer (pending jobs count)",
  "awaiting_retry": "integer (jobs awaiting retry)",
  "recent_failures": "integer (failed jobs in last 5 days)",
  "event_count": "integer (user's recent events)",
  "max_id": "integer (highest event ID)",
  "events_url": "string (events page URL)",
  "compute_time": "float (response generation time)"
}
```

### Scenario Export Response

```json
{
  "schema_version": "integer (export format version)",
  "name": "string (scenario name)",
  "description": "string (scenario description)",
  "source_url": "string (original import URL)",
  "guid": "string (scenario GUID)",
  "tag_fg_color": "string (foreground color)",
  "tag_bg_color": "string (background color)", 
  "icon": "string (FontAwesome icon)",
  "exported_at": "datetime (export timestamp)",
  "agents": "array[object] (agent configurations)",
  "links": "array[object] (agent connections)",
  "control_links": "array[object] (control connections)"
}
```

## Validation Rules

### Agent Validation

- `name`: Required, maximum 255 characters
- `type`: Required, must be valid Agent class name
- `options`: Required, must be valid JSON object
- `schedule`: Must be one of the valid SCHEDULES values
- `keep_events_for`: Must be one of the valid retention periods
- `source_ids`, `receiver_ids`, etc.: Must reference existing agents owned by the user

### Event Validation

- `agent_id`: Required, must reference existing agent
- `payload`: Required, must be valid JSON object
- `lat`, `lng`: Must be valid decimal coordinates if present
- `expires_at`: Must be future datetime if present

### Scenario Validation

- `name`: Required, maximum 255 characters
- `tag_fg_color`, `tag_bg_color`: Must be valid hex colors
- `icon`: Must be valid FontAwesome icon class
- `agent_ids`: Must reference existing agents owned by the user

### User Validation

- `username`: Required, unique, maximum 255 characters
- `email`: Required, unique, valid email format
- `password`: Required for creation, minimum 6 characters

## Data Relationships

```
User 1:N Agent
User 1:N Event  
User 1:N Scenario
User 1:N Service
User 1:N UserCredential

Agent 1:N Event
Agent N:M Agent (via Links - sources/receivers)
Agent N:M Agent (via ControlLinks - controllers/targets)
Agent N:M Scenario (via ScenarioMemberships)
Agent N:1 Service

Scenario N:M Agent (via ScenarioMemberships)

Event N:1 Agent
Event N:1 User
```

This schema reference provides the complete data structure for all Huginn API models and their validation requirements.