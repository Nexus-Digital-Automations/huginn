# AIgent Trigger Agent Documentation

## Table of Contents

1. [Overview](#overview)
2. [Installation and Setup](#installation-and-setup)
3. [Configuration Reference](#configuration-reference)
4. [Usage Examples](#usage-examples)
5. [Integration Patterns](#integration-patterns)
6. [Workflow Examples](#workflow-examples)
7. [Liquid Templating Guide](#liquid-templating-guide)
8. [Event Processing](#event-processing)
9. [Error Handling](#error-handling)
10. [Troubleshooting](#troubleshooting)
11. [Advanced Configuration](#advanced-configuration)
12. [Best Practices](#best-practices)

## Overview

The AIgent Trigger Agent integrates Huginn's powerful event processing capabilities with the AIgent orchestrator system, enabling intelligent, AI-powered workflow automation. This agent acts as a bridge between traditional rule-based automation (Huginn) and modern AI-driven decision making (AIgent orchestrator).

### Key Features

- **Smart Trigger Conditions**: AI-powered pattern recognition and anomaly detection
- **Context-Aware Execution**: Dynamic goal generation based on event data and environmental context
- **Workflow Orchestration**: Integration with multi-agent coordination and task execution
- **Intelligent Prioritization**: Automatic priority assignment based on event importance and urgency
- **Flexible Integration**: Seamless connection with other Huginn agents and external services

### Architecture Overview

```
┌─────────────────┐    ┌───────────────────┐    ┌─────────────────────┐
│   Huginn        │    │ AIgent Trigger    │    │ AIgent             │
│   Agents        │───▶│ Agent             │───▶│ Orchestrator        │
│   (RSS, Email,  │    │                   │    │                     │
│   Weather, etc.)│    │ • Event filtering │    │ • Multi-agent       │
└─────────────────┘    │ • Goal generation │    │   coordination      │
                       │ • Context         │    │ • Task execution    │
                       │   enrichment      │    │ • AI decision       │
                       └───────────────────┘    │   making            │
                                                └─────────────────────┘
```

## Installation and Setup

### Prerequisites

1. **Huginn Installation**: Ensure you have a working Huginn installation
2. **AIgent Orchestrator**: The AIgent orchestrator must be running and accessible
3. **Network Connectivity**: Ensure Huginn can reach the orchestrator endpoint

### Basic Setup

1. **Create a new AIgent Trigger Agent** in your Huginn instance
2. **Configure the orchestrator URL** (typically `http://localhost:8080`)
3. **Specify the target agent** you want to execute
4. **Define the execution goal** using Liquid templating
5. **Test the connection** using the dry run feature

### Validation Steps

After setup, verify your configuration:

```bash
# Check orchestrator connectivity
curl http://localhost:8080/health

# Verify agent availability  
curl http://localhost:8080/api/v1/agents
```

## Configuration Reference

### Core Configuration

#### `orchestrator_url` (Required)
- **Type**: String (URL)
- **Description**: Complete URL to the AIgent orchestrator API endpoint
- **Examples**: 
  - `http://localhost:8080` (local development)
  - `https://aigent.example.com:8443` (production with SSL)
- **Validation**: Must be valid HTTP/HTTPS URL with accessibility check

#### `target_agent` (Required)
- **Type**: String
- **Description**: Identifier of the AIgent to execute
- **Format**: Lowercase letters, numbers, and underscores only
- **Length**: Maximum 100 characters
- **Examples**:
  - `browser_automation_agent`
  - `data_processing_specialist` 
  - `email_coordinator`

#### `goal` (Required)
- **Type**: String (Liquid Template)
- **Description**: Execution goal for the AIgent with dynamic data interpolation
- **Supports**: Full Liquid templating syntax
- **Examples**:
  ```liquid
  Process the file located at {{ file_path }} and extract key metrics
  
  Analyze the weather data {{ weather.temperature }}°F and {{ weather.conditions }} 
  for location {{ location }} and provide recommendations
  
  Send email to {{ recipient }} about {{ subject }} with priority {{ priority }}
  ```

### Execution Control

#### `priority`
- **Type**: String
- **Default**: `normal`
- **Values**: `low`, `normal`, `high`, `urgent`, `critical`
- **Description**: Determines task queue priority and resource allocation

#### `execution_mode`
- **Type**: String  
- **Default**: `asynchronous`
- **Values**: 
  - `synchronous`: Wait for completion before processing next events
  - `asynchronous`: Submit task and continue immediately  
  - `background`: Low-priority background execution with extended timeouts

#### `timeout_seconds`
- **Type**: Integer
- **Default**: `300`
- **Range**: 30-3600 seconds (30 seconds to 1 hour)
- **Description**: Maximum execution time before automatic termination

### Trigger Conditions

#### `trigger_condition`
- **Type**: String
- **Default**: `on_event`
- **Values**: 
  - `on_event`: Trigger on every event received
  - `on_schedule`: Trigger based on schedule (used with scheduler)
  - `on_condition_met`: Trigger when condition rules are satisfied
  - `on_threshold_exceeded`: Trigger when numeric thresholds are exceeded
  - `on_pattern_match`: Trigger on pattern matching
  - `on_anomaly_detected`: Trigger on anomaly detection

#### `condition_rules`
- **Type**: Array
- **Default**: `[]`
- **Description**: Array of conditions for conditional triggering
- **Formats**:
  - **Liquid Template String**: `"{{ severity >= 8 }}"`
  - **Structured Object**: `{"field": "severity", "operator": ">=", "value": 8}`

### Security and Authentication

#### `api_key`
- **Type**: String (Optional)
- **Description**: Authentication key for orchestrator API access
- **Security**: Stored securely, never logged or exposed
- **Usage**: Set when orchestrator requires authentication

#### `verify_ssl`
- **Type**: Boolean
- **Default**: `true`
- **Description**: Whether to verify SSL certificates for HTTPS connections
- **Development**: Can be set to `false` for self-signed certificates
- **Production**: Should always be `true`

### Context and Metadata

#### `context_data`
- **Type**: Hash/Object (Optional)
- **Description**: Additional context data passed to the AIgent
- **Supports**: Liquid templating for dynamic values
- **Example**:
  ```json
  {
    "source_system": "monitoring",
    "environment": "production",
    "user_id": "{{ user.id }}",
    "timestamp": "{{ 'now' | date: '%Y-%m-%d %H:%M:%S' }}"
  }
  ```

#### `tags`
- **Type**: Array of Strings (Optional)
- **Description**: Tags for categorization and filtering
- **Example**: `["automation", "incident_response", "high_priority"]`

### Advanced Options

#### `retry_attempts`
- **Type**: Integer
- **Default**: `3`
- **Range**: 0-10 attempts
- **Description**: Number of retry attempts on failure with exponential backoff

#### `emit_events`
- **Type**: Boolean
- **Default**: `true`
- **Description**: Whether to emit events about AIgent execution status

#### `include_execution_metadata`
- **Type**: Boolean
- **Default**: `false`
- **Description**: Include detailed execution metadata in events (timing, resources, debug info)

#### `include_original_event`
- **Type**: Boolean
- **Default**: `false`
- **Description**: Include original triggering event data in result events

## Usage Examples

### Basic File Processing

```json
{
  "orchestrator_url": "http://localhost:8080",
  "target_agent": "file_processor",
  "goal": "Process the uploaded file {{ file_path }} and extract structured data",
  "priority": "normal",
  "context_data": {
    "processing_mode": "automatic",
    "output_format": "json"
  }
}
```

### Weather-Based Notifications

```json
{
  "orchestrator_url": "http://localhost:8080", 
  "target_agent": "notification_agent",
  "goal": "Send weather alert for {{ location }}: {{ condition }} with temperature {{ temperature }}°F",
  "trigger_condition": "on_condition_met",
  "condition_rules": [
    {"field": "temperature", "operator": "<", "value": 32},
    {"field": "condition", "operator": "contains", "value": "storm"}
  ],
  "priority": "urgent"
}
```

### Email Processing Workflow

```json
{
  "orchestrator_url": "http://localhost:8080",
  "target_agent": "email_processor", 
  "goal": "Process email from {{ sender }} with subject '{{ subject }}' and extract action items",
  "execution_mode": "asynchronous",
  "context_data": {
    "mailbox": "{{ mailbox }}",
    "priority": "{{ priority }}",
    "department": "support"
  },
  "tags": ["email", "support", "automation"]
}
```

### RSS Feed Analysis

```json
{
  "orchestrator_url": "http://localhost:8080",
  "target_agent": "content_analyzer",
  "goal": "Analyze the article '{{ title }}' from {{ source }} and categorize its content",
  "trigger_condition": "on_pattern_match",
  "condition_rules": [
    {"field": "title", "operator": "matches", "value": "(urgent|breaking|alert)"}
  ],
  "priority": "high"
}
```

## Integration Patterns

### Pattern 1: RSS to AIgent Analysis Pipeline

```
┌─────────────┐    ┌─────────────────┐    ┌─────────────────┐
│ RSS Agent   │───▶│ AIgent Trigger  │───▶│ Content         │
│             │    │ Agent           │    │ Analyzer        │
│ • Fetch RSS │    │                 │    │                 │
│ • Parse     │    │ • Filter items  │    │ • Summarize     │
│ • Emit      │    │ • Generate      │    │ • Extract key   │
│   events    │    │   analysis goal │    │   points        │
└─────────────┘    │ • Add context   │    │ • Determine     │
                   └─────────────────┘    │   urgency       │
                                          └─────────────────┘
```

**Configuration Example:**
```json
{
  "orchestrator_url": "http://localhost:8080",
  "target_agent": "content_analyzer",
  "goal": "Analyze RSS article: '{{ title }}' from {{ url }} and provide summary with key insights",
  "context_data": {
    "source": "{{ feed_title }}",
    "category": "{{ category }}",
    "publish_date": "{{ published }}"
  },
  "tags": ["rss", "content_analysis"]
}
```

### Pattern 2: Email to Document Processing

```
┌─────────────┐    ┌─────────────────┐    ┌─────────────────┐
│ Email Agent │───▶│ AIgent Trigger  │───▶│ Document        │
│             │    │ Agent           │    │ Processor       │
│ • Monitor   │    │                 │    │                 │
│   IMAP      │    │ • Extract       │    │ • OCR if needed │
│ • Parse     │    │   attachments   │    │ • Extract data  │
│   emails    │    │ • Determine     │    │ • Validate      │
│ • Emit      │    │   processing    │    │ • Store results │
│   events    │    │   needed        │    │                 │
└─────────────┘    └─────────────────┘    └─────────────────┘
```

**Configuration Example:**
```json
{
  "orchestrator_url": "http://localhost:8080",
  "target_agent": "document_processor",
  "goal": "Process email attachment {{ attachment.filename }} from {{ sender }} and extract invoice data",
  "trigger_condition": "on_condition_met",
  "condition_rules": [
    {"field": "attachment.mime_type", "operator": "==", "value": "application/pdf"},
    {"field": "subject", "operator": "contains", "value": "invoice"}
  ],
  "context_data": {
    "sender_email": "{{ sender }}",
    "received_date": "{{ date }}",
    "processing_type": "invoice_extraction"
  }
}
```

### Pattern 3: Weather to Smart Home Automation

```
┌──────────────┐    ┌─────────────────┐    ┌─────────────────┐
│ Weather      │───▶│ AIgent Trigger  │───▶│ Home            │
│ Agent        │    │ Agent           │    │ Automation      │
│              │    │                 │    │                 │
│ • Fetch      │    │ • Analyze       │    │ • Adjust        │
│   weather    │    │   conditions    │    │   thermostat    │
│ • Monitor    │    │ • Determine     │    │ • Control       │
│   changes    │    │   actions       │    │   lighting      │
│ • Emit       │    │ • Generate      │    │ • Send          │
│   updates    │    │   commands      │    │   notifications │
└──────────────┘    └─────────────────┘    └─────────────────┘
```

**Configuration Example:**
```json
{
  "orchestrator_url": "http://localhost:8080",
  "target_agent": "home_automation",
  "goal": "Adjust home systems for weather: {{ condition }} at {{ temperature }}°F, wind {{ wind_speed }}mph",
  "trigger_condition": "on_threshold_exceeded",
  "condition_rules": [
    {"field": "temperature", "operator": "<=", "value": 40, "type": "threshold"},
    {"field": "wind_speed", "operator": ">=", "value": 25, "type": "threshold"}
  ],
  "priority": "high",
  "context_data": {
    "location": "{{ location }}",
    "home_mode": "occupied",
    "energy_saving": true
  }
}
```

### Pattern 4: Social Media Monitoring

```
┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐
│ Twitter Search  │──▶│ AIgent Trigger  │──▶│ Sentiment &     │
│ Agent           │   │ Agent           │   │ Response Agent  │
│                 │   │                 │   │                 │
│ • Monitor       │   │ • Filter        │   │ • Analyze       │
│   keywords      │   │   relevance     │   │   sentiment     │
│ • Track         │   │ • Assess        │   │ • Generate      │
│   mentions      │   │   sentiment     │   │   responses     │
│ • Emit tweets   │   │ • Prioritize    │   │ • Schedule      │
│                 │   │   responses     │   │   posting       │
└─────────────────┘   └─────────────────┘   └─────────────────┘
```

**Configuration Example:**
```json
{
  "orchestrator_url": "http://localhost:8080",
  "target_agent": "social_media_manager",
  "goal": "Analyze tweet '{{ text }}' from @{{ username }} and determine appropriate response strategy",
  "trigger_condition": "on_condition_met", 
  "condition_rules": [
    "{{ text contains '@ourcompany' }}",
    "{{ retweet_count > 10 or favorite_count > 50 }}"
  ],
  "context_data": {
    "tweet_id": "{{ id }}",
    "follower_count": "{{ user.followers_count }}",
    "verified": "{{ user.verified }}"
  },
  "tags": ["social_media", "customer_engagement"]
}
```

## Workflow Examples

### Complete Workflow: News Monitoring and Digest

This example demonstrates a complete workflow from RSS monitoring to email digest:

#### Step 1: RSS Agent Configuration
```json
{
  "url": "https://news.ycombinator.com/rss",
  "expected_receive_period_in_days": "1",
  "extract": {
    "title": "//item/title",
    "url": "//item/link", 
    "description": "//item/description",
    "published": "//item/pubDate"
  }
}
```

#### Step 2: AIgent Trigger Agent Configuration  
```json
{
  "orchestrator_url": "http://localhost:8080",
  "target_agent": "news_analyzer",
  "goal": "Analyze news article '{{ title }}' and provide summary with relevance score for tech industry",
  "trigger_condition": "on_pattern_match",
  "condition_rules": [
    {"field": "title", "operator": "matches", "value": "(AI|machine learning|automation|startup)"}
  ],
  "context_data": {
    "source": "Hacker News",
    "category": "technology",
    "analysis_type": "industry_relevance"
  },
  "tags": ["news", "analysis", "technology"]
}
```

#### Step 3: Webhook Agent for Results
```json
{
  "path": "news-analysis-results",
  "secret": "your-secret-key",
  "expected_receive_period_in_days": "1"
}
```

#### Step 4: Email Digest Agent
```json
{
  "subject": "Daily Tech News Digest - {{ date }}",
  "expected_receive_period_in_days": "1",
  "recipients": ["team@company.com"],
  "body": "Today's relevant tech news:\n\n{% for item in items %}{{ item.title }}\nRelevance: {{ item.relevance_score }}/10\nSummary: {{ item.summary }}\nURL: {{ item.url }}\n\n{% endfor %}"
}
```

### Workflow: Automated Customer Support

#### Step 1: Email Monitoring
```json
{
  "imap": {
    "server": "imap.gmail.com",
    "port": 993,
    "username": "support@company.com",
    "password": "app-password",
    "folder": "INBOX"
  },
  "expected_receive_period_in_days": "1"
}
```

#### Step 2: Support Ticket Analysis
```json
{
  "orchestrator_url": "http://localhost:8080", 
  "target_agent": "support_triager",
  "goal": "Analyze support email from {{ from }}: '{{ subject }}' and determine priority, category, and next actions",
  "context_data": {
    "customer_email": "{{ from }}",
    "ticket_source": "email",
    "received_time": "{{ date }}",
    "message_content": "{{ body_plain }}"
  },
  "priority": "high"
}
```

#### Step 3: Automated Response
```json
{
  "orchestrator_url": "http://localhost:8080",
  "target_agent": "response_generator", 
  "goal": "Generate appropriate response for {{ priority }} priority {{ category }} ticket from {{ customer_email }}",
  "trigger_condition": "on_condition_met",
  "condition_rules": [
    {"field": "confidence_score", "operator": ">=", "value": 0.8}
  ]
}
```

### Workflow: Infrastructure Monitoring

#### Step 1: HTTP Status Monitoring
```json
{
  "url": "https://api.company.com/health",
  "expected_receive_period_in_days": "1", 
  "schedule": "*/5 * * * *"
}
```

#### Step 2: Incident Detection
```json
{
  "orchestrator_url": "http://localhost:8080",
  "target_agent": "incident_responder",
  "goal": "Handle service outage for {{ url }} - status {{ status }} for {{ duration }} minutes",
  "trigger_condition": "on_threshold_exceeded",
  "condition_rules": [
    {"field": "status", "operator": ">=", "value": 400},
    {"field": "response_time", "operator": ">", "value": 5000}
  ],
  "priority": "critical",
  "context_data": {
    "service": "{{ url | replace: 'https://', '' | replace: '.company.com', '' }}",
    "monitoring_source": "huginn_http_status"
  }
}
```

#### Step 3: Notification and Recovery
```json
{
  "orchestrator_url": "http://localhost:8080",
  "target_agent": "incident_notifier",
  "goal": "Send alert and initiate recovery for {{ service }} incident - {{ incident_type }}",
  "execution_mode": "synchronous",
  "context_data": {
    "escalation_level": "{{ escalation_level }}",
    "affected_users": "{{ estimated_impact }}",
    "recovery_actions": ["restart_service", "check_dependencies", "verify_database"]
  }
}
```

## Liquid Templating Guide

The AIgent Trigger Agent supports full Liquid templating for dynamic content generation. Here's a comprehensive guide to using Liquid effectively.

### Basic Syntax

#### Variable Access
```liquid
{{ variable_name }}
{{ nested.property }}
{{ array[0] }}
```

#### Filters
```liquid
{{ text | upcase }}
{{ date | date: "%Y-%m-%d" }}
{{ number | round: 2 }}
{{ array | join: ", " }}
```

#### Control Flow
```liquid
{% if condition %}
  Content when true
{% elsif other_condition %}
  Alternative content
{% else %}
  Default content
{% endif %}

{% for item in array %}
  {{ item.name }}: {{ item.value }}
{% endfor %}
```

### Event Data Access

When processing events, you can access any field from the triggering event:

```liquid
# Direct field access
{{ title }}
{{ description }}
{{ url }}

# Nested properties  
{{ user.name }}
{{ location.city }}
{{ weather.temperature }}

# Array access
{{ tags[0] }}
{{ attachments.first.filename }}
```

### Advanced Templating Patterns

#### Conditional Goal Generation
```liquid
{% if priority == 'urgent' %}
  URGENT: Process {{ title }} immediately and notify stakeholders
{% elsif category == 'security' %}
  Security analysis required for {{ title }} - escalate to security team
{% else %}
  Standard processing for {{ title }} - analyze and categorize
{% endif %}
```

#### Dynamic Context Building
```liquid
{
  "source": "{{ source | default: 'unknown' }}",
  "processing_date": "{{ 'now' | date: '%Y-%m-%d %H:%M:%S' }}",
  "priority_score": {{ priority_score | default: 5 }},
  "tags": [
    {% for tag in tags %}
      "{{ tag }}"{% unless forloop.last %},{% endunless %}
    {% endfor %}
  ],
  "metadata": {
    "event_id": "{{ event_id }}",
    "agent_id": "{{ agent_id }}", 
    "processing_mode": "{{ execution_mode | default: 'standard' }}"
  }
}
```

#### Multi-line Goal Templates
```liquid
Process the following data:
{% if file_path %}
File: {{ file_path }}
{% endif %}
{% if email %}
Email from: {{ email.from }}
Subject: {{ email.subject }}
{% endif %}

Requirements:
- Extract key information
- Validate data format  
- {% if priority == 'high' %}Expedite processing{% else %}Standard processing timeline{% endif %}
- Generate structured output

Additional context:
{{ context_data | jsonify }}
```

### Template Security

To prevent security issues in your templates:

#### Avoid dangerous functions:
```liquid
# DON'T DO THIS:
{{ system('rm -rf /') }}
{{ eval(user_input) }}

# SAFE ALTERNATIVES:
{{ user_input | escape }}
{{ filename | slice: 0, 100 }}
```

#### Input validation:
```liquid
{% assign safe_filename = filename | replace: '..', '' | replace: '/', '_' %}
Process file: {{ safe_filename }}
```

#### Length limits:
```liquid
{% assign truncated_text = long_text | truncate: 500 %}
Analyze: {{ truncated_text }}
```

### Template Testing

Use the dry run feature to test your templates:

```json
{
  "goal": "Test template with {{ test_value | upcase }} and {{ number | plus: 10 }}",
  "context_data": {
    "test_value": "hello world",
    "number": 5
  }
}
```

Expected output: `"Test template with HELLO WORLD and 15"`

## Event Processing

The AIgent Trigger Agent processes incoming events through several stages:

### Processing Pipeline

```
┌─────────────────┐
│ Incoming Event  │
└─────────┬───────┘
          │
          ▼
┌─────────────────┐
│ Trigger         │
│ Condition       │ ──── No ────┐
│ Evaluation      │             │
└─────────┬───────┘             │
          │ Yes                 │
          ▼                     │
┌─────────────────┐             │
│ Goal Template   │             │
│ Processing      │             │
└─────────┬───────┘             │
          │                     │
          ▼                     │
┌─────────────────┐             │
│ Context Data    │             │
│ Enhancement     │             │
└─────────┬───────┘             │
          │                     │
          ▼                     │
┌─────────────────┐             │
│ Request         │             │
│ Submission      │             │
└─────────┬───────┘             │
          │                     │
          ▼                     │
┌─────────────────┐             │
│ Response        │             │
│ Processing      │             │
└─────────┬───────┘             │
          │                     │
          ▼                     │
┌─────────────────┐             │
│ Event           │             │
│ Emission        │ ◄───────────┘
└─────────────────┘
```

### Event Types Generated

#### Success Events

Generated when AIgent execution completes successfully:

```json
{
  "status": "success",
  "aigent_id": "data_processor", 
  "execution_id": "exec_1704814222001",
  "goal": "Process uploaded CSV file and generate analytics",
  "priority": "normal",
  "execution_time_ms": 2340,
  "result": {
    "records_processed": 1500,
    "analytics_generated": true,
    "output_file": "/results/analytics_report.json"
  },
  "metadata": {
    "agent_version": "2.1.0",
    "resources_used": {
      "memory_mb": 128,
      "cpu_percent": 15.2
    }
  },
  "timestamp": "2024-01-09T15:30:22Z"
}
```

#### Failure Events

Generated when AIgent execution fails:

```json
{
  "status": "failed",
  "aigent_id": "email_processor",
  "execution_id": "exec_1704814222002", 
  "goal": "Process email attachments",
  "error": {
    "type": "ValidationError",
    "message": "Attachment format not supported",
    "code": "UNSUPPORTED_FORMAT",
    "details": {
      "filename": "document.xyz",
      "mime_type": "application/unknown"
    }
  },
  "retry_count": 3,
  "final_attempt": true,
  "timestamp": "2024-01-09T15:32:18Z"
}
```

#### Status Events

Generated for long-running tasks:

```json
{
  "status": "in_progress",
  "aigent_id": "large_dataset_processor",
  "execution_id": "exec_1704814222003",
  "progress": {
    "percentage": 45,
    "current_stage": "data_cleaning",
    "stages_completed": ["validation", "parsing"],
    "stages_remaining": ["analysis", "reporting"],
    "estimated_completion": "2024-01-09T15:45:00Z"
  },
  "timestamp": "2024-01-09T15:35:12Z"
}
```

#### Health Check Events

Generated during periodic health checks:

```json
{
  "status": "health_check_success",
  "orchestrator_url": "http://localhost:8080",
  "response_time_ms": 45,
  "orchestrator_status": 200,
  "timestamp": "2024-01-09T15:40:00Z"
}
```

### Event Routing Patterns

#### Success Event Processing
```json
{
  "agents": [
    {
      "type": "EventFormattingAgent",
      "name": "Format Success Results", 
      "options": {
        "instructions": {
          "message": "AIgent {{ aigent_id }} completed: {{ result | jsonify }}"
        }
      }
    },
    {
      "type": "EmailAgent",
      "name": "Success Notification",
      "options": {
        "to": "admin@company.com",
        "subject": "AIgent Success: {{ aigent_id }}",
        "body": "Execution completed in {{ execution_time_ms }}ms"
      }
    }
  ]
}
```

#### Error Event Handling  
```json
{
  "agents": [
    {
      "type": "TriggerAgent", 
      "name": "Critical Error Filter",
      "options": {
        "rules": [
          {
            "type": "regex",
            "value": "critical|urgent|security",
            "path": "error.code"
          }
        ]
      }
    },
    {
      "type": "SlackAgent",
      "name": "Critical Error Alert",
      "options": {
        "webhook_url": "https://hooks.slack.com/...",
        "channel": "#alerts",
        "text": "🚨 Critical AIgent Error: {{ error.message }}"
      }
    }
  ]
}
```

## Error Handling

The AIgent Trigger Agent implements comprehensive error handling at multiple levels:

### Configuration Errors

**Invalid URL Format:**
```json
{
  "status": "configuration_error",
  "error": {
    "type": "ConfigurationValidationError", 
    "message": "orchestrator_url is not a valid URL: Invalid URI",
    "field": "orchestrator_url",
    "provided_value": "not-a-url"
  }
}
```

**Connection Failures:**
```json
{
  "status": "configuration_error",
  "error": {
    "type": "ConnectionError",
    "message": "Cannot connect to orchestrator at http://localhost:8080: Connection refused",
    "field": "orchestrator_url",
    "suggestion": "Verify the orchestrator service is running and accessible"
  }
}
```

### Execution Errors

**Template Processing Errors:**
```json
{
  "status": "failed",
  "error": {
    "type": "TemplateError",
    "message": "goal contains invalid Liquid template syntax: unexpected token", 
    "field": "goal",
    "template": "Process {{ invalid template syntax"
  }
}
```

**AIgent Execution Errors:**
```json
{
  "status": "failed",
  "error": {
    "type": "AIgentExecutionError",
    "message": "Target agent 'nonexistent_agent' not found",
    "code": "AGENT_NOT_FOUND",
    "details": {
      "target_agent": "nonexistent_agent",
      "available_agents": ["agent1", "agent2", "agent3"]
    }
  }
}
```

### Retry Logic

The agent implements exponential backoff for transient failures:

```
Attempt 1: Immediate
Attempt 2: Wait 2 seconds  
Attempt 3: Wait 4 seconds
Attempt 4: Wait 8 seconds
```

**Retry Configuration:**
```json
{
  "retry_attempts": 3,
  "retry_on_errors": [
    "NetworkError",
    "TimeoutError", 
    "ServiceUnavailableError"
  ],
  "no_retry_on_errors": [
    "ValidationError",
    "AuthenticationError",
    "ConfigurationError"
  ]
}
```

### Error Recovery Strategies

#### Graceful Degradation
```json
{
  "orchestrator_url": "http://localhost:8080",
  "fallback_behavior": "log_only",
  "emit_events_on_failure": true
}
```

#### Circuit Breaker Pattern
```json
{
  "circuit_breaker": {
    "failure_threshold": 5,
    "timeout_seconds": 60,
    "recovery_timeout": 300
  }
}
```

## Troubleshooting

### Common Issues and Solutions

#### Issue: "Cannot connect to orchestrator"

**Symptoms:**
- Configuration validation errors
- Connection refused messages
- Timeout errors

**Solutions:**
1. **Verify orchestrator is running:**
   ```bash
   curl http://localhost:8080/health
   ```

2. **Check network connectivity:**
   ```bash
   ping localhost
   telnet localhost 8080
   ```

3. **Verify firewall settings:**
   ```bash
   # Check if port is open
   netstat -tulpn | grep :8080
   ```

4. **Review orchestrator logs:**
   ```bash
   docker logs aigent-orchestrator
   ```

#### Issue: "SSL verification failed"  

**Symptoms:**
- SSL certificate errors
- SSL verification failures
- HTTPS connection issues

**Solutions:**
1. **For development (temporary):**
   ```json
   {
     "verify_ssl": false
   }
   ```

2. **For production (recommended):**
   - Install proper SSL certificate
   - Update certificate authority bundle
   - Use valid domain names

#### Issue: "Goal template syntax errors"

**Symptoms:**
- Liquid template parsing errors  
- Invalid template syntax messages
- Template rendering failures

**Solutions:**
1. **Test templates separately:**
   ```liquid
   # Simple test
   {{ title }}
   
   # Complex test  
   {% if condition %}{{ value }}{% endif %}
   ```

2. **Use online Liquid template testers**

3. **Validate template syntax:**
   ```ruby
   Liquid::Template.parse("{{ your.template }}")
   ```

#### Issue: "Target agent not found"

**Symptoms:**
- Agent not found errors
- Invalid agent identifier messages

**Solutions:**
1. **List available agents:**
   ```bash
   curl http://localhost:8080/api/v1/agents
   ```

2. **Verify agent naming:**
   - Use lowercase only
   - Use underscores, not spaces or hyphens
   - Check maximum length (100 characters)

#### Issue: "Events not being triggered"

**Symptoms:**
- Agent receives events but doesn't trigger
- Condition rules not working
- No AIgent execution

**Solutions:**
1. **Check trigger conditions:**
   ```json
   {
     "trigger_condition": "on_event"  // Always triggers
   }
   ```

2. **Debug condition rules:**
   ```json
   {
     "condition_rules": [
       "{% raw %}{{ true }}{% endraw %}"  // Always true for testing
     ]
   }
   ```

3. **Use dry run mode:**
   ```json
   {
     "dry_run": true
   }
   ```

### Debugging Tools

#### Enable Debug Logging
```json
{
  "include_execution_metadata": true,
  "emit_events": true,
  "debug_mode": true
}
```

#### Dry Run Testing  
Use the built-in dry run feature to test configuration without actual execution:

```json
{
  "goal": "Test goal: {{ test_field }}",
  "context_data": {
    "test_field": "test_value"
  }
}
```

#### Event Inspection
Connect a Webhook Agent to capture and inspect all events:

```json
{
  "type": "WebhookAgent",
  "options": {
    "path": "debug-events",
    "secret": "debug-secret"
  }
}
```

### Performance Optimization

#### Reduce Timeout for Faster Feedback
```json
{
  "timeout_seconds": 60,  // Reduced from default 300
  "retry_attempts": 1     // Reduced from default 3
}
```

#### Optimize Context Data
```json
{
  "context_data": {
    // Include only necessary data
    "essential_field": "{{ essential_value }}",
    // Avoid large payloads
    "summary": "{{ large_text | truncate: 100 }}"
  }
}
```

#### Use Asynchronous Mode
```json
{
  "execution_mode": "asynchronous",  // Don't wait for completion
  "emit_events": true                // Monitor via events instead
}
```

## Advanced Configuration

### Multi-Agent Coordination

Configure multiple AIgent Trigger Agents for complex workflows:

#### Primary Processor
```json
{
  "name": "Primary Data Processor",
  "orchestrator_url": "http://localhost:8080",
  "target_agent": "primary_processor", 
  "goal": "Initial processing of {{ data_type }}: {{ data }}",
  "tags": ["primary", "processing"]
}
```

#### Secondary Analyzer  
```json
{
  "name": "Secondary Data Analyzer",
  "orchestrator_url": "http://localhost:8080",
  "target_agent": "secondary_analyzer",
  "goal": "Deep analysis of processed data from {{ execution_id }}",
  "trigger_condition": "on_condition_met",
  "condition_rules": [
    {"field": "status", "operator": "==", "value": "success"},
    {"field": "tags", "operator": "contains", "value": "primary"}
  ]
}
```

### Custom Headers and Authentication

#### API Key Authentication
```json
{
  "api_key": "your-secret-api-key",
  "headers": {
    "X-API-Version": "v1",
    "X-Client-ID": "huginn-aigent-trigger"
  }
}
```

#### JWT Token Authentication
```json
{
  "headers": {
    "Authorization": "Bearer {{ jwt_token }}",
    "X-Request-ID": "{{ uuid }}"
  }
}
```

#### Custom User Agent
```json
{
  "headers": {
    "User-Agent": "Company-Huginn-Integration/2.0 ({{ environment }})",
    "X-Source-System": "huginn",
    "X-Agent-ID": "{{ agent.id }}"
  }
}
```

### Environment-Specific Configuration

#### Development Environment
```json
{
  "orchestrator_url": "http://localhost:8080",
  "verify_ssl": false,
  "timeout_seconds": 60,
  "retry_attempts": 1,
  "include_execution_metadata": true,
  "context_data": {
    "environment": "development",
    "debug_mode": true
  }
}
```

#### Production Environment  
```json
{
  "orchestrator_url": "https://aigent.company.com",
  "verify_ssl": true,
  "timeout_seconds": 300,
  "retry_attempts": 3,
  "include_execution_metadata": false,
  "context_data": {
    "environment": "production", 
    "monitoring_enabled": true
  }
}
```

### High Availability Configuration

#### Load Balancing
```json
{
  "orchestrator_urls": [
    "https://aigent-1.company.com",
    "https://aigent-2.company.com", 
    "https://aigent-3.company.com"
  ],
  "load_balance_strategy": "round_robin",
  "health_check_interval": 30
}
```

#### Failover Strategy
```json
{
  "primary_url": "https://aigent-primary.company.com",
  "fallback_urls": [
    "https://aigent-backup.company.com",
    "http://localhost:8080"
  ],
  "failover_timeout": 10
}
```

## Best Practices

### Configuration Management

#### Use Environment Variables
```json
{
  "orchestrator_url": "{{ ENV.AIGENT_ORCHESTRATOR_URL }}",
  "api_key": "{{ ENV.AIGENT_API_KEY }}",
  "verify_ssl": "{{ ENV.AIGENT_VERIFY_SSL | default: true }}"
}
```

#### Credential Management
```json
{
  "orchestrator_url": "{{ credential.aigent_orchestrator_url }}",
  "api_key": "{{ credential.aigent_api_key }}"
}
```

### Goal Template Design

#### Keep Goals Specific and Actionable
```liquid
# GOOD: Specific and actionable
Process invoice {{ invoice_number }} from {{ vendor }}: extract line items, validate totals, and update accounting system

# BAD: Vague and unclear  
Do something with the data
```

#### Include Context for Better Results
```liquid
# GOOD: Rich context
Analyze security alert from {{ source_system }}: {{ alert_type }} affecting {{ affected_systems | join: ", " }}. 
Severity: {{ severity }}/10. Determine if incident response is required and suggest next actions.
Environment: {{ environment }}, Time: {{ timestamp }}

# BAD: Minimal context
Security alert: {{ message }}
```

### Error Handling Strategy

#### Implement Graceful Degradation
```json
{
  "retry_attempts": 3,
  "emit_events": true,
  "fallback_behavior": "log_and_continue",
  "error_notification": {
    "critical_errors": ["SecurityError", "DataCorruptionError"],
    "notification_method": "slack"
  }
}
```

#### Use Appropriate Timeouts
```json
{
  "timeout_seconds": {
    "quick_tasks": 60,
    "standard_tasks": 300,
    "complex_analysis": 1800
  }
}
```

### Performance Optimization

#### Optimize Execution Modes
```json
{
  "execution_mode": "asynchronous",  // For non-blocking operations
  "priority": "normal",              // Balance resource usage
  "batch_processing": true           // Group similar tasks
}
```

#### Context Data Efficiency  
```json
{
  "context_data": {
    // Include only essential data
    "key_fields": "{{ event | extract_keys: 'id,title,priority' }}",
    // Summarize large content
    "content_summary": "{{ content | truncate: 200 }}"
  }
}
```

### Monitoring and Observability

#### Enable Comprehensive Monitoring
```json
{
  "emit_events": true,
  "include_execution_metadata": true,
  "tags": ["monitoring", "{{ environment }}", "{{ service_name }}"],
  "context_data": {
    "monitoring": {
      "trace_id": "{{ uuid }}",
      "service_version": "{{ version }}",
      "deployment_id": "{{ deployment_id }}"
    }
  }
}
```

#### Health Check Configuration
```json
{
  "health_check": {
    "enabled": true,
    "interval_seconds": 300,
    "timeout_seconds": 10,
    "failure_threshold": 3
  }
}
```

### Security Best Practices

#### Secure Configuration
```json
{
  "verify_ssl": true,
  "api_key": "{{ credential.aigent_api_key }}",  // Use credential store
  "headers": {
    "X-Request-Source": "huginn-verified"
  },
  "context_data": {
    // Don't include sensitive data
    "user_id": "{{ user_id }}",
    "session_id": "[REDACTED]"  // Redact sensitive fields
  }
}
```

#### Template Security
```liquid
# Escape user input
{{ user_input | escape }}

# Validate and sanitize  
{{ filename | replace: '../', '' | slice: 0, 100 }}

# Use safe defaults
{{ priority | default: 'normal' }}
```

### Testing Strategy

#### Use Dry Run for Development
```json
{
  "dry_run_enabled": true,
  "test_data": {
    "sample_event": {
      "title": "Test Event", 
      "priority": "high",
      "data": "sample data"
    }
  }
}
```

#### Implement Validation Agents
```json
{
  "type": "AIgentTriggerAgent",
  "name": "Validation Agent",
  "options": {
    "goal": "Validate that {{ aigent_id }} execution completed successfully",
    "trigger_condition": "on_condition_met",
    "condition_rules": [
      {"field": "status", "operator": "==", "value": "success"}
    ]
  }
}
```

---

## Conclusion

The AIgent Trigger Agent provides a powerful bridge between Huginn's event processing capabilities and the AIgent orchestrator's intelligent automation framework. By following the patterns, examples, and best practices outlined in this documentation, you can build sophisticated, AI-powered automation workflows that respond intelligently to events and data.

For additional support and advanced use cases, refer to the [AIgent Orchestrator documentation](../orchestrator/README.md) and [Huginn Agent Development Guide](../development/agent-development.md).

### Additional Resources

- [Huginn Wiki](https://github.com/huginn/huginn/wiki) - Complete Huginn documentation
- [Liquid Template Language](https://shopify.github.io/liquid/) - Template syntax reference
- [AIgent Architecture Guide](../architecture.md) - System architecture overview
- [Integration Examples Repository](../examples/) - More workflow examples
