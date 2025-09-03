# Huginn Webhook Usage Examples and Patterns

This comprehensive guide provides production-ready examples for using webhooks in Huginn, covering both WebhookAgent (incoming webhooks) and DataOutputAgent (outgoing data feeds).

## Table of Contents

- [WebhookAgent Examples](#webhookagent-examples)
- [DataOutputAgent Examples](#dataoutputagent-examples) 
- [Real-World Integration Scenarios](#real-world-integration-scenarios)
- [Code Examples](#code-examples)
- [Advanced Patterns](#advanced-patterns)
- [Troubleshooting](#troubleshooting)
- [Testing and Validation](#testing-and-validation)

## WebhookAgent Examples

The WebhookAgent creates events by receiving HTTP requests (webhooks) from external sources.

### Basic Configuration

```json
{
  "secret": "your-secure-random-token-here",
  "expected_receive_period_in_days": 1,
  "payload_path": ".",
  "verbs": "post",
  "response": "Event Created",
  "code": "201"
}
```

**Webhook URL Format:**
```
https://your-huginn-domain.com/users/{user_id}/web_requests/{agent_id}/{secret}
```

### 1. GitHub Webhook Integration

Perfect for monitoring repository events, pull requests, and issues.

#### Agent Configuration
```json
{
  "secret": "github-webhook-secret-xyz789",
  "expected_receive_period_in_days": 30,
  "payload_path": ".",
  "event_headers": "X-GitHub-Event,X-GitHub-Delivery,User-Agent",
  "event_headers_key": "github_headers",
  "verbs": "post",
  "response": "Webhook received successfully",
  "code": "200"
}
```

#### GitHub Webhook Setup
1. Go to your repository's Settings → Webhooks
2. Add webhook with URL: `https://your-huginn.com/users/123/web_requests/456/github-webhook-secret-xyz789`
3. Select "application/json" content type
4. Choose events: Push, Pull requests, Issues

#### Sample Payload Processing
The webhook will create events with this structure:
```json
{
  "action": "opened",
  "pull_request": {
    "title": "Fix critical bug in authentication",
    "user": {"login": "developer"},
    "base": {"ref": "main"},
    "head": {"ref": "fix/auth-bug"}
  },
  "repository": {
    "name": "my-project",
    "full_name": "org/my-project"
  },
  "github_headers": {
    "X-GitHub-Event": "pull_request",
    "X-GitHub-Delivery": "unique-delivery-id",
    "User-Agent": "GitHub-Hookshot/abc123"
  }
}
```

### 2. Slack Webhook Integration

Receive notifications and commands from Slack.

#### Agent Configuration
```json
{
  "secret": "slack-webhook-token-abc123",
  "expected_receive_period_in_days": 7,
  "payload_path": ".",
  "event_headers": "User-Agent,X-Slack-Signature",
  "event_headers_key": "slack_headers",
  "verbs": "post",
  "response": "Message processed",
  "code": "200"
}
```

#### Slack App Setup
1. Create a Slack App at https://api.slack.com/apps
2. Enable Event Subscriptions
3. Set Request URL: `https://your-huginn.com/users/123/web_requests/456/slack-webhook-token-abc123`
4. Subscribe to events: `message.channels`, `app_mention`

### 3. IoT Device Data Collection

Collect sensor data from IoT devices or services.

#### Agent Configuration
```json
{
  "secret": "iot-sensor-key-def456",
  "expected_receive_period_in_days": 1,
  "payload_path": "sensor_data",
  "event_headers": "X-Device-ID,X-Sensor-Type",
  "event_headers_key": "device_info",
  "verbs": "post,put",
  "response": "Data recorded",
  "code": "201"
}
```

#### Expected JSON Payload
```json
{
  "timestamp": "2025-09-03T10:30:00Z",
  "device_id": "temp-sensor-01",
  "sensor_data": {
    "temperature": 23.5,
    "humidity": 65.2,
    "battery_level": 87,
    "location": {
      "latitude": 40.7128,
      "longitude": -74.0060
    }
  }
}
```

### 4. Multiple Event Creation from Arrays

Process webhooks that contain arrays of data, creating separate events for each item.

#### Agent Configuration
```json
{
  "secret": "batch-processor-ghi789",
  "expected_receive_period_in_days": 1,
  "payload_path": "items",
  "verbs": "post",
  "response": "{{items.size}} events created",
  "code": "201"
}
```

#### Input Payload
```json
{
  "batch_id": "batch_20250903_001",
  "items": [
    {"id": 1, "name": "Product A", "price": 29.99},
    {"id": 2, "name": "Product B", "price": 39.99},
    {"id": 3, "name": "Product C", "price": 19.99}
  ]
}
```

This will create 3 separate events, one for each item in the array.

### 5. Custom Response Headers and CORS

Enable cross-origin requests with custom response headers.

#### Agent Configuration
```json
{
  "secret": "cors-enabled-webhook-jkl012",
  "expected_receive_period_in_days": 7,
  "payload_path": ".",
  "verbs": "post,options",
  "response": "Success",
  "code": "200",
  "response_headers": {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Max-Age": "86400"
  }
}
```

### 6. reCAPTCHA Verification

Add bot protection to your webhooks using Google reCAPTCHA.

#### Agent Configuration
```json
{
  "secret": "protected-webhook-mno345",
  "expected_receive_period_in_days": 30,
  "payload_path": ".",
  "verbs": "post",
  "recaptcha_secret": "your-recaptcha-secret-key",
  "recaptcha_send_remote_addr": true,
  "score_threshold": 0.5,
  "response": "Verified and processed",
  "code": "200"
}
```

## DataOutputAgent Examples

The DataOutputAgent outputs received events as RSS or JSON feeds accessible via HTTP.

### Basic RSS Feed Configuration

```json
{
  "secrets": ["rss-feed-token-abc123"],
  "expected_receive_period_in_days": 2,
  "template": {
    "title": "My Huginn Feed",
    "description": "Latest events from my Huginn agents",
    "link": "https://my-blog.com",
    "item": {
      "title": "{{title}}",
      "description": "{{description}}",
      "link": "{{url}}",
      "pubDate": "{{created_at}}"
    }
  },
  "events_to_show": 50,
  "ttl": 60
}
```

**Access URLs:**
- RSS: `https://your-huginn.com/users/123/web_requests/456/rss-feed-token-abc123.xml`
- JSON: `https://your-huginn.com/users/123/web_requests/456/rss-feed-token-abc123.json`

### 1. News Feed Aggregator

Create RSS feed from multiple news sources.

#### Agent Configuration
```json
{
  "secrets": ["news-aggregator-xyz789"],
  "expected_receive_period_in_days": 1,
  "template": {
    "title": "Tech News Aggregator",
    "description": "Latest technology news from multiple sources",
    "link": "https://my-tech-blog.com",
    "icon": "https://my-tech-blog.com/favicon.ico",
    "item": {
      "title": "{{title}}",
      "description": "{{summary}} Source: {{source}}",
      "link": "{{url}}",
      "pubDate": "{{published_at}}",
      "author": "{{author}}",
      "category": "{{category}}"
    }
  },
  "events_to_show": 100,
  "ttl": 30,
  "ns_media": true,
  "response_headers": {
    "Cache-Control": "public, max-age=1800"
  }
}
```

### 2. Podcast Feed with iTunes Support

Create podcast RSS feed with iTunes-compatible metadata.

#### Agent Configuration
```json
{
  "secrets": ["podcast-feed-def456"],
  "expected_receive_period_in_days": 7,
  "template": {
    "title": "Tech Talk Podcast",
    "description": "Weekly discussions about technology trends",
    "link": "https://podcast.example.com",
    "icon": "https://podcast.example.com/artwork.jpg",
    "item": {
      "title": "{{episode_title}}",
      "description": "{{episode_description}}",
      "link": "{{episode_url}}",
      "pubDate": "{{published_date}}",
      "enclosure": {
        "_attributes": {
          "url": "{{audio_url}}",
          "length": "{{file_size}}",
          "type": "audio/mpeg"
        }
      },
      "itunes:duration": "{{duration}}",
      "itunes:episode": "{{episode_number}}",
      "itunes:season": "{{season_number}}"
    }
  },
  "events_to_show": 50,
  "ns_itunes": true,
  "ns_media": true
}
```

### 3. Multiple Authentication Secrets

Use different secrets for different access levels or clients.

#### Agent Configuration
```json
{
  "secrets": [
    "public-readonly-abc123",
    "partner-access-def456", 
    "admin-full-ghi789"
  ],
  "expected_receive_period_in_days": 1,
  "template": {
    "title": "API Data Feed",
    "description": "Real-time data from our systems",
    "item": {
      "title": "{{event_type}}: {{title}}",
      "description": "{{description}}",
      "pubDate": "{{timestamp}}",
      "guid": "{{event_id}}"
    }
  },
  "events_to_show": 200,
  "response_headers": {
    "X-Rate-Limit": "1000",
    "X-Rate-Window": "3600"
  }
}
```

### 4. JSON API Endpoint

Provide structured JSON data for API consumers.

#### Agent Configuration
```json
{
  "secrets": ["api-json-endpoint-jkl012"],
  "expected_receive_period_in_days": 1,
  "template": {
    "title": "Status Dashboard Data",
    "description": "System status and metrics",
    "item": {
      "service": "{{service_name}}",
      "status": "{{status}}",
      "response_time": "{{response_time_ms}}",
      "error_rate": "{{error_rate_percent}}",
      "last_checked": "{{checked_at}}",
      "metadata": {
        "version": "{{service_version}}",
        "region": "{{deployment_region}}"
      }
    }
  },
  "events_to_show": 20
}
```

**JSON Access:** `https://your-huginn.com/users/123/web_requests/456/api-json-endpoint-jkl012.json`

### 5. Event Ordering and Sorting

Control the order of events in your feed based on custom criteria.

#### Agent Configuration
```json
{
  "secrets": ["ordered-feed-mno345"],
  "expected_receive_period_in_days": 2,
  "template": {
    "title": "Priority Task Feed",
    "description": "Tasks ordered by priority and due date",
    "item": {
      "title": "[{{priority}}] {{task_name}}",
      "description": "Due: {{due_date}} | Assigned: {{assignee}}",
      "link": "{{task_url}}"
    }
  },
  "events_to_show": 30,
  "events_order": [["{{priority}}", "number", false], ["{{due_date}}", "time", true]],
  "events_list_order": [["{{due_date}}", "time", true]]
}
```

## Real-World Integration Scenarios

### Scenario 1: Complete CI/CD Pipeline Monitoring

Monitor your entire development workflow from code commits to deployment.

#### 1. GitHub Webhook Agent
```json
{
  "name": "GitHub Events",
  "type": "Agents::WebhookAgent",
  "options": {
    "secret": "github-cicd-monitor-abc123",
    "payload_path": ".",
    "event_headers": "X-GitHub-Event",
    "event_headers_key": "github_info"
  }
}
```

#### 2. Trigger Agent (Filter Important Events)
```json
{
  "name": "Important GitHub Events",
  "type": "Agents::TriggerAgent",
  "options": {
    "rules": [
      {
        "type": "regex",
        "value": "push|pull_request|release",
        "path": "github_info.X-GitHub-Event"
      }
    ]
  }
}
```

#### 3. DataOutputAgent (Status Dashboard)
```json
{
  "name": "CI/CD Status Feed",
  "type": "Agents::DataOutputAgent",
  "options": {
    "secrets": ["cicd-status-def456"],
    "template": {
      "title": "CI/CD Pipeline Status",
      "description": "Real-time development workflow status",
      "item": {
        "title": "{{action}} on {{repository.name}}",
        "description": "{{head_commit.message}} by {{head_commit.author.name}}",
        "link": "{{head_commit.url}}",
        "category": "{{github_info.X-GitHub-Event}}"
      }
    }
  }
}
```

### Scenario 2: Multi-Source Alert Aggregation

Collect alerts from various monitoring tools and services.

#### 1. Multiple Webhook Agents
```json
{
  "name": "Datadog Alerts",
  "type": "Agents::WebhookAgent",
  "options": {
    "secret": "datadog-alerts-ghi789",
    "payload_path": ".",
    "response": "Alert received"
  }
}
```

```json
{
  "name": "PagerDuty Incidents",
  "type": "Agents::WebhookAgent",
  "options": {
    "secret": "pagerduty-incidents-jkl012",
    "payload_path": "incident",
    "response": "Incident logged"
  }
}
```

#### 2. Event Formatting Agent
```json
{
  "name": "Alert Formatter",
  "type": "Agents::EventFormattingAgent",
  "options": {
    "instructions": {
      "alert_type": "{{source_type | default: 'unknown'}}",
      "severity": "{{severity | default: 'medium'}}",
      "message": "{{alert_message | default: title}}",
      "timestamp": "{{created_at}}",
      "service": "{{service_name | default: 'system'}}"
    }
  }
}
```

#### 3. Unified Alert Feed
```json
{
  "name": "Unified Alert Feed",
  "type": "Agents::DataOutputAgent",
  "options": {
    "secrets": ["unified-alerts-mno345"],
    "template": {
      "title": "System Alerts Dashboard",
      "description": "All system alerts in one place",
      "item": {
        "title": "[{{severity | upcase}}] {{service}}: {{message}}",
        "description": "Alert from {{alert_type}} at {{timestamp}}",
        "category": "{{severity}}"
      }
    },
    "events_order": [["{{severity}}", "string", false]]
  }
}
```

### Scenario 3: IoT Data Pipeline

Process sensor data from multiple IoT devices.

#### 1. Device Webhook Agents
```json
{
  "name": "Temperature Sensors",
  "type": "Agents::WebhookAgent",
  "options": {
    "secret": "temp-sensors-pqr678",
    "payload_path": "readings",
    "event_headers": "X-Device-ID,X-Location",
    "event_headers_key": "device_meta"
  }
}
```

#### 2. Data Processing Agent
```json
{
  "name": "Temperature Processor",
  "type": "Agents::JavaScriptAgent",
  "options": {
    "code": "Agent.check = function() {\n  var events = this.incomingEvents();\n  events.forEach(function(event) {\n    var temp = parseFloat(event.temperature);\n    var alert_level = 'normal';\n    if (temp > 30) alert_level = 'high';\n    if (temp < 10) alert_level = 'low';\n    \n    this.createEvent({\n      device_id: event.device_meta['X-Device-ID'],\n      location: event.device_meta['X-Location'],\n      temperature: temp,\n      humidity: event.humidity,\n      alert_level: alert_level,\n      timestamp: event.timestamp\n    });\n  }.bind(this));\n};"
  }
}
```

#### 3. Real-time Data Feed
```json
{
  "name": "IoT Data Stream",
  "type": "Agents::DataOutputAgent",
  "options": {
    "secrets": ["iot-data-stream-stu901"],
    "template": {
      "title": "IoT Sensor Data",
      "description": "Real-time environmental data",
      "item": {
        "title": "{{location}} - {{temperature}}°C",
        "description": "Humidity: {{humidity}}% | Alert: {{alert_level}}",
        "category": "{{alert_level}}",
        "location": "{{location}}",
        "temperature": "{{temperature}}",
        "humidity": "{{humidity}}"
      }
    },
    "events_to_show": 100
  }
}
```

## Code Examples

### curl Commands

#### Send to WebhookAgent
```bash
# Basic webhook post
curl -X POST \
  https://your-huginn.com/users/123/web_requests/456/your-secret-token \
  -H "Content-Type: application/json" \
  -d '{"event": "test", "data": {"temperature": 25.5}}'

# With custom headers
curl -X POST \
  https://your-huginn.com/users/123/web_requests/456/your-secret-token \
  -H "Content-Type: application/json" \
  -H "X-Device-ID: sensor-001" \
  -H "X-Location: office" \
  -d '{"readings": [{"temp": 25.5, "humidity": 60}]}'

# Test response
curl -X POST \
  https://your-huginn.com/users/123/web_requests/456/your-secret-token \
  -H "Content-Type: application/json" \
  -d '{"message": "hello"}' \
  -v
```

#### Fetch from DataOutputAgent
```bash
# Get RSS feed
curl https://your-huginn.com/users/123/web_requests/456/feed-secret.xml

# Get JSON data
curl https://your-huginn.com/users/123/web_requests/456/feed-secret.json

# With authentication header
curl -H "Authorization: Bearer your-token" \
  https://your-huginn.com/users/123/web_requests/456/feed-secret.json
```

### Python Examples

#### Send Data to WebhookAgent
```python
import requests
import json

# Basic webhook post
webhook_url = "https://your-huginn.com/users/123/web_requests/456/your-secret-token"
payload = {
    "event_type": "sensor_reading",
    "device_id": "temp-001",
    "data": {
        "temperature": 23.5,
        "humidity": 65.2,
        "timestamp": "2025-09-03T10:30:00Z"
    }
}

headers = {
    "Content-Type": "application/json",
    "X-Device-ID": "temp-001",
    "X-Location": "server-room"
}

response = requests.post(webhook_url, json=payload, headers=headers)
print(f"Status: {response.status_code}")
print(f"Response: {response.text}")

# Batch processing
batch_payload = {
    "batch_id": "batch_001",
    "items": [
        {"id": 1, "name": "Item A", "value": 100},
        {"id": 2, "name": "Item B", "value": 200},
        {"id": 3, "name": "Item C", "value": 300}
    ]
}

response = requests.post(webhook_url, json=batch_payload)
```

#### Fetch DataOutputAgent Data
```python
import requests
import feedparser
import json

# Fetch RSS feed
rss_url = "https://your-huginn.com/users/123/web_requests/456/feed-secret.xml"
feed = feedparser.parse(rss_url)

print(f"Feed Title: {feed.feed.title}")
print(f"Feed Description: {feed.feed.description}")

for entry in feed.entries:
    print(f"- {entry.title}")
    print(f"  Published: {entry.published}")
    print(f"  Link: {entry.link}")

# Fetch JSON data
json_url = "https://your-huginn.com/users/123/web_requests/456/feed-secret.json"
response = requests.get(json_url)
data = response.json()

print(f"Title: {data['title']}")
print(f"Items: {len(data['items'])}")

for item in data['items']:
    print(f"- {item.get('title', 'No title')}")
```

### JavaScript Examples

#### Browser/Node.js Webhook Calls
```javascript
// Modern fetch API
async function sendWebhookData(payload) {
  const webhookUrl = 'https://your-huginn.com/users/123/web_requests/456/your-secret-token';
  
  try {
    const response = await fetch(webhookUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Source': 'web-app',
        'X-User-ID': '12345'
      },
      body: JSON.stringify(payload)
    });
    
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    
    const result = await response.text();
    console.log('Webhook response:', result);
    
  } catch (error) {
    console.error('Webhook failed:', error);
  }
}

// Usage
sendWebhookData({
  event: 'user_action',
  action: 'button_click',
  user_id: 12345,
  page: '/dashboard',
  timestamp: new Date().toISOString()
});

// Fetch JSON feed data
async function fetchHuginnFeed() {
  const feedUrl = 'https://your-huginn.com/users/123/web_requests/456/feed-secret.json';
  
  try {
    const response = await fetch(feedUrl);
    const data = await response.json();
    
    console.log(`Feed: ${data.title}`);
    data.items.forEach(item => {
      console.log(`- ${item.title}`);
    });
    
    return data;
  } catch (error) {
    console.error('Failed to fetch feed:', error);
  }
}
```

### Ruby Examples

#### Send to WebhookAgent
```ruby
require 'net/http'
require 'json'
require 'uri'

# Basic webhook post
def send_webhook(data)
  uri = URI('https://your-huginn.com/users/123/web_requests/456/your-secret-token')
  
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true
  
  request = Net::HTTP::Post.new(uri)
  request['Content-Type'] = 'application/json'
  request['X-Source'] = 'ruby-script'
  request.body = data.to_json
  
  response = http.request(request)
  puts "Status: #{response.code}"
  puts "Response: #{response.body}"
end

# Usage
webhook_data = {
  event_type: 'system_status',
  service: 'web_server',
  status: 'healthy',
  metrics: {
    cpu_usage: 45.2,
    memory_usage: 67.8,
    disk_usage: 23.1
  },
  timestamp: Time.now.iso8601
}

send_webhook(webhook_data)
```

#### Fetch from DataOutputAgent
```ruby
require 'net/http'
require 'json'
require 'rss'

# Fetch RSS feed
def fetch_rss_feed(url)
  rss = RSS::Parser.parse(Net::HTTP.get(URI(url)))
  
  puts "Feed: #{rss.channel.title}"
  puts "Description: #{rss.channel.description}"
  
  rss.items.each do |item|
    puts "- #{item.title}"
    puts "  Published: #{item.pubDate}"
    puts "  Link: #{item.link}"
  end
end

# Fetch JSON feed
def fetch_json_feed(url)
  response = Net::HTTP.get(URI(url))
  data = JSON.parse(response)
  
  puts "Feed: #{data['title']}"
  data['items'].each do |item|
    puts "- #{item['title']}"
  end
end

# Usage
rss_url = 'https://your-huginn.com/users/123/web_requests/456/feed-secret.xml'
json_url = 'https://your-huginn.com/users/123/web_requests/456/feed-secret.json'

fetch_rss_feed(rss_url)
fetch_json_feed(json_url)
```

## Advanced Patterns

### 1. Webhook Chaining and Event Flow

Create complex workflows by chaining multiple webhook endpoints.

#### Primary Webhook Agent
```json
{
  "name": "Initial Webhook",
  "type": "Agents::WebhookAgent",
  "options": {
    "secret": "chain-start-abc123",
    "payload_path": ".",
    "response": "Processing initiated"
  }
}
```

#### Processing Agent
```json
{
  "name": "Data Processor",
  "type": "Agents::JavaScriptAgent",
  "options": {
    "code": "Agent.check = function() {\n  this.incomingEvents().forEach(function(event) {\n    // Add processing metadata\n    var processed = {\n      original_data: event,\n      processed_at: new Date().toISOString(),\n      processing_id: 'proc_' + Math.random().toString(36).substr(2, 9),\n      status: 'processed'\n    };\n    \n    this.createEvent(processed);\n  }.bind(this));\n};"
  }
}
```

#### Notification Webhook Agent
```json
{
  "name": "Notification Webhook",
  "type": "Agents::WebhookAgent",
  "options": {
    "secret": "chain-notify-def456",
    "payload_path": ".",
    "response": "Notification sent"
  }
}
```

### 2. Data Transformation Pipelines

Transform incoming data through multiple stages.

#### Schema Validation Agent
```json
{
  "name": "Schema Validator",
  "type": "Agents::JavaScriptAgent",
  "options": {
    "code": "Agent.check = function() {\n  this.incomingEvents().forEach(function(event) {\n    var isValid = true;\n    var errors = [];\n    \n    // Validate required fields\n    if (!event.user_id) {\n      isValid = false;\n      errors.push('Missing user_id');\n    }\n    \n    if (!event.timestamp) {\n      isValid = false;\n      errors.push('Missing timestamp');\n    }\n    \n    var result = {\n      original_event: event,\n      validation: {\n        is_valid: isValid,\n        errors: errors,\n        validated_at: new Date().toISOString()\n      }\n    };\n    \n    this.createEvent(result);\n  }.bind(this));\n};"
  }
}
```

#### Data Enrichment Agent
```json
{
  "name": "Data Enricher",
  "type": "Agents::JavaScriptAgent",
  "options": {
    "code": "Agent.check = function() {\n  this.incomingEvents().forEach(function(event) {\n    if (event.validation.is_valid) {\n      var enriched = event.original_event;\n      \n      // Add computed fields\n      enriched.day_of_week = new Date(enriched.timestamp).toLocaleDateString('en-US', {weekday: 'long'});\n      enriched.hour_of_day = new Date(enriched.timestamp).getHours();\n      enriched.enriched_at = new Date().toISOString();\n      \n      this.createEvent(enriched);\n    } else {\n      console.log('Skipping invalid event:', event.validation.errors);\n    }\n  }.bind(this));\n};"
  }
}
```

### 3. Error Handling and Retry Logic

Implement robust error handling for webhook processing.

#### Error Capture Agent
```json
{
  "name": "Error Handler",
  "type": "Agents::JavaScriptAgent",
  "options": {
    "code": "Agent.check = function() {\n  this.incomingEvents().forEach(function(event) {\n    try {\n      // Attempt processing\n      var processed = processData(event);\n      \n      this.createEvent({\n        status: 'success',\n        data: processed,\n        processed_at: new Date().toISOString()\n      });\n      \n    } catch (error) {\n      // Log error and create error event\n      console.log('Processing error:', error.message);\n      \n      this.createEvent({\n        status: 'error',\n        error_message: error.message,\n        original_event: event,\n        failed_at: new Date().toISOString(),\n        retry_count: event.retry_count || 0\n      });\n    }\n  }.bind(this));\n  \n  function processData(data) {\n    // Your processing logic here\n    if (!data.required_field) {\n      throw new Error('Missing required field');\n    }\n    return { processed: true, result: data.required_field.toUpperCase() };\n  }\n};"
  }
}
```

#### Retry Logic Agent
```json
{
  "name": "Retry Handler",
  "type": "Agents::TriggerAgent",
  "options": {
    "rules": [
      {
        "type": "field==value",
        "value": "error",
        "path": "status"
      },
      {
        "type": "field<value",
        "value": "3",
        "path": "retry_count"
      }
    ],
    "message": "Retrying failed event (attempt {{retry_count + 1}})"
  }
}
```

### 4. Monitoring and Logging Practices

Implement comprehensive monitoring for your webhook infrastructure.

#### Metrics Collection Agent
```json
{
  "name": "Webhook Metrics",
  "type": "Agents::JavaScriptAgent",
  "options": {
    "code": "Agent.check = function() {\n  this.incomingEvents().forEach(function(event) {\n    var metrics = {\n      event_type: event.type || 'unknown',\n      source: event.headers ? event.headers['User-Agent'] : 'unknown',\n      timestamp: new Date().toISOString(),\n      processing_time: Date.now() - new Date(event.received_at || event.created_at).getTime(),\n      payload_size: JSON.stringify(event).length,\n      success: true\n    };\n    \n    this.createEvent(metrics);\n  }.bind(this));\n};"
  }
}
```

#### Log Aggregation Feed
```json
{
  "name": "Webhook Logs Feed",
  "type": "Agents::DataOutputAgent",
  "options": {
    "secrets": ["webhook-logs-vwx234"],
    "template": {
      "title": "Webhook Processing Logs",
      "description": "Real-time webhook processing metrics and logs",
      "item": {
        "title": "{{event_type}} from {{source}}",
        "description": "Processing time: {{processing_time}}ms | Size: {{payload_size}} bytes",
        "category": "{{success ? 'success' : 'error'}}",
        "processing_time": "{{processing_time}}",
        "payload_size": "{{payload_size}}"
      }
    },
    "events_to_show": 500
  }
}
```

## Troubleshooting

### Common Issues and Solutions

#### 1. "Not Authorized" Error (401)

**Cause:** Incorrect secret in URL or webhook configuration

**Solutions:**
- Verify the secret matches exactly between webhook URL and agent configuration
- Check for leading/trailing spaces in the secret
- Ensure the secret doesn't contain special characters that need URL encoding
- Test with a simple secret like `test123` first

```bash
# Test with curl
curl -X POST https://your-huginn.com/users/123/web_requests/456/correct-secret \
  -d '{"test": "data"}' -v
```

#### 2. "Agent not found" Error (404)

**Cause:** Invalid agent ID or user ID in URL

**Solutions:**
- Verify the agent ID in your Huginn dashboard
- Ensure the user ID is correct
- Check that the agent is active and not deleted

#### 3. Events Not Being Created

**Possible Causes and Solutions:**

**Incorrect `payload_path`:**
```json
// If your JSON is: {"data": {"items": [1,2,3]}}
// Use payload_path: "data.items" to create 3 events
// Use payload_path: "data" to create 1 event with the data object
// Use payload_path: "." to create 1 event with entire payload
```

**HTTP Method Not Allowed:**
```json
{
  "verbs": "post,get,put"  // Specify allowed HTTP methods
}
```

**Payload Processing Errors:**
- Check agent logs for error messages
- Verify JSON structure matches expected format
- Test with simplified payloads first

#### 4. RSS/JSON Feed Not Loading

**Cause:** Incorrect feed URL or secret

**Solutions:**
- Verify the secret is in the `secrets` array
- Check the feed URL format: `/users/{user_id}/web_requests/{agent_id}/{secret}.{format}`
- Test the agent has received events recently
- Verify `expected_receive_period_in_days` hasn't expired

#### 5. CORS Issues with Browser Requests

**Solution:** Add CORS headers to webhook response
```json
{
  "response_headers": {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization"
  }
}
```

#### 6. Large Payloads Causing Timeouts

**Solutions:**
- Break large payloads into smaller chunks
- Use `payload_path` to extract specific data portions
- Implement pagination for data feeds
- Consider using background job processing

#### 7. reCAPTCHA Verification Failing

**Common Issues:**
- Wrong reCAPTCHA secret key
- Missing `g-recaptcha-response` in payload
- Score threshold too high for reCAPTCHA v3

**Solution:**
```json
{
  "recaptcha_secret": "your-secret-key-from-google",
  "score_threshold": 0.3,  // Lower threshold for more lenient verification
  "recaptcha_send_remote_addr": true
}
```

### Debug Steps

#### 1. Test with Simple Payload
```bash
curl -X POST https://your-huginn.com/users/123/web_requests/456/your-secret \
  -H "Content-Type: application/json" \
  -d '{"test": "hello"}' \
  -v
```

#### 2. Check Agent Logs
- Go to your agent's page in Huginn
- Click on "Logs" tab
- Look for error messages and processing information

#### 3. Verify Event Creation
- Check the agent's "Events" tab
- Look for recently created events
- Verify event payload structure

#### 4. Test Feed URLs
```bash
# Test RSS feed
curl https://your-huginn.com/users/123/web_requests/456/secret.xml -v

# Test JSON feed  
curl https://your-huginn.com/users/123/web_requests/456/secret.json -v
```

## Testing and Validation

### WebhookAgent Testing

#### 1. Basic Functionality Test
```bash
# Test script for webhook agent
#!/bin/bash

WEBHOOK_URL="https://your-huginn.com/users/123/web_requests/456/test-secret"

echo "Testing basic webhook..."
curl -X POST $WEBHOOK_URL \
  -H "Content-Type: application/json" \
  -d '{"test": "basic", "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"}' \
  -w "\nHTTP Status: %{http_code}\nResponse Time: %{time_total}s\n"

echo -e "\nTesting with headers..."
curl -X POST $WEBHOOK_URL \
  -H "Content-Type: application/json" \
  -H "X-Test-Header: custom-value" \
  -d '{"test": "headers", "data": {"value": 123}}' \
  -w "\nHTTP Status: %{http_code}\n"

echo -e "\nTesting array payload..."
curl -X POST $WEBHOOK_URL \
  -H "Content-Type: application/json" \
  -d '{"items": [{"id": 1}, {"id": 2}, {"id": 3}]}' \
  -w "\nHTTP Status: %{http_code}\n"
```

#### 2. Load Testing
```bash
# Simple load test
#!/bin/bash

WEBHOOK_URL="https://your-huginn.com/users/123/web_requests/456/load-test-secret"

for i in {1..100}; do
  curl -X POST $WEBHOOK_URL \
    -H "Content-Type: application/json" \
    -d '{"test_id": '$i', "data": "load test data"}' \
    --silent &
  
  if (( $i % 10 == 0 )); then
    wait  # Wait for every 10 requests to complete
    echo "Completed $i requests"
  fi
done

wait
echo "Load test complete: 100 requests sent"
```

#### 3. Error Condition Testing
```bash
# Test error conditions
#!/bin/bash

BASE_URL="https://your-huginn.com/users/123/web_requests/456"

echo "Testing wrong secret..."
curl -X POST $BASE_URL/wrong-secret \
  -d '{"test": "wrong_secret"}' \
  -w "\nExpected 401: %{http_code}\n"

echo -e "\nTesting wrong HTTP method..."
curl -X GET $BASE_URL/correct-secret \
  -w "\nExpected 401: %{http_code}\n"

echo -e "\nTesting malformed JSON..."
curl -X POST $BASE_URL/correct-secret \
  -H "Content-Type: application/json" \
  -d '{"invalid": json}' \
  -w "\nStatus: %{http_code}\n"
```

### DataOutputAgent Testing

#### 1. Feed Validation Script
```python
#!/usr/bin/env python3

import requests
import feedparser
import json
import sys

def test_rss_feed(url):
    """Test RSS feed validity"""
    print(f"Testing RSS feed: {url}")
    
    try:
        # Fetch and parse RSS
        feed = feedparser.parse(url)
        
        if feed.bozo:
            print(f"❌ RSS parsing error: {feed.bozo_exception}")
            return False
        
        print(f"✅ RSS Title: {feed.feed.title}")
        print(f"✅ RSS Description: {feed.feed.description}")
        print(f"✅ Item count: {len(feed.entries)}")
        
        # Validate first item
        if feed.entries:
            item = feed.entries[0]
            print(f"✅ First item title: {item.title}")
            print(f"✅ First item link: {item.link}")
        
        return True
        
    except Exception as e:
        print(f"❌ RSS test failed: {e}")
        return False

def test_json_feed(url):
    """Test JSON feed validity"""
    print(f"\nTesting JSON feed: {url}")
    
    try:
        response = requests.get(url)
        response.raise_for_status()
        
        data = response.json()
        
        print(f"✅ JSON Title: {data.get('title', 'No title')}")
        print(f"✅ JSON Description: {data.get('description', 'No description')}")
        print(f"✅ Item count: {len(data.get('items', []))}")
        
        # Validate structure
        required_fields = ['title', 'description', 'items']
        for field in required_fields:
            if field not in data:
                print(f"❌ Missing field: {field}")
                return False
        
        print("✅ JSON structure is valid")
        return True
        
    except Exception as e:
        print(f"❌ JSON test failed: {e}")
        return False

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 test_feeds.py <base_url_without_extension>")
        sys.exit(1)
    
    base_url = sys.argv[1]
    rss_url = f"{base_url}.xml"
    json_url = f"{base_url}.json"
    
    rss_ok = test_rss_feed(rss_url)
    json_ok = test_json_feed(json_url)
    
    if rss_ok and json_ok:
        print("\n🎉 All tests passed!")
        sys.exit(0)
    else:
        print("\n💥 Some tests failed!")
        sys.exit(1)
```

#### 2. Performance Testing
```bash
#!/bin/bash

# Performance test for data output agent
FEED_URL="https://your-huginn.com/users/123/web_requests/456/perf-test-secret.json"

echo "Running performance test on: $FEED_URL"

# Test response time
echo -e "\nTesting response times..."
for i in {1..10}; do
  curl -s -w "Request $i: %{time_total}s\n" -o /dev/null $FEED_URL
done

# Test concurrent requests
echo -e "\nTesting concurrent requests..."
for i in {1..5}; do
  curl -s $FEED_URL > /dev/null &
done
wait
echo "Concurrent test complete"

# Test with different formats
echo -e "\nTesting RSS format..."
RSS_URL="${FEED_URL%.json}.xml"
curl -s -w "RSS response time: %{time_total}s\n" -o /dev/null $RSS_URL
```

### Automated Testing Suite

#### Complete Test Script
```bash
#!/bin/bash

# Comprehensive Huginn webhook testing suite

set -e

# Configuration
HUGINN_BASE="https://your-huginn.com"
USER_ID="123"
WEBHOOK_AGENT_ID="456"
OUTPUT_AGENT_ID="789"
TEST_SECRET="test-webhook-secret"
FEED_SECRET="test-feed-secret"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

test_webhook() {
    local test_name="$1"
    local webhook_url="$2"
    local payload="$3"
    local expected_status="$4"
    
    log_info "Testing: $test_name"
    
    local response
    response=$(curl -s -w "HTTPSTATUS:%{http_code}" -X POST "$webhook_url" \
        -H "Content-Type: application/json" \
        -d "$payload")
    
    local body=$(echo "$response" | sed -E 's/HTTPSTATUS:[0-9]{3}$//')
    local status=$(echo "$response" | tr -d '\n' | sed -E 's/.*HTTPSTATUS:([0-9]{3})$/\1/')
    
    if [[ "$status" == "$expected_status" ]]; then
        log_info "✅ $test_name passed (Status: $status)"
        return 0
    else
        log_error "❌ $test_name failed (Expected: $expected_status, Got: $status)"
        return 1
    fi
}

# Main test execution
main() {
    log_info "Starting Huginn webhook test suite"
    
    local webhook_url="$HUGINN_BASE/users/$USER_ID/web_requests/$WEBHOOK_AGENT_ID/$TEST_SECRET"
    local feed_base_url="$HUGINN_BASE/users/$USER_ID/web_requests/$OUTPUT_AGENT_ID/$FEED_SECRET"
    
    local passed=0
    local failed=0
    
    # Webhook tests
    if test_webhook "Valid webhook request" "$webhook_url" '{"test": "data"}' "201"; then
        ((passed++))
    else
        ((failed++))
    fi
    
    if test_webhook "Array payload" "$webhook_url" '{"items": [1,2,3]}' "201"; then
        ((passed++))
    else
        ((failed++))
    fi
    
    if test_webhook "Wrong secret" "$HUGINN_BASE/users/$USER_ID/web_requests/$WEBHOOK_AGENT_ID/wrong-secret" '{"test": "data"}' "401"; then
        ((passed++))
    else
        ((failed++))
    fi
    
    # Feed tests
    log_info "Testing RSS feed"
    if curl -s -f "$feed_base_url.xml" > /dev/null; then
        log_info "✅ RSS feed accessible"
        ((passed++))
    else
        log_error "❌ RSS feed not accessible"
        ((failed++))
    fi
    
    log_info "Testing JSON feed"
    if curl -s -f "$feed_base_url.json" > /dev/null; then
        log_info "✅ JSON feed accessible"
        ((passed++))
    else
        log_error "❌ JSON feed not accessible"
        ((failed++))
    fi
    
    # Summary
    log_info "Test Results: $passed passed, $failed failed"
    
    if [[ $failed -eq 0 ]]; then
        log_info "🎉 All tests passed!"
        exit 0
    else
        log_error "💥 Some tests failed!"
        exit 1
    fi
}

main "$@"
```

This comprehensive documentation provides everything needed to implement and use webhooks effectively in Huginn. The examples are production-ready and can be adapted to specific use cases. Remember to always use secure secrets and follow security best practices when deploying webhook endpoints in production environments.