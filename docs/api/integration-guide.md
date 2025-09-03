# Huginn API Integration Guide

Huginn provides powerful APIs for integrating external systems through webhooks, data feeds, and agent management. This guide covers all aspects of API integration with practical examples and best practices.

## Table of Contents

1. [Getting Started](#getting-started)
2. [Authentication & Security](#authentication--security)
3. [Webhook Integration (Sending Data TO Huginn)](#webhook-integration-sending-data-to-huginn)
4. [Data Retrieval (Getting Data FROM Huginn)](#data-retrieval-getting-data-from-huginn)
5. [Agent Management API](#agent-management-api)
6. [Worker Status & Monitoring](#worker-status--monitoring)
7. [Integration Examples](#integration-examples)
8. [Error Handling & Best Practices](#error-handling--best-practices)
9. [Rate Limiting & Performance](#rate-limiting--performance)
10. [Troubleshooting](#troubleshooting)

## Getting Started

### Base Configuration

All Huginn API endpoints follow these patterns:

**Webhook Endpoints (Incoming Data):**
```
https://your-huginn-domain.com/users/{user_id}/web_requests/{agent_id}/{secret}
```

**Data Output Endpoints (Outgoing Data):**
```
https://your-huginn-domain.com/users/{user_id}/web_requests/{agent_id}/{secret}.{format}
```

### Required Information

To integrate with Huginn APIs, you need:

- **Domain**: Your Huginn instance URL
- **User ID**: Found in your account settings or agent URLs
- **Agent ID**: Unique identifier for each agent (visible in agent URLs)
- **Secret**: Authentication token configured in the agent

### Common Headers

```http
Content-Type: application/json
User-Agent: YourApp/1.0
Accept: application/json
```

## Authentication & Security

### Secret-Based Authentication

Huginn uses secret tokens for API authentication. Each agent that accepts web requests has configurable secrets.

#### Security Best Practices:

1. **Use Strong Secrets**: Generate cryptographically secure tokens
2. **Rotate Regularly**: Change secrets periodically
3. **Environment Variables**: Store secrets in environment variables, not code
4. **HTTPS Only**: Always use HTTPS in production
5. **Restrict Access**: Use firewalls and IP whitelisting when possible

#### Example Secret Configuration:
```json
{
  "secret": "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
  "verbs": "post,get",
  "expected_receive_period_in_days": 1
}
```

## Webhook Integration (Sending Data TO Huginn)

WebhookAgent receives external data via HTTP requests and creates Huginn events.

### Basic Webhook Setup

#### 1. Create a WebhookAgent

```json
{
  "type": "Agents::WebhookAgent",
  "name": "External Data Webhook",
  "options": {
    "secret": "your-secure-secret-here",
    "expected_receive_period_in_days": 1,
    "payload_path": ".",
    "verbs": "post",
    "response": "Event Created",
    "code": "201"
  }
}
```

#### 2. Webhook URL Format

```
POST https://your-huginn.com/users/123/web_requests/456/your-secure-secret-here
```

### Webhook Configuration Options

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `secret` | Authentication token | Generated UUID | `"abc123xyz"` |
| `verbs` | Allowed HTTP methods | `"post"` | `"post,get,put"` |
| `payload_path` | JSONPath to extract data | `"."` | `"$.data.items"` |
| `response` | Success response message | `"Event Created"` | `"Data received"` |
| `code` | HTTP response code | `201` | `200` |
| `event_headers` | Headers to include | `""` | `"X-Source,Authorization"` |

### Advanced Webhook Features

#### Custom Response Headers
```json
{
  "response_headers": {
    "Access-Control-Allow-Origin": "*",
    "X-API-Version": "1.0"
  }
}
```

#### Array Processing
When `payload_path` points to an array, Huginn creates one event per array element:

```json
// Incoming data
{
  "items": [
    {"id": 1, "name": "Item 1"},
    {"id": 2, "name": "Item 2"}
  ]
}

// Configuration
{
  "payload_path": "$.items"
}
// Results in 2 separate events
```

#### reCAPTCHA Integration
```json
{
  "recaptcha_secret": "your-recaptcha-secret",
  "recaptcha_send_remote_addr": true,
  "score_threshold": 0.5
}
```

### Webhook Integration Examples

#### JavaScript/Node.js
```javascript
const axios = require('axios');

const webhookUrl = 'https://huginn.example.com/users/123/web_requests/456/secret123';

async function sendToHuginn(data) {
  try {
    const response = await axios.post(webhookUrl, data, {
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'MyApp/1.0'
      },
      timeout: 10000
    });
    
    console.log('Success:', response.status, response.data);
    return response.data;
  } catch (error) {
    console.error('Failed to send webhook:', {
      status: error.response?.status,
      data: error.response?.data,
      message: error.message
    });
    throw error;
  }
}

// Usage
await sendToHuginn({
  event_type: 'user_action',
  user_id: 12345,
  action: 'purchase',
  amount: 99.99,
  timestamp: new Date().toISOString()
});
```

#### Python
```python
import requests
import json
from datetime import datetime

def send_to_huginn(webhook_url, data, timeout=10):
    """Send data to Huginn webhook with error handling"""
    
    headers = {
        'Content-Type': 'application/json',
        'User-Agent': 'MyApp/1.0'
    }
    
    try:
        response = requests.post(
            webhook_url,
            data=json.dumps(data),
            headers=headers,
            timeout=timeout
        )
        response.raise_for_status()
        
        print(f"Success: {response.status_code} - {response.text}")
        return response.json() if response.content else None
        
    except requests.exceptions.RequestException as e:
        print(f"Webhook failed: {e}")
        if hasattr(e, 'response') and e.response:
            print(f"Response: {e.response.status_code} - {e.response.text}")
        raise

# Usage
webhook_url = "https://huginn.example.com/users/123/web_requests/456/secret123"
data = {
    "sensor_id": "temp_01",
    "temperature": 23.5,
    "humidity": 65.2,
    "timestamp": datetime.now().isoformat()
}

send_to_huginn(webhook_url, data)
```

#### cURL Examples
```bash
# Simple POST
curl -X POST \
  "https://huginn.example.com/users/123/web_requests/456/secret123" \
  -H "Content-Type: application/json" \
  -d '{"message": "Hello from external system"}'

# With custom headers
curl -X POST \
  "https://huginn.example.com/users/123/web_requests/456/secret123" \
  -H "Content-Type: application/json" \
  -H "X-Source-System: monitoring" \
  -H "X-Priority: high" \
  -d '{
    "alert": "CPU usage critical",
    "server": "web-01",
    "cpu_usage": 95.5,
    "timestamp": "2024-01-15T10:30:00Z"
  }'

# GET request (if enabled)
curl -X GET \
  "https://huginn.example.com/users/123/web_requests/456/secret123?status=check&source=external"
```

## Data Retrieval (Getting Data FROM Huginn)

DataOutputAgent provides RSS and JSON feeds of Huginn event data.

### Basic Data Output Setup

#### 1. Create a DataOutputAgent

```json
{
  "type": "Agents::DataOutputAgent",
  "name": "API Data Feed",
  "options": {
    "secrets": ["feed-secret-123", "backup-secret-456"],
    "expected_receive_period_in_days": 2,
    "events_to_show": 50,
    "template": {
      "title": "My Huginn Data Feed",
      "description": "Real-time data from Huginn agents",
      "item": {
        "title": "{{title | default: 'Event'}}",
        "description": "{{description}}",
        "link": "{{url}}",
        "pubDate": "{{created_at}}"
      }
    }
  }
}
```

#### 2. Data Feed URLs

```
# JSON format
GET https://huginn.example.com/users/123/web_requests/789/feed-secret-123.json

# RSS/XML format  
GET https://huginn.example.com/users/123/web_requests/789/feed-secret-123.xml
```

### DataOutputAgent Configuration

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `secrets` | Array of valid auth tokens | Required | `["secret1", "secret2"]` |
| `events_to_show` | Number of events in feed | `40` | `100` |
| `ttl` | RSS cache time (minutes) | `60` | `30` |
| `events_order` | Event sorting criteria | Event creation time | `[["payload.priority", "number", true]]` |
| `template` | Output format template | Required | See examples below |

### Template Configuration

#### Basic Template
```json
{
  "template": {
    "title": "{{events.first.site_name | default: 'Data Feed'}}",
    "description": "Latest events from Huginn",
    "link": "https://example.com",
    "item": {
      "title": "{{title}}",
      "description": "{{content}}",
      "link": "{{url}}",
      "guid": "{{id}}"
    }
  }
}
```

#### Advanced Template with Custom Fields
```json
{
  "template": {
    "title": "IoT Sensor Data",
    "description": "Real-time sensor readings",
    "item": {
      "title": "{{sensor_name}} - {{reading_type}}",
      "description": "Value: {{value}} {{unit}} at {{timestamp}}",
      "link": "https://dashboard.example.com/sensors/{{sensor_id}}",
      "category": "{{sensor_type}}",
      "author": "{{sensor_location}}",
      "enclosure": {
        "_attributes": {
          "url": "{{chart_image_url}}",
          "type": "image/png",
          "length": "12345"
        }
      }
    }
  }
}
```

### Data Retrieval Examples

#### JavaScript/Node.js
```javascript
const axios = require('axios');

class HuginnDataFeed {
  constructor(baseUrl, userId, agentId, secret) {
    this.baseUrl = baseUrl;
    this.userId = userId;
    this.agentId = agentId;
    this.secret = secret;
  }

  async getJSON(limit = null) {
    const url = `${this.baseUrl}/users/${this.userId}/web_requests/${this.agentId}/${this.secret}.json`;
    
    try {
      const response = await axios.get(url, {
        timeout: 15000,
        headers: {
          'Accept': 'application/json',
          'User-Agent': 'HuginnClient/1.0'
        }
      });
      
      const data = response.data;
      return limit ? data.items.slice(0, limit) : data.items;
      
    } catch (error) {
      console.error('Failed to fetch data:', error.message);
      throw error;
    }
  }

  async getRSS() {
    const url = `${this.baseUrl}/users/${this.userId}/web_requests/${this.agentId}/${this.secret}.xml`;
    
    try {
      const response = await axios.get(url, {
        timeout: 15000,
        headers: {
          'Accept': 'application/rss+xml, application/xml, text/xml',
          'User-Agent': 'HuginnClient/1.0'
        }
      });
      
      return response.data;
      
    } catch (error) {
      console.error('Failed to fetch RSS:', error.message);
      throw error;
    }
  }

  async pollForUpdates(callback, intervalMs = 30000) {
    let lastEventId = null;
    
    const poll = async () => {
      try {
        const events = await this.getJSON(10);
        const newEvents = lastEventId 
          ? events.filter(event => event.id > lastEventId)
          : events;
          
        if (newEvents.length > 0) {
          lastEventId = Math.max(...newEvents.map(e => e.id));
          callback(newEvents);
        }
      } catch (error) {
        console.error('Polling error:', error.message);
      }
    };
    
    // Initial fetch
    await poll();
    
    // Set up polling interval
    return setInterval(poll, intervalMs);
  }
}

// Usage
const feed = new HuginnDataFeed(
  'https://huginn.example.com',
  123,
  789,
  'feed-secret-123'
);

// Get latest events as JSON
const events = await feed.getJSON(20);
console.log(`Received ${events.length} events`);

// Poll for real-time updates
const pollHandle = await feed.pollForUpdates((newEvents) => {
  console.log(`New events received: ${newEvents.length}`);
  newEvents.forEach(event => {
    console.log(`- ${event.title}: ${event.description}`);
  });
}, 15000);

// Stop polling later
clearInterval(pollHandle);
```

#### Python
```python
import requests
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import List, Dict, Optional

class HuginnDataFeed:
    def __init__(self, base_url: str, user_id: int, agent_id: int, secret: str):
        self.base_url = base_url.rstrip('/')
        self.user_id = user_id
        self.agent_id = agent_id
        self.secret = secret
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'HuginnPython/1.0'
        })

    def get_json(self, limit: Optional[int] = None) -> List[Dict]:
        """Fetch events as JSON"""
        url = f"{self.base_url}/users/{self.user_id}/web_requests/{self.agent_id}/{self.secret}.json"
        
        try:
            response = self.session.get(url, timeout=15)
            response.raise_for_status()
            
            data = response.json()
            items = data.get('items', [])
            
            return items[:limit] if limit else items
            
        except requests.RequestException as e:
            print(f"Failed to fetch JSON data: {e}")
            raise

    def get_rss(self) -> str:
        """Fetch events as RSS XML"""
        url = f"{self.base_url}/users/{self.user_id}/web_requests/{self.agent_id}/{self.secret}.xml"
        
        try:
            response = self.session.get(url, timeout=15)
            response.raise_for_status()
            
            return response.text
            
        except requests.RequestException as e:
            print(f"Failed to fetch RSS data: {e}")
            raise

    def parse_rss(self, rss_content: str) -> List[Dict]:
        """Parse RSS XML into structured data"""
        try:
            root = ET.fromstring(rss_content)
            items = []
            
            for item in root.findall('.//item'):
                event = {
                    'title': item.findtext('title', ''),
                    'description': item.findtext('description', ''),
                    'link': item.findtext('link', ''),
                    'pubDate': item.findtext('pubDate', ''),
                    'guid': item.findtext('guid', '')
                }
                items.append(event)
                
            return items
            
        except ET.ParseError as e:
            print(f"Failed to parse RSS: {e}")
            raise

    def monitor_events(self, callback, interval_seconds: int = 30):
        """Monitor for new events and call callback"""
        last_check = datetime.now()
        
        while True:
            try:
                events = self.get_json(50)
                
                # Filter events newer than last check
                new_events = []
                for event in events:
                    # Assuming event has timestamp field
                    if 'timestamp' in event:
                        event_time = datetime.fromisoformat(
                            event['timestamp'].replace('Z', '+00:00')
                        )
                        if event_time > last_check:
                            new_events.append(event)
                
                if new_events:
                    callback(new_events)
                    
                last_check = datetime.now()
                time.sleep(interval_seconds)
                
            except KeyboardInterrupt:
                print("Monitoring stopped")
                break
            except Exception as e:
                print(f"Monitoring error: {e}")
                time.sleep(interval_seconds)

# Usage
feed = HuginnDataFeed(
    base_url="https://huginn.example.com",
    user_id=123,
    agent_id=789,
    secret="feed-secret-123"
)

# Get latest 10 events
events = feed.get_json(limit=10)
print(f"Fetched {len(events)} events")

for event in events:
    print(f"- {event.get('title', 'No title')}")

# Monitor for new events
def handle_new_events(new_events):
    print(f"Received {len(new_events)} new events:")
    for event in new_events:
        print(f"  - {event.get('title', 'No title')}")

# feed.monitor_events(handle_new_events, interval_seconds=15)
```

#### Ruby
```ruby
require 'net/http'
require 'json'
require 'uri'
require 'rexml/document'

class HuginnDataFeed
  def initialize(base_url, user_id, agent_id, secret)
    @base_url = base_url.chomp('/')
    @user_id = user_id
    @agent_id = agent_id
    @secret = secret
  end

  def get_json(limit: nil)
    url = "#{@base_url}/users/#{@user_id}/web_requests/#{@agent_id}/#{@secret}.json"
    
    response = fetch_url(url, 'application/json')
    data = JSON.parse(response.body)
    
    items = data['items'] || []
    limit ? items.take(limit) : items
  end

  def get_rss
    url = "#{@base_url}/users/#{@user_id}/web_requests/#{@agent_id}/#{@secret}.xml"
    
    response = fetch_url(url, 'application/rss+xml')
    response.body
  end

  def parse_rss(rss_content)
    doc = REXML::Document.new(rss_content)
    items = []
    
    doc.elements.each('//item') do |item|
      event = {
        title: item.elements['title']&.text || '',
        description: item.elements['description']&.text || '',
        link: item.elements['link']&.text || '',
        pub_date: item.elements['pubDate']&.text || '',
        guid: item.elements['guid']&.text || ''
      }
      items << event
    end
    
    items
  end

  private

  def fetch_url(url, accept_type)
    uri = URI.parse(url)
    
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = uri.scheme == 'https'
    http.read_timeout = 15
    
    request = Net::HTTP::Get.new(uri)
    request['Accept'] = accept_type
    request['User-Agent'] = 'HuginnRuby/1.0'
    
    response = http.request(request)
    
    unless response.code.to_i == 200
      raise "HTTP #{response.code}: #{response.message}"
    end
    
    response
  end
end

# Usage
feed = HuginnDataFeed.new(
  'https://huginn.example.com',
  123,
  789,
  'feed-secret-123'
)

# Fetch JSON data
events = feed.get_json(limit: 15)
puts "Fetched #{events.length} events"

events.each do |event|
  puts "- #{event['title']}: #{event['description']}"
end

# Fetch and parse RSS
rss_content = feed.get_rss
rss_events = feed.parse_rss(rss_content)
puts "RSS contains #{rss_events.length} items"
```

### Real-time vs Polling Strategies

#### Polling Best Practices
1. **Reasonable Intervals**: Don't poll more than once every 15-30 seconds
2. **Exponential Backoff**: Increase intervals on errors
3. **Conditional Requests**: Use ETags or timestamps when possible
4. **Graceful Degradation**: Handle timeouts and failures gracefully

#### Webhook Alternative
Instead of polling DataOutputAgent, consider using WebhookAgent in reverse:
1. Configure DataOutputAgent to trigger another agent
2. Use PostAgent or similar to send data to your external system
3. Implement webhook endpoint in your system to receive real-time data

## Agent Management API

While Huginn doesn't provide a full REST API for agent management, you can interact with agents programmatically through the web interface endpoints.

### Available Endpoints

#### Agent Listing
```http
GET /agents.json
Authorization: [Session-based authentication required]
```

#### Agent Details  
```http
GET /agents/{agent_id}.json
Authorization: [Session-based authentication required]
```

#### Agent Execution
```http
POST /agents/{agent_id}/run
Authorization: [Session-based authentication required]
```

#### Event Management
```http
GET /agents/{agent_id}/events.json
POST /agents/{agent_id}/reemit_events
DELETE /agents/{agent_id}/remove_events
```

### Scenario Export/Import

#### Export Scenario
```http
GET /scenarios/{scenario_id}/export
# No authentication required for public scenarios
```

Response includes complete scenario configuration:
```json
{
  "schema_version": 1,
  "name": "My Scenario",
  "description": "Automated workflow",
  "agents": [...],
  "links": [...],
  "control_links": [...]
}
```

### Agent Configuration via API

Since direct agent management requires authentication, consider these patterns:

#### 1. Configuration Templates
Pre-create agent templates and use webhook data to modify behavior:

```javascript
// WebhookAgent that configures other agents based on incoming data
const configWebhook = {
  type: "Agents::WebhookAgent",
  options: {
    secret: "config-secret",
    payload_path: ".",
    // Process configuration updates
  }
};
```

#### 2. Dynamic Agent Behavior
Use memory and options interpolation for dynamic behavior:

```json
{
  "options": {
    "url": "{{credential.api_base_url}}/{{memory.current_endpoint}}",
    "headers": {
      "Authorization": "Bearer {{credential.api_token}}",
      "X-Source": "{{memory.data_source}}"
    }
  }
}
```

## Worker Status & Monitoring

### Worker Status Endpoint

```http
GET /worker_status
Authorization: [Session-based authentication required]
```

Response:
```json
{
  "pending": 5,
  "awaiting_retry": 2,
  "recent_failures": 1,
  "event_count": 150,
  "max_id": 2847,
  "events_url": "/events?hl=2840-2847",
  "compute_time": 0.045
}
```

### Health Check Integration

```javascript
const axios = require('axios');

class HuginnMonitor {
  constructor(baseUrl, credentials) {
    this.baseUrl = baseUrl;
    this.credentials = credentials;
  }

  async getWorkerStatus() {
    try {
      const response = await axios.get(`${this.baseUrl}/worker_status`, {
        // Add session-based authentication
        timeout: 10000
      });
      
      return response.data;
    } catch (error) {
      throw new Error(`Worker status check failed: ${error.message}`);
    }
  }

  async isHealthy() {
    try {
      const status = await this.getWorkerStatus();
      
      // Define health criteria
      const maxPending = 100;
      const maxFailures = 10;
      
      return (
        status.pending < maxPending &&
        status.recent_failures < maxFailures
      );
      
    } catch (error) {
      return false;
    }
  }

  async getHealthReport() {
    const status = await this.getWorkerStatus();
    
    return {
      healthy: await this.isHealthy(),
      details: {
        pendingJobs: status.pending,
        retryingJobs: status.awaiting_retry,
        recentFailures: status.recent_failures,
        totalEvents: status.event_count,
        lastProcessTime: status.compute_time
      },
      timestamp: new Date().toISOString()
    };
  }
}
```

## Integration Examples

### Complete IoT Data Pipeline

```javascript
const axios = require('axios');

class IoTHuginnIntegration {
  constructor(config) {
    this.config = config;
    this.webhookUrl = `${config.huginn.baseUrl}/users/${config.huginn.userId}/web_requests/${config.huginn.webhookAgentId}/${config.huginn.webhookSecret}`;
    this.feedUrl = `${config.huginn.baseUrl}/users/${config.huginn.userId}/web_requests/${config.huginn.dataAgentId}/${config.huginn.feedSecret}.json`;
  }

  // Send sensor data to Huginn
  async sendSensorData(sensorId, readings) {
    const payload = {
      sensor_id: sensorId,
      timestamp: new Date().toISOString(),
      readings: readings,
      location: this.config.sensors[sensorId]?.location,
      metadata: {
        firmware_version: "1.2.3",
        battery_level: readings.battery || null
      }
    };

    try {
      const response = await axios.post(this.webhookUrl, payload, {
        timeout: 10000,
        headers: {
          'Content-Type': 'application/json',
          'X-Device-ID': sensorId
        }
      });

      console.log(`Sensor data sent: ${sensorId}`, response.status);
      return response.data;
    } catch (error) {
      console.error(`Failed to send sensor data: ${error.message}`);
      throw error;
    }
  }

  // Get processed alerts from Huginn
  async getAlerts(limit = 20) {
    try {
      const response = await axios.get(this.feedUrl, {
        timeout: 15000
      });

      const events = response.data.items || [];
      
      // Filter for alert events
      return events
        .filter(event => event.alert_type)
        .slice(0, limit)
        .map(event => ({
          id: event.guid,
          type: event.alert_type,
          severity: event.severity || 'info',
          message: event.title,
          details: event.description,
          timestamp: event.pubDate,
          sensor: event.sensor_id,
          value: event.trigger_value
        }));

    } catch (error) {
      console.error(`Failed to fetch alerts: ${error.message}`);
      return [];
    }
  }

  // Monitor for critical alerts
  async monitorAlerts(callback) {
    let lastCheck = new Date();
    
    const check = async () => {
      try {
        const alerts = await this.getAlerts(50);
        
        const newAlerts = alerts.filter(alert => {
          const alertTime = new Date(alert.timestamp);
          return alertTime > lastCheck && alert.severity === 'critical';
        });

        if (newAlerts.length > 0) {
          callback(newAlerts);
        }

        lastCheck = new Date();
      } catch (error) {
        console.error(`Alert monitoring error: ${error.message}`);
      }
    };

    // Check immediately
    await check();
    
    // Then check every 30 seconds
    return setInterval(check, 30000);
  }
}

// Usage
const iot = new IoTHuginnIntegration({
  huginn: {
    baseUrl: 'https://huginn.example.com',
    userId: 123,
    webhookAgentId: 456,
    webhookSecret: 'sensor-data-secret',
    dataAgentId: 789,
    feedSecret: 'alert-feed-secret'
  },
  sensors: {
    'temp_01': { location: 'Server Room' },
    'temp_02': { location: 'Data Center' }
  }
});

// Send sensor readings
await iot.sendSensorData('temp_01', {
  temperature: 28.5,
  humidity: 65,
  battery: 87
});

// Monitor for critical alerts
iot.monitorAlerts((criticalAlerts) => {
  console.log(`CRITICAL ALERTS: ${criticalAlerts.length}`);
  criticalAlerts.forEach(alert => {
    console.log(`- ${alert.message} (${alert.sensor})`);
    // Trigger notifications, escalations, etc.
  });
});
```

### E-commerce Order Processing

```python
import requests
import json
from datetime import datetime
from typing import Dict, List

class EcommerceHuginnIntegration:
    def __init__(self, huginn_config: Dict):
        self.config = huginn_config
        self.base_url = huginn_config['base_url'].rstrip('/')
        self.user_id = huginn_config['user_id']
        
        # Different agents for different purposes
        self.agents = {
            'orders': {
                'webhook_id': huginn_config['order_webhook_agent_id'],
                'secret': huginn_config['order_webhook_secret']
            },
            'inventory': {
                'webhook_id': huginn_config['inventory_webhook_agent_id'],
                'secret': huginn_config['inventory_webhook_secret']
            },
            'notifications': {
                'data_id': huginn_config['notification_data_agent_id'],
                'secret': huginn_config['notification_data_secret']
            }
        }

    def send_order(self, order_data: Dict) -> bool:
        """Send new order to Huginn for processing"""
        webhook_url = f"{self.base_url}/users/{self.user_id}/web_requests/{self.agents['orders']['webhook_id']}/{self.agents['orders']['secret']}"
        
        # Enrich order data
        payload = {
            'order_id': order_data['id'],
            'customer_id': order_data['customer']['id'],
            'customer_email': order_data['customer']['email'],
            'total_amount': order_data['total'],
            'currency': order_data['currency'],
            'items': order_data['items'],
            'shipping_address': order_data['shipping'],
            'payment_method': order_data['payment']['method'],
            'order_timestamp': datetime.now().isoformat(),
            'source': 'ecommerce_api'
        }
        
        try:
            response = requests.post(
                webhook_url,
                json=payload,
                headers={
                    'Content-Type': 'application/json',
                    'X-Order-Source': 'web',
                    'X-Priority': 'high' if payload['total_amount'] > 1000 else 'normal'
                },
                timeout=10
            )
            response.raise_for_status()
            
            print(f"Order {order_data['id']} sent to Huginn")
            return True
            
        except requests.RequestException as e:
            print(f"Failed to send order {order_data['id']}: {e}")
            return False

    def update_inventory(self, sku: str, quantity_change: int, reason: str = 'sale'):
        """Update inventory levels"""
        webhook_url = f"{self.base_url}/users/{self.user_id}/web_requests/{self.agents['inventory']['webhook_id']}/{self.agents['inventory']['secret']}"
        
        payload = {
            'sku': sku,
            'quantity_change': quantity_change,
            'reason': reason,
            'timestamp': datetime.now().isoformat(),
            'source': 'inventory_system'
        }
        
        try:
            response = requests.post(webhook_url, json=payload, timeout=10)
            response.raise_for_status()
            return True
        except requests.RequestException as e:
            print(f"Failed to update inventory for {sku}: {e}")
            return False

    def get_notifications(self, limit: int = 50) -> List[Dict]:
        """Get notifications and alerts from Huginn"""
        feed_url = f"{self.base_url}/users/{self.user_id}/web_requests/{self.agents['notifications']['data_id']}/{self.agents['notifications']['secret']}.json"
        
        try:
            response = requests.get(feed_url, timeout=15)
            response.raise_for_status()
            
            data = response.json()
            return data.get('items', [])[:limit]
            
        except requests.RequestException as e:
            print(f"Failed to fetch notifications: {e}")
            return []

    def process_order_webhook(self, order: Dict):
        """Complete order processing workflow"""
        try:
            # 1. Send order to Huginn
            order_sent = self.send_order(order)
            if not order_sent:
                return False
            
            # 2. Update inventory for each item
            inventory_updates = []
            for item in order['items']:
                updated = self.update_inventory(
                    item['sku'], 
                    -item['quantity'],  # Decrease inventory
                    'order_fulfillment'
                )
                inventory_updates.append(updated)
            
            # 3. Check if all inventory updates succeeded
            if not all(inventory_updates):
                print(f"Warning: Some inventory updates failed for order {order['id']}")
            
            return True
            
        except Exception as e:
            print(f"Order processing failed: {e}")
            return False

# Usage
huginn = EcommerceHuginnIntegration({
    'base_url': 'https://huginn.example.com',
    'user_id': 123,
    'order_webhook_agent_id': 456,
    'order_webhook_secret': 'order-processor-secret',
    'inventory_webhook_agent_id': 457,
    'inventory_webhook_secret': 'inventory-secret',
    'notification_data_agent_id': 789,
    'notification_data_secret': 'notification-secret'
})

# Process a new order
order = {
    'id': 'ORD-001',
    'customer': {
        'id': 'CUST-123',
        'email': 'customer@example.com'
    },
    'total': 299.99,
    'currency': 'USD',
    'items': [
        {'sku': 'PROD-001', 'quantity': 2, 'price': 149.99}
    ],
    'shipping': {
        'address': '123 Main St',
        'city': 'Example City'
    },
    'payment': {
        'method': 'credit_card'
    }
}

success = huginn.process_order_webhook(order)
print(f"Order processing {'succeeded' if success else 'failed'}")

# Check for notifications
notifications = huginn.get_notifications(10)
print(f"Found {len(notifications)} notifications")
```

### Social Media Monitoring

```ruby
require 'net/http'
require 'json'
require 'uri'

class SocialMediaMonitor
  def initialize(huginn_config)
    @config = huginn_config
    @base_url = huginn_config[:base_url].chomp('/')
    @user_id = huginn_config[:user_id]
  end

  def send_social_mention(platform, mention_data)
    agent_config = @config[:agents][platform.to_sym]
    return false unless agent_config

    webhook_url = "#{@base_url}/users/#{@user_id}/web_requests/#{agent_config[:webhook_id]}/#{agent_config[:secret]}"
    
    payload = {
      platform: platform,
      mention_id: mention_data[:id],
      author: mention_data[:author],
      content: mention_data[:text],
      url: mention_data[:url],
      engagement: {
        likes: mention_data[:likes] || 0,
        shares: mention_data[:shares] || 0,
        comments: mention_data[:comments] || 0
      },
      sentiment: analyze_sentiment(mention_data[:text]),
      hashtags: extract_hashtags(mention_data[:text]),
      mentions: extract_mentions(mention_data[:text]),
      timestamp: mention_data[:created_at] || Time.now.iso8601,
      source: 'social_monitor'
    }

    begin
      uri = URI.parse(webhook_url)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = uri.scheme == 'https'
      
      request = Net::HTTP::Post.new(uri)
      request['Content-Type'] = 'application/json'
      request['X-Platform'] = platform
      request.body = payload.to_json
      
      response = http.request(request)
      response.code.to_i == 201
      
    rescue => e
      puts "Failed to send #{platform} mention: #{e.message}"
      false
    end
  end

  def get_brand_mentions(limit: 20)
    feed_url = "#{@base_url}/users/#{@user_id}/web_requests/#{@config[:data_agent_id]}/#{@config[:data_secret]}.json"
    
    begin
      uri = URI.parse(feed_url)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = uri.scheme == 'https'
      
      response = http.get(uri)
      return [] unless response.code.to_i == 200
      
      data = JSON.parse(response.body)
      mentions = data['items'] || []
      
      # Filter and format mentions
      mentions.select { |m| m['mention_type'] == 'brand' }
              .first(limit)
              .map do |mention|
        {
          id: mention['mention_id'],
          platform: mention['platform'],
          author: mention['author'],
          content: mention['content'],
          sentiment: mention['sentiment'],
          engagement_score: calculate_engagement_score(mention),
          urgency: mention['urgency'] || 'low',
          timestamp: mention['timestamp']
        }
      end
      
    rescue => e
      puts "Failed to fetch brand mentions: #{e.message}"
      []
    end
  end

  def monitor_brand_health
    mentions = get_brand_mentions(limit: 100)
    
    return {} if mentions.empty?
    
    total = mentions.length
    positive = mentions.count { |m| m[:sentiment] == 'positive' }
    negative = mentions.count { |m| m[:sentiment] == 'negative' }
    neutral = mentions.count { |m| m[:sentiment] == 'neutral' }
    
    urgent_mentions = mentions.select { |m| m[:urgency] == 'high' }
    
    {
      total_mentions: total,
      sentiment_breakdown: {
        positive: (positive.to_f / total * 100).round(1),
        negative: (negative.to_f / total * 100).round(1),
        neutral: (neutral.to_f / total * 100).round(1)
      },
      urgent_mentions: urgent_mentions.length,
      engagement_average: mentions.map { |m| m[:engagement_score] }.sum / total,
      platforms: mentions.group_by { |m| m[:platform] }.transform_values(&:count),
      timestamp: Time.now.iso8601
    }
  end

  private

  def analyze_sentiment(text)
    # Simple sentiment analysis - replace with actual service
    positive_words = ['good', 'great', 'awesome', 'love', 'excellent']
    negative_words = ['bad', 'terrible', 'hate', 'awful', 'worst']
    
    text_lower = text.downcase
    positive_score = positive_words.count { |word| text_lower.include?(word) }
    negative_score = negative_words.count { |word| text_lower.include?(word) }
    
    if positive_score > negative_score
      'positive'
    elsif negative_score > positive_score
      'negative'
    else
      'neutral'
    end
  end

  def extract_hashtags(text)
    text.scan(/#\w+/).map(&:downcase)
  end

  def extract_mentions(text)
    text.scan(/@\w+/).map(&:downcase)
  end

  def calculate_engagement_score(mention)
    engagement = mention['engagement'] || {}
    likes = engagement['likes'] || 0
    shares = engagement['shares'] || 0
    comments = engagement['comments'] || 0
    
    # Weighted engagement score
    (likes * 1) + (shares * 3) + (comments * 2)
  end
end

# Usage
monitor = SocialMediaMonitor.new(
  base_url: 'https://huginn.example.com',
  user_id: 123,
  agents: {
    twitter: {
      webhook_id: 456,
      secret: 'twitter-mentions-secret'
    },
    facebook: {
      webhook_id: 457,
      secret: 'facebook-mentions-secret'
    },
    instagram: {
      webhook_id: 458,
      secret: 'instagram-mentions-secret'
    }
  },
  data_agent_id: 789,
  data_secret: 'brand-mentions-feed-secret'
)

# Send a Twitter mention
twitter_mention = {
  id: 'tweet-123456',
  author: '@customer',
  text: 'Just tried @YourBrand product and it\'s awesome! #satisfied #recommend',
  url: 'https://twitter.com/customer/status/123456',
  likes: 15,
  shares: 3,
  comments: 2,
  created_at: Time.now.iso8601
}

monitor.send_social_mention('twitter', twitter_mention)

# Get brand health report
health = monitor.monitor_brand_health
puts "Brand Health Report:"
puts "Total mentions: #{health[:total_mentions]}"
puts "Positive sentiment: #{health[:sentiment_breakdown][:positive]}%"
puts "Urgent mentions: #{health[:urgent_mentions]}"
```

## Error Handling & Best Practices

### Common HTTP Status Codes

| Code | Meaning | Cause | Solution |
|------|---------|-------|---------|
| `200` | Success | Request processed | Continue normal operation |
| `201` | Created | Webhook event created | Continue normal operation |
| `400` | Bad Request | Invalid payload format | Check JSON syntax and required fields |
| `401` | Unauthorized | Wrong secret | Verify secret token |
| `404` | Not Found | Invalid agent/user ID | Check URL parameters |
| `422` | Unprocessable | Validation failed | Review agent options and payload |
| `500` | Server Error | Internal Huginn error | Check Huginn logs, retry later |

### Retry Logic Implementation

```javascript
class HuginnClient {
  constructor(config) {
    this.config = config;
    this.maxRetries = config.maxRetries || 3;
    this.baseDelay = config.baseDelay || 1000;
  }

  async sendWithRetry(url, data, options = {}) {
    let lastError;
    
    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      try {
        const response = await this.makeRequest(url, data, options);
        return response;
      } catch (error) {
        lastError = error;
        
        // Don't retry on client errors (4xx)
        if (error.response?.status >= 400 && error.response?.status < 500) {
          throw error;
        }
        
        // Don't retry on last attempt
        if (attempt === this.maxRetries) {
          break;
        }
        
        // Exponential backoff with jitter
        const delay = this.baseDelay * Math.pow(2, attempt) + Math.random() * 1000;
        console.log(`Attempt ${attempt + 1} failed, retrying in ${delay}ms...`);
        await this.sleep(delay);
      }
    }
    
    throw new Error(`Request failed after ${this.maxRetries + 1} attempts: ${lastError.message}`);
  }

  async makeRequest(url, data, options) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), options.timeout || 10000);
    
    try {
      const response = await fetch(url, {
        method: options.method || 'POST',
        headers: {
          'Content-Type': 'application/json',
          'User-Agent': 'HuginnClient/1.0',
          ...options.headers
        },
        body: JSON.stringify(data),
        signal: controller.signal
      });
      
      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`HTTP ${response.status}: ${errorText}`);
      }
      
      return response;
    } finally {
      clearTimeout(timeout);
    }
  }

  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}
```

### Circuit Breaker Pattern

```python
import time
from enum import Enum
from typing import Callable, Any

class CircuitState(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"

class CircuitBreaker:
    def __init__(self, failure_threshold=5, recovery_timeout=60, expected_exception=Exception):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.expected_exception = expected_exception
        
        self.failure_count = 0
        self.last_failure_time = None
        self.state = CircuitState.CLOSED

    def call(self, func: Callable, *args, **kwargs) -> Any:
        if self.state == CircuitState.OPEN:
            if self._should_attempt_reset():
                self.state = CircuitState.HALF_OPEN
            else:
                raise Exception("Circuit breaker is OPEN")

        try:
            result = func(*args, **kwargs)
            self._on_success()
            return result
        except self.expected_exception as e:
            self._on_failure()
            raise e

    def _should_attempt_reset(self) -> bool:
        if self.last_failure_time is None:
            return False
        return (time.time() - self.last_failure_time) >= self.recovery_timeout

    def _on_success(self):
        self.failure_count = 0
        self.state = CircuitState.CLOSED

    def _on_failure(self):
        self.failure_count += 1
        self.last_failure_time = time.time()
        
        if self.failure_count >= self.failure_threshold:
            self.state = CircuitState.OPEN

# Usage
class HuginnClientWithCircuitBreaker:
    def __init__(self, base_url, circuit_breaker=None):
        self.base_url = base_url
        self.circuit_breaker = circuit_breaker or CircuitBreaker(
            failure_threshold=3,
            recovery_timeout=30
        )

    def send_webhook(self, url, data):
        def _send():
            response = requests.post(url, json=data, timeout=10)
            response.raise_for_status()
            return response

        return self.circuit_breaker.call(_send)
```

### Validation & Data Integrity

```javascript
const Joi = require('joi');

class HuginnWebhookValidator {
  constructor() {
    // Define schemas for different data types
    this.schemas = {
      sensorData: Joi.object({
        sensor_id: Joi.string().required(),
        timestamp: Joi.date().iso().required(),
        readings: Joi.object({
          temperature: Joi.number().min(-50).max(100),
          humidity: Joi.number().min(0).max(100),
          battery: Joi.number().min(0).max(100)
        }).required(),
        location: Joi.string().optional(),
        metadata: Joi.object().optional()
      }),

      orderData: Joi.object({
        order_id: Joi.string().required(),
        customer_id: Joi.string().required(),
        total_amount: Joi.number().positive().required(),
        currency: Joi.string().length(3).required(),
        items: Joi.array().items(
          Joi.object({
            sku: Joi.string().required(),
            quantity: Joi.number().integer().positive().required(),
            price: Joi.number().positive().required()
          })
        ).min(1).required()
      }),

      socialMention: Joi.object({
        platform: Joi.string().valid('twitter', 'facebook', 'instagram').required(),
        mention_id: Joi.string().required(),
        author: Joi.string().required(),
        content: Joi.string().max(2000).required(),
        url: Joi.string().uri().required(),
        timestamp: Joi.date().iso().required()
      })
    };
  }

  validate(dataType, payload) {
    const schema = this.schemas[dataType];
    if (!schema) {
      throw new Error(`Unknown data type: ${dataType}`);
    }

    const { error, value } = schema.validate(payload, {
      abortEarly: false,
      stripUnknown: true
    });

    if (error) {
      throw new Error(`Validation failed: ${error.details.map(d => d.message).join(', ')}`);
    }

    return value;
  }

  sanitize(payload) {
    // Remove potentially dangerous content
    const sanitized = JSON.parse(JSON.stringify(payload));
    
    const sanitizeValue = (obj) => {
      if (typeof obj === 'string') {
        // Remove script tags, clean up HTML
        return obj.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
                 .replace(/javascript:/gi, '')
                 .trim();
      } else if (Array.isArray(obj)) {
        return obj.map(sanitizeValue);
      } else if (obj && typeof obj === 'object') {
        const result = {};
        for (const [key, value] of Object.entries(obj)) {
          result[key] = sanitizeValue(value);
        }
        return result;
      }
      return obj;
    };

    return sanitizeValue(sanitized);
  }
}

// Usage
const validator = new HuginnWebhookValidator();

async function sendValidatedWebhook(dataType, payload, webhookUrl) {
  try {
    // 1. Sanitize input
    const sanitizedPayload = validator.sanitize(payload);
    
    // 2. Validate against schema
    const validatedPayload = validator.validate(dataType, sanitizedPayload);
    
    // 3. Send to Huginn
    const response = await axios.post(webhookUrl, validatedPayload, {
      timeout: 10000,
      headers: {
        'Content-Type': 'application/json',
        'X-Data-Type': dataType,
        'X-Validation': 'passed'
      }
    });
    
    console.log('Validated webhook sent successfully');
    return response.data;
    
  } catch (error) {
    console.error('Webhook validation/sending failed:', error.message);
    throw error;
  }
}
```

### Logging & Debugging

```python
import logging
import json
import time
from datetime import datetime

class HuginnIntegrationLogger:
    def __init__(self, log_level=logging.INFO):
        self.logger = logging.getLogger('huginn_integration')
        self.logger.setLevel(log_level)
        
        # Create handlers
        console_handler = logging.StreamHandler()
        file_handler = logging.FileHandler('huginn_integration.log')
        
        # Create formatters
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        console_handler.setFormatter(formatter)
        file_handler.setFormatter(formatter)
        
        # Add handlers
        self.logger.addHandler(console_handler)
        self.logger.addHandler(file_handler)

    def log_webhook_request(self, url, payload, response=None, error=None, duration=None):
        log_data = {
            'type': 'webhook_request',
            'timestamp': datetime.now().isoformat(),
            'url': url,
            'payload_size': len(json.dumps(payload)),
            'duration_ms': duration
        }
        
        if response:
            log_data.update({
                'status_code': response.status_code,
                'response_size': len(response.text) if response.text else 0
            })
            self.logger.info(f"Webhook successful: {json.dumps(log_data)}")
        
        if error:
            log_data.update({
                'error': str(error),
                'error_type': type(error).__name__
            })
            self.logger.error(f"Webhook failed: {json.dumps(log_data)}")

    def log_data_fetch(self, url, result_count=None, error=None, duration=None):
        log_data = {
            'type': 'data_fetch',
            'timestamp': datetime.now().isoformat(),
            'url': url,
            'duration_ms': duration
        }
        
        if result_count is not None:
            log_data['result_count'] = result_count
            self.logger.info(f"Data fetch successful: {json.dumps(log_data)}")
        
        if error:
            log_data.update({
                'error': str(error),
                'error_type': type(error).__name__
            })
            self.logger.error(f"Data fetch failed: {json.dumps(log_data)}")

# Usage decorator
def log_huginn_operation(logger):
    def decorator(func):
        def wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                duration = (time.time() - start_time) * 1000
                
                # Log based on function type
                if 'webhook' in func.__name__:
                    logger.log_webhook_request(
                        url=kwargs.get('url', 'unknown'),
                        payload=kwargs.get('payload', {}),
                        response=result,
                        duration=duration
                    )
                elif 'fetch' in func.__name__ or 'get' in func.__name__:
                    logger.log_data_fetch(
                        url=kwargs.get('url', 'unknown'),
                        result_count=len(result) if isinstance(result, list) else 1,
                        duration=duration
                    )
                
                return result
            except Exception as error:
                duration = (time.time() - start_time) * 1000
                
                if 'webhook' in func.__name__:
                    logger.log_webhook_request(
                        url=kwargs.get('url', 'unknown'),
                        payload=kwargs.get('payload', {}),
                        error=error,
                        duration=duration
                    )
                elif 'fetch' in func.__name__ or 'get' in func.__name__:
                    logger.log_data_fetch(
                        url=kwargs.get('url', 'unknown'),
                        error=error,
                        duration=duration
                    )
                
                raise
        return wrapper
    return decorator
```

## Rate Limiting & Performance

### Understanding Huginn Limits

Huginn itself doesn't impose hard rate limits, but you should consider:

1. **Server Resources**: CPU, memory, and disk I/O
2. **Database Performance**: Event storage and querying
3. **Background Job Processing**: DelayedJob queue capacity
4. **Network Bandwidth**: Especially for data feeds

### Client-Side Rate Limiting

```javascript
class RateLimitedHuginnClient {
  constructor(config) {
    this.config = config;
    this.requestQueue = [];
    this.requestCount = 0;
    this.windowStart = Date.now();
    
    // Default limits
    this.maxRequests = config.maxRequests || 60;  // per minute
    this.windowSize = config.windowSize || 60000; // 1 minute in ms
    this.concurrency = config.concurrency || 5;   // max concurrent requests
    this.activeRequests = 0;
  }

  async request(url, data, options = {}) {
    return new Promise((resolve, reject) => {
      this.requestQueue.push({
        url,
        data,
        options,
        resolve,
        reject,
        timestamp: Date.now()
      });
      
      this.processQueue();
    });
  }

  async processQueue() {
    // Clean up old requests from rate limit window
    const now = Date.now();
    if (now - this.windowStart >= this.windowSize) {
      this.requestCount = 0;
      this.windowStart = now;
    }

    // Process requests if we have capacity
    while (
      this.requestQueue.length > 0 &&
      this.activeRequests < this.concurrency &&
      this.requestCount < this.maxRequests
    ) {
      const request = this.requestQueue.shift();
      this.executeRequest(request);
    }

    // Schedule next processing if queue not empty
    if (this.requestQueue.length > 0) {
      setTimeout(() => this.processQueue(), 1000);
    }
  }

  async executeRequest(request) {
    this.activeRequests++;
    this.requestCount++;

    try {
      const response = await this.makeHttpRequest(
        request.url,
        request.data,
        request.options
      );
      request.resolve(response);
    } catch (error) {
      request.reject(error);
    } finally {
      this.activeRequests--;
      
      // Continue processing queue
      setTimeout(() => this.processQueue(), 100);
    }
  }

  async makeHttpRequest(url, data, options) {
    const response = await fetch(url, {
      method: options.method || 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...options.headers
      },
      body: JSON.stringify(data)
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    return response;
  }

  getQueueStatus() {
    return {
      queueLength: this.requestQueue.length,
      activeRequests: this.activeRequests,
      requestsInWindow: this.requestCount,
      windowTimeLeft: Math.max(0, this.windowSize - (Date.now() - this.windowStart))
    };
  }
}

// Usage
const client = new RateLimitedHuginnClient({
  maxRequests: 30,     // 30 requests per minute
  windowSize: 60000,   // 1 minute
  concurrency: 3       // max 3 concurrent requests
});

// Send multiple requests - they'll be rate limited automatically
const webhookUrl = 'https://huginn.example.com/users/123/web_requests/456/secret';

for (let i = 0; i < 100; i++) {
  client.request(webhookUrl, { 
    message: `Batch message ${i}`,
    timestamp: new Date().toISOString()
  }).then(response => {
    console.log(`Message ${i} sent successfully`);
  }).catch(error => {
    console.error(`Message ${i} failed:`, error.message);
  });
}

// Monitor queue status
setInterval(() => {
  const status = client.getQueueStatus();
  console.log('Queue status:', status);
}, 5000);
```

### Batch Processing

```python
import asyncio
import aiohttp
import json
from typing import List, Dict
from datetime import datetime

class BatchHuginnProcessor:
    def __init__(self, webhook_url: str, batch_size: int = 10, delay_between_batches: float = 1.0):
        self.webhook_url = webhook_url
        self.batch_size = batch_size
        self.delay_between_batches = delay_between_batches
        
    async def process_events_in_batches(self, events: List[Dict]) -> Dict:
        """Process events in batches to avoid overwhelming Huginn"""
        results = {
            'total': len(events),
            'successful': 0,
            'failed': 0,
            'errors': []
        }
        
        # Split events into batches
        batches = [events[i:i + self.batch_size] for i in range(0, len(events), self.batch_size)]
        
        async with aiohttp.ClientSession() as session:
            for batch_num, batch in enumerate(batches, 1):
                print(f"Processing batch {batch_num}/{len(batches)} ({len(batch)} events)")
                
                # Process batch concurrently
                tasks = [self.send_event(session, event) for event in batch]
                batch_results = await asyncio.gather(*tasks, return_exceptions=True)
                
                # Collect results
                for result in batch_results:
                    if isinstance(result, Exception):
                        results['failed'] += 1
                        results['errors'].append(str(result))
                    else:
                        results['successful'] += 1
                
                # Wait between batches
                if batch_num < len(batches):
                    await asyncio.sleep(self.delay_between_batches)
        
        return results
    
    async def send_event(self, session: aiohttp.ClientSession, event: Dict) -> Dict:
        """Send individual event"""
        try:
            async with session.post(
                self.webhook_url,
                json=event,
                headers={'Content-Type': 'application/json'},
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:
                response.raise_for_status()
                return await response.text()
        except Exception as e:
            raise Exception(f"Event {event.get('id', 'unknown')} failed: {e}")

# Usage
async def main():
    # Generate sample events
    events = []
    for i in range(100):
        events.append({
            'id': f'event_{i}',
            'timestamp': datetime.now().isoformat(),
            'data': f'Sample data {i}',
            'priority': 'normal'
        })
    
    processor = BatchHuginnProcessor(
        webhook_url='https://huginn.example.com/users/123/web_requests/456/secret',
        batch_size=5,  # Process 5 events at a time
        delay_between_batches=0.5  # Wait 500ms between batches
    )
    
    results = await processor.process_events_in_batches(events)
    
    print(f"Processing complete:")
    print(f"  Total: {results['total']}")
    print(f"  Successful: {results['successful']}")
    print(f"  Failed: {results['failed']}")
    
    if results['errors']:
        print(f"  Errors: {len(results['errors'])}")
        for error in results['errors'][:5]:  # Show first 5 errors
            print(f"    - {error}")

# Run the batch processor
# asyncio.run(main())
```

### Caching & Optimization

```javascript
const NodeCache = require('node-cache');

class CachedHuginnClient {
  constructor(config) {
    this.config = config;
    
    // Cache for data feeds (TTL in seconds)
    this.dataCache = new NodeCache({
      stdTTL: config.dataCacheTTL || 300,  // 5 minutes
      checkperiod: 60  // Check for expired keys every minute
    });
    
    // Cache for agent configurations
    this.configCache = new NodeCache({
      stdTTL: config.configCacheTTL || 3600,  // 1 hour
      checkperiod: 300  // Check every 5 minutes
    });
  }

  async getDataWithCache(feedUrl, options = {}) {
    const cacheKey = this.generateCacheKey(feedUrl, options);
    
    // Check cache first
    const cached = this.dataCache.get(cacheKey);
    if (cached && !options.bypassCache) {
      console.log('Returning cached data');
      return {
        data: cached,
        fromCache: true,
        timestamp: new Date().toISOString()
      };
    }

    // Fetch fresh data
    try {
      const response = await fetch(feedUrl, {
        timeout: 15000,
        headers: {
          'Accept': 'application/json',
          'User-Agent': 'CachedHuginnClient/1.0'
        }
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const data = await response.json();
      
      // Cache the response
      this.dataCache.set(cacheKey, data, options.cacheTTL);
      
      return {
        data,
        fromCache: false,
        timestamp: new Date().toISOString()
      };
      
    } catch (error) {
      // Return cached data if available, even if expired
      const expiredCache = this.dataCache.get(cacheKey);
      if (expiredCache) {
        console.warn('Using expired cache due to fetch error:', error.message);
        return {
          data: expiredCache,
          fromCache: true,
          expired: true,
          error: error.message,
          timestamp: new Date().toISOString()
        };
      }
      
      throw error;
    }
  }

  async sendWebhookWithDeduplication(webhookUrl, data, options = {}) {
    // Generate content-based hash for deduplication
    const contentHash = this.generateContentHash(data);
    const dedupeKey = `webhook_${contentHash}`;
    
    // Check if we've sent this exact content recently
    if (!options.allowDuplicates && this.configCache.has(dedupeKey)) {
      console.log('Duplicate webhook prevented');
      return {
        sent: false,
        reason: 'duplicate_content',
        originalTimestamp: this.configCache.get(dedupeKey)
      };
    }

    // Send webhook
    try {
      const response = await fetch(webhookUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Deduplication-Hash': contentHash
        },
        body: JSON.stringify(data)
      });

      if (response.ok) {
        // Record this content hash to prevent duplicates
        this.configCache.set(dedupeKey, new Date().toISOString(), 
                           options.dedupeTTL || 3600);
        
        return {
          sent: true,
          status: response.status,
          timestamp: new Date().toISOString()
        };
      } else {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      
    } catch (error) {
      console.error('Webhook send failed:', error.message);
      throw error;
    }
  }

  generateCacheKey(url, options) {
    const key = `${url}_${JSON.stringify(options)}`;
    return Buffer.from(key).toString('base64');
  }

  generateContentHash(data) {
    const crypto = require('crypto');
    return crypto.createHash('sha256')
                 .update(JSON.stringify(data))
                 .digest('hex')
                 .substring(0, 16);
  }

  getCacheStats() {
    return {
      dataCache: {
        keys: this.dataCache.keys().length,
        hits: this.dataCache.getStats().hits,
        misses: this.dataCache.getStats().misses
      },
      configCache: {
        keys: this.configCache.keys().length,
        hits: this.configCache.getStats().hits,
        misses: this.configCache.getStats().misses
      }
    };
  }

  clearCache(type = 'all') {
    if (type === 'all' || type === 'data') {
      this.dataCache.flushAll();
    }
    if (type === 'all' || type === 'config') {
      this.configCache.flushAll();
    }
  }
}

// Usage
const client = new CachedHuginnClient({
  dataCacheTTL: 300,    // Cache feed data for 5 minutes
  configCacheTTL: 3600  // Cache config data for 1 hour
});

// Cached data retrieval
const feedData = await client.getDataWithCache(
  'https://huginn.example.com/users/123/web_requests/789/secret.json',
  { cacheTTL: 180 }  // Custom cache time for this request
);

console.log(`Data retrieved (from cache: ${feedData.fromCache})`);

// Deduplicated webhook sending
const webhookResult = await client.sendWebhookWithDeduplication(
  'https://huginn.example.com/users/123/web_requests/456/secret',
  { message: 'Important alert', severity: 'high' },
  { allowDuplicates: false, dedupeTTL: 1800 }  // Prevent duplicates for 30 minutes
);

console.log(`Webhook sent: ${webhookResult.sent}`);

// Check cache performance
const stats = client.getCacheStats();
console.log('Cache stats:', stats);
```

## Troubleshooting

### Common Issues & Solutions

#### 1. "Not Authorized" (401 Error)
**Cause**: Incorrect secret token
**Solutions**:
- Verify the secret matches exactly (case-sensitive)
- Check URL path parameters (user_id, agent_id, secret)
- Ensure agent is configured to accept your HTTP method (verbs option)

```bash
# Test with curl to isolate the issue
curl -v -X POST \
  "https://huginn.example.com/users/123/web_requests/456/correct-secret" \
  -H "Content-Type: application/json" \
  -d '{"test": "data"}'
```

#### 2. "Agent not found" (404 Error)
**Cause**: Invalid agent ID or user ID
**Solutions**:
- Verify agent ID from Huginn web interface
- Check that agent exists and belongs to the specified user
- Ensure agent type supports web requests

#### 3. Empty or No Response from Data Feed
**Cause**: No events in agent or wrong URL format
**Solutions**:
- Check if source agents are creating events
- Verify DataOutputAgent has received events
- Test both .json and .xml endpoints
- Check events_to_show configuration

```javascript
// Debug data feed issues
async function debugDataFeed(feedUrl) {
  try {
    // Test JSON endpoint
    const jsonResponse = await fetch(feedUrl.replace('.xml', '.json'));
    const jsonData = await jsonResponse.json();
    
    console.log('JSON feed status:', jsonResponse.status);
    console.log('Items count:', jsonData.items?.length || 0);
    
    // Test XML endpoint
    const xmlResponse = await fetch(feedUrl.replace('.json', '.xml'));
    const xmlData = await xmlResponse.text();
    
    console.log('XML feed status:', xmlResponse.status);
    console.log('XML length:', xmlData.length);
    
  } catch (error) {
    console.error('Feed debug failed:', error.message);
  }
}
```

#### 4. Slow Response Times
**Cause**: Large datasets or server load
**Solutions**:
- Reduce events_to_show in DataOutputAgent
- Implement client-side caching
- Use pagination if available
- Check Huginn server resources

#### 5. Webhook Timeouts
**Cause**: Long processing time or server issues
**Solutions**:
- Increase client timeout values
- Implement retry logic with exponential backoff
- Check Huginn server logs
- Reduce payload size

### Debug Tools & Scripts

```python
import requests
import json
import time
from datetime import datetime

class HuginnDebugger:
    def __init__(self, base_url, user_id):
        self.base_url = base_url.rstrip('/')
        self.user_id = user_id

    def test_webhook_agent(self, agent_id, secret, test_payload=None):
        """Test webhook agent connectivity and response"""
        webhook_url = f"{self.base_url}/users/{self.user_id}/web_requests/{agent_id}/{secret}"
        
        if test_payload is None:
            test_payload = {
                "test": True,
                "timestamp": datetime.now().isoformat(),
                "debug_id": f"debug_{int(time.time())}"
            }
        
        print(f"Testing webhook: {webhook_url}")
        print(f"Payload: {json.dumps(test_payload, indent=2)}")
        
        try:
            start_time = time.time()
            response = requests.post(
                webhook_url,
                json=test_payload,
                headers={
                    'Content-Type': 'application/json',
                    'User-Agent': 'HuginnDebugger/1.0'
                },
                timeout=30
            )
            duration = time.time() - start_time
            
            print(f"\n✅ Success!")
            print(f"Status: {response.status_code}")
            print(f"Response: {response.text}")
            print(f"Duration: {duration:.3f}s")
            print(f"Headers: {dict(response.headers)}")
            
            return True
            
        except requests.exceptions.RequestException as e:
            print(f"\n❌ Failed!")
            print(f"Error: {e}")
            if hasattr(e, 'response') and e.response:
                print(f"Status: {e.response.status_code}")
                print(f"Response: {e.response.text}")
            return False

    def test_data_output_agent(self, agent_id, secret):
        """Test data output agent feeds"""
        base_url = f"{self.base_url}/users/{self.user_id}/web_requests/{agent_id}/{secret}"
        
        formats = ['json', 'xml']
        results = {}
        
        for format_type in formats:
            feed_url = f"{base_url}.{format_type}"
            print(f"\nTesting {format_type.upper()} feed: {feed_url}")
            
            try:
                start_time = time.time()
                response = requests.get(feed_url, timeout=30)
                duration = time.time() - start_time
                
                if response.ok:
                    if format_type == 'json':
                        data = response.json()
                        item_count = len(data.get('items', []))
                        print(f"✅ JSON feed working - {item_count} items")
                        results[format_type] = {'success': True, 'items': item_count}
                    else:
                        content_length = len(response.text)
                        print(f"✅ XML feed working - {content_length} characters")
                        results[format_type] = {'success': True, 'size': content_length}
                    
                    print(f"Duration: {duration:.3f}s")
                else:
                    print(f"❌ {format_type.upper()} feed failed: {response.status_code}")
                    print(f"Response: {response.text}")
                    results[format_type] = {'success': False, 'error': response.status_code}
                    
            except Exception as e:
                print(f"❌ {format_type.upper()} feed error: {e}")
                results[format_type] = {'success': False, 'error': str(e)}
        
        return results

    def test_connectivity(self):
        """Test basic connectivity to Huginn instance"""
        test_url = f"{self.base_url}/about"
        
        print(f"Testing connectivity to: {self.base_url}")
        
        try:
            response = requests.get(test_url, timeout=10)
            if response.ok:
                print("✅ Huginn instance is reachable")
                return True
            else:
                print(f"⚠️  Huginn responded with status: {response.status_code}")
                return False
        except Exception as e:
            print(f"❌ Cannot reach Huginn: {e}")
            return False

    def run_full_diagnostic(self, agents_config):
        """Run complete diagnostic suite"""
        print("🔍 Starting Huginn Integration Diagnostic\n")
        print("=" * 50)
        
        # Test connectivity
        print("\n1. Testing Connectivity")
        print("-" * 25)
        connectivity_ok = self.test_connectivity()
        
        if not connectivity_ok:
            print("❌ Basic connectivity failed. Check Huginn URL and network.")
            return
        
        # Test each agent
        for agent_name, config in agents_config.items():
            print(f"\n2. Testing {agent_name}")
            print("-" * (15 + len(agent_name)))
            
            if config['type'] == 'webhook':
                success = self.test_webhook_agent(
                    config['agent_id'], 
                    config['secret'],
                    config.get('test_payload')
                )
            elif config['type'] == 'data_output':
                results = self.test_data_output_agent(
                    config['agent_id'],
                    config['secret']
                )
                success = all(r['success'] for r in results.values())
            
            if success:
                print(f"✅ {agent_name} is working correctly")
            else:
                print(f"❌ {agent_name} has issues")
        
        print("\n" + "=" * 50)
        print("🏁 Diagnostic Complete")

# Usage
debugger = HuginnDebugger('https://huginn.example.com', 123)

# Test individual components
debugger.test_webhook_agent(456, 'webhook-secret')
debugger.test_data_output_agent(789, 'feed-secret')

# Run full diagnostic
agents_config = {
    'sensor_webhook': {
        'type': 'webhook',
        'agent_id': 456,
        'secret': 'sensor-data-secret',
        'test_payload': {'sensor_id': 'debug', 'temperature': 25.0}
    },
    'alerts_feed': {
        'type': 'data_output',
        'agent_id': 789,
        'secret': 'alerts-feed-secret'
    }
}

debugger.run_full_diagnostic(agents_config)
```

### Health Check Implementation

```javascript
class HuginnHealthChecker {
  constructor(endpoints) {
    this.endpoints = endpoints;
    this.healthHistory = [];
    this.maxHistorySize = 100;
  }

  async checkHealth() {
    const timestamp = new Date().toISOString();
    const results = {
      timestamp,
      overall: 'healthy',
      endpoints: {},
      summary: {
        total: 0,
        healthy: 0,
        degraded: 0,
        failed: 0
      }
    };

    for (const [name, config] of Object.entries(this.endpoints)) {
      results.endpoints[name] = await this.checkEndpoint(name, config);
      results.summary.total++;
      
      switch (results.endpoints[name].status) {
        case 'healthy':
          results.summary.healthy++;
          break;
        case 'degraded':
          results.summary.degraded++;
          break;
        case 'failed':
          results.summary.failed++;
          break;
      }
    }

    // Determine overall health
    if (results.summary.failed > 0) {
      results.overall = 'failed';
    } else if (results.summary.degraded > 0) {
      results.overall = 'degraded';
    }

    // Store in history
    this.healthHistory.push(results);
    if (this.healthHistory.length > this.maxHistorySize) {
      this.healthHistory.shift();
    }

    return results;
  }

  async checkEndpoint(name, config) {
    const start = Date.now();
    const result = {
      name,
      status: 'healthy',
      responseTime: null,
      error: null,
      details: {}
    };

    try {
      if (config.type === 'webhook') {
        await this.checkWebhook(config.url, config.testPayload);
      } else if (config.type === 'datafeed') {
        const data = await this.checkDataFeed(config.url);
        result.details.itemCount = data.items?.length || 0;
      }
      
      result.responseTime = Date.now() - start;
      
      // Classify based on response time
      if (result.responseTime > config.slowThreshold || 10000) {
        result.status = 'degraded';
        result.details.reason = 'slow_response';
      }
      
    } catch (error) {
      result.status = 'failed';
      result.error = error.message;
      result.responseTime = Date.now() - start;
    }

    return result;
  }

  async checkWebhook(url, testPayload = { health_check: true }) {
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(testPayload),
      timeout: 10000
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    return response;
  }

  async checkDataFeed(url) {
    const response = await fetch(url, { timeout: 15000 });
    
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    return await response.json();
  }

  getHealthTrend(periods = 10) {
    const recent = this.healthHistory.slice(-periods);
    if (recent.length === 0) return null;

    const trend = {
      avgResponseTime: 0,
      successRate: 0,
      incidents: []
    };

    let totalResponseTime = 0;
    let totalRequests = 0;
    let successfulRequests = 0;

    recent.forEach((check, index) => {
      Object.values(check.endpoints).forEach(endpoint => {
        totalRequests++;
        totalResponseTime += endpoint.responseTime || 0;
        
        if (endpoint.status === 'healthy') {
          successfulRequests++;
        } else {
          trend.incidents.push({
            timestamp: check.timestamp,
            endpoint: endpoint.name,
            status: endpoint.status,
            error: endpoint.error
          });
        }
      });
    });

    trend.avgResponseTime = Math.round(totalResponseTime / totalRequests);
    trend.successRate = Math.round((successfulRequests / totalRequests) * 100);

    return trend;
  }

  async startMonitoring(intervalMs = 60000, onHealthChange = null) {
    console.log('Starting health monitoring...');
    
    const monitor = async () => {
      try {
        const health = await this.checkHealth();
        console.log(`Health check: ${health.overall} (${health.summary.healthy}/${health.summary.total} healthy)`);
        
        if (onHealthChange) {
          onHealthChange(health);
        }
      } catch (error) {
        console.error('Health check failed:', error.message);
      }
    };

    // Initial check
    await monitor();

    // Schedule periodic checks
    return setInterval(monitor, intervalMs);
  }
}

// Usage
const healthChecker = new HuginnHealthChecker({
  sensorWebhook: {
    type: 'webhook',
    url: 'https://huginn.example.com/users/123/web_requests/456/secret',
    testPayload: { health_check: true, timestamp: new Date().toISOString() },
    slowThreshold: 5000
  },
  alertsFeed: {
    type: 'datafeed',
    url: 'https://huginn.example.com/users/123/web_requests/789/secret.json',
    slowThreshold: 8000
  },
  ordersFeed: {
    type: 'datafeed', 
    url: 'https://huginn.example.com/users/123/web_requests/790/secret.json',
    slowThreshold: 6000
  }
});

// Run single health check
const health = await healthChecker.checkHealth();
console.log('Current health:', health.overall);

// Get health trend
const trend = healthChecker.getHealthTrend(5);
if (trend) {
  console.log(`Success rate: ${trend.successRate}%, Avg response: ${trend.avgResponseTime}ms`);
}

// Start continuous monitoring
const monitorHandle = await healthChecker.startMonitoring(30000, (health) => {
  if (health.overall !== 'healthy') {
    console.warn('⚠️  System health degraded:', health.overall);
    // Send alert notifications
  }
});

// Stop monitoring later
// clearInterval(monitorHandle);
```

---

## Summary

This comprehensive guide covers all aspects of Huginn API integration:

- **WebhookAgent** for receiving external data
- **DataOutputAgent** for exposing Huginn data  
- **Authentication** using secret tokens
- **Real-world examples** in multiple languages
- **Error handling** and retry strategies
- **Performance optimization** and caching
- **Rate limiting** and batch processing
- **Monitoring and debugging** tools

### Key Takeaways:

1. **Security First**: Always use HTTPS and rotate secrets regularly
2. **Handle Errors Gracefully**: Implement retry logic and circuit breakers  
3. **Optimize Performance**: Use caching, batching, and rate limiting
4. **Monitor Health**: Implement comprehensive health checks
5. **Validate Data**: Sanitize and validate all inputs
6. **Debug Systematically**: Use structured logging and debugging tools

For additional support, consult the [Huginn Wiki](https://github.com/huginn/huginn/wiki) or the agent-specific documentation within your Huginn instance.