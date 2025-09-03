# Webhook Integration Examples

This document provides practical examples for integrating webhooks with Huginn agents.

## Table of Contents

1. [Basic Webhook Setup](#basic-webhook-setup)
2. [E-commerce Integration](#e-commerce-integration)
3. [GitHub Integration](#github-integration)
4. [Monitoring and Alerting](#monitoring-and-alerting)
5. [Social Media Integration](#social-media-integration)
6. [IoT Device Integration](#iot-device-integration)

## Basic Webhook Setup

### Creating a Simple WebhookAgent

First, create a WebhookAgent through the API:

```bash
curl -X POST https://your-huginn.com/agents \
  -H "Content-Type: application/json" \
  -H "Cookie: _huginn_session=your-session" \
  -d '{
    "name": "Basic Webhook Receiver",
    "type": "Agents::WebhookAgent",
    "options": {
      "secret": "my-unique-secret-123",
      "expected_receive_period_in_days": 1,
      "payload_path": ".",
      "verbs": "post,get",
      "response": "Received successfully",
      "code": "200",
      "response_headers": {
        "Access-Control-Allow-Origin": "*"
      }
    }
  }'
```

### Sending Data to the Webhook

```python
import requests
import json
from datetime import datetime

def send_to_huginn(data, user_id=1, agent_id=123, secret="my-unique-secret-123"):
    """Send data to Huginn webhook"""
    url = f"https://your-huginn.com/users/{user_id}/web_requests/{agent_id}/{secret}"
    
    payload = {
        "timestamp": datetime.now().isoformat(),
        "data": data
    }
    
    response = requests.post(
        url,
        json=payload,
        headers={'Content-Type': 'application/json'}
    )
    
    print(f"Status: {response.status_code}")
    print(f"Response: {response.text}")
    
    return response.ok

# Example usage
send_to_huginn({"event": "test", "value": 42})
```

## E-commerce Integration

### Shopify Order Webhook

```json
{
  "name": "Shopify Order Webhook",
  "type": "Agents::WebhookAgent",
  "options": {
    "secret": "shopify-orders-webhook-secret",
    "expected_receive_period_in_days": 1,
    "payload_path": ".",
    "verbs": "post",
    "response": "Order processed",
    "event_headers": "X-Shopify-Topic,X-Shopify-Shop-Domain,X-Shopify-Hmac-Sha256",
    "event_headers_key": "shopify_headers"
  }
}
```

Configure Shopify to send orders to:
```
https://your-huginn.com/users/1/web_requests/123/shopify-orders-webhook-secret
```

### Processing Shopify Order Data

```javascript
// Shopify webhook payload processing
function processShopifyOrder(webhookPayload) {
    const order = webhookPayload;
    
    const processedData = {
        order_id: order.id,
        customer_email: order.email,
        customer_name: `${order.billing_address.first_name} ${order.billing_address.last_name}`,
        total_price: order.total_price,
        currency: order.currency,
        line_items: order.line_items.map(item => ({
            name: item.name,
            quantity: item.quantity,
            price: item.price
        })),
        created_at: order.created_at,
        order_status: order.financial_status
    };
    
    // Send to Huginn for further processing
    sendToHuginn(processedData);
    
    return processedData;
}
```

### Stripe Payment Webhook

```json
{
  "name": "Stripe Payment Webhook",
  "type": "Agents::WebhookAgent", 
  "options": {
    "secret": "stripe-payment-webhook-secret",
    "expected_receive_period_in_days": 1,
    "payload_path": "data.object",
    "verbs": "post",
    "response": "Payment processed",
    "event_headers": "Stripe-Signature",
    "event_headers_key": "stripe_headers"
  }
}
```

## GitHub Integration

### GitHub Repository Events

```json
{
  "name": "GitHub Repository Webhook",
  "type": "Agents::WebhookAgent",
  "options": {
    "secret": "github-repo-webhook-secret",
    "expected_receive_period_in_days": 7,
    "payload_path": ".",
    "verbs": "post",
    "response": "Event processed",
    "event_headers": "X-GitHub-Event,X-GitHub-Delivery,X-Hub-Signature-256",
    "event_headers_key": "github_headers"
  }
}
```

### Processing GitHub Events

```python
def process_github_event(payload, headers):
    """Process GitHub webhook events"""
    event_type = headers.get('X-GitHub-Event', 'unknown')
    
    if event_type == 'push':
        return process_push_event(payload)
    elif event_type == 'pull_request':
        return process_pr_event(payload)
    elif event_type == 'issues':
        return process_issue_event(payload)
    else:
        return {"event_type": event_type, "action": payload.get('action', 'unknown')}

def process_push_event(payload):
    """Process git push events"""
    return {
        "event": "git_push",
        "repository": payload['repository']['full_name'],
        "branch": payload['ref'].replace('refs/heads/', ''),
        "commits": len(payload['commits']),
        "pusher": payload['pusher']['name'],
        "compare_url": payload['compare']
    }

def process_pr_event(payload):
    """Process pull request events"""
    pr = payload['pull_request']
    return {
        "event": "pull_request",
        "action": payload['action'],
        "repository": payload['repository']['full_name'],
        "pr_number": pr['number'],
        "title": pr['title'],
        "author": pr['user']['login'],
        "url": pr['html_url'],
        "base_branch": pr['base']['ref'],
        "head_branch": pr['head']['ref']
    }
```

### Configure GitHub Webhook

Set your webhook URL in GitHub repository settings:
```
Payload URL: https://your-huginn.com/users/1/web_requests/123/github-repo-webhook-secret
Content type: application/json
Events: Push, Pull requests, Issues
```

## Monitoring and Alerting

### Server Health Monitoring

```python
import psutil
import requests
import time

class ServerMonitor:
    def __init__(self, huginn_webhook_url):
        self.webhook_url = huginn_webhook_url
    
    def get_system_stats(self):
        """Get current system statistics"""
        return {
            "timestamp": time.time(),
            "cpu_percent": psutil.cpu_percent(interval=1),
            "memory_percent": psutil.virtual_memory().percent,
            "disk_percent": psutil.disk_usage('/').percent,
            "load_average": psutil.getloadavg()[0],
            "network_io": dict(psutil.net_io_counters()._asdict())
        }
    
    def send_alert(self, alert_type, message, severity="warning"):
        """Send alert to Huginn"""
        payload = {
            "alert_type": alert_type,
            "message": message,
            "severity": severity,
            "hostname": psutil.uname().node,
            "timestamp": time.time()
        }
        
        requests.post(self.webhook_url, json=payload)
    
    def monitor(self):
        """Continuous monitoring loop"""
        while True:
            stats = self.get_system_stats()
            
            # Check thresholds
            if stats["cpu_percent"] > 80:
                self.send_alert("cpu_high", f"CPU usage: {stats['cpu_percent']}%", "warning")
            
            if stats["memory_percent"] > 85:
                self.send_alert("memory_high", f"Memory usage: {stats['memory_percent']}%", "critical")
            
            if stats["disk_percent"] > 90:
                self.send_alert("disk_full", f"Disk usage: {stats['disk_percent']}%", "critical")
            
            # Send regular stats
            requests.post(self.webhook_url, json=stats)
            
            time.sleep(60)  # Check every minute

# Usage
monitor = ServerMonitor("https://your-huginn.com/users/1/web_requests/456/server-monitor-secret")
monitor.monitor()
```

### Application Performance Monitoring

```javascript
// Express.js middleware for APM
const express = require('express');
const app = express();

class APMReporter {
    constructor(webhookUrl) {
        this.webhookUrl = webhookUrl;
        this.metrics = {
            requests: 0,
            errors: 0,
            response_times: []
        };
    }

    middleware() {
        return (req, res, next) => {
            const start = Date.now();
            
            res.on('finish', () => {
                const duration = Date.now() - start;
                this.recordRequest(req, res, duration);
            });
            
            next();
        };
    }

    recordRequest(req, res, duration) {
        this.metrics.requests++;
        this.metrics.response_times.push(duration);
        
        if (res.statusCode >= 400) {
            this.metrics.errors++;
        }
        
        // Send alert for slow requests
        if (duration > 5000) {  // 5 seconds
            this.sendAlert({
                type: 'slow_request',
                url: req.url,
                method: req.method,
                duration: duration,
                status_code: res.statusCode
            });
        }
        
        // Keep only last 100 response times
        if (this.metrics.response_times.length > 100) {
            this.metrics.response_times = this.metrics.response_times.slice(-100);
        }
    }

    async sendAlert(data) {
        try {
            await fetch(this.webhookUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            });
        } catch (error) {
            console.error('Failed to send APM alert:', error);
        }
    }

    startPeriodicReporting(intervalMinutes = 5) {
        setInterval(() => {
            this.sendMetricsSummary();
        }, intervalMinutes * 60 * 1000);
    }

    sendMetricsSummary() {
        const avgResponseTime = this.metrics.response_times.reduce((a, b) => a + b, 0) 
                               / this.metrics.response_times.length;
        
        const summary = {
            timestamp: new Date().toISOString(),
            total_requests: this.metrics.requests,
            total_errors: this.metrics.errors,
            error_rate: (this.metrics.errors / this.metrics.requests) * 100,
            avg_response_time: avgResponseTime,
            max_response_time: Math.max(...this.metrics.response_times),
            min_response_time: Math.min(...this.metrics.response_times)
        };
        
        this.sendAlert(summary);
        
        // Reset counters
        this.metrics = { requests: 0, errors: 0, response_times: [] };
    }
}

// Usage
const apm = new APMReporter('https://your-huginn.com/users/1/web_requests/789/apm-webhook-secret');
app.use(apm.middleware());
apm.startPeriodicReporting(5);
```

## Social Media Integration

### Twitter/X Mention Tracking

```json
{
  "name": "Social Media Webhook",
  "type": "Agents::WebhookAgent",
  "options": {
    "secret": "social-media-webhook-secret",
    "expected_receive_period_in_days": 1,
    "payload_path": ".",
    "verbs": "post",
    "response": "Mention tracked"
  }
}
```

```python
# Using tweepy or similar library to monitor mentions
import tweepy
import requests

class TwitterMentionTracker:
    def __init__(self, api_keys, huginn_webhook_url):
        self.api = tweepy.Client(bearer_token=api_keys['bearer_token'])
        self.webhook_url = huginn_webhook_url
    
    def process_mention(self, tweet):
        """Process a mention and send to Huginn"""
        mention_data = {
            "platform": "twitter",
            "type": "mention",
            "tweet_id": tweet.id,
            "author": tweet.author.username,
            "text": tweet.text,
            "created_at": tweet.created_at.isoformat(),
            "url": f"https://twitter.com/user/status/{tweet.id}",
            "metrics": {
                "retweet_count": tweet.public_metrics.retweet_count,
                "like_count": tweet.public_metrics.like_count,
                "reply_count": tweet.public_metrics.reply_count
            }
        }
        
        requests.post(self.webhook_url, json=mention_data)
        return mention_data

# Usage
tracker = TwitterMentionTracker(api_keys, webhook_url)
# Set up streaming or polling to detect mentions
```

### Instagram Webhook (Business API)

```json
{
  "name": "Instagram Webhook",
  "type": "Agents::WebhookAgent",
  "options": {
    "secret": "instagram-webhook-secret",
    "expected_receive_period_in_days": 1,
    "payload_path": ".",
    "verbs": "post,get",
    "response": "Instagram event processed"
  }
}
```

## IoT Device Integration

### Sensor Data Collection

```python
import random
import time
import requests
from datetime import datetime

class IoTSensorSimulator:
    def __init__(self, device_id, webhook_url):
        self.device_id = device_id
        self.webhook_url = webhook_url
    
    def generate_sensor_data(self):
        """Simulate IoT sensor readings"""
        return {
            "device_id": self.device_id,
            "timestamp": datetime.now().isoformat(),
            "sensors": {
                "temperature": round(random.uniform(15.0, 35.0), 2),
                "humidity": round(random.uniform(30.0, 80.0), 2),
                "pressure": round(random.uniform(990.0, 1030.0), 2),
                "light": round(random.uniform(0, 1000), 0),
                "motion_detected": random.choice([True, False])
            },
            "battery_level": round(random.uniform(20.0, 100.0), 1),
            "signal_strength": random.randint(-90, -30)
        }
    
    def send_data(self):
        """Send sensor data to Huginn"""
        data = self.generate_sensor_data()
        
        try:
            response = requests.post(
                self.webhook_url,
                json=data,
                timeout=10
            )
            
            if response.ok:
                print(f"Data sent successfully: {data['sensors']['temperature']}°C")
            else:
                print(f"Failed to send data: {response.status_code}")
                
        except Exception as e:
            print(f"Error sending data: {e}")
    
    def run_continuous(self, interval_seconds=60):
        """Run continuous data collection"""
        print(f"Starting IoT device {self.device_id}")
        
        while True:
            self.send_data()
            time.sleep(interval_seconds)

# Usage
device = IoTSensorSimulator(
    "sensor-001", 
    "https://your-huginn.com/users/1/web_requests/999/iot-sensor-secret"
)
device.run_continuous(interval_seconds=30)
```

### Smart Home Device Integration

```javascript
// Home Assistant integration
class HomeAssistantIntegration {
    constructor(hassUrl, accessToken, huginnWebhookUrl) {
        this.hassUrl = hassUrl;
        this.accessToken = accessToken;
        this.huginnWebhookUrl = huginnWebhookUrl;
    }

    async getDeviceStates() {
        const response = await fetch(`${this.hassUrl}/api/states`, {
            headers: {
                'Authorization': `Bearer ${this.accessToken}`
            }
        });
        
        return response.json();
    }

    async monitorDeviceChanges() {
        const states = await this.getDeviceStates();
        
        const importantDevices = states.filter(state => 
            state.entity_id.includes('door') ||
            state.entity_id.includes('window') ||
            state.entity_id.includes('motion') ||
            state.entity_id.includes('temperature')
        );

        for (const device of importantDevices) {
            await this.sendDeviceUpdate(device);
        }
    }

    async sendDeviceUpdate(device) {
        const updateData = {
            source: 'home_assistant',
            entity_id: device.entity_id,
            friendly_name: device.attributes.friendly_name,
            state: device.state,
            last_changed: device.last_changed,
            attributes: device.attributes
        };

        try {
            await fetch(this.huginnWebhookUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(updateData)
            });
        } catch (error) {
            console.error(`Failed to send update for ${device.entity_id}:`, error);
        }
    }
}

// Usage
const homeAssistant = new HomeAssistantIntegration(
    'http://your-hass:8123',
    'your-access-token',
    'https://your-huginn.com/users/1/web_requests/888/smart-home-secret'
);

// Monitor every 5 minutes
setInterval(() => {
    homeAssistant.monitorDeviceChanges();
}, 5 * 60 * 1000);
```

### Weather Station Integration

```python
import requests
import json
from datetime import datetime

class WeatherStationIntegration:
    def __init__(self, station_api_url, huginn_webhook_url):
        self.station_api_url = station_api_url
        self.huginn_webhook_url = huginn_webhook_url
    
    def fetch_weather_data(self):
        """Fetch data from weather station API"""
        try:
            response = requests.get(self.station_api_url)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"Error fetching weather data: {e}")
            return None
    
    def process_weather_data(self, raw_data):
        """Process and normalize weather station data"""
        return {
            "source": "weather_station",
            "timestamp": datetime.now().isoformat(),
            "location": raw_data.get('location', 'Unknown'),
            "weather": {
                "temperature": raw_data.get('temperature'),
                "humidity": raw_data.get('humidity'),
                "pressure": raw_data.get('pressure'),
                "wind_speed": raw_data.get('wind_speed'),
                "wind_direction": raw_data.get('wind_direction'),
                "precipitation": raw_data.get('precipitation', 0),
                "uv_index": raw_data.get('uv_index'),
                "visibility": raw_data.get('visibility')
            },
            "air_quality": {
                "aqi": raw_data.get('aqi'),
                "pm25": raw_data.get('pm25'),
                "pm10": raw_data.get('pm10')
            }
        }
    
    def send_to_huginn(self, processed_data):
        """Send processed weather data to Huginn"""
        try:
            response = requests.post(
                self.huginn_webhook_url,
                json=processed_data,
                headers={'Content-Type': 'application/json'}
            )
            
            if response.ok:
                print(f"Weather data sent: {processed_data['weather']['temperature']}°C")
            else:
                print(f"Failed to send weather data: {response.status_code}")
                
        except Exception as e:
            print(f"Error sending to Huginn: {e}")
    
    def run_collection(self):
        """Main data collection loop"""
        raw_data = self.fetch_weather_data()
        
        if raw_data:
            processed_data = self.process_weather_data(raw_data)
            self.send_to_huginn(processed_data)

# Usage
weather_station = WeatherStationIntegration(
    'https://your-weather-station/api/current',
    'https://your-huginn.com/users/1/web_requests/777/weather-webhook-secret'
)

# Run every 15 minutes
import schedule
schedule.every(15).minutes.do(weather_station.run_collection)

while True:
    schedule.run_pending()
    time.sleep(1)
```

These examples demonstrate various real-world webhook integration patterns with Huginn, from simple data collection to complex IoT and monitoring scenarios. Each example includes error handling and can be adapted for specific use cases.