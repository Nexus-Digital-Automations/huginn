# Huginn API Examples & Integration Guide

This guide provides practical examples and integration patterns for working with the Huginn API.

## Table of Contents

- [Authentication Examples](#authentication-examples)
- [Agent Management Examples](#agent-management-examples)
- [Webhook Integration Examples](#webhook-integration-examples)
- [Data Output Examples](#data-output-examples)
- [Complex Workflow Examples](#complex-workflow-examples)
- [Error Handling Patterns](#error-handling-patterns)
- [Security Best Practices](#security-best-practices)

## Authentication Examples

### Login and Session Management

```javascript
// JavaScript example - Login
async function loginToHuginn(username, password) {
  const response = await fetch('/users/sign_in', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'X-Requested-With': 'XMLHttpRequest'
    },
    body: new URLSearchParams({
      'user[login]': username,
      'user[password]': password
    }),
    credentials: 'include' // Important: include cookies
  });
  
  if (response.ok) {
    console.log('Login successful');
    return true;
  } else {
    console.error('Login failed');
    return false;
  }
}

// Make authenticated API calls
async function getAgents() {
  const response = await fetch('/agents.json', {
    credentials: 'include' // Include session cookies
  });
  
  if (response.ok) {
    return await response.json();
  } else {
    throw new Error('Failed to fetch agents');
  }
}
```

```python
# Python example using requests
import requests

class HuginnClient:
    def __init__(self, base_url):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        
    def login(self, username, password):
        # Get CSRF token first
        login_page = self.session.get(f'{self.base_url}/users/sign_in')
        
        # Extract CSRF token from login form
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(login_page.content, 'html.parser')
        csrf_token = soup.find('input', {'name': 'authenticity_token'})['value']
        
        # Perform login
        response = self.session.post(f'{self.base_url}/users/sign_in', {
            'user[login]': username,
            'user[password]': password,
            'authenticity_token': csrf_token
        })
        
        return response.status_code == 200
        
    def get_agents(self):
        response = self.session.get(f'{self.base_url}/agents.json')
        response.raise_for_status()
        return response.json()
```

## Agent Management Examples

### Creating Different Agent Types

```javascript
// Create a WebhookAgent
async function createWebhookAgent() {
  const agentData = {
    agent: {
      name: "GitHub Webhook Receiver",
      type: "Agents::WebhookAgent",
      options: {
        secret: "github-webhook-secret-123",
        expected_receive_period_in_days: 1,
        payload_path: ".",
        event_headers: "X-GitHub-Event,X-GitHub-Delivery",
        event_headers_key: "headers",
        verbs: "post",
        response: "Webhook received successfully",
        code: "200"
      },
      schedule: "never"
    }
  };
  
  const response = await fetch('/agents', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    credentials: 'include',
    body: JSON.stringify(agentData)
  });
  
  if (response.ok) {
    const agent = await response.json();
    console.log(`Created agent with ID: ${agent.id}`);
    return agent;
  } else {
    const error = await response.json();
    console.error('Failed to create agent:', error);
    throw new Error('Agent creation failed');
  }
}

// Create a Website Scraper Agent
async function createWebsiteAgent() {
  const agentData = {
    agent: {
      name: "News Scraper",
      type: "Agents::WebsiteAgent",
      options: {
        url: "https://example-news.com/rss",
        type: "xml",
        mode: "on_change",
        extract: {
          title: {
            xpath: "//item/title",
            value: "./text()"
          },
          url: {
            xpath: "//item/link",
            value: "./text()"
          },
          description: {
            xpath: "//item/description",
            value: "./text()"
          }
        }
      },
      schedule: "every_1h",
      keep_events_for: 604800 // 7 days
    }
  };
  
  return await createAgent(agentData);
}

// Create Data Output Agent for RSS feed
async function createRSSFeedAgent(sourceAgentIds) {
  const agentData = {
    agent: {
      name: "News RSS Feed",
      type: "Agents::DataOutputAgent", 
      options: {
        secrets: ["public-feed-secret"],
        expected_receive_period_in_days: 2,
        template: {
          title: "My Curated News Feed",
          description: "Latest news items collected by Huginn",
          item: {
            title: "{{title}}",
            description: "{{description}}",
            link: "{{url}}",
            pubDate: "{{date_published}}"
          }
        },
        events_to_show: 20,
        ns_media: "true"
      },
      source_ids: sourceAgentIds
    }
  };
  
  return await createAgent(agentData);
}
```

### Agent Connections and Workflows

```javascript
// Connect agents in a workflow
async function createNewsWorkflow() {
  try {
    // 1. Create scraper agent
    const scraper = await createWebsiteAgent();
    
    // 2. Create filter agent to process scraped data
    const filter = await createAgent({
      agent: {
        name: "News Filter",
        type: "Agents::EventFormattingAgent",
        options: {
          instructions: {
            title: "{{title | strip_tags | truncate: 100}}",
            clean_description: "{{description | strip_tags | truncate: 500}}",
            published: "{{date_published}}",
            source_url: "{{url}}"
          },
          mode: "clean"
        },
        source_ids: [scraper.id]
      }
    });
    
    // 3. Create output feed
    const feed = await createRSSFeedAgent([filter.id]);
    
    // 4. Create scenario to group them
    const scenario = await createScenario({
      name: "News Aggregation Workflow",
      description: "Scrapes news, processes, and outputs RSS feed",
      agent_ids: [scraper.id, filter.id, feed.id]
    });
    
    console.log(`Created workflow with ${scenario.agent_ids.length} agents`);
    return scenario;
    
  } catch (error) {
    console.error('Failed to create workflow:', error);
  }
}
```

## Webhook Integration Examples

### GitHub Integration

```javascript
// GitHub webhook handler setup
async function setupGitHubIntegration() {
  // 1. Create webhook receiver
  const webhookAgent = await createAgent({
    agent: {
      name: "GitHub Events",
      type: "Agents::WebhookAgent",
      options: {
        secret: "github-secret-123",
        payload_path: ".",
        event_headers: "X-GitHub-Event",
        verbs: "post"
      }
    }
  });
  
  // 2. Create event processor
  const processor = await createAgent({
    agent: {
      name: "GitHub Event Processor", 
      type: "Agents::JavaScriptAgent",
      options: {
        code: `
          Agent.receive = function() {
            var events = this.incomingEvents();
            
            for (var i = 0; i < events.length; i++) {
              var event = events[i];
              var payload = event.payload;
              
              // Process different GitHub event types
              if (event.payload.headers && event.payload.headers['X-GitHub-Event']) {
                var eventType = event.payload.headers['X-GitHub-Event'];
                
                switch(eventType) {
                  case 'push':
                    this.createEvent({
                      type: 'git_push',
                      repository: payload.repository.name,
                      branch: payload.ref.replace('refs/heads/', ''),
                      commits: payload.commits.length,
                      author: payload.pusher.name
                    });
                    break;
                    
                  case 'pull_request':
                    this.createEvent({
                      type: 'pull_request',
                      action: payload.action,
                      repository: payload.repository.name,
                      title: payload.pull_request.title,
                      author: payload.pull_request.user.login
                    });
                    break;
                }
              }
            }
          };
        `
      },
      source_ids: [webhookAgent.id]
    }
  });
  
  console.log(`GitHub webhook URL: /users/{user_id}/web_requests/${webhookAgent.id}/github-secret-123`);
  return { webhookAgent, processor };
}
```

### Slack Integration

```python
# Python example for Slack webhook integration
def setup_slack_integration(huginn_client):
    # Create Slack webhook receiver
    slack_webhook = huginn_client.create_agent({
        "agent": {
            "name": "Slack Notifications",
            "type": "Agents::WebhookAgent",
            "options": {
                "secret": "slack-webhook-secret",
                "payload_path": ".",
                "verbs": "post",
                "response": "Message processed"
            }
        }
    })
    
    # Create Slack message sender
    slack_sender = huginn_client.create_agent({
        "agent": {
            "name": "Slack Sender", 
            "type": "Agents::SlackAgent",
            "options": {
                "webhook_url": "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK",
                "channel": "#general",
                "username": "Huginn Bot",
                "message": "Alert: {{message}}",
                "icon": ":warning:"
            },
            "source_ids": [slack_webhook["id"]]
        }
    })
    
    return slack_webhook, slack_sender

# Send test message to Slack
def send_slack_message(webhook_url):
    import requests
    
    payload = {
        "message": "Test alert from Huginn!",
        "priority": "high",
        "timestamp": "2023-01-01T12:00:00Z"
    }
    
    response = requests.post(webhook_url, json=payload)
    return response.status_code == 200
```

## Data Output Examples

### RSS Feed Creation

```javascript
// Create comprehensive RSS feed with multiple sources
async function createAdvancedRSSFeed(sourceAgentIds) {
  const feedAgent = await createAgent({
    agent: {
      name: "Multi-Source RSS Feed",
      type: "Agents::DataOutputAgent",
      options: {
        secrets: ["rss-feed-key-123"],
        expected_receive_period_in_days: 1,
        template: {
          title: "Aggregated Content Feed",
          description: "Combined content from multiple sources",
          link: "https://my-domain.com",
          self: "https://my-domain.com/feeds/aggregated.xml",
          icon: "https://my-domain.com/favicon.ico",
          item: {
            title: "{{title}}",
            description: "{{description | truncate: 500}}",
            link: "{{url}}",
            pubDate: "{{created_at}}",
            guid: {
              "_attributes": {"isPermaLink": "false"},
              "_contents": "{{id}}"
            },
            enclosure: {
              "_attributes": {
                "url": "{{media_url}}",
                "type": "{{media_type}}",
                "length": "{{media_size}}"
              }
            }
          }
        },
        events_to_show: 50,
        ttl: 60,
        ns_media: "true",
        ns_itunes: "true",
        response_headers: {
          "Access-Control-Allow-Origin": "*",
          "Cache-Control": "public, max-age=3600"
        }
      },
      source_ids: sourceAgentIds
    }
  });
  
  const feedUrl = `/users/{user_id}/web_requests/${feedAgent.id}/rss-feed-key-123.xml`;
  console.log(`RSS feed available at: ${feedUrl}`);
  return feedAgent;
}

// JSON API endpoint creation
async function createJSONAPI(sourceAgentIds) {
  const apiAgent = await createAgent({
    agent: {
      name: "JSON API Endpoint",
      type: "Agents::DataOutputAgent",
      options: {
        secrets: ["json-api-key-456"],
        template: {
          title: "API Data",
          description: "JSON API for mobile app",
          item: {
            id: "{{id}}",
            title: "{{title}}",
            content: "{{description}}",
            url: "{{url}}",
            image: "{{image_url}}",
            published_at: "{{created_at}}",
            tags: "{{tags | split: ',' | json}}"
          }
        },
        events_to_show: 100,
        response_headers: {
          "Access-Control-Allow-Origin": "*",
          "Content-Type": "application/json"
        }
      },
      source_ids: sourceAgentIds
    }
  });
  
  const apiUrl = `/users/{user_id}/web_requests/${apiAgent.id}/json-api-key-456.json`;
  console.log(`JSON API available at: ${apiUrl}`);
  return apiAgent;
}
```

## Complex Workflow Examples

### E-commerce Price Monitoring

```javascript
async function createPriceMonitoringWorkflow() {
  // 1. Website scrapers for different stores
  const amazonScraper = await createAgent({
    agent: {
      name: "Amazon Price Scraper",
      type: "Agents::WebsiteAgent",
      options: {
        url: "https://www.amazon.com/dp/PRODUCT_ID",
        type: "html",
        mode: "on_change",
        extract: {
          price: {
            css: ".a-price-whole",
            value: "normalize-space(.)"
          },
          availability: {
            css: "#availability span", 
            value: "normalize-space(.)"
          },
          title: {
            css: "#productTitle",
            value: "normalize-space(.)"
          }
        },
        headers: {
          "User-Agent": "Mozilla/5.0 (compatible; price-monitor)"
        }
      },
      schedule: "every_1h"
    }
  });
  
  // 2. Price change detector
  const priceDetector = await createAgent({
    agent: {
      name: "Price Change Detector",
      type: "Agents::ChangeDetectorAgent", 
      options: {
        property: "price",
        expected_receive_period_in_days: 1
      },
      source_ids: [amazonScraper.id]
    }
  });
  
  // 3. Price alert formatter
  const alertFormatter = await createAgent({
    agent: {
      name: "Price Alert Formatter",
      type: "Agents::EventFormattingAgent",
      options: {
        instructions: {
          alert_type: "price_change",
          product: "{{title}}",
          old_price: "${{last_price}}",
          new_price: "${{price}}",
          savings: "{{last_price | minus: price | prepend: '$'}}",
          url: "https://www.amazon.com/dp/PRODUCT_ID",
          timestamp: "{{created_at}}"
        }
      },
      source_ids: [priceDetector.id]
    }
  });
  
  // 4. Email notifications
  const emailAlert = await createAgent({
    agent: {
      name: "Price Alert Email",
      type: "Agents::EmailAgent",
      options: {
        recipients: ["user@example.com"],
        subject: "Price Alert: {{product}}",
        body: `
          Good news! The price for {{product}} has changed:
          
          Old Price: {{old_price}}
          New Price: {{new_price}}
          You save: {{savings}}
          
          View product: {{url}}
          
          Alert generated at: {{timestamp}}
        `,
        content_type: "text/plain"
      },
      source_ids: [alertFormatter.id]
    }
  });
  
  // 5. Create scenario
  const scenario = await createScenario({
    name: "Price Monitoring System",
    description: "Monitors product prices and sends alerts",
    agent_ids: [amazonScraper.id, priceDetector.id, alertFormatter.id, emailAlert.id]
  });
  
  return scenario;
}
```

### Social Media Monitoring

```javascript
async function createSocialMediaMonitoring() {
  // 1. Twitter search
  const twitterSearch = await createAgent({
    agent: {
      name: "Twitter Brand Mentions",
      type: "Agents::TwitterSearchAgent",
      options: {
        search: "YourBrand OR @yourbrand -RT",
        result_type: "recent",
        count: 100,
        expected_receive_period_in_days: 1
      },
      schedule: "every_10m"
    }
  });
  
  // 2. Sentiment analysis
  const sentimentAnalyzer = await createAgent({
    agent: {
      name: "Tweet Sentiment Analyzer",
      type: "Agents::SentimentAgent",
      options: {
        content: "{{text}}",
        expected_receive_period_in_days: 1
      },
      source_ids: [twitterSearch.id]
    }
  });
  
  // 3. Negative sentiment filter
  const negativeFilter = await createAgent({
    agent: {
      name: "Negative Sentiment Filter", 
      type: "Agents::TriggerAgent",
      options: {
        rules: [{
          type: "field<value",
          path: "sentiment_score",
          value: 0.3
        }],
        message: "Negative mention detected"
      },
      source_ids: [sentimentAnalyzer.id]
    }
  });
  
  // 4. Slack notification for negative mentions
  const slackAlert = await createAgent({
    agent: {
      name: "Negative Mention Alert",
      type: "Agents::SlackAgent",
      options: {
        webhook_url: "YOUR_SLACK_WEBHOOK_URL",
        channel: "#social-monitoring",
        username: "Social Monitor",
        message: `
          🚨 Negative Brand Mention Detected
          
          User: {{user.name}} (@{{user.screen_name}})
          Tweet: {{text}}
          Sentiment Score: {{sentiment_score}}
          URL: {{url}}
          
          Please review and respond if necessary.
        `,
        icon: ":warning:"
      },
      source_ids: [negativeFilter.id]
    }
  });
  
  return {
    twitter: twitterSearch.id,
    sentiment: sentimentAnalyzer.id,
    filter: negativeFilter.id,
    alert: slackAlert.id
  };
}
```

## Error Handling Patterns

### Robust API Client

```javascript
class HuginnAPIClient {
  constructor(baseURL) {
    this.baseURL = baseURL;
  }
  
  async makeRequest(path, options = {}) {
    const url = `${this.baseURL}${path}`;
    const defaultOptions = {
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest'
      }
    };
    
    const mergedOptions = { ...defaultOptions, ...options };
    
    try {
      const response = await fetch(url, mergedOptions);
      
      if (!response.ok) {
        await this.handleErrorResponse(response);
      }
      
      const contentType = response.headers.get('content-type');
      if (contentType && contentType.includes('application/json')) {
        return await response.json();
      } else {
        return await response.text();
      }
    } catch (error) {
      console.error(`API request failed: ${error.message}`);
      throw error;
    }
  }
  
  async handleErrorResponse(response) {
    const contentType = response.headers.get('content-type');
    let errorData;
    
    if (contentType && contentType.includes('application/json')) {
      errorData = await response.json();
    } else {
      errorData = { message: await response.text() };
    }
    
    switch (response.status) {
      case 401:
        throw new Error('Authentication required. Please log in.');
      case 403:
        throw new Error('Access denied. Check permissions or secret tokens.');
      case 404:
        throw new Error('Resource not found.');
      case 422:
        const errors = errorData.errors || {};
        const errorMessages = Object.entries(errors).map(
          ([field, messages]) => `${field}: ${messages.join(', ')}`
        ).join('; ');
        throw new Error(`Validation failed: ${errorMessages}`);
      case 423:
        throw new Error('Resource is temporarily locked. Try again later.');
      default:
        throw new Error(`Request failed: ${response.status} ${response.statusText}`);
    }
  }
  
  async createAgentSafely(agentData) {
    try {
      return await this.makeRequest('/agents', {
        method: 'POST',
        body: JSON.stringify({ agent: agentData })
      });
    } catch (error) {
      console.error('Failed to create agent:', error.message);
      // Attempt recovery or provide user feedback
      throw error;
    }
  }
}
```

### Validation Helpers

```javascript
// Agent validation helpers
function validateAgentData(agentData) {
  const errors = [];
  
  if (!agentData.name || agentData.name.trim().length === 0) {
    errors.push('Agent name is required');
  }
  
  if (!agentData.type) {
    errors.push('Agent type is required');
  }
  
  if (agentData.type === 'Agents::WebhookAgent') {
    if (!agentData.options || !agentData.options.secret) {
      errors.push('WebhookAgent requires a secret');
    }
    if (agentData.options && agentData.options.secret && agentData.options.secret.length < 4) {
      errors.push('Secret must be at least 4 characters');
    }
  }
  
  if (agentData.schedule && !isValidSchedule(agentData.schedule)) {
    errors.push('Invalid schedule value');
  }
  
  return errors;
}

function isValidSchedule(schedule) {
  const validSchedules = [
    'every_1m', 'every_2m', 'every_5m', 'every_10m', 'every_30m',
    'every_1h', 'every_2h', 'every_5h', 'every_12h',
    'every_1d', 'every_2d', 'every_7d',
    'midnight', '1am', '2am', '3am', '4am', '5am', '6am', '7am', '8am', '9am', '10am', '11am',
    'noon', '1pm', '2pm', '3pm', '4pm', '5pm', '6pm', '7pm', '8pm', '9pm', '10pm', '11pm',
    'never'
  ];
  return validSchedules.includes(schedule);
}
```

## Security Best Practices

### Secret Management

```javascript
// Generate secure secrets
function generateSecret(length = 32) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let secret = '';
  for (let i = 0; i < length; i++) {
    secret += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return secret;
}

// Secret validation
function validateSecret(secret) {
  return {
    isValid: secret && secret.length >= 8 && /^[a-zA-Z0-9\-_]+$/.test(secret),
    errors: [
      ...((!secret || secret.length < 8) ? ['Secret must be at least 8 characters'] : []),
      ...((secret && !/^[a-zA-Z0-9\-_]+$/.test(secret)) ? ['Secret can only contain letters, numbers, hyphens, and underscores'] : [])
    ]
  };
}

// Environment-based configuration
const CONFIG = {
  baseURL: process.env.HUGINN_BASE_URL || 'http://localhost:3000',
  webhookSecrets: {
    github: process.env.GITHUB_WEBHOOK_SECRET,
    slack: process.env.SLACK_WEBHOOK_SECRET,
    generic: process.env.GENERIC_WEBHOOK_SECRET
  }
};
```

### Rate Limiting and Monitoring

```javascript
// Rate limiting helper
class RateLimiter {
  constructor(maxRequests = 100, windowMs = 60000) {
    this.maxRequests = maxRequests;
    this.windowMs = windowMs;
    this.requests = [];
  }
  
  canMakeRequest() {
    const now = Date.now();
    this.requests = this.requests.filter(time => now - time < this.windowMs);
    
    if (this.requests.length >= this.maxRequests) {
      return false;
    }
    
    this.requests.push(now);
    return true;
  }
  
  async waitForSlot() {
    while (!this.canMakeRequest()) {
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
  }
}

// Usage in API client
const rateLimiter = new RateLimiter(50, 60000); // 50 requests per minute

async function makeRateLimitedRequest(url, options) {
  await rateLimiter.waitForSlot();
  return await fetch(url, options);
}
```

This examples guide provides practical patterns for integrating with Huginn's API across different use cases and programming languages. For additional details, consult the [Full API Reference](reference.md) and [Quick Reference](quick-reference.md).