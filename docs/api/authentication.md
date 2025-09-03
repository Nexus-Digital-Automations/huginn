# Huginn API Authentication and Security Guide

## Overview

Huginn uses a comprehensive authentication and authorization system based on Rails Devise with session-based authentication for the web interface and secret-based authentication for webhook endpoints. This document outlines the security architecture, authentication mechanisms, and best practices for secure integrations.

## Table of Contents

1. [Authentication System Overview](#authentication-system-overview)
2. [Web Interface Authentication](#web-interface-authentication)
3. [Webhook Authentication](#webhook-authentication)
4. [API Endpoint Security](#api-endpoint-security)
5. [Security Patterns](#security-patterns)
6. [Best Practices](#best-practices)
7. [Common Errors and Solutions](#common-errors-and-solutions)
8. [Examples](#examples)

## Authentication System Overview

Huginn implements a multi-layered authentication system:

- **Session-based authentication** for web interface (using Devise)
- **Secret-based authentication** for webhook endpoints
- **User-scoped authorization** for all resources
- **OAuth integration** for external services
- **Invitation code system** for user registration

### Core Security Principles

- All resources are scoped to the authenticated user
- Webhook endpoints require secret validation
- CSRF protection for state-changing operations
- OAuth integration for external service authentication
- Account lockout protection against brute force attacks

## Web Interface Authentication

### Devise Configuration

Huginn uses Devise with the following modules:

```ruby
devise :database_authenticatable, :registerable,
       :recoverable, :rememberable, :trackable,
       :validatable, :lockable, :omniauthable,
       *(:confirmable if ENV['REQUIRE_CONFIRMED_EMAIL'] == 'true')
```

### Authentication Features

- **Username or Email Login**: Users can authenticate with either username or email
- **Account Locking**: Configurable failed attempt limits (default: 10 attempts)
- **Password Requirements**: Minimum 8 characters (configurable via `MIN_PASSWORD_LENGTH`)
- **Session Management**: Secure session handling with configurable timeouts
- **Remember Me**: Optional persistent sessions with secure cookies in production

### User Registration

Registration requires an invitation code system:

```ruby
# Environment configuration
INVITATION_CODES = [ENV['INVITATION_CODE'] || 'try-huginn']

# Skip invitation code requirement (development)
ENV['SKIP_INVITATION_CODE'] != 'true'
```

### Session Security

**Production Configuration:**
```ruby
# Secure cookies in production
config.rememberable_options = { secure: true }

# Force SSL (optional)
config.force_ssl = ENV['FORCE_SSL'] == 'true'
```

## Webhook Authentication

### Web Request Endpoints

Huginn provides webhook endpoints that bypass session authentication:

```
POST/GET/PUT/DELETE /users/:user_id/web_requests/:agent_id/:secret
```

### Security Implementation

The `WebRequestsController` implements security through:

```ruby
class WebRequestsController < ApplicationController
  skip_before_action :verify_authenticity_token  # CSRF not applicable to webhooks
  skip_before_action :authenticate_user!         # Uses secret-based auth instead
  
  def handle_request
    user = User.find_by_id(params[:user_id])
    agent = user.agents.find_by_id(params[:agent_id])
    # Secret validation happens in agent's receive_web_request method
  end
end
```

### Secret Validation Pattern

Each agent that receives webhooks validates the secret:

```ruby
# Example from WebhookAgent
def receive_web_request(request)
  secret = request.path_parameters[:secret]
  return ["Not Authorized", 401] unless secret == interpolated['secret']
  # Process request...
end
```

### Secret Generation

Secrets are typically generated using secure random values:

```ruby
def default_options
  {
    "secret" => SecureRandom.uuid,
    # other options...
  }
end
```

## API Endpoint Security

### Resource-Scoped Authorization

All API endpoints enforce user-based authorization:

**Agents Controller:**
```ruby
def index
  @agents = current_user.agents.page(params[:page])
end

def show
  @agent = current_user.agents.find(params[:id])
end
```

**Events Controller:**
```ruby
def index
  @events = current_user.events.preload(:agent).page(params[:page])
end
```

**Scenarios Controller:**
```ruby
def show
  @scenario = current_user.scenarios.find(params[:id])
end
```

### Authentication Requirements

| Endpoint | Authentication | Authorization |
|----------|---------------|---------------|
| `/agents` | Session required | User-scoped |
| `/events` | Session required | User-scoped |
| `/scenarios` | Session required | User-scoped |
| `/scenarios/:id/export` | Optional* | Public scenarios or owner |
| `/web_requests/:user_id/:agent_id/:secret` | Secret-based | Agent secret validation |

*Public scenarios can be exported without authentication

## Security Patterns

### CSRF Protection

**Default Protection:**
```ruby
# ApplicationController
before_action :verify_authenticity_token  # Applied to all controllers
```

**Selective Bypass:**
```ruby
# WebRequestsController (webhooks don't need CSRF protection)
skip_before_action :verify_authenticity_token
```

### Input Sanitization

**HTML Sanitization:**
```ruby
# application.rb
config.action_view.sanitized_allowed_tags = %w[strong em b i p code pre ...]
config.action_view.sanitized_allowed_attributes = %w[href src width height ...]
```

### Parameter Security

**Strong Parameters:**
```ruby
def agent_params
  params[:agent].permit([:memory, :name, :type, :schedule, :disabled, 
                        :keep_events_for, :propagate_immediately, 
                        source_ids: [], receiver_ids: [], 
                        scenario_ids: []] + agent_params_options)
end
```

### reCAPTCHA Integration

Webhook agents can optionally integrate reCAPTCHA:

```ruby
# WebhookAgent reCAPTCHA validation
if recaptcha_secret = interpolated['recaptcha_secret'].presence
  # Validate reCAPTCHA response
  response = faraday.post('https://www.google.com/recaptcha/api/siteverify', {
    secret: recaptcha_secret,
    response: params.delete('g-recaptcha-response')
  })
  
  body = JSON.parse(response.body)
  return ["Not Authorized", 401] unless body['success']
end
```

### OAuth Security

External service authentication uses OAuth with secure token storage:

```ruby
# Service model for OAuth tokens
class Service < ActiveRecord::Base
  validates_presence_of :token
  
  def refresh_token!
    # Secure token refresh implementation
  end
end
```

## Best Practices

### 1. Secret Management

**Generate Strong Secrets:**
```ruby
# Use cryptographically secure random values
secret = SecureRandom.uuid
secret = SecureRandom.hex(32)  # For longer secrets
```

**Secret Rotation:**
- Regularly rotate webhook secrets
- Update secrets in both Huginn and external services
- Monitor for unauthorized access attempts

### 2. User Credentials

**Secure Storage:**
```ruby
# UserCredential model enforces validation
validates :credential_name, presence: true, uniqueness: { scope: :user_id }
validates :credential_value, presence: true
```

**Access Patterns:**
```ruby
# Agents access credentials securely
def credential(name)
  user.user_credentials.where(credential_name: name).first&.credential_value
end
```

### 3. Production Security

**Environment Variables:**
```bash
# Essential security environment variables
INVITATION_CODE=your-secure-invitation-code
MIN_PASSWORD_LENGTH=8
FORCE_SSL=true
RAILS_MASTER_KEY=your-master-key

# OAuth credentials
TWITTER_OAUTH_KEY=your-key
TWITTER_OAUTH_SECRET=your-secret
```

**SSL/TLS Configuration:**
```ruby
# Force SSL in production
config.force_ssl = true

# Secure cookie configuration
config.rememberable_options = { secure: true }
```

### 4. Webhook Security

**Validate All Requests:**
```ruby
def receive_web_request(request)
  # Always validate secret first
  secret = request.path_parameters[:secret]
  return ["Not Authorized", 401] unless secret == expected_secret
  
  # Validate HTTP method
  allowed_methods = %w[post get put delete]
  return ["Method Not Allowed", 405] unless allowed_methods.include?(request.method.downcase)
  
  # Process request...
end
```

**IP Whitelisting (optional):**
```ruby
# In webhook agents, optionally validate source IP
def receive_web_request(request)
  allowed_ips = %w[192.168.1.0/24 10.0.0.0/8]
  client_ip = request.remote_ip
  return ["Forbidden", 403] unless ip_allowed?(client_ip, allowed_ips)
end
```

## Common Errors and Solutions

### Authentication Errors

**Error: "Invalid login or password"**
- **Cause**: Incorrect username/email or password
- **Solution**: Verify credentials, check account lockout status

**Error: "Account is locked"**
- **Cause**: Exceeded maximum failed login attempts
- **Solution**: Wait for unlock timeout or contact admin for manual unlock

**Error: "Not Authorized" (401) on webhooks**
- **Cause**: Invalid or missing secret in webhook URL
- **Solution**: Verify secret matches agent configuration

### Authorization Errors

**Error: "Agent not found" (404)**
- **Cause**: Agent ID doesn't exist or doesn't belong to user
- **Solution**: Verify agent ownership and ID correctness

**Error: "Scenario not found" (404)**
- **Cause**: Scenario ID doesn't exist or user lacks access
- **Solution**: Check scenario ownership or public status

### CSRF Errors

**Error: "Invalid authenticity token"**
- **Cause**: Missing or invalid CSRF token in form submission
- **Solution**: Ensure forms include `<%= csrf_meta_tags %>` and proper token handling

## Examples

### 1. Webhook Setup

**Agent Configuration:**
```json
{
  "name": "My Webhook",
  "type": "Agents::WebhookAgent",
  "options": {
    "secret": "abc123-secure-secret-xyz789",
    "payload_path": ".",
    "verbs": "post,get",
    "response": "Event received"
  }
}
```

**Webhook URL:**
```
https://your-huginn-instance.com/users/1/web_requests/123/abc123-secure-secret-xyz789
```

**Example Request:**
```bash
curl -X POST \
  https://your-huginn-instance.com/users/1/web_requests/123/abc123-secure-secret-xyz789 \
  -H "Content-Type: application/json" \
  -d '{"message": "Hello from external service"}'
```

### 2. API Authentication

**Session-based API Request:**
```bash
# Login first to establish session
curl -X POST https://your-huginn-instance.com/users/sign_in \
  -H "Content-Type: application/json" \
  -d '{"user": {"login": "username", "password": "password"}}' \
  -c cookies.txt

# Make authenticated API request
curl -X GET https://your-huginn-instance.com/agents.json \
  -H "Accept: application/json" \
  -b cookies.txt
```

### 3. OAuth Service Integration

**Service Creation Flow:**
1. User initiates OAuth flow: `/auth/twitter`
2. External service redirects back: `/auth/twitter/callback`
3. Huginn creates/updates service record with tokens
4. Agents can use service for authenticated requests

### 4. User Credential Management

**Creating Credentials:**
```ruby
# Via web interface or programmatically
user.user_credentials.create!(
  credential_name: "api_key", 
  credential_value: "secret-api-key-value"
)
```

**Using Credentials in Agents:**
```ruby
def check
  api_key = credential("api_key")
  return error("API key not found") unless api_key
  
  # Use api_key for external service requests
end
```

## Security Monitoring

### Logging

Huginn logs authentication events and security-relevant activities:

- Failed login attempts
- Account lockouts
- Webhook request processing
- Agent execution errors

### Monitoring Recommendations

1. **Monitor failed authentication attempts**
2. **Set up alerts for account lockouts**
3. **Track webhook endpoint access patterns**
4. **Review agent logs for security errors**
5. **Monitor OAuth token refresh activities**

---

This document provides a comprehensive guide to Huginn's authentication and security systems. For additional security considerations or custom implementations, consult the source code and Rails security best practices documentation.