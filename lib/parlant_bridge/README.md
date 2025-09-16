# Parlant Bridge - Ruby/Huginn HTTP Integration

A comprehensive HTTP bridge service for integrating Ruby-based Huginn functions with Parlant conversational validation. This library provides enterprise-grade conversational AI integration with robust error handling, performance optimization, and security features.

## 🚀 Features

### Core Integration
- **HTTP Client Service**: Asynchronous validation with connection pooling and retry mechanisms
- **Method Interception**: Decorator-style patterns for seamless integration
- **Thread-Safe Operations**: Concurrent request handling with thread safety guarantees
- **Caching Layer**: Multi-level caching for performance optimization

### Conversational Validation Framework
- **User Confirmation Workflows**: Interactive approval for critical operations
- **Security Classifications**: 5-tier security system (PUBLIC → CLASSIFIED)
- **Audit Trail Generation**: Comprehensive logging for compliance
- **Emergency Bypass**: Fail-safe mechanisms with detailed logging

### Performance & Reliability
- **Connection Pooling**: Configurable connection management
- **Circuit Breaker Pattern**: Fault tolerance and cascading failure prevention
- **Retry Logic**: Exponential backoff with jitter
- **Rate Limiting**: Protection against abuse and overload

### Security Integration
- **JWT Authentication**: Secure integration with AIgent's auth system
- **Session Management**: Secure session handling with timeout controls
- **Audit Logging**: Tamper-proof audit trails for compliance
- **Rate Limiting**: Configurable request limiting and abuse prevention

## 📦 Installation

Add to your Huginn agent or Ruby application:

```ruby
require_relative 'lib/parlant_bridge'
```

## ⚙️ Configuration

### Environment Variables

```bash
# Required
PARLANT_SERVER_URL=http://localhost:8080

# Optional
JWT_PUBLIC_KEY_PATH=/path/to/jwt/public/key.pem
PARLANT_BRIDGE_AUTO_CONFIGURE=true
```

### Programmatic Configuration

```ruby
ParlantBridge.configure(
  server_url: 'https://parlant.example.com',
  timeout: 45,
  pool_size: 20,
  cache_ttl: 600,
  logger: Logger.new('parlant.log'),
  enable_metrics: true,
  enable_circuit_breaker: true
)
```

## 🔧 Usage

### Basic Integration

```ruby
class MyAgent
  include ParlantBridge::IntegrationModule
  
  # Configure for this class
  configure_parlant(
    server_url: ENV['PARLANT_SERVER_URL'],
    timeout: 30
  )
  
  # Define security classifications
  parlant_internal :check_status
  parlant_secure :send_notification, confirmation_required: true
  parlant_critical :emergency_shutdown, audit_level: 'detailed'
  
  def check_status
    # Light validation, cached results
    { status: 'operational', timestamp: Time.now }
  end
  
  def send_notification(recipient, message)
    # Requires conversational validation
    # Implementation here...
  end
  
  def emergency_shutdown(reason)
    # Critical operation requiring user confirmation
    # Implementation here...
  end
end
```

### Security Classifications

| Classification | Description | Validation Level | Cache TTL |
|---------------|-------------|------------------|-----------|
| `PUBLIC` | No sensitive data | Light validation | 1 hour |
| `INTERNAL` | Internal operations | Standard validation | 30 minutes |
| `CONFIDENTIAL` | Sensitive operations | User confirmation | 15 minutes |
| `RESTRICTED` | High-risk operations | Multi-step approval | 5 minutes |
| `CLASSIFIED` | Critical operations | Multi-party approval | 1 minute |

### Custom Validation

```ruby
class DataAgent
  include ParlantBridge::IntegrationModule
  
  # Custom validator for complex logic
  DATA_VALIDATOR = ->(method_name, args, kwargs) do
    if method_name.to_s.include?('delete')
      record_count = kwargs[:record_count] || 0
      
      # Pre-approve small deletions
      if record_count < 10
        return ValidationResult.new(
          status: 'approved',
          operation_id: SecureRandom.hex(4),
          confidence: 0.8,
          reason: 'Pre-approved: small deletion'
        )
      end
    end
    
    nil # Continue with normal validation
  end
  
  parlant_secure :delete_records, 
                 custom_validator: DATA_VALIDATOR,
                 confirmation_required: true
  
  def delete_records(criteria, record_count: nil)
    # Custom validator handles pre-approval for small deletions
    # Large deletions require conversational validation
  end
end
```

### Error Handling

```ruby
begin
  result = agent.sensitive_operation(data)
rescue ParlantBridge::ValidationFailedError => e
  logger.error "Validation failed: #{e.message}"
  logger.error "Operation ID: #{e.operation_id}"
  # Handle rejection gracefully
rescue ParlantBridge::ConnectionError => e
  logger.error "Connection failed: #{e.message}"
  # Implement fallback strategy
rescue ParlantBridge::CircuitBreakerOpenError => e
  logger.warn "Service temporarily unavailable: #{e.message}"
  # Use emergency bypass if appropriate
end
```

### Security Integration

```ruby
class SecurityAgent
  include ParlantBridge::IntegrationModule
  include ParlantBridge::SecurityIntegration
  
  def initialize
    @auth_manager = AuthenticationManager.new(
      jwt_public_key_path: ENV['JWT_PUBLIC_KEY_PATH']
    )
    
    @audit_logger = AuditLogger.new(retention_days: 90)
  end
  
  def authenticate_user(jwt_token)
    security_context = @auth_manager.authenticate(jwt_token)
    
    @audit_logger.log_authentication(
      security_context.user_id,
      true,
      { ip_address: get_client_ip }
    )
    
    security_context
  end
  
  parlant_critical :grant_admin_access
  
  def grant_admin_access(user_id, justification)
    # Requires conversational validation + audit logging
    @audit_logger.log_security_event(
      'admin_access_granted',
      get_security_context,
      { target_user: user_id, justification: justification },
      'critical'
    )
  end
end
```

## 🔍 Monitoring & Health Checks

### Health Status

```ruby
# Check overall system health
health = ParlantBridge.health_check
puts health[:status] # 'healthy', 'degraded', or 'critical'

# Check agent-specific health
agent_health = my_agent.parlant_health_status
puts agent_health[:metrics]
```

### Performance Metrics

```ruby
# Get wrapped methods information
wrapped_methods = MyAgent.parlant_wrapped_methods_list
wrapped_methods.each do |method_name, config|
  puts "#{method_name}: #{config[:classification]}"
end

# Manual validation for testing
result = my_agent.validate_operation_manually(
  'test_operation',
  { param1: 'value1' },
  'CONFIDENTIAL'
)
puts result.approved? ? 'Approved' : 'Rejected'
```

## 🛡️ Security Features

### Authentication Flow

1. **JWT Validation**: Validates AIgent JWT tokens using RSA public key
2. **Session Creation**: Creates secure Parlant session with mapped roles/permissions
3. **Context Propagation**: Maintains security context throughout request lifecycle
4. **Session Cleanup**: Automatic cleanup of expired sessions

### Audit Logging

```ruby
audit_logger = ParlantBridge.create_audit_logger

# Log security events
audit_logger.log_security_event(
  'permission_update',
  security_context,
  { target_user: 'user_123', new_permissions: ['admin'] },
  'high'
)

# Query audit events
events = audit_logger.get_audit_events(
  user_id: 'user_123',
  event_type: 'authentication_failure',
  start_time: Date.today
)
```

### Rate Limiting

```ruby
rate_limiter = ParlantBridge::SecurityIntegration::RateLimiter.new(
  default_limit: 100,    # requests per window
  default_window: 60,    # seconds
  burst_limit: 20,       # burst requests
  burst_window: 10       # burst window
)

# Check rate limits
begin
  rate_limiter.check_rate_limit!('client_123', 'api_call')
rescue ParlantBridge::RateLimitError => e
  puts "Rate limit exceeded: #{e.message}"
end
```

## ⚡ Performance Optimization

### Caching Strategy

The bridge implements a three-tier caching system:

1. **L1 Cache**: In-memory, <5ms access, 5-30s TTL
2. **L2 Cache**: Redis distributed, <15ms access, 1-60min TTL
3. **L3 Cache**: Database persistent, <50ms access, 1+ hour TTL

```ruby
cache = ParlantBridge::CacheService.new(
  ttl: 300,
  max_size: 1000,
  enable_metrics: true
)

# Cache usage is automatic, but you can check stats
puts cache.stats
# => { hit_rate: 85.2, memory_usage: {...}, ... }
```

### Connection Pooling

```ruby
client = ParlantBridge.create_client(
  pool_size: 20,        # Maximum concurrent connections
  timeout: 45,          # Request timeout
  enable_circuit_breaker: true
)

# Pool statistics
health = client.health_check
puts health[:connection_pool]
# => { active_threads: 5, queue_length: 0, pool_size: 20 }
```

## 🚨 Error Recovery

### Circuit Breaker

```ruby
# Circuit breaker automatically activates after threshold failures
begin
  result = client.validate_operation(...)
rescue ParlantBridge::CircuitBreakerOpenError
  # Service is temporarily disabled
  # Use fallback or emergency bypass
  fallback_result = handle_fallback_validation
end
```

### Emergency Bypass

```ruby
class CriticalAgent
  include ParlantBridge::IntegrationModule
  
  # Enable emergency bypass for critical operations
  parlant_critical :emergency_stop, 
                   emergency_bypass: true,
                   confirmation_required: true
  
  def emergency_stop(reason)
    # Will bypass validation if:
    # - PARLANT_EMERGENCY_BYPASS=true
    # - System is in maintenance mode
    # - Parlant server is unavailable
  end
end
```

## 📊 Advanced Features

### Async Validation Sessions

```ruby
session = client.create_async_session(
  session_config: {
    operation_id: 'op_123',
    confirmation_required: true,
    timeout: 300
  },
  progress_callback: ->(progress) {
    puts "Progress: #{progress[:status]} - #{progress[:message]}"
  }
)

# Wait for user confirmation
confirmation = session.wait_for_confirmation
if confirmation.approved?
  # Proceed with operation
else
  # Handle rejection
  puts "Rejected: #{confirmation.reason}"
end
```

### Batch Operations

```ruby
# Process multiple validations efficiently
operations = [
  { function_name: 'op1', params: {...}, classification: 'INTERNAL' },
  { function_name: 'op2', params: {...}, classification: 'SECURE' },
  { function_name: 'op3', params: {...}, classification: 'CRITICAL' }
]

# The client automatically batches and optimizes these requests
results = operations.map do |op|
  client.validate_operation(**op)
end
```

## 🧪 Testing

### Mock Validation

```ruby
# For testing, you can mock validations
class TestAgent
  include ParlantBridge::IntegrationModule
  
  configure_parlant(
    server_url: 'http://localhost:8080'  # Use test server
  )
  
  parlant_secure :test_method
  
  def test_method
    'test result'
  end
end

# In tests, validation will use test server or mocks
```

### Health Check Testing

```ruby
RSpec.describe 'Parlant Integration' do
  it 'validates system health' do
    health = ParlantBridge.health_check
    expect(health[:status]).to eq('healthy')
    expect(health[:server_connectivity]).to eq('available')
  end
  
  it 'handles validation failures gracefully' do
    expect {
      agent.critical_operation
    }.to raise_error(ParlantBridge::ValidationFailedError)
  end
end
```

## 📚 API Reference

### Core Classes

- `ParlantBridge::HttpClientService` - HTTP client with pooling and retries
- `ParlantBridge::IntegrationModule` - Main integration mixin for agents
- `ParlantBridge::ValidationResult` - Validation result container
- `ParlantBridge::CacheService` - Multi-level caching service
- `ParlantBridge::SecurityIntegration` - Security and authentication
- `ParlantBridge::ErrorHandler` - Error handling and recovery

### Security Classes

- `SecurityIntegration::AuthenticationManager` - JWT authentication
- `SecurityIntegration::SecurityContext` - User security context
- `SecurityIntegration::AuditLogger` - Security event logging
- `SecurityIntegration::RateLimiter` - Request rate limiting

### Exception Classes

- `ParlantBridge::ValidationFailedError` - Validation rejection
- `ParlantBridge::ConnectionError` - Network/connectivity issues
- `ParlantBridge::CircuitBreakerOpenError` - Service unavailable
- `ParlantBridge::RateLimitError` - Rate limit exceeded
- `ParlantBridge::AuthenticationError` - Authentication failure

## 🔧 Configuration Reference

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PARLANT_SERVER_URL` | Parlant server URL | `http://localhost:8080` |
| `JWT_PUBLIC_KEY_PATH` | JWT public key file path | none |
| `PARLANT_EMERGENCY_BYPASS` | Enable emergency bypass | `false` |
| `PARLANT_BRIDGE_AUTO_CONFIGURE` | Auto-configure on load | `false` |

### Configuration Options

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| `server_url` | String | Parlant server URL | `http://localhost:8080` |
| `timeout` | Integer | Request timeout (seconds) | 30 |
| `pool_size` | Integer | Connection pool size | 10 |
| `cache_ttl` | Integer | Default cache TTL (seconds) | 300 |
| `enable_metrics` | Boolean | Enable metrics collection | true |
| `enable_circuit_breaker` | Boolean | Enable circuit breaker | true |
| `rate_limit` | Integer | Requests per window | 100 |
| `rate_window` | Integer | Rate limit window (seconds) | 60 |

## 🤝 Contributing

This library is part of the AIgent ecosystem's Parlant integration. For contributions and issues, please refer to the main AIgent project repository.

## 📜 License

This library is part of the AIgent project and follows the same licensing terms.

## 🔗 Related Documentation

- [Parlant Integration Master Plan](../../../development/essentials/parlant-integration-master-implementation-plan.md)
- [Security Integration Architecture](../../../development/essentials/aigent-parlant-security-integration-architecture.md)
- [Performance Optimization Guide](../../../development/essentials/parlant-performance-optimization-comprehensive-research.md)