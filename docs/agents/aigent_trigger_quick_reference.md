# AIgent Trigger Agent - Quick Reference Guide

## Basic Configuration

### Minimal Setup
```json
{
  "orchestrator_url": "http://localhost:8080",
  "target_agent": "general_purpose_agent", 
  "goal": "Process the incoming data: {{ event | jsonify }}"
}
```

### Production Setup
```json
{
  "orchestrator_url": "https://aigent.company.com",
  "target_agent": "specialized_agent",
  "goal": "{{ goal_template }}",
  "priority": "high",
  "execution_mode": "asynchronous",
  "verify_ssl": true,
  "api_key": "{{ credential.aigent_api_key }}",
  "retry_attempts": 3,
  "emit_events": true
}
```

## Trigger Conditions Quick Reference

### Always Trigger
```json
{
  "trigger_condition": "on_event"
}
```

### Conditional Triggering
```json
{
  "trigger_condition": "on_condition_met",
  "condition_rules": [
    {"field": "priority", "operator": ">=", "value": 5},
    {"field": "category", "operator": "==", "value": "urgent"}
  ]
}
```

### Threshold-Based
```json
{
  "trigger_condition": "on_threshold_exceeded",
  "condition_rules": [
    {"field": "temperature", "operator": ">", "value": 85, "type": "threshold"}
  ]
}
```

### Pattern Matching
```json
{
  "trigger_condition": "on_pattern_match",
  "condition_rules": [
    {"field": "title", "operator": "matches", "value": "(urgent|critical|emergency)"}
  ]
}
```

## Common Goal Templates

### File Processing
```liquid
Process the uploaded file {{ filename }} and extract structured data. 
File type: {{ file_type }}, Size: {{ file_size }} bytes
```

### Email Analysis
```liquid
Analyze email from {{ sender }} with subject '{{ subject }}'. 
Determine sentiment, extract action items, and suggest response priority.
```

### Data Analysis
```liquid
Analyze the data: {{ data | jsonify }}. 
Identify trends, anomalies, and provide actionable insights.
```

### Content Generation
```liquid
Create content about {{ topic }} for {{ target_audience }}. 
Include key points: {{ key_points | join: ', ' }} and maintain {{ brand_voice }} tone.
```

## Priority Levels

| Level | Use Case |
|-------|----------|
| `low` | Background tasks, non-urgent processing |
| `normal` | Standard operations, regular processing |
| `high` | Important tasks, time-sensitive operations |
| `urgent` | Critical tasks, immediate attention required |
| `critical` | Emergency situations, highest priority |

## Execution Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| `synchronous` | Wait for completion | Real-time processing, immediate results needed |
| `asynchronous` | Submit and continue | Most common, non-blocking operation |
| `background` | Low-priority, extended timeout | Long-running tasks, resource-intensive operations |

## Context Data Examples

### Customer Service
```json
{
  "context_data": {
    "customer_tier": "{{ customer.plan }}",
    "previous_tickets": "{{ customer.tickets_count }}",
    "satisfaction_score": "{{ customer.avg_satisfaction }}",
    "issue_category": "{{ detected_category }}"
  }
}
```

### Content Processing
```json
{
  "context_data": {
    "content_type": "{{ document_type }}",
    "source_system": "{{ origin }}",
    "processing_mode": "automated",
    "quality_requirements": {
      "accuracy": "high",
      "speed": "normal"
    }
  }
}
```

### Business Intelligence
```json
{
  "context_data": {
    "analysis_framework": "competitive_intelligence",
    "time_horizon": "quarterly", 
    "focus_areas": ["market_trends", "competitor_analysis"],
    "reporting_format": "executive_summary"
  }
}
```

## Error Handling Configuration

### Basic Error Handling
```json
{
  "retry_attempts": 3,
  "emit_events": true,
  "timeout_seconds": 300
}
```

### Advanced Error Handling
```json
{
  "retry_attempts": 5,
  "timeout_seconds": 600,
  "emit_events": true,
  "include_execution_metadata": true,
  "include_original_event": true
}
```

## Security Configuration

### Development
```json
{
  "verify_ssl": false,
  "include_execution_metadata": true
}
```

### Production
```json
{
  "verify_ssl": true,
  "api_key": "{{ credential.aigent_api_key }}",
  "headers": {
    "X-API-Version": "v1",
    "X-Client-ID": "huginn-integration"
  }
}
```

## Common Patterns

### RSS to Analysis
```
RSS Agent → AIgent Trigger → Content Analyzer → Email Digest
```

### Email Support
```
IMAP Agent → AIgent Trigger → Support Triager → Response Generator
```

### Monitoring Alert
```
HTTP Status Agent → AIgent Trigger → Incident Analyzer → Alert System
```

### Content Pipeline
```
Webhook Agent → AIgent Trigger → Content Creator → Multi-Channel Publisher
```

## Testing and Debugging

### Dry Run Configuration
```json
{
  "goal": "Test processing of {{ test_data }}",
  "context_data": {
    "test_mode": true,
    "sample_data": "{{ sample_input }}"
  }
}
```

### Debug Mode
```json
{
  "emit_events": true,
  "include_execution_metadata": true,
  "include_original_event": true,
  "timeout_seconds": 60
}
```

## Environment Variables

### Docker Compose
```yaml
environment:
  - AIGENT_ORCHESTRATOR_URL=http://orchestrator:8080
  - AIGENT_API_KEY=${AIGENT_API_KEY}
  - AIGENT_VERIFY_SSL=true
```

### Configuration Template
```json
{
  "orchestrator_url": "{{ ENV.AIGENT_ORCHESTRATOR_URL }}",
  "api_key": "{{ ENV.AIGENT_API_KEY }}",
  "verify_ssl": "{{ ENV.AIGENT_VERIFY_SSL | default: true }}"
}
```

## Performance Optimization

### High Throughput
```json
{
  "execution_mode": "asynchronous",
  "timeout_seconds": 60,
  "retry_attempts": 1,
  "emit_events": false
}
```

### Resource Conservation
```json
{
  "execution_mode": "background",
  "priority": "low",
  "context_data": {
    "minimal_processing": true
  }
}
```

## Troubleshooting Checklist

### Connection Issues
- [ ] Orchestrator URL is correct and accessible
- [ ] Network connectivity between Huginn and orchestrator
- [ ] Firewall rules allow communication
- [ ] SSL/TLS certificates are valid (if using HTTPS)

### Authentication Issues
- [ ] API key is correct and active
- [ ] Credentials are properly stored in Huginn
- [ ] Headers are correctly formatted
- [ ] Authentication method matches orchestrator requirements

### Template Issues
- [ ] Liquid syntax is valid
- [ ] Referenced fields exist in event data
- [ ] Template produces expected output in dry run
- [ ] Special characters are properly escaped

### Performance Issues
- [ ] Timeout values are appropriate for task complexity
- [ ] Execution mode matches use case requirements
- [ ] Retry attempts are not excessive
- [ ] Context data size is reasonable

## Event Outputs

### Success Event Structure
```json
{
  "status": "success",
  "aigent_id": "target_agent_name",
  "execution_id": "unique_execution_id",
  "goal": "processed_goal_template",
  "result": { "ai_generated_results": "..." },
  "execution_time_ms": 1500,
  "timestamp": "2024-01-15T14:30:22Z"
}
```

### Error Event Structure
```json
{
  "status": "failed", 
  "error": {
    "type": "ErrorType",
    "message": "Error description",
    "code": "ERROR_CODE"
  },
  "retry_count": 2,
  "timestamp": "2024-01-15T14:30:22Z"
}
```

---

## Quick Links

- [Full Documentation](aigent_trigger_agent.md)
- [Integration Guide](../../docs/aigent-huginn-integration-guide.md)
- [Example Scenarios](examples/aigent_trigger_scenarios.md)
- [Huginn Agent Documentation](https://github.com/huginn/huginn/wiki)

## Support

For issues or questions:
1. Check the troubleshooting section above
2. Review the full documentation
3. Check orchestrator logs for detailed error information
4. Verify network connectivity and authentication