# Pre-Completion Validation System

A comprehensive quality gates system for Huginn that ensures features meet all acceptance criteria, performance targets, security requirements, and deployment readiness before completion.

## Overview

The Pre-Completion Validation system implements the quality gates defined in `development/modes/development.md` and provides automated validation across five critical areas:

1. **Feature Completeness** - Validates all acceptance criteria are met
2. **Integration Testing** - Executes end-to-end workflow validation
3. **Performance Verification** - Ensures response times and resource usage within targets
4. **Security Validation** - Performs vulnerability scanning and access control testing
5. **Rollback Readiness** - Tests deployment reversal strategy and procedures

## Architecture

```
lib/quality_gates/
├── pre_completion.rb          # Main orchestrator
├── completeness_validator.rb  # Acceptance criteria validation
├── integration_tester.rb      # End-to-end workflow testing
├── performance_validator.rb   # Performance benchmarking
├── security_validator.rb      # Security vulnerability scanning
└── rollback_validator.rb      # Deployment rollback testing
```

## Installation

The system is automatically available in Rails environments. To set up configuration:

```bash
# Generate configuration templates
rake quality_gates:generate_config

# Check system status
rake quality_gates:status
```

## Usage

### Command Line Interface

```bash
# Run complete pre-completion validation
rake quality_gates:pre_completion["Feature Name"]

# Run individual validation phases
rake quality_gates:completeness["Feature Name"]
rake quality_gates:integration["Feature Name"] 
rake quality_gates:performance["Feature Name"]
rake quality_gates:security["Feature Name"]
rake quality_gates:rollback["Feature Name"]

# Environment variable approach
FEATURE_NAME="User Authentication" rake quality_gates:pre_completion
```

### Programmatic Usage

```ruby
require 'quality_gates/pre_completion'

# Configure validation
config = {
  feature_name: 'User Registration',
  acceptance_criteria: [
    'User can create account with valid email',
    'User receives confirmation email',
    'User can login after confirmation'
  ],
  performance_targets: {
    response_time: 200,  # milliseconds
    memory_usage: 100,   # MB
    throughput: 50       # requests per second
  },
  security_requirements: {
    authentication: true,
    authorization: true,
    input_validation: true
  },
  rollback_strategy: {
    database_migrations: true,
    rollback_timeout: 300
  }
}

# Run validation
validator = QualityGates::PreCompletion.new(config)
result = validator.validate_all

# Check results
if result.success?
  puts "✅ Feature ready for deployment"
  puts "Execution time: #{result.execution_time}s"
else
  puts "❌ Validation failed: #{result.failure_summary}"
  result.failures.each { |f| puts "- #{f[:message]}" }
end
```

## Configuration

### Configuration Files

Generate configuration templates:

```bash
rake quality_gates:generate_config
```

This creates configuration files in `config/quality_gates/`:

- `acceptance_criteria.yml` - Define feature acceptance criteria
- `performance_targets.yml` - Set performance thresholds
- `security_requirements.yml` - Configure security validation
- `rollback_strategy.yml` - Define rollback procedures
- `integration_tests.yml` - Specify integration test workflows

### Environment Variables

You can also configure validation using environment variables:

```bash
# Feature acceptance criteria (comma-separated)
export ACCEPTANCE_CRITERIA="Login works,Logout works,Session management"

# Performance targets
export PERFORMANCE_RESPONSE_TIME=200
export PERFORMANCE_MEMORY_USAGE=100
export PERFORMANCE_THROUGHPUT=50

# Security requirements
export SECURITY_AUTHENTICATION=true
export SECURITY_AUTHORIZATION=true

# Rollback configuration
export ROLLBACK_DB_MIGRATIONS=true
export ROLLBACK_TIMEOUT=300

# Integration tests (comma-separated)
export INTEGRATION_TESTS="User workflow,API integration,Error handling"
```

## Validation Components

### Feature Completeness Validator

Validates acceptance criteria through:
- RSpec test suite execution for feature-specific tests
- Manual acceptance criteria verification
- Feature flag and configuration validation
- Documentation completeness check
- API endpoint validation

```ruby
validator = QualityGates::CompletenessValidator.new(
  feature_name: 'User Management',
  acceptance_criteria: [
    'User can register with valid credentials',
    'User receives email confirmation',
    'User can login and access dashboard'
  ]
)

result = validator.validate
```

### Integration Tester

Executes end-to-end workflow validation:
- Rails integration test suite execution
- Database transaction integrity tests
- API endpoint integration testing
- External service integration validation
- Cross-component interaction testing
- Event flow and messaging validation

```ruby
tester = QualityGates::IntegrationTester.new(
  feature_name: 'Payment Processing',
  integration_tests: [
    'Payment flow workflow',
    'Refund processing workflow', 
    'Payment failure handling'
  ]
)

result = tester.run_tests
```

### Performance Validator

Validates system performance characteristics:
- Response time benchmarking
- Memory usage profiling
- CPU utilization monitoring
- Throughput testing
- Garbage collection analysis
- Database query performance
- Object allocation tracking

```ruby
validator = QualityGates::PerformanceValidator.new(
  feature_name: 'Search API',
  performance_targets: {
    response_time: 150,
    memory_usage: 75,
    throughput: 100,
    database_queries: 5
  }
)

result = validator.validate
```

### Security Validator

Performs comprehensive security validation:
- Authentication mechanism testing
- Authorization control validation
- Input validation and sanitization checks
- SQL injection vulnerability scanning
- XSS protection validation
- CSRF protection verification
- Security header configuration
- Encryption and hashing validation

```ruby
validator = QualityGates::SecurityValidator.new(
  feature_name: 'Admin Panel',
  security_requirements: {
    authentication: true,
    authorization: true,
    input_validation: true,
    csrf_protection: true,
    secure_headers: true
  }
)

result = validator.validate
```

### Rollback Validator

Validates deployment rollback readiness:
- Database migration rollback testing
- Configuration change reversal validation
- Feature flag rollback testing
- Service dependency rollback validation
- Data integrity verification post-rollback
- Rollback timing and timeout validation
- Emergency rollback procedure testing

```ruby
validator = QualityGates::RollbackValidator.new(
  feature_name: 'API Version 2',
  rollback_strategy: {
    database_migrations: true,
    configuration_changes: ['api_routes.yml'],
    feature_flags: ['enable_api_v2'],
    rollback_timeout: 180
  }
)

result = validator.validate
```

## Reports

The system generates comprehensive reports in `development/reports/`:

```
pre_completion_validation_feature_name_20250905_143000.md
```

Reports include:
- Overall validation status
- Individual phase results with timing
- Detailed failure analysis
- Performance metrics
- Security vulnerability findings
- Rollback readiness assessment
- Recommendations for deployment

## Integration with CI/CD

### GitHub Actions Example

```yaml
name: Pre-Completion Validation
on: [pull_request]

jobs:
  quality-gates:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: ruby/setup-ruby@v1
        with:
          ruby-version: 3.2.4
          bundler-cache: true
      
      - name: Run Pre-Completion Validation
        run: |
          FEATURE_NAME="${{ github.event.pull_request.title }}" \
          bundle exec rake quality_gates:pre_completion
        env:
          RAILS_ENV: test
          
      - name: Upload Validation Report
        uses: actions/upload-artifact@v2
        if: always()
        with:
          name: validation-report
          path: development/reports/pre_completion_validation_*.md
```

### Jenkins Pipeline Example

```groovy
pipeline {
    agent any
    
    environment {
        RAILS_ENV = 'test'
        FEATURE_NAME = "${env.GIT_BRANCH}"
    }
    
    stages {
        stage('Pre-Completion Validation') {
            steps {
                script {
                    sh 'bundle install'
                    sh 'bundle exec rake quality_gates:pre_completion'
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: 'development/reports/pre_completion_validation_*.md', allowEmptyArchive: true
                }
            }
        }
    }
}
```

## Best Practices

### 1. Feature Definition
- Define clear, testable acceptance criteria
- Include both functional and non-functional requirements
- Document expected user workflows

### 2. Performance Targets
- Set realistic performance thresholds based on user expectations
- Consider different targets for different environments
- Include both response time and resource utilization metrics

### 3. Security Requirements
- Enable security validation for all user-facing features
- Pay special attention to authentication and authorization
- Regularly update security scanning rules

### 4. Rollback Strategy
- Always test rollback procedures in staging
- Document step-by-step rollback instructions
- Include verification steps for post-rollback validation

### 5. Integration Testing
- Cover critical user journeys end-to-end
- Test error conditions and edge cases
- Validate external service integrations

## Troubleshooting

### Common Issues

**1. RSpec Tests Not Found**
```bash
# Ensure RSpec is properly configured
bundle exec rspec --version

# Check test file patterns match your project structure
```

**2. Performance Tests Failing**
```bash
# Check if performance targets are realistic
# Monitor actual performance during development
# Adjust targets in performance_targets.yml
```

**3. Security Validation Issues**
```bash
# Ensure required security gems are installed
bundle exec gem list | grep -E "(devise|bcrypt|rack-cors)"

# Check Rails security configuration
```

**4. Database Migration Rollback Errors**
```bash
# Verify migration files have proper rollback methods
# Test rollback in development environment first
bundle exec rails db:rollback STEP=1
```

### Debug Mode

Enable verbose logging for detailed debugging:

```ruby
# Create logger with debug level
logger = Logger.new($stdout)
logger.level = Logger::DEBUG

validator = QualityGates::PreCompletion.new({
  feature_name: 'Debug Feature',
  # ... other config
})

# Run with custom logger
result = validator.validate_all
```

## Extending the System

### Adding Custom Validators

```ruby
module QualityGates
  class CustomValidator
    def initialize(feature_name:, custom_config: {}, logger: nil)
      @feature_name = feature_name
      @custom_config = custom_config
      @logger = logger || setup_default_logger
    end

    def validate
      # Custom validation logic
      {
        success: true,
        failures: [],
        checks_run: 1,
        execution_time: 0.5,
        details: "Custom validation completed"
      }
    end

    private

    def setup_default_logger
      # Standard logger setup
    end
  end
end
```

### Custom Rake Tasks

```ruby
namespace :quality_gates do
  desc 'Run custom validation'
  task :custom, [:feature_name] => :environment do |_task, args|
    validator = QualityGates::CustomValidator.new(
      feature_name: args[:feature_name]
    )
    
    result = validator.validate
    puts result[:success] ? "✅ PASSED" : "❌ FAILED"
  end
end
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all existing tests pass
5. Update documentation
6. Submit a pull request

## Support

For issues and questions:
1. Check the troubleshooting section
2. Review existing GitHub issues
3. Create a detailed issue with reproduction steps
4. Include validation reports and logs

## License

This Pre-Completion Validation system is part of the Huginn project and follows the same licensing terms.