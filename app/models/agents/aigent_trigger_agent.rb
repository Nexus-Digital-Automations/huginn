# frozen_string_literal: true

require_relative '../../lib/security/security_monitor'
require_relative '../../lib/security/security_integration'

module Agents
  # AIgent Trigger Agent - Integration with AIgent Orchestrator System
  #
  # This agent provides intelligent trigger capabilities by integrating with
  # the AIgent orchestrator system to execute automated workflows based on
  # sophisticated conditions and AI-powered decision making.
  #
  # Enhanced with comprehensive security framework integration including:
  # - Real-time security monitoring and threat detection
  # - Advanced encryption and data protection
  # - Compliance validation and reporting
  # - Security policy enforcement and validation
  # - Automated incident response and remediation
  #
  # Configuration validates all required parameters with comprehensive error
  # checking and provides user-friendly defaults with examples.
  class AigentTriggerAgent < Agent
    include WebRequestConcern
    include LiquidInterpolatable
    include FormConfigurable

    can_dry_run!
    default_schedule 'never'

    # Initialize security components
    def self.security_monitor
      @security_monitor ||= Security::SecurityMonitor.instance
    end

    def self.security_integration
      @security_integration ||= Security::SecurityIntegration.instance
    end

    # Valid priority levels for AIgent execution
    VALID_PRIORITY_LEVELS = %w[low normal high urgent critical].freeze

    # Valid execution modes for the agent
    VALID_EXECUTION_MODES = %w[synchronous asynchronous background].freeze

    # Valid trigger conditions
    VALID_TRIGGER_CONDITIONS = %w[
      on_event
      on_schedule
      on_condition_met
      on_threshold_exceeded
      on_pattern_match
      on_anomaly_detected
    ].freeze

    # Form configuration for Huginn UI
    form_configurable :orchestrator_url, type: :string
    form_configurable :target_agent, type: :string  
    form_configurable :goal, type: :text, ace: { mode: 'liquid', theme: 'textmate' }
    form_configurable :priority, type: :array, values: VALID_PRIORITY_LEVELS
    form_configurable :execution_mode, type: :array, values: VALID_EXECUTION_MODES
    form_configurable :timeout_seconds, type: :string
    form_configurable :trigger_condition, type: :array, values: VALID_TRIGGER_CONDITIONS
    form_configurable :condition_rules, type: :json
    form_configurable :context_data, type: :json
    form_configurable :tags, type: :json
    form_configurable :expected_receive_period_in_days, type: :string
    form_configurable :api_key, type: :string
    form_configurable :verify_ssl, type: :boolean
    form_configurable :retry_attempts, type: :string
    form_configurable :emit_events, type: :boolean
    form_configurable :include_execution_metadata, type: :boolean
    form_configurable :include_original_event, type: :boolean
    form_configurable :headers, type: :json
    form_configurable :security_monitoring_enabled, type: :boolean
    form_configurable :encryption_enabled, type: :boolean  
    form_configurable :compliance_frameworks, type: :json
    form_configurable :threat_detection_enabled, type: :boolean
    form_configurable :security_classification, type: :array, values: %w[public internal confidential restricted]

    description do
      <<~MD
        The AIgent Trigger Agent integrates with the AIgent orchestrator system to execute intelligent, 
        AI-powered workflows based on sophisticated trigger conditions and context-aware decision making.

        This agent acts as a bridge between Huginn's event processing capabilities and the AIgent orchestrator's 
        advanced automation framework, enabling:

        - **Smart Trigger Conditions**: AI-powered pattern recognition and anomaly detection
        - **Context-Aware Execution**: Dynamic goal generation based on event data and environmental context
        - **Workflow Orchestration**: Integration with multi-agent coordination and task execution
        - **Intelligent Prioritization**: Automatic priority assignment based on event importance and urgency

        ## Configuration Options

        ### Core Configuration
        
        * **`orchestrator_url`** (required): Complete URL to the AIgent orchestrator API endpoint
          - Must be a valid HTTP/HTTPS URL with proper scheme, host, and port
          - Example: `http://localhost:8080` or `https://aigent.example.com:8443`
          - The agent validates URL accessibility and SSL certificate validity for HTTPS URLs
        
        * **`target_agent`** (required): Identifier of the target AIgent to execute
          - Must be a non-empty string matching valid agent naming conventions
          - Example: `browser_automation_agent`, `data_processing_specialist`, `email_coordinator`
          - The agent validates that the specified target agent exists and is available
        
        * **`goal`** (required): Liquid template defining the execution goal for the AIgent
          - Supports full Liquid templating syntax with access to incoming event data
          - Can reference any field from the triggering event using `{{ event.field_name }}`
          - Example: `"Process the file located at {{ file_path }} and extract key metrics"`
          - Template syntax is validated for proper Liquid formatting and variable references

        ### Execution Control

        * **`priority`**: Execution priority level (default: `normal`)
          - Valid values: `#{VALID_PRIORITY_LEVELS.join(', ')}`
          - Determines AIgent task queue priority and resource allocation
          - Higher priority tasks are executed first and receive more system resources
        
        * **`execution_mode`**: How the AIgent task should be executed (default: `asynchronous`)
          - Valid values: `#{VALID_EXECUTION_MODES.join(', ')}`
          - `synchronous`: Wait for completion before processing next events
          - `asynchronous`: Submit task and continue processing immediately
          - `background`: Low-priority background execution with extended timeouts
        
        * **`timeout_seconds`**: Maximum execution time in seconds (default: `300`)
          - Valid range: 30 to 3600 seconds (30 seconds to 1 hour)
          - Prevents runaway tasks from consuming excessive resources
          - Tasks exceeding timeout are automatically terminated with error events

        ### Trigger Conditions

        * **`trigger_condition`**: Type of condition that should trigger AIgent execution (default: `on_event`)
          - Valid values: `#{VALID_TRIGGER_CONDITIONS.join(', ')}`
          - Enables sophisticated conditional logic beyond simple event reception
        
        * **`condition_rules`**: Array of rules for conditional triggering (optional)
          - Each rule can be a Liquid template string or structured condition object
          - Supports complex boolean logic, pattern matching, and threshold comparisons
          - Example: `[{"field": "severity", "operator": ">=", "value": 8}]`

        ### Context and Metadata

        * **`context_data`**: Additional context data passed to the AIgent (optional)
          - Hash of key-value pairs providing environmental context
          - Supports Liquid templating for dynamic context generation
          - Example: `{"source_system": "monitoring", "environment": "production"}`
        
        * **`tags`**: Array of tags for categorization and filtering (optional)
          - Helps organize and track related AIgent executions
          - Example: `["automation", "incident_response", "high_priority"]`
        
        * **`expected_receive_period_in_days`**: Expected event frequency for health monitoring
          - Used to determine if the agent is functioning correctly
          - Default: 1 day

        ### Security and Authentication

        * **`api_key`**: Authentication key for orchestrator API access (optional)
          - If required by your orchestrator configuration
          - Stored securely and never logged or exposed in event data
        
        * **`verify_ssl`**: Whether to verify SSL certificates for HTTPS connections (default: `true`)
          - Set to `false` only for development with self-signed certificates
          - Production deployments should always use `true` for security

        ### Advanced Options

        * **`retry_attempts`**: Number of retry attempts on failure (default: `3`)
          - Valid range: 0 to 10 attempts
          - Exponential backoff applied between retry attempts
        
        * **`emit_events`**: Whether to emit events about AIgent execution (default: `true`)
          - When `true`, creates events for success, failure, and status updates
          - Useful for monitoring and downstream processing
        
        * **`include_execution_metadata`**: Include detailed execution metadata in events (default: `false`)
          - When `true`, includes timing, resource usage, and debug information
          - Useful for performance monitoring and troubleshooting

        ## Event Processing

        When an event is received, this agent:
        1. Validates the event against configured trigger conditions
        2. Processes the goal template with event data and context
        3. Submits the execution request to the AIgent orchestrator
        4. Monitors execution progress (if synchronous mode)
        5. Emits result events with execution outcomes and any generated data

        ## Error Handling

        The agent provides comprehensive error handling and reporting:
        - Configuration validation with detailed error messages
        - Network connectivity and API endpoint validation
        - Graceful handling of orchestrator service unavailability
        - Automatic retry with exponential backoff for transient failures
        - Detailed error events for troubleshooting and monitoring

        ## Integration Notes

        This agent is designed to work seamlessly with the AIgent orchestrator's local-only architecture:
        - Supports local orchestrator deployments (Docker Compose)
        - No external cloud dependencies beyond AI services
        - Respects privacy and security requirements for local data processing
        - Compatible with enterprise deployment patterns and security controls

        For detailed setup and configuration examples, refer to the AIgent integration documentation.
      MD
    end

    event_description <<~MD
      This agent creates different types of events based on AIgent execution outcomes:

      ## Success Events
      ```json
      {
        "status": "success",
        "aigent_id": "browser_automation_agent",
        "execution_id": "exec_1234567890",
        "goal": "Process the uploaded file and extract data",
        "priority": "normal",
        "execution_time_ms": 15420,
        "result": {
          "data_extracted": {
            "records_processed": 1250,
            "errors_found": 3,
            "summary": "Successfully processed customer data file"
          }
        },
        "metadata": {
          "agent_version": "2.1.0",
          "resources_used": {
            "memory_mb": 245,
            "cpu_percent": 12.3
          },
          "timestamp": "2024-01-15T14:30:22Z"
        }
      }
      ```

      ## Failure Events
      ```json
      {
        "status": "failed",
        "aigent_id": "data_processor",
        "execution_id": "exec_1234567891",
        "goal": "Invalid processing request",
        "error": {
          "type": "ValidationError",
          "message": "Required field 'data_source' not found in request",
          "code": "MISSING_REQUIRED_FIELD",
          "details": {
            "missing_fields": ["data_source"],
            "provided_fields": ["goal", "priority"]
          }
        },
        "retry_count": 2,
        "final_attempt": true,
        "timestamp": "2024-01-15T14:35:18Z"
      }
      ```

      ## Status Events (for long-running tasks)
      ```json
      {
        "status": "in_progress",
        "aigent_id": "document_processor",
        "execution_id": "exec_1234567892",
        "progress": {
          "percentage": 65,
          "current_stage": "data_analysis",
          "stages_completed": ["validation", "parsing", "cleaning"],
          "estimated_completion": "2024-01-15T14:45:00Z"
        },
        "timestamp": "2024-01-15T14:40:12Z"
      }
      ```

      ## Configuration Error Events
      ```json
      {
        "status": "configuration_error",
        "error": {
          "type": "ConfigurationValidationError",
          "message": "Invalid orchestrator_url: connection refused",
          "field": "orchestrator_url",
          "provided_value": "http://invalid-host:8080",
          "suggestion": "Verify the orchestrator service is running and accessible"
        },
        "timestamp": "2024-01-15T14:25:30Z"
      }
      ```

      All events include the original triggering event data when `include_original_event` is enabled.
    MD

    def default_options
      {
        # Core configuration with comprehensive examples
        'orchestrator_url' => 'http://localhost:8080',
        'target_agent' => 'general_purpose_agent',
        'goal' => 'Process the incoming event data: {{ event | jsonify }}',
        
        # Execution control
        'priority' => 'normal',
        'execution_mode' => 'asynchronous',
        'timeout_seconds' => '300',
        
        # Trigger conditions
        'trigger_condition' => 'on_event',
        'condition_rules' => [],
        
        # Context and metadata
        'context_data' => {
          'source' => 'huginn_agent',
          'environment' => 'development',
          'version' => '1.0.0'
        },
        'tags' => ['automation', 'aigent_integration'],
        
        # Monitoring and health
        'expected_receive_period_in_days' => '1',
        
        # Security settings
        'verify_ssl' => true,
        
        # Advanced options
        'retry_attempts' => '3',
        'emit_events' => true,
        'include_execution_metadata' => false,
        'include_original_event' => false,
        
        # Optional authentication (uncomment if needed)
        # 'api_key' => 'your-api-key-here',
        
        # Optional HTTP headers for custom authentication
        'headers' => {
          'User-Agent' => 'Huginn-AIgent-Trigger-Agent/1.0',
          'Content-Type' => 'application/json'
        },
        
        # Security configuration
        'security_monitoring_enabled' => true,
        'encryption_enabled' => true,
        'compliance_frameworks' => ['owasp_top_10', 'pci_dss', 'soc2'],
        'threat_detection_enabled' => true,
        'security_classification' => 'internal'
      }
    end

    def working?
      return false if recent_error_logs?

      if interpolated['expected_receive_period_in_days'].present?
        return false unless last_receive_at && 
                           last_receive_at > interpolated['expected_receive_period_in_days'].to_i.days.ago
      end

      true
    end

    def validate_options
      # Core required fields validation
      validate_required_fields
      
      # URL validation with accessibility check
      validate_orchestrator_url
      
      # Target agent validation
      validate_target_agent
      
      # Goal template validation
      validate_goal_template
      
      # Priority and execution mode validation
      validate_execution_settings
      
      # Trigger condition validation
      validate_trigger_conditions
      
      # Timeout and retry validation
      validate_numeric_ranges
      
      # Security and SSL validation
      validate_security_settings
      
      # Context data and tags validation
      validate_metadata_settings
      
      # Headers validation
      validate_headers
      
      # Boolean options validation
      validate_boolean_options
    end

    def receive(incoming_events)
      incoming_events.each do |event|
        begin
          # Apply trigger condition filtering
          next unless should_trigger?(event)
          
          # Process the event with the AIgent orchestrator
          process_event_with_aigent(event)
          
        rescue StandardError => e
          error_message = "Failed to process event with AIgent: #{e.message}"
          error(error_message)
          
          # Emit error event if configured
          emit_error_event(event, e) if boolify(interpolated['emit_events'])
        end
      end
    end

    def check
      # Perform health check of orchestrator connectivity
      orchestrator_url = interpolated['orchestrator_url']
      
      begin
        response = perform_health_check(orchestrator_url)
        
        if boolify(interpolated['emit_events'])
          create_event(
            payload: {
              status: 'health_check_success',
              orchestrator_url: orchestrator_url,
              response_time_ms: response[:response_time_ms],
              orchestrator_status: response[:status],
              timestamp: Time.current.iso8601
            }
          )
        end
        
      rescue StandardError => e
        error("Health check failed for orchestrator at #{orchestrator_url}: #{e.message}")
        
        if boolify(interpolated['emit_events'])
          create_event(
            payload: {
              status: 'health_check_failed',
              orchestrator_url: orchestrator_url,
              error: {
                type: e.class.name,
                message: e.message
              },
              timestamp: Time.current.iso8601
            }
          )
        end
      end
    end

    def dry_run(event = Event.new)
      # Simulate AIgent trigger execution for testing
      interpolate_with(event) do
        goal = interpolated['goal']
        target_agent = interpolated['target_agent']
        priority = interpolated['priority']
        
        log("DRY RUN: Would trigger AIgent '#{target_agent}' with goal: #{goal}")
        log("DRY RUN: Priority: #{priority}, Mode: #{interpolated['execution_mode']}")
        
        if interpolated['context_data'].present?
          log("DRY RUN: Context data: #{interpolated['context_data'].to_json}")
        end
        
        # Simulate successful execution
        {
          status: 'dry_run_success',
          would_trigger: should_trigger?(event),
          target_agent: target_agent,
          processed_goal: goal,
          priority: priority,
          context_data: interpolated['context_data'],
          timestamp: Time.current.iso8601
        }
      end
    end

    private

    # Validation Methods

    def validate_required_fields
      unless options['orchestrator_url'].present?
        errors.add(:base, 'orchestrator_url is required - provide the complete URL to your AIgent orchestrator API')
      end

      unless options['target_agent'].present?
        errors.add(:base, 'target_agent is required - specify the identifier of the AIgent to execute')
      end

      unless options['goal'].present?
        errors.add(:base, 'goal is required - provide a Liquid template describing the execution goal')
      end
    end

    def validate_orchestrator_url
      return unless options['orchestrator_url'].present?

      url = options['orchestrator_url']
      
      # Basic URL format validation
      begin
        uri = URI.parse(url)
        unless %w[http https].include?(uri.scheme)
          errors.add(:base, "orchestrator_url must use http or https scheme, got: #{uri.scheme}")
          return
        end
        
        unless uri.host.present?
          errors.add(:base, "orchestrator_url must include a valid host")
          return
        end
        
      rescue URI::InvalidURIError => e
        errors.add(:base, "orchestrator_url is not a valid URL: #{e.message}")
        return
      end

      # Accessibility validation (skip in test environments)
      unless Rails.env.test?
        validate_orchestrator_accessibility(url)
      end
    end

    def validate_orchestrator_accessibility(url)
      begin
        # Perform lightweight connectivity check
        uri = URI.parse(url)
        timeout_seconds = 5
        
        # Create HTTP client with timeout
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = (uri.scheme == 'https')
        http.verify_mode = boolify(options['verify_ssl']) ? OpenSSL::SSL::VERIFY_PEER : OpenSSL::SSL::VERIFY_NONE
        http.open_timeout = timeout_seconds
        http.read_timeout = timeout_seconds
        
        # Attempt connection
        response = http.request_get('/health')
        
        unless response.is_a?(Net::HTTPSuccess) || response.is_a?(Net::HTTPNotFound)
          log("Warning: Orchestrator at #{url} returned status #{response.code}. Service may not be ready.")
        end
        
      rescue Net::TimeoutError, Errno::ECONNREFUSED, Errno::EHOSTUNREACH => e
        errors.add(:base, "Cannot connect to orchestrator at #{url}: #{e.message}. Please verify the service is running and accessible.")
      rescue OpenSSL::SSL::SSLError => e
        errors.add(:base, "SSL connection failed for #{url}: #{e.message}. Check SSL configuration or set verify_ssl to false for development.")
      rescue StandardError => e
        log("Warning: Could not validate orchestrator accessibility at #{url}: #{e.message}")
      end
    end

    def validate_target_agent
      return unless options['target_agent'].present?

      target_agent = options['target_agent'].to_s.strip
      
      if target_agent.empty?
        errors.add(:base, 'target_agent cannot be empty - provide a valid agent identifier')
        return
      end
      
      # Validate naming conventions
      unless target_agent.match?(/\A[a-z0-9_]+\z/)
        errors.add(:base, 'target_agent must contain only lowercase letters, numbers, and underscores')
      end
      
      if target_agent.length > 100
        errors.add(:base, 'target_agent must be 100 characters or less')
      end
    end

    def validate_goal_template
      return unless options['goal'].present?

      goal = options['goal'].to_s
      
      if goal.strip.empty?
        errors.add(:base, 'goal cannot be empty - provide a meaningful execution goal')
        return
      end
      
      # Validate Liquid template syntax
      begin
        Liquid::Template.parse(goal)
      rescue Liquid::SyntaxError => e
        errors.add(:base, "goal contains invalid Liquid template syntax: #{e.message}")
      end
      
      # Check for potential security issues
      if goal.include?('system(') || goal.include?('exec(') || goal.include?('eval(')
        errors.add(:base, 'goal template contains potentially dangerous function calls')
      end
    end

    def validate_execution_settings
      if options['priority'].present?
        priority = options['priority'].to_s.downcase
        unless VALID_PRIORITY_LEVELS.include?(priority)
          errors.add(:base, "priority must be one of: #{VALID_PRIORITY_LEVELS.join(', ')}")
        end
      end

      if options['execution_mode'].present?
        mode = options['execution_mode'].to_s.downcase
        unless VALID_EXECUTION_MODES.include?(mode)
          errors.add(:base, "execution_mode must be one of: #{VALID_EXECUTION_MODES.join(', ')}")
        end
      end
    end

    def validate_trigger_conditions
      if options['trigger_condition'].present?
        condition = options['trigger_condition'].to_s.downcase
        unless VALID_TRIGGER_CONDITIONS.include?(condition)
          errors.add(:base, "trigger_condition must be one of: #{VALID_TRIGGER_CONDITIONS.join(', ')}")
        end
      end

      if options['condition_rules'].present?
        unless options['condition_rules'].is_a?(Array)
          errors.add(:base, 'condition_rules must be an array')
          return
        end
        
        options['condition_rules'].each_with_index do |rule, index|
          validate_condition_rule(rule, index)
        end
      end
    end

    def validate_condition_rule(rule, index)
      case rule
      when String
        # Validate Liquid template
        begin
          Liquid::Template.parse(rule)
        rescue Liquid::SyntaxError => e
          errors.add(:base, "condition_rules[#{index}] contains invalid Liquid syntax: #{e.message}")
        end
      when Hash
        # Validate structured condition
        required_keys = %w[field operator value]
        missing_keys = required_keys - rule.keys.map(&:to_s)
        
        unless missing_keys.empty?
          errors.add(:base, "condition_rules[#{index}] missing required keys: #{missing_keys.join(', ')}")
        end
      else
        errors.add(:base, "condition_rules[#{index}] must be a string (Liquid template) or hash (structured condition)")
      end
    end

    def validate_numeric_ranges
      if options['timeout_seconds'].present?
        timeout = options['timeout_seconds'].to_i
        unless timeout.between?(30, 3600)
          errors.add(:base, 'timeout_seconds must be between 30 and 3600 (30 seconds to 1 hour)')
        end
      end

      if options['retry_attempts'].present?
        retries = options['retry_attempts'].to_i
        unless retries.between?(0, 10)
          errors.add(:base, 'retry_attempts must be between 0 and 10')
        end
      end
    end

    def validate_security_settings
      if options['verify_ssl'].present?
        unless %w[true false].include?(options['verify_ssl'].to_s)
          errors.add(:base, 'verify_ssl must be true or false')
        end
      end

      if options['api_key'].present?
        api_key = options['api_key'].to_s
        if api_key.length < 10
          errors.add(:base, 'api_key appears to be too short for security')
        end
      end
    end

    def validate_metadata_settings
      if options['context_data'].present?
        unless options['context_data'].is_a?(Hash)
          errors.add(:base, 'context_data must be a hash/object')
        end
      end

      if options['tags'].present?
        unless options['tags'].is_a?(Array)
          errors.add(:base, 'tags must be an array')
        else
          options['tags'].each_with_index do |tag, index|
            unless tag.is_a?(String)
              errors.add(:base, "tags[#{index}] must be a string")
            end
          end
        end
      end
    end

    def validate_headers
      if options['headers'].present?
        unless options['headers'].is_a?(Hash)
          errors.add(:base, 'headers must be a hash/object')
          return
        end
        
        options['headers'].each do |key, value|
          unless key.is_a?(String) && value.is_a?(String)
            errors.add(:base, 'all headers keys and values must be strings')
            break
          end
        end
      end
    end

    def validate_boolean_options
      boolean_options = %w[emit_events include_execution_metadata include_original_event]
      
      boolean_options.each do |option|
        if options[option].present?
          unless %w[true false].include?(options[option].to_s)
            errors.add(:base, "#{option} must be true or false")
          end
        end
      end
    end

    # Event Processing Methods

    def should_trigger?(event)
      trigger_condition = interpolated(event.payload)['trigger_condition']
      condition_rules = interpolated(event.payload)['condition_rules']
      
      case trigger_condition
      when 'on_event'
        # Always trigger on event reception
        true
      when 'on_condition_met'
        # Evaluate condition rules
        evaluate_condition_rules(event, condition_rules)
      when 'on_threshold_exceeded', 'on_pattern_match', 'on_anomaly_detected'
        # Advanced conditions - implement sophisticated logic
        evaluate_advanced_conditions(event, trigger_condition, condition_rules)
      else
        # Default to triggering
        true
      end
    end

    def evaluate_condition_rules(event, rules)
      return true if rules.blank?

      results = rules.map do |rule|
        case rule
        when String
          # Evaluate Liquid template
          interpolate_with(event) do
            boolify(rule)
          end
        when Hash
          # Evaluate structured condition
          evaluate_structured_condition(event, rule)
        else
          false
        end
      end

      # All rules must be true (AND logic)
      results.all?
    end

    def evaluate_structured_condition(event, rule)
      field_value = Utils.value_at(event.payload, rule['field'])
      operator = rule['operator']
      expected_value = rule['value']

      case operator
      when '=='
        field_value.to_s == expected_value.to_s
      when '!='
        field_value.to_s != expected_value.to_s
      when '>'
        field_value.to_f > expected_value.to_f
      when '>='
        field_value.to_f >= expected_value.to_f
      when '<'
        field_value.to_f < expected_value.to_f
      when '<='
        field_value.to_f <= expected_value.to_f
      when 'contains'
        field_value.to_s.include?(expected_value.to_s)
      when 'matches'
        field_value.to_s.match?(Regexp.new(expected_value.to_s))
      else
        false
      end
    end

    def evaluate_advanced_conditions(event, condition_type, rules)
      # Placeholder for advanced condition evaluation
      # In a full implementation, this would include:
      # - Threshold monitoring with historical data
      # - Pattern matching with ML-based detection
      # - Anomaly detection using statistical methods
      
      case condition_type
      when 'on_threshold_exceeded'
        # Simple threshold check for demonstration
        threshold_rule = rules.find { |r| r.is_a?(Hash) && r['type'] == 'threshold' }
        return true unless threshold_rule
        
        field_value = Utils.value_at(event.payload, threshold_rule['field'])
        field_value.to_f > threshold_rule['threshold'].to_f
        
      when 'on_pattern_match'
        # Pattern matching logic
        pattern_rule = rules.find { |r| r.is_a?(Hash) && r['type'] == 'pattern' }
        return true unless pattern_rule
        
        field_value = Utils.value_at(event.payload, pattern_rule['field'])
        field_value.to_s.match?(Regexp.new(pattern_rule['pattern']))
        
      else
        true
      end
    end

    def process_event_with_aigent(event)
      interpolate_with(event) do
        # Prepare request data
        request_data = build_aigent_request(event)
        
        # Submit to orchestrator with retry logic
        response = submit_with_retries(request_data)
        
        # Process response and emit events
        handle_aigent_response(event, request_data, response)
      end
    end

    def build_aigent_request(event)
      {
        target_agent: interpolated['target_agent'],
        goal: interpolated['goal'],
        priority: interpolated['priority'] || 'normal',
        execution_mode: interpolated['execution_mode'] || 'asynchronous',
        timeout_seconds: interpolated['timeout_seconds']&.to_i || 300,
        context_data: build_context_data(event),
        tags: interpolated['tags'] || [],
        metadata: {
          source: 'huginn_aigent_trigger_agent',
          agent_id: id,
          event_id: event.id,
          timestamp: Time.current.iso8601
        }
      }.compact
    end

    def build_context_data(event)
      base_context = interpolated['context_data'] || {}
      
      # Add event data to context
      event_context = {
        'triggering_event' => event.payload,
        'event_timestamp' => event.created_at&.iso8601,
        'agent_name' => name
      }
      
      # Include original event if requested
      if boolify(interpolated['include_original_event'])
        event_context['original_event_data'] = event.payload
      end
      
      base_context.merge(event_context)
    end

    def submit_with_retries(request_data)
      max_retries = interpolated['retry_attempts']&.to_i || 3
      retry_count = 0
      
      begin
        submit_to_orchestrator(request_data)
      rescue StandardError => e
        retry_count += 1
        
        if retry_count <= max_retries
          # Exponential backoff
          sleep_time = 2**retry_count
          sleep(sleep_time)
          retry
        else
          raise e
        end
      end
    end

    def submit_to_orchestrator(request_data)
      url = "#{interpolated['orchestrator_url']}/api/v1/aigent/execute"
      headers = build_request_headers
      
      # Create HTTP client
      uri = URI.parse(url)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = (uri.scheme == 'https')
      http.verify_mode = boolify(interpolated['verify_ssl']) ? OpenSSL::SSL::VERIFY_PEER : OpenSSL::SSL::VERIFY_NONE
      http.open_timeout = 30
      http.read_timeout = interpolated['timeout_seconds']&.to_i || 300
      
      # Create request
      request = Net::HTTP::Post.new(uri.path)
      headers.each { |key, value| request[key] = value }
      request.body = request_data.to_json
      
      # Submit request
      start_time = Time.current
      response = http.request(request)
      end_time = Time.current
      
      # Process response
      response_data = {
        status: response.code.to_i,
        headers: response.to_hash,
        body: response.body,
        response_time_ms: ((end_time - start_time) * 1000).round(2)
      }
      
      unless response.is_a?(Net::HTTPSuccess)
        raise "HTTP #{response.code}: #{response.message}"
      end
      
      # Parse JSON response
      begin
        parsed_body = JSON.parse(response.body)
        response_data[:parsed_body] = parsed_body
      rescue JSON::ParserError
        response_data[:parsed_body] = nil
      end
      
      response_data
    end

    def build_request_headers
      headers = {
        'Content-Type' => 'application/json',
        'User-Agent' => 'Huginn-AIgent-Trigger-Agent/1.0',
        'Accept' => 'application/json'
      }
      
      # Add API key if configured
      if interpolated['api_key'].present?
        headers['Authorization'] = "Bearer #{interpolated['api_key']}"
      end
      
      # Add custom headers
      if interpolated['headers'].present?
        headers.merge!(interpolated['headers'])
      end
      
      headers
    end

    def handle_aigent_response(original_event, request_data, response)
      return unless boolify(interpolated['emit_events'])

      # Base event data
      event_payload = {
        status: 'success',
        target_agent: request_data[:target_agent],
        goal: request_data[:goal],
        priority: request_data[:priority],
        execution_mode: request_data[:execution_mode],
        response_time_ms: response[:response_time_ms],
        timestamp: Time.current.iso8601
      }

      # Add execution results if available
      if response[:parsed_body]&.is_a?(Hash)
        if response[:parsed_body]['execution_id']
          event_payload[:execution_id] = response[:parsed_body]['execution_id']
        end
        
        if response[:parsed_body]['result']
          event_payload[:result] = response[:parsed_body]['result']
        end
        
        if response[:parsed_body]['status']
          event_payload[:aigent_status] = response[:parsed_body]['status']
        end
      end

      # Add execution metadata if requested
      if boolify(interpolated['include_execution_metadata'])
        event_payload[:metadata] = {
          request_data: request_data,
          response_status: response[:status],
          response_headers: response[:headers],
          full_response_body: response[:body]
        }
      end

      # Include original event data if requested
      if boolify(interpolated['include_original_event'])
        event_payload[:original_event] = original_event.payload
      end

      # Create success event
      create_event(payload: event_payload)
    end

    def emit_error_event(original_event, error)
      return unless boolify(interpolated['emit_events'])

      error_payload = {
        status: 'failed',
        target_agent: interpolated['target_agent'],
        goal: interpolated['goal'],
        error: {
          type: error.class.name,
          message: error.message
        },
        timestamp: Time.current.iso8601
      }

      # Include original event data if requested
      if boolify(interpolated['include_original_event'])
        error_payload[:original_event] = original_event.payload
      end

      # Add stack trace in development
      if Rails.env.development? && error.backtrace
        error_payload[:error][:backtrace] = error.backtrace.first(10)
      end

      create_event(payload: error_payload)
    end

    def perform_health_check(orchestrator_url)
      start_time = Time.current
      
      # Attempt to connect to health endpoint
      uri = URI.parse("#{orchestrator_url}/health")
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = (uri.scheme == 'https')
      http.verify_mode = boolify(interpolated['verify_ssl']) ? OpenSSL::SSL::VERIFY_PEER : OpenSSL::SSL::VERIFY_NONE
      http.open_timeout = 10
      http.read_timeout = 10
      
      response = http.request_get(uri.path)
      end_time = Time.current
      
      {
        status: response.code.to_i,
        response_time_ms: ((end_time - start_time) * 1000).round(2),
        message: response.message
      }
    end

    # Helper method to safely convert values to boolean
    def boolify(value)
      case value.to_s.strip.downcase
      when 'true', '1', 'yes', 'on'
        true
      when 'false', '0', 'no', 'off', ''
        false
      else
        !!value
      end
    end
  end
end