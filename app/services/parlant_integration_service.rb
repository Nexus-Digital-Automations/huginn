# frozen_string_literal: true

require 'httparty'
require 'logger'

##
# Parlant Integration Service for Huginn
# 
# Provides conversational AI validation for all Huginn monitoring, alerting, 
# and observability functions. Implements function-level Parlant integration
# to ensure AI execution precision and safety guardrails.
#
# @example Basic Usage
#   service = ParlantIntegrationService.new
#   result = service.validate_operation(
#     operation: "agent_check",
#     context: { agent_id: 123, agent_type: "WeatherAgent" },
#     user_intent: "Check weather conditions for monitoring"
#   )
#
# @author Parlant Integration Team
# @since 1.0.0
class ParlantIntegrationService
  include HTTParty

  # Parlant API Configuration
  PARLANT_API_BASE_URL = ENV.fetch('PARLANT_API_BASE_URL', 'http://localhost:8000').freeze
  PARLANT_API_TIMEOUT = ENV.fetch('PARLANT_API_TIMEOUT_MS', '10000').to_i / 1000.0
  PARLANT_ENABLED = ENV.fetch('PARLANT_ENABLED', 'true') == 'true'
  PARLANT_CACHE_ENABLED = ENV.fetch('PARLANT_CACHE_ENABLED', 'true') == 'true'
  PARLANT_CACHE_MAX_AGE = ENV.fetch('PARLANT_CACHE_MAX_AGE_MS', '300000').to_i / 1000.0

  # Risk Level Definitions for Huginn Operations
  RISK_LEVELS = {
    low: %w[agent_status check_health log_info],
    medium: %w[agent_check receive_events build_event update_config],
    high: %w[create_event execute_agent delete_agent system_command],
    critical: %w[mass_delete system_shutdown emergency_stop]
  }.freeze

  # Operation Categories for Huginn
  OPERATION_CATEGORIES = {
    monitoring: %w[agent_check system_health error_tracking performance_metrics],
    alerting: %w[create_alert send_notification escalate_alert],
    observability: %w[log_event trace_execution metric_collection],
    configuration: %w[update_agent_config modify_scenario change_schedule],
    execution: %w[run_agent trigger_event process_webhook]
  }.freeze

  attr_reader :logger, :cache, :metrics

  ##
  # Initialize Parlant Integration Service
  #
  # Sets up HTTP client, caching, logging, and performance metrics
  # for conversational AI validation of Huginn operations.
  def initialize
    @logger = Rails.logger || Logger.new(STDOUT)
    @cache = PARLANT_CACHE_ENABLED ? Rails.cache : nil
    @metrics = initialize_metrics
    @operation_id_counter = 0
    @conversation_context = {}

    configure_http_client
    log_service_initialization
  end

  ##
  # Validate Operation with Conversational AI
  #
  # Core method for validating Huginn operations through Parlant's
  # conversational AI engine. Provides safety guardrails and intent
  # verification for all monitoring and alerting functions.
  #
  # @param operation [String] The operation being performed
  # @param context [Hash] Operation context including agent details
  # @param user_intent [String] Natural language description of user intent
  # @param risk_assessment [Hash] Optional custom risk assessment
  # @return [Hash] Validation result with approval status and metadata
  #
  # @example Agent Check Validation
  #   result = validate_operation(
  #     operation: "agent_check",
  #     context: { 
  #       agent_id: 123, 
  #       agent_type: "WeatherAgent",
  #       user_id: current_user.id 
  #     },
  #     user_intent: "Check weather monitoring agent status"
  #   )
  #
  # @example Event Creation Validation
  #   result = validate_operation(
  #     operation: "create_event",
  #     context: { 
  #       event_type: "weather_alert",
  #       payload: { temperature: 95, location: "NYC" },
  #       agent_id: 123
  #     },
  #     user_intent: "Create high temperature alert for monitoring"
  #   )
  def validate_operation(operation:, context: {}, user_intent: nil, risk_assessment: nil)
    operation_id = generate_operation_id
    start_time = Time.current

    log_validation_start(operation_id, operation, context, user_intent)

    return bypass_result(operation_id, "Parlant disabled") unless PARLANT_ENABLED

    begin
      # Check cache first for performance optimization
      cache_key = generate_cache_key(operation, context, user_intent)
      cached_result = get_cached_result(cache_key)
      return add_operation_metadata(cached_result, operation_id, start_time) if cached_result

      # Perform risk assessment
      risk_level = risk_assessment || assess_operation_risk(operation, context)
      
      # Build validation request
      validation_request = build_validation_request(
        operation, context, user_intent, risk_level, operation_id
      )

      # Execute conversational validation
      validation_result = execute_parlant_validation(validation_request, operation_id)

      # Process and enhance result
      enhanced_result = process_validation_result(validation_result, risk_level, operation_id)

      # Cache successful validations
      cache_validation_result(cache_key, enhanced_result) if enhanced_result[:approved]

      # Update metrics
      record_validation_metrics(operation_id, enhanced_result, Time.current - start_time)

      log_validation_completion(operation_id, enhanced_result)
      add_operation_metadata(enhanced_result, operation_id, start_time)

    rescue StandardError => e
      handle_validation_error(e, operation_id, operation, context)
    end
  end

  ##
  # Validate Agent Check Operation
  #
  # Specialized validation for Huginn agent check operations.
  # Ensures agent monitoring activities align with user intent.
  #
  # @param agent_id [Integer] The agent ID being checked
  # @param agent_type [String] Type of agent (WeatherAgent, RSSAgent, etc.)
  # @param check_context [Hash] Additional check context
  # @return [Hash] Validation result for agent check
  def validate_agent_check(agent_id:, agent_type:, check_context: {})
    context = {
      agent_id: agent_id,
      agent_type: agent_type,
      operation_type: 'scheduled_check',
      **check_context
    }

    validate_operation(
      operation: 'agent_check',
      context: context,
      user_intent: "Perform scheduled monitoring check for #{agent_type} agent #{agent_id}"
    )
  end

  ##
  # Validate Event Creation
  #
  # Validates event creation operations through conversational AI.
  # Ensures event data and triggers align with monitoring objectives.
  #
  # @param event_data [Hash] Event payload and metadata
  # @param agent_context [Hash] Creating agent information
  # @return [Hash] Validation result for event creation
  def validate_event_creation(event_data:, agent_context: {})
    context = {
      event_type: event_data[:event_type] || 'generic',
      payload_size: event_data.to_s.length,
      agent_id: agent_context[:agent_id],
      **agent_context
    }

    validate_operation(
      operation: 'create_event',
      context: context,
      user_intent: "Create monitoring event: #{event_data[:event_type] || 'system event'}"
    )
  end

  ##
  # Validate Error Monitoring Operation
  #
  # Validates error monitoring and alerting operations.
  # Ensures error handling aligns with monitoring policies.
  #
  # @param error_context [Hash] Error details and severity
  # @param monitoring_action [String] Action being taken
  # @return [Hash] Validation result for error monitoring
  def validate_error_monitoring(error_context:, monitoring_action:)
    context = {
      error_severity: error_context[:severity] || 'medium',
      error_type: error_context[:error_type],
      affected_agents: error_context[:affected_agents] || [],
      monitoring_action: monitoring_action
    }

    validate_operation(
      operation: 'error_monitoring',
      context: context,
      user_intent: "Monitor and respond to #{context[:error_severity]} severity error"
    )
  end

  ##
  # Get Service Health Status
  #
  # Returns comprehensive health status of Parlant integration
  # including API connectivity, cache status, and performance metrics.
  #
  # @return [Hash] Service health status and metrics
  def health_status
    {
      parlant_enabled: PARLANT_ENABLED,
      api_connectivity: check_api_connectivity,
      cache_status: check_cache_status,
      performance_metrics: get_performance_metrics,
      recent_validations: get_recent_validation_stats,
      timestamp: Time.current.iso8601
    }
  end

  private

  ##
  # Configure HTTP Client for Parlant API
  #
  # Sets up HTTParty configuration with timeouts, headers,
  # and error handling for Parlant API communication.
  def configure_http_client
    self.class.base_uri PARLANT_API_BASE_URL
    self.class.default_timeout PARLANT_API_TIMEOUT
    self.class.default_options.update(
      headers: {
        'Content-Type' => 'application/json',
        'Accept' => 'application/json',
        'User-Agent' => 'Huginn-Parlant-Integration/1.0.0'
      }
    )
  end

  ##
  # Initialize Performance Metrics
  #
  # Sets up metrics tracking for validation performance,
  # success rates, and response times.
  #
  # @return [Hash] Initialized metrics structure
  def initialize_metrics
    {
      total_validations: 0,
      successful_validations: 0,
      failed_validations: 0,
      average_response_time: 0.0,
      cache_hits: 0,
      cache_misses: 0
    }
  end

  ##
  # Assess Operation Risk Level
  #
  # Evaluates the risk level of a Huginn operation based on
  # operation type, context, and potential impact.
  #
  # @param operation [String] The operation being assessed
  # @param context [Hash] Operation context
  # @return [Hash] Risk assessment with level and factors
  def assess_operation_risk(operation, context)
    risk_level = determine_base_risk_level(operation)
    risk_factors = analyze_risk_factors(operation, context)
    
    {
      level: risk_level,
      factors: risk_factors,
      requires_approval: risk_level.in?(%w[high critical]),
      assessment_time: Time.current.iso8601
    }
  end

  ##
  # Determine Base Risk Level
  #
  # Maps operations to base risk levels based on potential impact.
  #
  # @param operation [String] The operation to assess
  # @return [String] Risk level (low, medium, high, critical)
  def determine_base_risk_level(operation)
    RISK_LEVELS.each do |level, operations|
      return level.to_s if operation.in?(operations)
    end
    'medium' # Default for unmapped operations
  end

  ##
  # Analyze Risk Factors
  #
  # Identifies specific risk factors based on operation context.
  #
  # @param operation [String] The operation being analyzed
  # @param context [Hash] Operation context
  # @return [Array<String>] List of risk factors
  def analyze_risk_factors(operation, context)
    factors = []
    
    factors << 'bulk_operation' if context[:bulk] || (context[:count] && context[:count] > 10)
    factors << 'production_environment' if Rails.env.production?
    factors << 'sensitive_data' if operation.include?('credential') || operation.include?('secret')
    factors << 'system_modification' if operation.include?('delete') || operation.include?('destroy')
    factors << 'external_integration' if context[:external_api] || context[:webhook]
    
    factors
  end

  ##
  # Build Validation Request
  #
  # Constructs request payload for Parlant API validation.
  #
  # @param operation [String] Operation being validated
  # @param context [Hash] Operation context
  # @param user_intent [String] User intent description
  # @param risk_assessment [Hash] Risk assessment results
  # @param operation_id [String] Unique operation identifier
  # @return [Hash] Validation request payload
  def build_validation_request(operation, context, user_intent, risk_assessment, operation_id)
    {
      operation_id: operation_id,
      operation: operation,
      context: sanitize_context(context),
      user_intent: user_intent || "Perform #{operation} operation",
      risk_assessment: risk_assessment,
      system_info: {
        service: 'huginn',
        environment: Rails.env,
        timestamp: Time.current.iso8601,
        user_agent: 'Huginn-Parlant-Integration'
      },
      validation_settings: {
        require_approval: risk_assessment[:requires_approval],
        timeout_ms: (PARLANT_API_TIMEOUT * 1000).to_i,
        cache_enabled: PARLANT_CACHE_ENABLED
      }
    }
  end

  ##
  # Execute Parlant Validation
  #
  # Makes HTTP request to Parlant API for conversational validation.
  #
  # @param request_payload [Hash] Validation request data
  # @param operation_id [String] Operation identifier for logging
  # @return [Hash] Parlant API response
  def execute_parlant_validation(request_payload, operation_id)
    @logger.debug "[ParlantIntegration] [#{operation_id}] Executing validation", {
      operation: request_payload[:operation],
      risk_level: request_payload[:risk_assessment][:level]
    }

    response = self.class.post('/api/v1/validate', {
      body: request_payload.to_json,
      headers: build_request_headers(operation_id)
    })

    handle_api_response(response, operation_id)
  end

  ##
  # Handle API Response
  #
  # Processes Parlant API response and handles various response scenarios.
  #
  # @param response [HTTParty::Response] API response
  # @param operation_id [String] Operation identifier
  # @return [Hash] Processed response data
  def handle_api_response(response, operation_id)
    case response.code
    when 200
      response.parsed_response
    when 400
      raise StandardError, "Bad request: #{response.body}"
    when 401
      raise StandardError, "Unauthorized: Check API key configuration"
    when 404
      raise StandardError, "Parlant API endpoint not found"
    when 429
      raise StandardError, "Rate limit exceeded"
    when 500..599
      raise StandardError, "Parlant API server error: #{response.code}"
    else
      raise StandardError, "Unexpected response: #{response.code} #{response.body}"
    end
  end

  ##
  # Process Validation Result
  #
  # Enhances and standardizes validation results from Parlant API.
  #
  # @param validation_result [Hash] Raw validation result
  # @param risk_assessment [Hash] Risk assessment data
  # @param operation_id [String] Operation identifier
  # @return [Hash] Enhanced validation result
  def process_validation_result(validation_result, risk_assessment, operation_id)
    {
      approved: validation_result['approved'] || false,
      confidence: validation_result['confidence'] || 0.0,
      reasoning: validation_result['reasoning'] || 'No reasoning provided',
      risk_level: risk_assessment[:level],
      operation_id: operation_id,
      validation_metadata: {
        parlant_session_id: validation_result['session_id'],
        response_time_ms: validation_result['response_time_ms'],
        model_version: validation_result['model_version'],
        validation_timestamp: Time.current.iso8601
      },
      recommendations: validation_result['recommendations'] || [],
      warnings: validation_result['warnings'] || []
    }
  end

  ##
  # Cache Validation Result
  #
  # Stores successful validation results in cache for performance.
  #
  # @param cache_key [String] Cache key
  # @param result [Hash] Validation result to cache
  def cache_validation_result(cache_key, result)
    return unless @cache && result[:approved]

    @cache.write(cache_key, result, expires_in: PARLANT_CACHE_MAX_AGE)
    @metrics[:cache_misses] += 1
    
    @logger.debug "[ParlantIntegration] Cached validation result", { cache_key: cache_key }
  end

  ##
  # Get Cached Result
  #
  # Retrieves cached validation result if available and valid.
  #
  # @param cache_key [String] Cache key to check
  # @return [Hash, nil] Cached result or nil if not found
  def get_cached_result(cache_key)
    return nil unless @cache

    result = @cache.read(cache_key)
    if result
      @metrics[:cache_hits] += 1
      @logger.debug "[ParlantIntegration] Cache hit", { cache_key: cache_key }
    end
    
    result
  end

  ##
  # Generate Cache Key
  #
  # Creates deterministic cache key from operation parameters.
  #
  # @param operation [String] Operation name
  # @param context [Hash] Operation context
  # @param user_intent [String] User intent
  # @return [String] Cache key
  def generate_cache_key(operation, context, user_intent)
    key_data = {
      operation: operation,
      context_hash: Digest::SHA256.hexdigest(context.to_json),
      intent_hash: Digest::SHA256.hexdigest(user_intent.to_s)
    }
    
    "parlant_validation:#{Digest::SHA256.hexdigest(key_data.to_json)}"
  end

  ##
  # Generate Operation ID
  #
  # Creates unique identifier for operation tracking.
  #
  # @return [String] Unique operation ID
  def generate_operation_id
    @operation_id_counter += 1
    "huginn_parlant_#{Time.current.to_i}_#{@operation_id_counter}"
  end

  ##
  # Sanitize Context
  #
  # Removes sensitive data from context for API transmission.
  #
  # @param context [Hash] Raw context data
  # @return [Hash] Sanitized context
  def sanitize_context(context)
    sanitized = context.dup
    
    # Remove sensitive fields
    %w[password secret token api_key credential].each do |sensitive_key|
      sanitized.delete(sensitive_key)
      sanitized.delete(sensitive_key.to_sym)
    end
    
    # Truncate large payloads
    sanitized.each do |key, value|
      if value.is_a?(String) && value.length > 1000
        sanitized[key] = "#{value[0..997]}..."
      end
    end
    
    sanitized
  end

  ##
  # Build Request Headers
  #
  # Constructs HTTP headers for Parlant API requests.
  #
  # @param operation_id [String] Operation identifier
  # @return [Hash] Request headers
  def build_request_headers(operation_id)
    {
      'X-Operation-ID' => operation_id,
      'X-Service' => 'huginn',
      'X-Environment' => Rails.env,
      'Authorization' => "Bearer #{ENV['PARLANT_API_KEY']}"
    }.compact
  end

  ##
  # Record Validation Metrics
  #
  # Updates performance metrics after validation completion.
  #
  # @param operation_id [String] Operation identifier
  # @param result [Hash] Validation result
  # @param duration [Float] Validation duration in seconds
  def record_validation_metrics(operation_id, result, duration)
    @metrics[:total_validations] += 1
    
    if result[:approved]
      @metrics[:successful_validations] += 1
    else
      @metrics[:failed_validations] += 1
    end
    
    # Update average response time
    current_avg = @metrics[:average_response_time]
    total_count = @metrics[:total_validations]
    @metrics[:average_response_time] = ((current_avg * (total_count - 1)) + duration) / total_count
    
    @logger.info "[ParlantIntegration] [#{operation_id}] Metrics updated", {
      total_validations: @metrics[:total_validations],
      success_rate: (@metrics[:successful_validations].to_f / @metrics[:total_validations] * 100).round(2),
      avg_response_time: @metrics[:average_response_time].round(3)
    }
  end

  ##
  # Bypass Result for Disabled Mode
  #
  # Returns approval result when Parlant is disabled.
  #
  # @param operation_id [String] Operation identifier
  # @param reason [String] Bypass reason
  # @return [Hash] Bypass result
  def bypass_result(operation_id, reason)
    {
      approved: true,
      bypassed: true,
      bypass_reason: reason,
      operation_id: operation_id,
      confidence: 1.0,
      reasoning: "Parlant validation bypassed: #{reason}",
      validation_metadata: {
        bypass_timestamp: Time.current.iso8601
      }
    }
  end

  ##
  # Add Operation Metadata
  #
  # Adds timing and operation metadata to validation results.
  #
  # @param result [Hash] Validation result
  # @param operation_id [String] Operation identifier
  # @param start_time [Time] Operation start time
  # @return [Hash] Result with added metadata
  def add_operation_metadata(result, operation_id, start_time)
    result.merge(
      operation_id: operation_id,
      total_duration_ms: ((Time.current - start_time) * 1000).round(2),
      processed_at: Time.current.iso8601
    )
  end

  ##
  # Handle Validation Error
  #
  # Handles errors during validation process with appropriate fallback.
  #
  # @param error [StandardError] The error that occurred
  # @param operation_id [String] Operation identifier
  # @param operation [String] Operation being validated
  # @param context [Hash] Operation context
  # @return [Hash] Error handling result
  def handle_validation_error(error, operation_id, operation, context)
    @logger.error "[ParlantIntegration] [#{operation_id}] Validation failed", {
      error: error.message,
      operation: operation,
      context: context,
      backtrace: error.backtrace&.first(3)
    }

    @metrics[:failed_validations] += 1

    # Return safe default based on risk level
    risk_level = determine_base_risk_level(operation)
    safe_default = risk_level.in?(%w[high critical]) ? false : true

    {
      approved: safe_default,
      error: true,
      error_message: error.message,
      operation_id: operation_id,
      confidence: 0.0,
      reasoning: "Validation failed due to error: #{error.message}",
      validation_metadata: {
        error_timestamp: Time.current.iso8601,
        error_class: error.class.name
      }
    }
  end

  ##
  # Check API Connectivity
  #
  # Tests connection to Parlant API.
  #
  # @return [Hash] Connectivity status
  def check_api_connectivity
    response = self.class.get('/api/v1/health', timeout: 5)
    { 
      connected: response.code == 200, 
      response_time_ms: response.time * 1000,
      last_check: Time.current.iso8601
    }
  rescue StandardError => e
    { 
      connected: false, 
      error: e.message,
      last_check: Time.current.iso8601
    }
  end

  ##
  # Check Cache Status
  #
  # Verifies cache functionality and performance.
  #
  # @return [Hash] Cache status
  def check_cache_status
    return { enabled: false } unless @cache

    {
      enabled: true,
      hits: @metrics[:cache_hits],
      misses: @metrics[:cache_misses],
      hit_rate: calculate_cache_hit_rate
    }
  end

  ##
  # Calculate Cache Hit Rate
  #
  # Computes cache hit rate percentage.
  #
  # @return [Float] Hit rate percentage
  def calculate_cache_hit_rate
    total_requests = @metrics[:cache_hits] + @metrics[:cache_misses]
    return 0.0 if total_requests.zero?
    
    (@metrics[:cache_hits].to_f / total_requests * 100).round(2)
  end

  ##
  # Get Performance Metrics
  #
  # Returns current performance metrics.
  #
  # @return [Hash] Performance metrics
  def get_performance_metrics
    @metrics.merge(
      success_rate: calculate_success_rate,
      cache_hit_rate: calculate_cache_hit_rate
    )
  end

  ##
  # Calculate Success Rate
  #
  # Computes validation success rate percentage.
  #
  # @return [Float] Success rate percentage
  def calculate_success_rate
    return 0.0 if @metrics[:total_validations].zero?
    
    (@metrics[:successful_validations].to_f / @metrics[:total_validations] * 100).round(2)
  end

  ##
  # Get Recent Validation Stats
  #
  # Returns recent validation statistics.
  #
  # @return [Hash] Recent validation stats
  def get_recent_validation_stats
    {
      last_hour_validations: 0, # Would need time-based tracking
      recent_success_rate: calculate_success_rate,
      average_response_time: @metrics[:average_response_time]
    }
  end

  ##
  # Log Service Initialization
  #
  # Logs service startup information.
  def log_service_initialization
    @logger.info "[ParlantIntegration] Service initialized", {
      parlant_enabled: PARLANT_ENABLED,
      api_base_url: PARLANT_API_BASE_URL,
      cache_enabled: PARLANT_CACHE_ENABLED,
      timeout_seconds: PARLANT_API_TIMEOUT,
      environment: Rails.env
    }
  end

  ##
  # Log Validation Start
  #
  # Logs the beginning of a validation operation.
  #
  # @param operation_id [String] Operation identifier
  # @param operation [String] Operation being validated
  # @param context [Hash] Operation context
  # @param user_intent [String] User intent
  def log_validation_start(operation_id, operation, context, user_intent)
    @logger.info "[ParlantIntegration] [#{operation_id}] Validation started", {
      operation: operation,
      context_keys: context.keys,
      user_intent: user_intent,
      timestamp: Time.current.iso8601
    }
  end

  ##
  # Log Validation Completion
  #
  # Logs the completion of a validation operation.
  #
  # @param operation_id [String] Operation identifier
  # @param result [Hash] Validation result
  def log_validation_completion(operation_id, result)
    @logger.info "[ParlantIntegration] [#{operation_id}] Validation completed", {
      approved: result[:approved],
      confidence: result[:confidence],
      risk_level: result[:risk_level],
      bypassed: result[:bypassed] || false,
      timestamp: Time.current.iso8601
    }
  end
end