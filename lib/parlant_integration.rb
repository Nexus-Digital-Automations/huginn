# frozen_string_literal: true

require 'net/http'
require 'json'
require 'uri'
require 'logger'

#
# ParlantIntegration - Ruby HTTP Bridge for Huginn Agent Validation
#
# Provides comprehensive conversational AI validation for Huginn monitoring and automation agents
# implementing function-level wrapping with Parlant's conversational validation engine.
#
# Features:
# - Pre-execution conversational validation of all agent operations
# - Real-time intent verification through natural language processing
# - Safety guardrails and compliance enforcement for monitoring systems
# - Complete conversational audit trail for enterprise requirements
# - HTTP bridge integration with AIgent's Parlant service
#
# Architecture: Ruby HTTP bridge to TypeScript Parlant service
# Security: Enterprise-grade validation with conversational authentication
# Performance: Sub-2000ms validation with intelligent caching (target: <1000ms)
#
module ParlantIntegration
  class ServiceError < StandardError; end
  class ValidationError < ServiceError; end
  class AuthenticationError < ServiceError; end
  class TimeoutError < ServiceError; end

  # Risk level assessment for Huginn agent operations
  module RiskLevel
    MINIMAL = 'MINIMAL'           # Read operations, info queries
    LOW = 'LOW'                   # Basic monitoring, status checks
    MEDIUM = 'MEDIUM'             # Data transformation, notifications
    HIGH = 'HIGH'                 # External API calls, destructive operations
    CRITICAL = 'CRITICAL'         # System modifications, security operations
  end

  # Security classification levels for agent operations
  module SecurityLevel
    PUBLIC = 'PUBLIC'             # No validation required
    INTERNAL = 'INTERNAL'         # Basic validation, logged operations
    CONFIDENTIAL = 'CONFIDENTIAL' # Conversational confirmation required
    RESTRICTED = 'RESTRICTED'     # Multi-step approval with audit trail
    CLASSIFIED = 'CLASSIFIED'     # Multi-party approval with comprehensive audit
  end

  #
  # Core Parlant Integration Service for Huginn
  #
  # Provides HTTP bridge to AIgent's Parlant service for conversational validation
  # of all Huginn agent operations with comprehensive audit trails.
  #
  class Service
    include Singleton

    attr_reader :logger, :config

    def initialize
      @logger = Rails.logger || Logger.new($stdout)
      @config = load_configuration
      @client = create_http_client
      @session_cache = {}
      @validation_cache = {}

      # Initialize performance metrics
      @metrics = {
        total_validations: 0,
        cache_hits: 0,
        average_response_time: 0.0,
        errors: 0
      }

      logger.info "[ParlantIntegration] Service initialized with endpoint: #{@config[:endpoint]}"
    rescue StandardError => e
      logger.error "[ParlantIntegration] Initialization failed: #{e.message}"
      raise ServiceError, "Failed to initialize Parlant integration: #{e.message}"
    end

    #
    # Validate and execute an agent function with conversational approval
    #
    # @param agent [Agent] The Huginn agent instance
    # @param function_name [String] Name of the function being called
    # @param function_params [Hash] Parameters passed to the function
    # @param block [Proc] The actual function to execute after validation
    # @return [Object] Result of the function execution
    # @raise [ValidationError] If validation fails or is rejected
    #
    def validate_and_execute(agent, function_name, function_params = {}, &block)
      operation_id = generate_operation_id
      start_time = Time.now

      logger.info "[ParlantIntegration] Starting validation for #{agent.class.name}##{function_name} [#{operation_id}]"

      begin
        # 1. Risk assessment and classification
        risk_level = assess_risk(agent, function_name, function_params)
        security_level = classify_security(agent, function_name, function_params)

        # 2. Check cache for similar operations
        cache_key = generate_cache_key(agent, function_name, function_params)
        cached_result = get_cached_validation(cache_key, risk_level)
        
        if cached_result
          @metrics[:cache_hits] += 1
          logger.info "[ParlantIntegration] Using cached validation for #{function_name} [#{operation_id}]"
          return execute_with_audit(agent, function_name, cached_result, &block)
        end

        # 3. Create conversational context
        context = build_conversation_context(agent, operation_id)

        # 4. Prepare validation request
        validation_request = {
          operation_id: operation_id,
          agent_type: agent.class.name,
          function_name: function_name,
          function_params: sanitize_params(function_params),
          action_description: generate_action_description(agent, function_name, function_params),
          risk_level: risk_level,
          security_level: security_level,
          context: context,
          timestamp: Time.now.iso8601
        }

        # 5. Send validation request to Parlant service
        validation_result = send_validation_request(validation_request)

        # 6. Cache successful validation
        cache_validation(cache_key, validation_result, risk_level)

        # 7. Execute function with comprehensive audit
        result = execute_with_audit(agent, function_name, validation_result, &block)

        # 8. Update performance metrics
        update_metrics(start_time, true)

        logger.info "[ParlantIntegration] Successfully executed #{function_name} [#{operation_id}] in #{(Time.now - start_time) * 1000}ms"
        result

      rescue ValidationError => e
        logger.error "[ParlantIntegration] Validation failed for #{function_name} [#{operation_id}]: #{e.message}"
        update_metrics(start_time, false)
        raise
      rescue StandardError => e
        logger.error "[ParlantIntegration] Unexpected error in #{function_name} [#{operation_id}]: #{e.message}"
        logger.error e.backtrace.join("\n")
        update_metrics(start_time, false)
        raise ServiceError, "Parlant validation failed: #{e.message}"
      end
    end

    #
    # Create audit trail entry for agent operation
    #
    # @param agent [Agent] The Huginn agent instance
    # @param operation [String] Operation performed
    # @param result [Hash] Operation result
    # @param metadata [Hash] Additional metadata
    #
    def create_audit_trail(agent, operation, result, metadata = {})
      audit_entry = {
        timestamp: Time.now.iso8601,
        agent_id: agent.id,
        agent_type: agent.class.name,
        operation: operation,
        user_id: agent.user_id,
        result_status: result[:status] || 'unknown',
        metadata: metadata
      }

      # Send audit trail to central logging service
      Thread.new do
        begin
          send_audit_entry(audit_entry)
        rescue StandardError => e
          logger.error "[ParlantIntegration] Failed to send audit entry: #{e.message}"
        end
      end

      logger.info "[ParlantIntegration] Audit trail created for #{agent.class.name}##{operation}"
    end

    #
    # Health check for Parlant service connection
    #
    # @return [Hash] Health status and metrics
    #
    def health_check
      start_time = Time.now
      
      begin
        response = @client.get('/health')
        response_time = (Time.now - start_time) * 1000

        {
          status: 'healthy',
          response_time_ms: response_time.round(2),
          parlant_service_status: response.code == '200' ? 'available' : 'degraded',
          metrics: @metrics
        }
      rescue StandardError => e
        {
          status: 'unhealthy',
          error: e.message,
          response_time_ms: ((Time.now - start_time) * 1000).round(2),
          metrics: @metrics
        }
      end
    end

    private

    #
    # Load Parlant integration configuration
    #
    def load_configuration
      {
        endpoint: ENV.fetch('PARLANT_SERVICE_ENDPOINT', 'http://localhost:3001'),
        timeout: ENV.fetch('PARLANT_TIMEOUT_SECONDS', '30').to_i,
        api_key: ENV['PARLANT_API_KEY'],
        cache_ttl: ENV.fetch('PARLANT_CACHE_TTL_MINUTES', '15').to_i,
        enable_caching: ENV.fetch('PARLANT_ENABLE_CACHING', 'true') == 'true',
        log_level: ENV.fetch('PARLANT_LOG_LEVEL', 'info').to_sym
      }
    end

    #
    # Create HTTP client for Parlant service communication
    #
    def create_http_client
      uri = URI(@config[:endpoint])
      
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = (uri.scheme == 'https')
      http.read_timeout = @config[:timeout]
      http.open_timeout = @config[:timeout]
      
      http
    end

    #
    # Assess risk level for agent operation
    #
    # @param agent [Agent] The Huginn agent
    # @param function_name [String] Function being called
    # @param params [Hash] Function parameters
    # @return [String] Risk level
    #
    def assess_risk(agent, function_name, params)
      # High-risk operations
      return RiskLevel::CRITICAL if function_name.match?(/delete|destroy|remove|drop/)
      return RiskLevel::HIGH if function_name.match?(/send|post|put|create|update/)
      return RiskLevel::HIGH if agent.is_a?(Agents::ShellCommandAgent)

      # Medium-risk operations
      return RiskLevel::MEDIUM if function_name.match?(/receive|process|transform/)
      return RiskLevel::MEDIUM if agent.is_a?(Agents::EmailAgent)

      # Low-risk operations
      return RiskLevel::LOW if function_name.match?(/check|fetch|get|read/)
      
      # Default to minimal risk
      RiskLevel::MINIMAL
    end

    #
    # Classify security level for agent operation
    #
    # @param agent [Agent] The Huginn agent
    # @param function_name [String] Function being called
    # @param params [Hash] Function parameters
    # @return [String] Security level
    #
    def classify_security(agent, function_name, params)
      # Critical security operations
      return SecurityLevel::CLASSIFIED if agent.is_a?(Agents::ShellCommandAgent)
      return SecurityLevel::RESTRICTED if function_name.match?(/send|post/) && 
                                         (agent.is_a?(Agents::EmailAgent) || 
                                          agent.is_a?(Agents::JabberAgent) || 
                                          agent.is_a?(Agents::TwitterPublishAgent))

      # Confidential operations requiring confirmation
      return SecurityLevel::CONFIDENTIAL if agent.is_a?(Agents::PostAgent) ||
                                           agent.is_a?(Agents::WebhookAgent) ||
                                           function_name.match?(/create|update|delete/)

      # Internal operations with logging
      return SecurityLevel::INTERNAL if function_name.match?(/process|transform|check/)

      # Public operations
      SecurityLevel::PUBLIC
    end

    #
    # Build conversation context for Parlant validation
    #
    # @param agent [Agent] The Huginn agent
    # @param operation_id [String] Unique operation identifier
    # @return [Hash] Conversation context
    #
    def build_conversation_context(agent, operation_id)
      {
        user_id: agent.user_id&.to_s || 'system',
        agent_id: agent.id&.to_s || 'unknown',
        agent_role: 'huginn_monitoring_agent',
        operation_id: operation_id,
        session_metadata: {
          agent_type: agent.class.name,
          agent_name: agent.name || 'unnamed',
          created_at: agent.created_at&.iso8601,
          last_check_at: agent.last_check_at&.iso8601
        }
      }
    end

    #
    # Generate human-readable action description
    #
    # @param agent [Agent] The Huginn agent
    # @param function_name [String] Function being called
    # @param params [Hash] Function parameters
    # @return [String] Action description
    #
    def generate_action_description(agent, function_name, params)
      case agent
      when Agents::RssAgent
        "Monitor RSS feed at #{params[:url] || 'configured URL'} and emit events for new items"
      when Agents::WeatherAgent
        "Fetch weather forecast for location #{params[:location] || 'configured location'}"
      when Agents::EmailAgent
        recipients = params[:recipients] || 'configured recipients'
        "Send email notification to #{recipients} with subject '#{params[:subject] || 'notification'}'"
      when Agents::WebsiteAgent
        "Monitor website #{params[:url] || 'configured URL'} for changes and extract data"
      when Agents::PostAgent
        "Send HTTP POST request to #{params[:url] || 'configured endpoint'} with data"
      when Agents::ShellCommandAgent
        "Execute shell command: #{params[:command] || 'configured command'}"
      else
        "Execute #{function_name} operation for #{agent.class.name.split('::').last}"
      end
    end

    #
    # Send validation request to Parlant service
    #
    # @param request [Hash] Validation request data
    # @return [Hash] Validation result
    # @raise [ValidationError] If validation fails
    #
    def send_validation_request(request)
      uri = URI("#{@config[:endpoint]}/api/v1/validate")
      
      http_request = Net::HTTP::Post.new(uri)
      http_request['Content-Type'] = 'application/json'
      http_request['Authorization'] = "Bearer #{@config[:api_key]}" if @config[:api_key]
      http_request.body = request.to_json

      response = @client.request(http_request)

      case response.code.to_i
      when 200
        result = JSON.parse(response.body)
        raise ValidationError, result['reason'] unless result['approved']
        result
      when 401
        raise AuthenticationError, 'Invalid Parlant API key'
      when 408, 504
        raise TimeoutError, 'Parlant service timeout'
      else
        raise ValidationError, "Parlant service error: #{response.code} #{response.body}"
      end

    rescue Net::TimeoutError => e
      raise TimeoutError, "Parlant service timeout: #{e.message}"
    rescue JSON::ParserError => e
      raise ValidationError, "Invalid Parlant response: #{e.message}"
    end

    #
    # Execute function with comprehensive audit trail
    #
    # @param agent [Agent] The Huginn agent
    # @param function_name [String] Function name
    # @param validation_result [Hash] Parlant validation result
    # @param block [Proc] Function to execute
    # @return [Object] Function result
    #
    def execute_with_audit(agent, function_name, validation_result, &block)
      execution_start = Time.now

      begin
        # Execute the validated function
        result = yield if block_given?

        # Create success audit trail
        create_audit_trail(agent, function_name, {
          status: 'success',
          validation_id: validation_result['id'],
          execution_time_ms: ((Time.now - execution_start) * 1000).round(2),
          approved_by: validation_result['reasoning']
        })

        result

      rescue StandardError => e
        # Create failure audit trail
        create_audit_trail(agent, function_name, {
          status: 'failure',
          error: e.message,
          validation_id: validation_result['id'],
          execution_time_ms: ((Time.now - execution_start) * 1000).round(2)
        })

        raise
      end
    end

    #
    # Generate cache key for validation caching
    #
    def generate_cache_key(agent, function_name, params)
      key_data = "#{agent.class.name}:#{function_name}:#{params.sort.to_h}"
      Digest::SHA256.hexdigest(key_data)[0..16]
    end

    #
    # Get cached validation result
    #
    def get_cached_validation(cache_key, risk_level)
      return nil unless @config[:enable_caching]
      return nil if risk_level == RiskLevel::CRITICAL # Never cache critical operations

      cached = @validation_cache[cache_key]
      return nil unless cached
      return nil if cached[:expires_at] < Time.now

      cached[:result]
    end

    #
    # Cache validation result
    #
    def cache_validation(cache_key, result, risk_level)
      return unless @config[:enable_caching]
      return if risk_level == RiskLevel::CRITICAL

      # Calculate TTL based on risk level
      ttl_minutes = case risk_level
                   when RiskLevel::MINIMAL then @config[:cache_ttl] * 4
                   when RiskLevel::LOW then @config[:cache_ttl] * 2
                   when RiskLevel::MEDIUM then @config[:cache_ttl]
                   when RiskLevel::HIGH then @config[:cache_ttl] / 2
                   else 0
                   end

      return if ttl_minutes <= 0

      @validation_cache[cache_key] = {
        result: result,
        created_at: Time.now,
        expires_at: Time.now + (ttl_minutes * 60)
      }

      # Clean up expired entries
      cleanup_cache if rand < 0.1 # 10% chance to cleanup
    end

    #
    # Send audit entry to central logging
    #
    def send_audit_entry(audit_entry)
      uri = URI("#{@config[:endpoint]}/api/v1/audit")
      
      http_request = Net::HTTP::Post.new(uri)
      http_request['Content-Type'] = 'application/json'
      http_request['Authorization'] = "Bearer #{@config[:api_key]}" if @config[:api_key]
      http_request.body = audit_entry.to_json

      @client.request(http_request)
    end

    #
    # Clean up expired cache entries
    #
    def cleanup_cache
      now = Time.now
      @validation_cache.reject! { |_, cached| cached[:expires_at] < now }
    end

    #
    # Sanitize parameters for logging/transmission
    #
    def sanitize_params(params)
      params.transform_values do |value|
        case value
        when /password|secret|key|token/i then '[REDACTED]'
        when String then value.length > 1000 ? "#{value[0..997]}..." : value
        else value
        end
      end
    end

    #
    # Generate unique operation ID
    #
    def generate_operation_id
      "huginn_#{Time.now.to_i}_#{SecureRandom.hex(4)}"
    end

    #
    # Update performance metrics
    #
    def update_metrics(start_time, success)
      duration = Time.now - start_time
      @metrics[:total_validations] += 1
      @metrics[:average_response_time] = (@metrics[:average_response_time] * (@metrics[:total_validations] - 1) + duration) / @metrics[:total_validations]
      @metrics[:errors] += 1 unless success
    end
  end

  #
  # Mixin module for Huginn agents to enable Parlant integration
  #
  # Include this module in Agent classes to automatically wrap critical methods
  # with conversational validation through Parlant.
  #
  module AgentIntegration
    def self.included(base)
      base.extend(ClassMethods)
    end

    module ClassMethods
      #
      # Mark a method for Parlant validation
      #
      # @param method_name [Symbol] Method to wrap
      # @param risk_level [String] Risk level for the operation
      #
      def parlant_validate(method_name, risk_level: ParlantIntegration::RiskLevel::MEDIUM)
        original_method = instance_method(method_name)
        
        define_method(method_name) do |*args, **kwargs, &block|
          ParlantIntegration::Service.instance.validate_and_execute(
            self, 
            method_name.to_s, 
            { args: args, kwargs: kwargs }
          ) do
            original_method.bind(self).call(*args, **kwargs, &block)
          end
        end
      end

      #
      # Mark multiple methods for Parlant validation
      #
      def parlant_validate_methods(*method_names, risk_level: ParlantIntegration::RiskLevel::MEDIUM)
        method_names.each { |method_name| parlant_validate(method_name, risk_level: risk_level) }
      end
    end

    #
    # Log agent operation with Parlant audit trail
    #
    def parlant_audit(operation, result = {}, metadata = {})
      ParlantIntegration::Service.instance.create_audit_trail(self, operation, result, metadata)
    end

    #
    # Validate single operation without method wrapping
    #
    def parlant_validate_operation(operation_name, params = {}, &block)
      ParlantIntegration::Service.instance.validate_and_execute(self, operation_name, params, &block)
    end
  end
end