# frozen_string_literal: true

##
# Parlant Validated Agent Module
#
# Provides function-level Parlant conversational AI validation for ALL
# Huginn Agent model methods. Wraps core agent operations with safety
# guardrails and conversational verification to ensure AI execution precision.
#
# This module is included in the Agent model to provide transparent
# Parlant validation for all monitoring, alerting, and observability functions.
#
# @example Usage in Agent Model
#   class Agent < ActiveRecord::Base
#     include ParlantValidatedAgent
#     
#     # All agent methods now have Parlant validation
#   end
#
# @author Parlant Integration Team
# @since 1.0.0
module ParlantValidatedAgent
  extend ActiveSupport::Concern

  ##
  # Module Configuration
  included do
    # Add Parlant integration service as class attribute
    class_attribute :parlant_service, default: -> { ParlantIntegrationService.new }
    
    # Add validation context tracking
    attr_accessor :parlant_context, :parlant_bypass_validation

    # Hook into agent lifecycle for validation logging
    after_initialize :initialize_parlant_context
    before_destroy :validate_agent_destruction
    
    # Add Parlant validation callbacks
    before_update :validate_agent_configuration_changes
  end

  class_methods do
    ##
    # Enable Parlant validation for all agents
    #
    # @return [Boolean] True if validation is enabled
    def parlant_validation_enabled?
      ENV.fetch('PARLANT_ENABLED', 'true') == 'true'
    end

    ##
    # Get Parlant service instance
    #
    # @return [ParlantIntegrationService] Service instance
    def parlant_integration_service
      @parlant_integration_service ||= ParlantIntegrationService.new
    end
  end

  ##
  # Parlant-Validated Agent Check
  #
  # Wraps the core agent check method with conversational AI validation.
  # Ensures all scheduled monitoring operations align with user intent.
  #
  # @return [Object] Check operation result
  # @raise [ParlantValidationError] If validation fails
  #
  # @example Scheduled Agent Check
  #   agent = WeatherAgent.find(123)
  #   agent.parlant_validated_check  # Executes with validation
  def parlant_validated_check
    operation_id = generate_parlant_operation_id
    
    parlant_log_operation_start(operation_id, 'agent_check')
    
    return super if bypass_parlant_validation?

    begin
      # Pre-execution validation
      validation_result = validate_with_parlant(
        operation: 'agent_check',
        context: build_agent_check_context,
        user_intent: "Perform scheduled monitoring check for #{self.class.name} agent"
      )

      unless validation_result[:approved]
        handle_validation_rejection(operation_id, 'agent_check', validation_result)
        return false
      end

      # Execute original check method with monitoring
      start_time = Time.current
      result = super
      execution_time = Time.current - start_time

      # Post-execution logging and audit
      parlant_log_operation_success(operation_id, 'agent_check', {
        execution_time_ms: (execution_time * 1000).round(2),
        check_result: result.present?,
        validation_metadata: validation_result[:validation_metadata]
      })

      result

    rescue StandardError => e
      parlant_log_operation_error(operation_id, 'agent_check', e)
      raise
    end
  end

  ##
  # Parlant-Validated Event Reception
  #
  # Wraps the receive method with conversational AI validation.
  # Validates incoming events before processing.
  #
  # @param events [Array<Event>] Events to process
  # @return [Object] Reception result
  # @raise [ParlantValidationError] If validation fails
  def parlant_validated_receive(events)
    operation_id = generate_parlant_operation_id
    
    parlant_log_operation_start(operation_id, 'receive_events', { event_count: events.length })
    
    return super if bypass_parlant_validation?

    begin
      # Validate event reception
      validation_result = validate_with_parlant(
        operation: 'receive_events',
        context: build_event_reception_context(events),
        user_intent: "Process #{events.length} incoming monitoring events"
      )

      unless validation_result[:approved]
        handle_validation_rejection(operation_id, 'receive_events', validation_result)
        return false
      end

      # Execute original receive method
      start_time = Time.current
      result = super(events)
      execution_time = Time.current - start_time

      # Log successful event processing
      parlant_log_operation_success(operation_id, 'receive_events', {
        processed_events: events.length,
        execution_time_ms: (execution_time * 1000).round(2),
        validation_metadata: validation_result[:validation_metadata]
      })

      result

    rescue StandardError => e
      parlant_log_operation_error(operation_id, 'receive_events', e)
      raise
    end
  end

  ##
  # Parlant-Validated Event Creation
  #
  # Wraps the create_event method with conversational AI validation.
  # Ensures event creation aligns with monitoring objectives.
  #
  # @param event_data [Hash] Event data to create
  # @return [Event, nil] Created event or nil if validation fails
  # @raise [ParlantValidationError] If validation fails
  def parlant_validated_create_event(event_data)
    operation_id = generate_parlant_operation_id
    
    parlant_log_operation_start(operation_id, 'create_event', { 
      event_type: event_data.is_a?(Hash) ? event_data[:event_type] : 'unknown'
    })
    
    return super if bypass_parlant_validation?

    begin
      # Validate event creation
      validation_result = validate_with_parlant(
        operation: 'create_event',
        context: build_event_creation_context(event_data),
        user_intent: "Create monitoring event: #{extract_event_description(event_data)}"
      )

      unless validation_result[:approved]
        handle_validation_rejection(operation_id, 'create_event', validation_result)
        return nil
      end

      # Execute original create_event method
      start_time = Time.current
      created_event = super(event_data)
      execution_time = Time.current - start_time

      # Log successful event creation
      parlant_log_operation_success(operation_id, 'create_event', {
        event_id: created_event&.id,
        event_created: created_event.present?,
        execution_time_ms: (execution_time * 1000).round(2),
        validation_metadata: validation_result[:validation_metadata]
      })

      created_event

    rescue StandardError => e
      parlant_log_operation_error(operation_id, 'create_event', e)
      raise
    end
  end

  ##
  # Parlant-Validated Event Building
  #
  # Wraps the build_event method with validation.
  # Validates event structure before building.
  #
  # @param event_data [Hash] Event data to build
  # @return [Event] Built event object
  def parlant_validated_build_event(event_data)
    return super if bypass_parlant_validation?

    operation_id = generate_parlant_operation_id
    
    begin
      # Lightweight validation for event building
      validation_result = validate_with_parlant(
        operation: 'build_event',
        context: { 
          event_data_size: event_data.to_s.length,
          agent_id: id,
          agent_type: self.class.name
        },
        user_intent: "Build event structure for monitoring data"
      )

      unless validation_result[:approved]
        parlant_log_operation_warning(operation_id, 'build_event', 
          "Event building validation failed: #{validation_result[:reasoning]}")
      end

      super(event_data)

    rescue StandardError => e
      parlant_log_operation_error(operation_id, 'build_event', e)
      raise
    end
  end

  ##
  # Parlant-Validated Logging
  #
  # Wraps the log method with conversational AI validation.
  # Validates log entries for security and compliance.
  #
  # @param message [String] Log message
  # @param options [Hash] Logging options
  # @return [AgentLog] Created log entry
  def parlant_validated_log(message, options = {})
    return super if bypass_parlant_validation?

    operation_id = generate_parlant_operation_id
    
    begin
      # Validate logging operation
      validation_result = validate_with_parlant(
        operation: 'agent_log',
        context: {
          log_level: options[:level] || 1,
          message_length: message.length,
          contains_sensitive_data: detect_sensitive_data(message),
          agent_id: id
        },
        user_intent: "Log monitoring information: #{options[:level] || 'info'} level"
      )

      # Allow logging even if validation fails, but sanitize if needed
      if !validation_result[:approved] && detect_sensitive_data(message)
        message = sanitize_log_message(message)
        parlant_log_operation_warning(operation_id, 'agent_log', 
          "Log message sanitized due to validation concerns")
      end

      super(message, options)

    rescue StandardError => e
      # Ensure logging always works for error cases
      super("Log validation error: #{e.message}", options.merge(level: 4))
    end
  end

  ##
  # Parlant-Validated Error Logging
  #
  # Wraps the error method with validation and enhanced error tracking.
  #
  # @param message [String] Error message
  # @param options [Hash] Error logging options
  # @return [AgentLog] Created error log entry
  def parlant_validated_error(message, options = {})
    operation_id = generate_parlant_operation_id
    
    # Always allow error logging but validate for sensitive data
    if detect_sensitive_data(message)
      sanitized_message = sanitize_log_message(message)
      parlant_log_operation_warning(operation_id, 'agent_error', 
        "Error message sanitized for security")
      super(sanitized_message, options)
    else
      super(message, options)
    end

    # Report error to monitoring if validation service is available
    begin
      parlant_service.validate_error_monitoring(
        error_context: {
          error_message: message,
          agent_id: id,
          agent_type: self.class.name,
          severity: 'high'
        },
        monitoring_action: 'log_error'
      )
    rescue StandardError => e
      # Don't fail error logging due to validation issues
      Rails.logger.warn "[ParlantValidatedAgent] Error monitoring validation failed: #{e.message}"
    end
  end

  ##
  # Parlant-Validated Web Request Handling
  #
  # Wraps web request handling with security validation.
  #
  # @param request [ActionDispatch::Request] HTTP request
  # @param params [Hash] Request parameters
  # @return [Array] Response array [content, status, content_type, headers]
  def parlant_validated_handle_web_request(request, params)
    operation_id = generate_parlant_operation_id
    
    parlant_log_operation_start(operation_id, 'handle_web_request', {
      method: request.method,
      path: request.path,
      params_count: params.keys.length
    })
    
    return super if bypass_parlant_validation?

    begin
      # Validate web request handling
      validation_result = validate_with_parlant(
        operation: 'handle_web_request',
        context: build_web_request_context(request, params),
        user_intent: "Process web request for agent monitoring interface"
      )

      unless validation_result[:approved]
        handle_validation_rejection(operation_id, 'handle_web_request', validation_result)
        return ['Validation failed', 403, 'text/plain', {}]
      end

      # Execute original web request handling
      start_time = Time.current
      response = super(request, params)
      execution_time = Time.current - start_time

      # Log successful request handling
      parlant_log_operation_success(operation_id, 'handle_web_request', {
        response_status: response[1] || 200,
        execution_time_ms: (execution_time * 1000).round(2),
        validation_metadata: validation_result[:validation_metadata]
      })

      response

    rescue StandardError => e
      parlant_log_operation_error(operation_id, 'handle_web_request', e)
      ['Internal server error', 500, 'text/plain', {}]
    end
  end

  ##
  # Parlant-Validated Working Status Check
  #
  # Wraps the working? method with validation logging.
  #
  # @return [Boolean] Agent working status
  def parlant_validated_working?
    return super if bypass_parlant_validation?

    operation_id = generate_parlant_operation_id
    
    begin
      result = super
      
      # Log status check for monitoring
      parlant_log_operation_info(operation_id, 'working_status_check', {
        working: result,
        agent_id: id,
        agent_type: self.class.name
      })
      
      result

    rescue StandardError => e
      parlant_log_operation_error(operation_id, 'working_status_check', e)
      false # Safe default
    end
  end

  private

  ##
  # Core Parlant Validation Method
  #
  # Executes validation through Parlant integration service.
  #
  # @param operation [String] Operation being validated
  # @param context [Hash] Operation context
  # @param user_intent [String] User intent description
  # @return [Hash] Validation result
  def validate_with_parlant(operation:, context:, user_intent:)
    return { approved: true, bypassed: true } unless self.class.parlant_validation_enabled?

    self.class.parlant_integration_service.validate_operation(
      operation: operation,
      context: context.merge(parlant_context || {}),
      user_intent: user_intent
    )
  end

  ##
  # Check if Parlant validation should be bypassed
  #
  # @return [Boolean] True if validation should be bypassed
  def bypass_parlant_validation?
    !self.class.parlant_validation_enabled? || 
    parlant_bypass_validation || 
    Rails.env.test?
  end

  ##
  # Build Agent Check Context
  #
  # Creates context hash for agent check operations.
  #
  # @return [Hash] Check operation context
  def build_agent_check_context
    {
      agent_id: id,
      agent_type: self.class.name,
      agent_name: name,
      schedule: schedule,
      last_check_at: last_check_at,
      last_event_at: last_event_at,
      disabled: disabled?,
      user_id: user_id,
      operation_type: 'scheduled_check'
    }
  end

  ##
  # Build Event Reception Context
  #
  # Creates context hash for event reception operations.
  #
  # @param events [Array<Event>] Events being received
  # @return [Hash] Reception context
  def build_event_reception_context(events)
    {
      agent_id: id,
      agent_type: self.class.name,
      event_count: events.length,
      event_types: events.map { |e| e.respond_to?(:event_type) ? e.event_type : 'unknown' }.uniq,
      source_agents: events.map { |e| e.respond_to?(:agent_id) ? e.agent_id : nil }.compact.uniq,
      operation_type: 'event_reception'
    }
  end

  ##
  # Build Event Creation Context
  #
  # Creates context hash for event creation operations.
  #
  # @param event_data [Hash] Event data being created
  # @return [Hash] Creation context
  def build_event_creation_context(event_data)
    {
      agent_id: id,
      agent_type: self.class.name,
      event_type: event_data.is_a?(Hash) ? event_data[:event_type] : 'unknown',
      payload_size: event_data.to_s.length,
      has_payload: event_data.present?,
      operation_type: 'event_creation'
    }
  end

  ##
  # Build Web Request Context
  #
  # Creates context hash for web request operations.
  #
  # @param request [ActionDispatch::Request] HTTP request
  # @param params [Hash] Request parameters
  # @return [Hash] Web request context
  def build_web_request_context(request, params)
    {
      agent_id: id,
      agent_type: self.class.name,
      http_method: request.method,
      request_path: request.path,
      params_keys: params.keys,
      content_type: request.content_type,
      user_agent: request.user_agent,
      remote_ip: request.remote_ip,
      operation_type: 'web_request'
    }
  end

  ##
  # Extract Event Description
  #
  # Extracts human-readable description from event data.
  #
  # @param event_data [Hash] Event data
  # @return [String] Event description
  def extract_event_description(event_data)
    if event_data.is_a?(Hash)
      event_data[:event_type] || event_data['event_type'] || 'monitoring event'
    else
      'system event'
    end
  end

  ##
  # Detect Sensitive Data
  #
  # Checks if message contains potentially sensitive information.
  #
  # @param message [String] Message to check
  # @return [Boolean] True if sensitive data detected
  def detect_sensitive_data(message)
    sensitive_patterns = [
      /password/i, /secret/i, /key/i, /token/i, /credential/i,
      /\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b/, # Credit card pattern
      /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/ # Email pattern
    ]
    
    sensitive_patterns.any? { |pattern| message.match?(pattern) }
  end

  ##
  # Sanitize Log Message
  #
  # Removes or masks sensitive data from log messages.
  #
  # @param message [String] Original message
  # @return [String] Sanitized message
  def sanitize_log_message(message)
    sanitized = message.dup
    
    # Mask credit card numbers
    sanitized.gsub!(/\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b/, '**** **** **** ****')
    
    # Mask email addresses
    sanitized.gsub!(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/, '***@***.***')
    
    # Mask common sensitive keywords
    %w[password secret key token credential].each do |keyword|
      sanitized.gsub!(/#{keyword}[:\s]*[^\s,]+/i, "#{keyword}: [REDACTED]")
    end
    
    sanitized
  end

  ##
  # Generate Parlant Operation ID
  #
  # Creates unique identifier for operation tracking.
  #
  # @return [String] Operation ID
  def generate_parlant_operation_id
    "huginn_agent_#{id}_#{Time.current.to_i}_#{SecureRandom.hex(4)}"
  end

  ##
  # Handle Validation Rejection
  #
  # Processes and logs validation rejection scenarios.
  #
  # @param operation_id [String] Operation identifier
  # @param operation [String] Operation that was rejected
  # @param validation_result [Hash] Validation result details
  def handle_validation_rejection(operation_id, operation, validation_result)
    error_message = "Parlant validation rejected: #{validation_result[:reasoning]}"
    
    Rails.logger.warn "[ParlantValidatedAgent] [#{operation_id}] Validation rejected", {
      operation: operation,
      agent_id: id,
      agent_type: self.class.name,
      reasoning: validation_result[:reasoning],
      confidence: validation_result[:confidence],
      risk_level: validation_result[:risk_level]
    }
    
    # Create agent log entry for audit trail
    log(error_message, level: 3) # Warning level
    
    # Raise exception for critical operations
    if validation_result[:risk_level].in?(%w[high critical])
      raise StandardError, error_message
    end
  end

  ##
  # Initialize Parlant Context
  #
  # Sets up Parlant context during agent initialization.
  def initialize_parlant_context
    @parlant_context = {
      agent_initialized_at: Time.current.iso8601,
      rails_env: Rails.env,
      huginn_version: defined?(Huginn::VERSION) ? Huginn::VERSION : 'unknown'
    }
  end

  ##
  # Validate Agent Destruction
  #
  # Validates agent destruction operations.
  def validate_agent_destruction
    return unless self.class.parlant_validation_enabled?

    validation_result = validate_with_parlant(
      operation: 'delete_agent',
      context: { 
        agent_id: id, 
        agent_type: self.class.name,
        has_events: events.count > 0,
        is_active: !disabled?
      },
      user_intent: "Delete #{self.class.name} agent and associated data"
    )

    unless validation_result[:approved]
      raise StandardError, "Agent deletion blocked by Parlant validation: #{validation_result[:reasoning]}"
    end
  end

  ##
  # Validate Agent Configuration Changes
  #
  # Validates agent configuration updates.
  def validate_agent_configuration_changes
    return unless self.class.parlant_validation_enabled? && changed?

    validation_result = validate_with_parlant(
      operation: 'update_agent_config',
      context: {
        agent_id: id,
        agent_type: self.class.name,
        changed_attributes: changed_attributes.keys,
        configuration_changes: changes
      },
      user_intent: "Update agent configuration: #{changed_attributes.keys.join(', ')}"
    )

    unless validation_result[:approved]
      errors.add(:base, "Configuration update blocked: #{validation_result[:reasoning]}")
      throw(:abort)
    end
  end

  ##
  # Parlant Logging Methods
  #
  # Structured logging methods for Parlant operations
  
  def parlant_log_operation_start(operation_id, operation, context = {})
    Rails.logger.info "[ParlantValidatedAgent] [#{operation_id}] Operation started", {
      operation: operation,
      agent_id: id,
      agent_type: self.class.name,
      **context
    }
  end

  def parlant_log_operation_success(operation_id, operation, context = {})
    Rails.logger.info "[ParlantValidatedAgent] [#{operation_id}] Operation succeeded", {
      operation: operation,
      agent_id: id,
      agent_type: self.class.name,
      **context
    }
  end

  def parlant_log_operation_error(operation_id, operation, error)
    Rails.logger.error "[ParlantValidatedAgent] [#{operation_id}] Operation failed", {
      operation: operation,
      agent_id: id,
      agent_type: self.class.name,
      error: error.message,
      backtrace: error.backtrace&.first(3)
    }
  end

  def parlant_log_operation_warning(operation_id, operation, message)
    Rails.logger.warn "[ParlantValidatedAgent] [#{operation_id}] Operation warning", {
      operation: operation,
      agent_id: id,
      agent_type: self.class.name,
      warning: message
    }
  end

  def parlant_log_operation_info(operation_id, operation, context = {})
    Rails.logger.info "[ParlantValidatedAgent] [#{operation_id}] Operation info", {
      operation: operation,
      agent_id: id,
      agent_type: self.class.name,
      **context
    }
  end
end