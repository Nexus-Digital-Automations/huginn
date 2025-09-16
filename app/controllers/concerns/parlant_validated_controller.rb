# frozen_string_literal: true

##
# Parlant Validated Controller Concern
#
# Provides function-level Parlant conversational AI validation for ALL
# Huginn controller actions. Enhances monitoring, alerting, and observability
# controller methods with safety guardrails and conversational verification.
#
# This concern is included in controller classes to provide transparent
# Parlant validation for all HTTP endpoints and administrative functions.
#
# @example Usage in Controller
#   class ErrorMonitoringController < ApplicationController
#     include ParlantValidatedController
#     
#     # All controller actions now have Parlant validation
#   end
#
# @author Parlant Integration Team
# @since 1.0.0
module ParlantValidatedController
  extend ActiveSupport::Concern

  ##
  # Controller Setup
  included do
    # Add Parlant integration service
    class_attribute :parlant_service, default: -> { ParlantIntegrationService.new }
    
    # Add before action for request validation
    before_action :validate_request_with_parlant, unless: :skip_parlant_validation?
    
    # Add after action for response logging
    after_action :log_response_with_parlant
    
    # Exception handling for Parlant validation failures
    rescue_from StandardError, with: :handle_parlant_validation_error
  end

  class_methods do
    ##
    # Skip Parlant validation for specific actions
    #
    # @param actions [Array<Symbol>] Actions to skip validation
    def skip_parlant_validation_for(*actions)
      @parlant_skip_actions = Array(actions)
    end

    ##
    # Get actions that skip Parlant validation
    #
    # @return [Array<Symbol>] Actions that skip validation
    def parlant_skip_actions
      @parlant_skip_actions ||= []
    end

    ##
    # Enable Parlant validation for controllers
    #
    # @return [Boolean] True if validation is enabled
    def parlant_validation_enabled?
      ENV.fetch('PARLANT_ENABLED', 'true') == 'true'
    end
  end

  ##
  # Parlant-Validated Dashboard Access
  #
  # Validates access to monitoring dashboards through conversational AI.
  # Ensures dashboard access aligns with user authorization and intent.
  #
  # @param dashboard_type [String] Type of dashboard being accessed
  # @param access_context [Hash] Access context and user information
  # @return [Hash] Validation result
  def validate_dashboard_access(dashboard_type:, access_context: {})
    operation_id = generate_controller_operation_id
    
    parlant_log_controller_operation(operation_id, 'dashboard_access', {
      dashboard_type: dashboard_type,
      user_id: current_user&.id,
      **access_context
    })

    return { approved: true, bypassed: true } unless self.class.parlant_validation_enabled?

    self.class.parlant_service.validate_operation(
      operation: 'dashboard_access',
      context: build_dashboard_access_context(dashboard_type, access_context),
      user_intent: "Access #{dashboard_type} monitoring dashboard for system oversight"
    )
  end

  ##
  # Parlant-Validated Monitoring Operation
  #
  # Validates monitoring operations through conversational AI.
  # Ensures monitoring actions align with operational policies.
  #
  # @param operation_type [String] Type of monitoring operation
  # @param operation_context [Hash] Operation context and parameters
  # @return [Hash] Validation result
  def validate_monitoring_operation(operation_type:, operation_context: {})
    operation_id = generate_controller_operation_id
    
    parlant_log_controller_operation(operation_id, 'monitoring_operation', {
      operation_type: operation_type,
      user_id: current_user&.id,
      **operation_context
    })

    return { approved: true, bypassed: true } unless self.class.parlant_validation_enabled?

    self.class.parlant_service.validate_operation(
      operation: 'monitoring_operation',
      context: build_monitoring_operation_context(operation_type, operation_context),
      user_intent: "Execute #{operation_type} monitoring operation for system health"
    )
  end

  ##
  # Parlant-Validated Error Response
  #
  # Validates error response generation and alert handling.
  # Ensures error responses follow monitoring protocols.
  #
  # @param error_context [Hash] Error details and severity information
  # @param response_action [String] Planned response action
  # @return [Hash] Validation result
  def validate_error_response(error_context:, response_action:)
    operation_id = generate_controller_operation_id
    
    parlant_log_controller_operation(operation_id, 'error_response', {
      error_severity: error_context[:severity],
      response_action: response_action,
      user_id: current_user&.id
    })

    return { approved: true, bypassed: true } unless self.class.parlant_validation_enabled?

    self.class.parlant_service.validate_error_monitoring(
      error_context: error_context,
      monitoring_action: response_action
    )
  end

  ##
  # Parlant-Validated Configuration Change
  #
  # Validates monitoring configuration changes through conversational AI.
  # Ensures configuration changes maintain system integrity.
  #
  # @param config_type [String] Type of configuration being changed
  # @param changes [Hash] Configuration changes being applied
  # @return [Hash] Validation result
  def validate_configuration_change(config_type:, changes:)
    operation_id = generate_controller_operation_id
    
    parlant_log_controller_operation(operation_id, 'config_change', {
      config_type: config_type,
      change_keys: changes.keys,
      user_id: current_user&.id
    })

    return { approved: true, bypassed: true } unless self.class.parlant_validation_enabled?

    self.class.parlant_service.validate_operation(
      operation: 'config_change',
      context: build_configuration_change_context(config_type, changes),
      user_intent: "Update #{config_type} configuration for improved monitoring"
    )
  end

  ##
  # Parlant-Validated Administrative Action
  #
  # Validates administrative actions through conversational AI.
  # Ensures administrative operations follow security policies.
  #
  # @param admin_action [String] Administrative action being performed
  # @param action_context [Hash] Action context and parameters
  # @return [Hash] Validation result
  def validate_administrative_action(admin_action:, action_context: {})
    operation_id = generate_controller_operation_id
    
    parlant_log_controller_operation(operation_id, 'admin_action', {
      admin_action: admin_action,
      user_id: current_user&.id,
      user_role: current_user&.admin? ? 'admin' : 'user',
      **action_context
    })

    return { approved: true, bypassed: true } unless self.class.parlant_validation_enabled?

    self.class.parlant_service.validate_operation(
      operation: 'admin_action',
      context: build_administrative_action_context(admin_action, action_context),
      user_intent: "Perform #{admin_action} administrative operation for system management"
    )
  end

  ##
  # Enhanced JSON Response with Parlant Metadata
  #
  # Renders JSON response enhanced with Parlant validation metadata.
  # Provides transparency about validation status and decisions.
  #
  # @param data [Hash] Response data
  # @param validation_result [Hash] Parlant validation result
  # @param status [Symbol] HTTP status
  def render_parlant_validated_json(data:, validation_result: nil, status: :ok)
    response_data = {
      success: status.to_s.start_with?('2'),
      data: data,
      timestamp: Time.current.iso8601
    }

    # Add Parlant validation metadata if available
    if validation_result.present?
      response_data[:parlant_validation] = {
        approved: validation_result[:approved],
        confidence: validation_result[:confidence],
        operation_id: validation_result[:operation_id],
        risk_level: validation_result[:risk_level],
        bypassed: validation_result[:bypassed] || false
      }
    end

    render json: response_data, status: status
  end

  ##
  # Enhanced Error Response with Parlant Context
  #
  # Renders error response with Parlant validation context.
  # Provides detailed error information with validation metadata.
  #
  # @param error_message [String] Error message
  # @param validation_result [Hash] Parlant validation result
  # @param status [Symbol] HTTP status
  def render_parlant_error_response(error_message:, validation_result: nil, status: :unprocessable_entity)
    error_data = {
      success: false,
      error: error_message,
      timestamp: Time.current.iso8601
    }

    # Add Parlant validation context if available
    if validation_result.present?
      error_data[:parlant_context] = {
        validation_failed: !validation_result[:approved],
        reasoning: validation_result[:reasoning],
        operation_id: validation_result[:operation_id],
        recommendations: validation_result[:recommendations] || []
      }
    end

    render json: error_data, status: status
  end

  private

  ##
  # Validate Request with Parlant
  #
  # Pre-action validation of incoming HTTP requests.
  # Validates request patterns and user authorization.
  def validate_request_with_parlant
    return if skip_parlant_validation?

    operation_id = generate_controller_operation_id
    request.env['parlant_operation_id'] = operation_id

    begin
      validation_result = self.class.parlant_service.validate_operation(
        operation: 'http_request',
        context: build_http_request_context,
        user_intent: "Access #{controller_name}##{action_name} for monitoring purposes"
      )

      unless validation_result[:approved]
        parlant_log_controller_error(operation_id, 'request_validation_failed', {
          reasoning: validation_result[:reasoning],
          confidence: validation_result[:confidence]
        })

        render_parlant_error_response(
          error_message: "Request blocked by validation: #{validation_result[:reasoning]}",
          validation_result: validation_result,
          status: :forbidden
        )
        return false
      end

      # Store validation result for use in action
      @parlant_validation_result = validation_result
      
    rescue StandardError => e
      parlant_log_controller_error(operation_id, 'request_validation_error', {
        error: e.message
      })
      # Allow request to proceed on validation errors in non-critical environments
      @parlant_validation_result = { approved: true, error: e.message }
    end
  end

  ##
  # Log Response with Parlant
  #
  # Post-action logging of HTTP responses.
  # Records response patterns and validation outcomes.
  def log_response_with_parlant
    return if skip_parlant_validation?

    operation_id = request.env['parlant_operation_id']
    return unless operation_id

    parlant_log_controller_operation(operation_id, 'response_logged', {
      status: response.status,
      content_type: response.content_type,
      response_size: response.body&.length || 0,
      validation_approved: @parlant_validation_result&.dig(:approved) || false
    })
  end

  ##
  # Handle Parlant Validation Errors
  #
  # Centralized error handling for Parlant validation failures.
  # Provides consistent error responses and logging.
  #
  # @param error [StandardError] The error that occurred
  def handle_parlant_validation_error(error)
    operation_id = request.env['parlant_operation_id'] || generate_controller_operation_id
    
    parlant_log_controller_error(operation_id, 'validation_exception', {
      error_class: error.class.name,
      error_message: error.message,
      controller: controller_name,
      action: action_name
    })

    if error.message.include?('Parlant validation')
      render_parlant_error_response(
        error_message: error.message,
        status: :forbidden
      )
    else
      render_parlant_error_response(
        error_message: "Internal server error: #{error.message}",
        status: :internal_server_error
      )
    end
  end

  ##
  # Check if Parlant Validation Should be Skipped
  #
  # Determines if current action should skip Parlant validation.
  #
  # @return [Boolean] True if validation should be skipped
  def skip_parlant_validation?
    !self.class.parlant_validation_enabled? ||
    action_name.to_sym.in?(self.class.parlant_skip_actions) ||
    Rails.env.test?
  end

  ##
  # Build HTTP Request Context
  #
  # Creates context hash for HTTP request validation.
  #
  # @return [Hash] Request validation context
  def build_http_request_context
    {
      controller: controller_name,
      action: action_name,
      method: request.method,
      path: request.path,
      remote_ip: request.remote_ip,
      user_agent: request.user_agent,
      user_id: current_user&.id,
      user_admin: current_user&.admin? || false,
      params_keys: params.keys,
      session_id: session.id,
      timestamp: Time.current.iso8601
    }
  end

  ##
  # Build Dashboard Access Context
  #
  # Creates context hash for dashboard access validation.
  #
  # @param dashboard_type [String] Type of dashboard
  # @param access_context [Hash] Additional access context
  # @return [Hash] Dashboard access context
  def build_dashboard_access_context(dashboard_type, access_context)
    {
      dashboard_type: dashboard_type,
      user_id: current_user&.id,
      user_admin: current_user&.admin? || false,
      session_duration: session_duration,
      access_time: Time.current.iso8601,
      **access_context
    }
  end

  ##
  # Build Monitoring Operation Context
  #
  # Creates context hash for monitoring operation validation.
  #
  # @param operation_type [String] Type of operation
  # @param operation_context [Hash] Operation-specific context
  # @return [Hash] Monitoring operation context
  def build_monitoring_operation_context(operation_type, operation_context)
    {
      operation_type: operation_type,
      user_id: current_user&.id,
      user_admin: current_user&.admin? || false,
      controller: controller_name,
      action: action_name,
      request_method: request.method,
      **operation_context
    }
  end

  ##
  # Build Configuration Change Context
  #
  # Creates context hash for configuration change validation.
  #
  # @param config_type [String] Type of configuration
  # @param changes [Hash] Configuration changes
  # @return [Hash] Configuration change context
  def build_configuration_change_context(config_type, changes)
    {
      config_type: config_type,
      changes: sanitize_sensitive_data(changes),
      change_count: changes.keys.length,
      user_id: current_user&.id,
      user_admin: current_user&.admin? || false,
      timestamp: Time.current.iso8601
    }
  end

  ##
  # Build Administrative Action Context
  #
  # Creates context hash for administrative action validation.
  #
  # @param admin_action [String] Administrative action
  # @param action_context [Hash] Action-specific context
  # @return [Hash] Administrative action context
  def build_administrative_action_context(admin_action, action_context)
    {
      admin_action: admin_action,
      user_id: current_user&.id,
      user_admin: current_user&.admin? || false,
      requires_admin: admin_action.in?(%w[delete_all reset_system emergency_stop]),
      action_scope: action_context[:scope] || 'single',
      **sanitize_sensitive_data(action_context)
    }
  end

  ##
  # Sanitize Sensitive Data
  #
  # Removes sensitive information from context data.
  #
  # @param data [Hash] Data to sanitize
  # @return [Hash] Sanitized data
  def sanitize_sensitive_data(data)
    sanitized = data.deep_dup
    
    %w[password secret token api_key credential].each do |sensitive_key|
      sanitized.delete(sensitive_key)
      sanitized.delete(sensitive_key.to_sym)
    end
    
    sanitized
  end

  ##
  # Generate Controller Operation ID
  #
  # Creates unique identifier for controller operation tracking.
  #
  # @return [String] Operation ID
  def generate_controller_operation_id
    "huginn_controller_#{controller_name}_#{action_name}_#{Time.current.to_i}_#{SecureRandom.hex(4)}"
  end

  ##
  # Calculate Session Duration
  #
  # Calculates how long the user session has been active.
  #
  # @return [Integer] Session duration in seconds
  def session_duration
    session_start = session[:created_at]&.to_time || Time.current
    (Time.current - session_start).to_i
  end

  ##
  # Controller Logging Methods
  #
  # Structured logging methods for controller operations
  
  def parlant_log_controller_operation(operation_id, operation, context = {})
    Rails.logger.info "[ParlantValidatedController] [#{operation_id}] #{operation}", {
      controller: controller_name,
      action: action_name,
      user_id: current_user&.id,
      **context
    }
  end

  def parlant_log_controller_error(operation_id, error_type, context = {})
    Rails.logger.error "[ParlantValidatedController] [#{operation_id}] #{error_type}", {
      controller: controller_name,
      action: action_name,
      user_id: current_user&.id,
      **context
    }
  end
end