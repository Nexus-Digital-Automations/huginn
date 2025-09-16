# frozen_string_literal: true

require_relative 'http_client_service'
require_relative 'validation_result'
require_relative 'cache_service'

module ParlantBridge
  ##
  # Integration Module for Ruby/Huginn Parlant Integration
  # Provides method interception patterns, decorator-style patterns, and thread-safe
  # validation mechanisms for easy integration across Huginn agents.
  #
  # @example Basic integration
  #   class MyAgent < Agent
  #     include ParlantBridge::IntegrationModule
  #     
  #     parlant_secure :sensitive_operation, classification: 'CONFIDENTIAL'
  #     parlant_critical :dangerous_operation, confirmation_required: true
  #     
  #     def sensitive_operation(data)
  #       # This method will automatically be wrapped with Parlant validation
  #       # Implementation here...
  #     end
  #   end
  #
  module IntegrationModule
    extend ActiveSupport::Concern

    # Exception classes for integration errors
    class ValidationFailedError < StandardError
      attr_reader :operation_id, :validation_result
      
      def initialize(message, operation_id, validation_result = nil)
        super(message)
        @operation_id = operation_id
        @validation_result = validation_result
      end
    end

    class ConfigurationError < StandardError; end
    class IntegrationNotConfiguredError < StandardError; end

    included do
      class_attribute :parlant_client, instance_writer: false
      class_attribute :parlant_wrapped_methods, instance_writer: false, default: {}
      class_attribute :parlant_config, instance_writer: false, default: {}
      
      # Initialize Parlant integration on first include
      initialize_parlant_integration unless parlant_client
    end

    class_methods do
      ##
      # Configure Parlant integration for the class
      #
      # @param server_url [String] Parlant server URL
      # @param pool_size [Integer] Connection pool size
      # @param timeout [Integer] Request timeout
      # @param cache_ttl [Integer] Cache TTL in seconds
      # @param logger [Logger] Logger instance
      #
      def configure_parlant(server_url: nil, pool_size: 10, timeout: 30, 
                           cache_ttl: 300, logger: nil)
        config = {
          server_url: server_url || ENV['PARLANT_SERVER_URL'] || 'http://localhost:8080',
          pool_size: pool_size,
          timeout: timeout,
          cache_ttl: cache_ttl,
          logger: logger || Rails.logger
        }
        
        self.parlant_config = config
        initialize_parlant_integration
      end

      ##
      # Mark method as requiring Parlant validation with PUBLIC classification
      #
      # @param method_name [Symbol] Method to wrap
      # @param options [Hash] Additional validation options
      #
      def parlant_validated(method_name, **options)
        wrap_method_with_parlant(method_name, 'PUBLIC', options)
      end

      ##
      # Mark method as requiring Parlant validation with INTERNAL classification
      #
      # @param method_name [Symbol] Method to wrap
      # @param options [Hash] Additional validation options
      #
      def parlant_internal(method_name, **options)
        wrap_method_with_parlant(method_name, 'INTERNAL', options)
      end

      ##
      # Mark method as requiring Parlant validation with CONFIDENTIAL classification
      #
      # @param method_name [Symbol] Method to wrap
      # @param options [Hash] Additional validation options
      #
      def parlant_secure(method_name, **options)
        wrap_method_with_parlant(method_name, 'CONFIDENTIAL', options)
      end

      ##
      # Mark method as requiring Parlant validation with RESTRICTED classification
      #
      # @param method_name [Symbol] Method to wrap
      # @param options [Hash] Additional validation options
      #
      def parlant_restricted(method_name, **options)
        wrap_method_with_parlant(method_name, 'RESTRICTED', options)
      end

      ##
      # Mark method as requiring Parlant validation with CLASSIFIED classification
      #
      # @param method_name [Symbol] Method to wrap
      # @param options [Hash] Additional validation options
      #
      def parlant_critical(method_name, **options)
        wrap_method_with_parlant(method_name, 'CLASSIFIED', options)
      end

      ##
      # Bulk wrap multiple methods with the same classification
      #
      # @param methods [Array<Symbol>] Methods to wrap
      # @param classification [String] Security classification
      # @param options [Hash] Additional validation options
      #
      def parlant_wrap_methods(methods, classification = 'INTERNAL', **options)
        methods.each do |method_name|
          wrap_method_with_parlant(method_name, classification, options)
        end
      end

      ##
      # Get all methods wrapped with Parlant validation
      #
      # @return [Hash] Map of method names to their configuration
      #
      def parlant_wrapped_methods_list
        parlant_wrapped_methods.dup
      end

      private

      ##
      # Initialize Parlant HTTP client service
      #
      def initialize_parlant_integration
        raise ConfigurationError, 'PARLANT_SERVER_URL environment variable required' unless parlant_config[:server_url]
        
        self.parlant_client = HttpClientService.new(
          server_url: parlant_config[:server_url],
          pool_size: parlant_config[:pool_size],
          timeout: parlant_config[:timeout],
          cache_ttl: parlant_config[:cache_ttl],
          logger: parlant_config[:logger]
        )
        
        parlant_config[:logger]&.info("Parlant integration initialized for #{self}")
      end

      ##
      # Wrap method with Parlant validation
      #
      def wrap_method_with_parlant(method_name, classification, options)
        # Store method configuration
        method_config = {
          classification: classification,
          confirmation_required: options[:confirmation_required] || false,
          bypass_cache: options[:bypass_cache] || false,
          custom_validator: options[:custom_validator],
          audit_level: options[:audit_level] || 'standard',
          emergency_bypass: options[:emergency_bypass] || false
        }
        
        parlant_wrapped_methods[method_name] = method_config
        
        # Define method wrapper
        define_method("#{method_name}_with_parlant_validation") do |*args, **kwargs, &block|
          validate_and_execute_method(method_name, method_config, args, kwargs, &block)
        end
        
        # Alias original method and replace with wrapped version
        alias_method("#{method_name}_without_parlant_validation", method_name)
        alias_method(method_name, "#{method_name}_with_parlant_validation")
        
        # Make wrapper private if original was private
        private method_name if private_method_defined?("#{method_name}_without_parlant_validation")
      end
    end

    ##
    # Instance methods for Parlant integration
    #

    ##
    # Execute method with Parlant validation
    # Thread-safe validation mechanism with comprehensive error handling
    #
    def validate_and_execute_method(method_name, config, args, kwargs, &block)
      operation_id = generate_operation_id
      start_time = Time.now
      
      log_method_entry(method_name, operation_id, args, kwargs)
      
      # Skip validation if emergency bypass is enabled and conditions met
      if emergency_bypass_active?(config)
        log_emergency_bypass(method_name, operation_id)
        return execute_original_method(method_name, args, kwargs, &block)
      end
      
      # Build validation request
      validation_request = build_validation_request(method_name, config, args, kwargs)
      
      # Custom validator hook
      if config[:custom_validator]
        custom_result = config[:custom_validator].call(method_name, args, kwargs)
        return custom_result if custom_result
      end
      
      # Execute validation
      validation_result = execute_parlant_validation(validation_request, config[:bypass_cache])
      
      # Handle validation result
      case validation_result.status
      when 'approved'
        log_validation_approved(method_name, operation_id, validation_result)
        result = execute_original_method(method_name, args, kwargs, &block)
        log_method_completion(method_name, operation_id, result, Time.now - start_time)
        result
        
      when 'rejected'
        log_validation_rejected(method_name, operation_id, validation_result)
        raise ValidationFailedError.new(
          "Operation rejected: #{validation_result.reason}",
          operation_id,
          validation_result
        )
        
      when 'requires_confirmation'
        confirmation_result = handle_confirmation_workflow(validation_result)
        if confirmation_result.approved?
          result = execute_original_method(method_name, args, kwargs, &block)
          log_method_completion(method_name, operation_id, result, Time.now - start_time)
          result
        else
          raise ValidationFailedError.new(
            "Operation rejected by user: #{confirmation_result.reason}",
            operation_id,
            validation_result
          )
        end
        
      else
        raise ValidationFailedError.new(
          "Unknown validation status: #{validation_result.status}",
          operation_id,
          validation_result
        )
      end
      
    rescue StandardError => e
      log_method_error(method_name, operation_id, e, Time.now - start_time)
      handle_method_error(e, method_name, config, args, kwargs, &block)
    end

    ##
    # Execute validation with Parlant service
    #
    def execute_parlant_validation(request, bypass_cache = false)
      raise IntegrationNotConfiguredError, 'Parlant client not configured' unless self.class.parlant_client
      
      # Add bypass cache option to request if specified
      request[:options] = { bypass_cache: true } if bypass_cache
      
      self.class.parlant_client.validate_operation(
        function_name: request[:function_name],
        parameters: request[:parameters],
        user_context: request[:user_context],
        security_classification: request[:security_classification],
        conversation_id: request[:conversation_id]
      )
    end

    ##
    # Handle confirmation workflow for operations requiring user approval
    #
    def handle_confirmation_workflow(validation_result)
      # Create confirmation session
      session = self.class.parlant_client.create_async_session(
        session_config: {
          operation_id: validation_result.operation_id,
          confirmation_required: true,
          timeout: 300 # 5 minutes for user response
        },
        progress_callback: method(:handle_confirmation_progress)
      )
      
      # Wait for user confirmation
      session.wait_for_confirmation
    end

    ##
    # Handle confirmation progress updates
    #
    def handle_confirmation_progress(progress_data)
      logger&.info("Confirmation progress - OpID: #{progress_data[:operation_id]}, Status: #{progress_data[:status]}")
      
      # Emit progress event if supported
      emit_progress_event(progress_data) if respond_to?(:emit_progress_event)
    end

    ##
    # Get current user context for validation
    #
    def get_user_context
      {
        user_id: current_user_id,
        role: current_user_role,
        agent_type: self.class.name,
        agent_id: respond_to?(:id) ? id : nil,
        session_id: current_session_id,
        ip_address: current_ip_address,
        timestamp: Time.now.iso8601
      }
    end

    ##
    # Get Parlant integration health status
    #
    def parlant_health_status
      return { status: 'not_configured' } unless self.class.parlant_client
      
      self.class.parlant_client.health_check
    end

    ##
    # Manual validation for dynamic operations
    #
    def validate_operation_manually(operation_name, params = {}, classification = 'INTERNAL')
      request = {
        function_name: operation_name,
        parameters: params,
        user_context: get_user_context,
        security_classification: classification,
        conversation_id: current_conversation_id
      }
      
      execute_parlant_validation(request)
    end

    private

    ##
    # Build validation request payload
    #
    def build_validation_request(method_name, config, args, kwargs)
      {
        function_name: "#{self.class.name}##{method_name}",
        parameters: build_parameters_hash(args, kwargs),
        user_context: get_user_context,
        security_classification: config[:classification],
        conversation_id: current_conversation_id,
        audit_level: config[:audit_level]
      }
    end

    ##
    # Build parameters hash from method arguments
    #
    def build_parameters_hash(args, kwargs)
      params = {}
      
      # Add positional arguments
      args.each_with_index do |arg, index|
        params["arg_#{index}"] = serialize_parameter(arg)
      end
      
      # Add keyword arguments
      kwargs.each do |key, value|
        params[key.to_s] = serialize_parameter(value)
      end
      
      params
    end

    ##
    # Serialize parameter for safe transmission
    #
    def serialize_parameter(param)
      case param
      when String, Numeric, TrueClass, FalseClass, NilClass
        param
      when Array
        param.map { |item| serialize_parameter(item) }
      when Hash
        param.transform_values { |value| serialize_parameter(value) }
      else
        param.respond_to?(:to_h) ? param.to_h : param.to_s
      end
    rescue StandardError
      param.to_s
    end

    ##
    # Execute original method without validation
    #
    def execute_original_method(method_name, args, kwargs, &block)
      if kwargs.empty?
        method("#{method_name}_without_parlant_validation").call(*args, &block)
      else
        method("#{method_name}_without_parlant_validation").call(*args, **kwargs, &block)
      end
    end

    ##
    # Handle method execution errors
    #
    def handle_method_error(error, method_name, config, args, kwargs, &block)
      # Emergency bypass for critical system operations
      if config[:emergency_bypass] && critical_system_error?(error)
        logger&.warn("Emergency bypass activated for #{method_name}: #{error.message}")
        return execute_original_method(method_name, args, kwargs, &block)
      end
      
      # Re-raise the error
      raise error
    end

    ##
    # Check if emergency bypass conditions are met
    #
    def emergency_bypass_active?(config)
      return false unless config[:emergency_bypass]
      
      # Check for emergency conditions
      ENV['PARLANT_EMERGENCY_BYPASS'] == 'true' ||
        system_maintenance_mode? ||
        parlant_server_unavailable?
    end

    ##
    # Check if error is critical system error warranting bypass
    #
    def critical_system_error?(error)
      error.is_a?(SystemExit) || 
        error.is_a?(Interrupt) ||
        error.message.include?('system critical')
    end

    ##
    # Check if system is in maintenance mode
    #
    def system_maintenance_mode?
      File.exist?('/tmp/maintenance_mode') || ENV['MAINTENANCE_MODE'] == 'true'
    end

    ##
    # Check if Parlant server is unavailable
    #
    def parlant_server_unavailable?
      return false unless self.class.parlant_client
      
      health = self.class.parlant_client.health_check
      health[:status] == 'critical'
    rescue StandardError
      true
    end

    ##
    # Generate unique operation ID
    #
    def generate_operation_id
      "#{self.class.name.downcase}_#{Time.now.to_i}_#{SecureRandom.hex(4)}"
    end

    ##
    # Logging methods
    #
    
    def log_method_entry(method_name, operation_id, args, kwargs)
      logger&.info("Method entry - #{method_name}, OpID: #{operation_id}, Args: #{args.length}, Kwargs: #{kwargs.keys}")
    end

    def log_validation_approved(method_name, operation_id, result)
      logger&.info("Validation approved - #{method_name}, OpID: #{operation_id}, Confidence: #{result.confidence}")
    end

    def log_validation_rejected(method_name, operation_id, result)
      logger&.warn("Validation rejected - #{method_name}, OpID: #{operation_id}, Reason: #{result.reason}")
    end

    def log_method_completion(method_name, operation_id, result, execution_time)
      logger&.info("Method completed - #{method_name}, OpID: #{operation_id}, Time: #{execution_time.round(3)}s")
    end

    def log_method_error(method_name, operation_id, error, execution_time)
      logger&.error("Method error - #{method_name}, OpID: #{operation_id}, Error: #{error.message}, Time: #{execution_time.round(3)}s")
    end

    def log_emergency_bypass(method_name, operation_id)
      logger&.warn("Emergency bypass - #{method_name}, OpID: #{operation_id}")
    end

    ##
    # Context helper methods (to be implemented by including class)
    #
    
    def current_user_id
      respond_to?(:user) ? user&.id : ENV['USER_ID'] || 'system'
    end

    def current_user_role
      respond_to?(:user) ? user&.role : ENV['USER_ROLE'] || 'agent'
    end

    def current_session_id
      respond_to?(:session) ? session&.id : SecureRandom.hex(8)
    end

    def current_conversation_id
      @current_conversation_id ||= SecureRandom.hex(8)
    end

    def current_ip_address
      respond_to?(:request) ? request&.remote_ip : '127.0.0.1'
    end

    def logger
      self.class.parlant_config[:logger] || 
        (defined?(Rails) ? Rails.logger : Logger.new($stdout))
    end
  end
end