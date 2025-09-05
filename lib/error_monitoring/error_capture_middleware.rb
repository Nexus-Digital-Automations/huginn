# frozen_string_literal: true

# Error Capture Middleware for Huginn
# Captures and processes all application errors for comprehensive monitoring
#
# Dependencies: Rails, ErrorTracker, RecoveryManager
# Usage: Add to Rails middleware stack in config/application.rb
module ErrorMonitoring
  ##
  # ErrorCaptureMiddleware intercepts all application errors and integrates them
  # with the error monitoring system for comprehensive tracking and recovery
  #
  # Features:
  # - Automatic error capture for all HTTP requests
  # - Context extraction from request/response cycle
  # - Integration with error tracking and recovery systems
  # - Performance impact monitoring
  # - Configurable error filtering and sampling
  # - Request correlation tracking
  #
  # @example Add to Rails application
  #   # config/application.rb
  #   config.middleware.use ErrorMonitoring::ErrorCaptureMiddleware
  #
  # @example Configure error sampling
  #   ErrorCaptureMiddleware.configure do |config|
  #     config.sample_rate = 0.1  # Sample 10% of errors
  #     config.ignore_patterns = [/health_check/]
  #   end
  #
  class ErrorCaptureMiddleware
    # Default configuration
    DEFAULT_CONFIG = {
      enabled: true,
      sample_rate: 1.0,           # Capture all errors by default
      ignore_patterns: [
        /\/health/,               # Health check endpoints
        /\/assets/,               # Static assets
        /favicon\.ico/,           # Favicon requests
        /robots\.txt/             # Robots.txt requests
      ],
      max_context_size: 10_000,   # Maximum context data size in characters
      capture_request_body: false, # Security: don't capture request bodies by default
      capture_response_body: false, # Don't capture response bodies by default
      performance_threshold: 5.seconds, # Report slow requests
      enable_recovery: true,      # Enable automatic recovery attempts
      correlation_header: 'X-Request-ID' # Request correlation header
    }.freeze

    class << self
      attr_accessor :config

      def configure
        self.config ||= DEFAULT_CONFIG.dup
        yield(config) if block_given?
        config
      end
    end

    # Initialize configuration
    self.configure

    def initialize(app)
      @app = app
      @config = self.class.config
      
      Rails.logger.info "[ErrorCaptureMiddleware] Initialized error capture middleware", {
        enabled: @config[:enabled],
        sample_rate: @config[:sample_rate],
        performance_threshold: @config[:performance_threshold]
      }
    end

    def call(env)
      return @app.call(env) unless @config[:enabled]
      
      request_start = Time.current
      correlation_id = extract_correlation_id(env)
      request_context = extract_request_context(env, correlation_id)
      
      # Skip monitoring for ignored patterns
      if should_ignore_request?(request_context[:path])
        return @app.call(env)
      end
      
      begin
        Rails.logger.debug "[ErrorCaptureMiddleware] Processing request", {
          correlation_id: correlation_id,
          method: request_context[:method],
          path: request_context[:path]
        }
        
        # Process request through the application
        status, headers, response = @app.call(env)
        
        # Check for slow requests
        request_duration = Time.current - request_start
        if request_duration > @config[:performance_threshold]
          handle_slow_request(request_context, request_duration, status)
        end
        
        # Track successful requests for baseline metrics
        track_successful_request(request_context, status, request_duration)
        
        [status, headers, response]
      rescue => error
        # Capture and process the error
        request_duration = Time.current - request_start
        handle_application_error(error, request_context, request_duration, env)
        
        # Re-raise the error to maintain normal Rails error handling
        raise error
      end
    end

    private

    ##
    # Extract correlation ID from request headers or generate new one
    def extract_correlation_id(env)
      # Try to get correlation ID from header
      correlation_id = env[@config[:correlation_header]] || 
                      env["HTTP_#{@config[:correlation_header].upcase.tr('-', '_')}"]
      
      # Generate new correlation ID if not present
      correlation_id ||= generate_correlation_id
      
      correlation_id
    end

    ##
    # Extract comprehensive request context
    def extract_request_context(env, correlation_id)
      request = Rack::Request.new(env)
      
      context = {
        correlation_id: correlation_id,
        timestamp: Time.current,
        method: request.request_method,
        path: request.path,
        query_string: request.query_string,
        user_agent: request.user_agent,
        remote_ip: request.ip,
        referer: request.referer,
        content_type: request.content_type,
        content_length: request.content_length,
        scheme: request.scheme,
        host: request.host,
        port: request.port
      }
      
      # Add session information if available
      if env['rack.session']
        context[:session_id] = env['rack.session'].id rescue nil
        context[:user_id] = env['rack.session']['user_id'] rescue nil
      end
      
      # Add request headers (filtered for security)
      context[:headers] = extract_safe_headers(env)
      
      # Add request parameters (filtered for security)
      context[:parameters] = extract_safe_parameters(request)
      
      # Add request body if configured (be very careful with this)
      if @config[:capture_request_body] && should_capture_body?(request)
        context[:request_body] = safely_read_request_body(request)
      end
      
      # Limit context size to prevent memory issues
      limit_context_size(context)
    end

    ##
    # Check if request should be ignored based on patterns
    def should_ignore_request?(path)
      return false if path.nil?
      
      @config[:ignore_patterns].any? { |pattern| path.match?(pattern) }
    end

    ##
    # Handle application errors with comprehensive monitoring
    def handle_application_error(error, request_context, request_duration, env)
      operation_start = Time.current
      
      Rails.logger.error "[ErrorCaptureMiddleware] Application error captured", {
        correlation_id: request_context[:correlation_id],
        error_class: error.class.name,
        error_message: error.message,
        request_path: request_context[:path],
        request_duration_ms: (request_duration * 1000).round(2)
      }
      
      begin
        # Sample errors if configured
        return unless should_sample_error?
        
        # Enhance context with error-specific information
        enhanced_context = request_context.merge({
          error_occurred_at: Time.current,
          request_duration: request_duration,
          environment: Rails.env,
          rails_version: Rails::VERSION::STRING,
          ruby_version: RUBY_VERSION,
          error_context: {
            backtrace: error.backtrace&.first(10),
            cause: error.cause&.message,
            request_id: request_context[:correlation_id]
          }
        })
        
        # Add framework-specific context
        enhanced_context.merge!(extract_framework_context(env, error))
        
        # Track error with monitoring system
        error_record = ErrorTracker.track_error(error, {
          source: 'http_middleware',
          category: determine_error_category(error, request_context),
          severity: determine_error_severity(error, request_context),
          metadata: enhanced_context,
          correlation_id: request_context[:correlation_id]
        })
        
        # Attempt automatic recovery if enabled
        if @config[:enable_recovery] && should_attempt_recovery?(error, request_context)
          attempt_error_recovery(error, enhanced_context, error_record)
        end
        
        # Track middleware performance
        processing_time = ((Time.current - operation_start) * 1000).round(2)
        Rails.logger.debug "[ErrorCaptureMiddleware] Error processing completed", {
          correlation_id: request_context[:correlation_id],
          processing_time_ms: processing_time,
          error_record_id: error_record&.id
        }
        
      rescue => monitoring_error
        # Prevent monitoring system errors from affecting the application
        Rails.logger.error "[ErrorCaptureMiddleware] Error monitoring failed", {
          correlation_id: request_context[:correlation_id],
          original_error: error.message,
          monitoring_error: monitoring_error.message,
          stack_trace: monitoring_error.backtrace&.first(3)
        }
      end
    end

    ##
    # Handle slow requests that exceed performance threshold
    def handle_slow_request(request_context, request_duration, status)
      Rails.logger.warn "[ErrorCaptureMiddleware] Slow request detected", {
        correlation_id: request_context[:correlation_id],
        path: request_context[:path],
        duration_ms: (request_duration * 1000).round(2),
        threshold_ms: (@config[:performance_threshold] * 1000).round(2),
        status: status
      }
      
      # Create performance warning error
      performance_error = StandardError.new(
        "Slow request: #{request_context[:path]} took #{request_duration.round(2)}s"
      )
      
      # Track as low-severity performance issue
      ErrorTracker.track_error(performance_error, {
        source: 'performance_monitoring',
        category: :system,
        severity: :low,
        metadata: {
          request_duration: request_duration,
          performance_threshold: @config[:performance_threshold],
          path: request_context[:path],
          method: request_context[:method],
          status: status
        },
        correlation_id: request_context[:correlation_id]
      })
    end

    ##
    # Track successful requests for baseline metrics
    def track_successful_request(request_context, status, request_duration)
      # Only track occasionally to avoid performance impact
      return unless rand < 0.01 # 1% sampling for successful requests
      
      Rails.logger.debug "[ErrorCaptureMiddleware] Successful request tracked", {
        correlation_id: request_context[:correlation_id],
        path: request_context[:path],
        status: status,
        duration_ms: (request_duration * 1000).round(2)
      }
    end

    ##
    # Determine error category based on error type and context
    def determine_error_category(error, request_context)
      # Rails-specific error categorization
      case error
      when ActiveRecord::ActiveRecordError
        :database_query
      when ActionController::RoutingError
        :validation
      when ActionController::ParameterMissing
        :validation
      when ActionController::UnknownFormat
        :validation
      when Rack::TimeoutError, Timeout::Error
        :network
      when SecurityError, ActionController::InvalidAuthenticityToken
        :authentication
      when ActionController::UnpermittedParameters
        :authorization
      else
        # Categorize based on HTTP context
        case request_context[:path]
        when /\/api\//
          :external_api
        when /\/auth/, /\/login/, /\/oauth/
          :authentication
        else
          :system
        end
      end
    end

    ##
    # Determine error severity based on error type and context  
    def determine_error_severity(error, request_context)
      # Critical errors that require immediate attention
      return :critical if error.is_a?(SystemExit) || error.is_a?(SecurityError)
      return :critical if error.is_a?(ActiveRecord::ConnectionNotEstablished)
      
      # High priority errors
      return :high if error.is_a?(ActiveRecord::StatementTimeout)
      return :high if error.is_a?(ActionController::InvalidAuthenticityToken)
      
      # Medium priority by default for application errors
      return :medium if error.is_a?(StandardError)
      
      # Low priority for validation and client errors
      return :low if error.is_a?(ArgumentError)
      return :low if request_context[:path]&.match?(/\/assets\//)
      
      :medium
    end

    ##
    # Check if automatic recovery should be attempted
    def should_attempt_recovery?(error, request_context)
      # Don't attempt recovery for client errors (4xx-like errors)
      return false if error.is_a?(ActionController::ParameterMissing)
      return false if error.is_a?(ActionController::RoutingError)
      
      # Don't attempt recovery for authentication errors (security risk)
      return false if error.is_a?(ActionController::InvalidAuthenticityToken)
      
      # Attempt recovery for system and infrastructure errors
      return true if error.is_a?(ActiveRecord::ConnectionNotEstablished)
      return true if error.is_a?(Timeout::Error)
      
      # Default: attempt recovery for server errors
      true
    end

    ##
    # Attempt error recovery using recovery manager
    def attempt_error_recovery(error, context, error_record)
      Rails.logger.info "[ErrorCaptureMiddleware] Attempting error recovery", {
        correlation_id: context[:correlation_id],
        error_class: error.class.name
      }
      
      recovery_result = RecoveryManager.attempt_recovery(error, {
        source: 'http_middleware',
        correlation_id: context[:correlation_id],
        request_context: context,
        error_record_id: error_record&.id
      })
      
      if recovery_result[:success]
        Rails.logger.info "[ErrorCaptureMiddleware] Error recovery successful", {
          correlation_id: context[:correlation_id],
          strategy: recovery_result[:strategy]
        }
      else
        Rails.logger.warn "[ErrorCaptureMiddleware] Error recovery failed", {
          correlation_id: context[:correlation_id],
          reason: recovery_result[:reason]
        }
      end
      
      recovery_result
    end

    ##
    # Extract framework-specific context information
    def extract_framework_context(env, error)
      context = {}
      
      # Rails controller and action information
      if env['action_controller.instance']
        controller = env['action_controller.instance']
        context[:controller] = controller.class.name
        context[:action] = controller.action_name
      end
      
      # Rails route information
      if env['action_dispatch.request.path_parameters']
        path_params = env['action_dispatch.request.path_parameters']
        context[:route_params] = path_params.except(:controller, :action)
      end
      
      # Database connection information
      if error.is_a?(ActiveRecord::ActiveRecordError)
        context[:database_config] = {
          adapter: ActiveRecord::Base.connection.adapter_name,
          database: ActiveRecord::Base.connection.current_database
        } rescue {}
      end
      
      context
    end

    ##
    # Extract safe headers (filter out sensitive information)
    def extract_safe_headers(env)
      safe_headers = {}
      
      env.each do |key, value|
        # Only include HTTP headers
        next unless key.start_with?('HTTP_')
        
        # Convert to readable header name
        header_name = key.sub(/^HTTP_/, '').tr('_', '-').downcase
        
        # Skip sensitive headers
        next if sensitive_header?(header_name)
        
        # Limit header value size
        header_value = value.to_s
        header_value = header_value[0..500] + '...' if header_value.length > 500
        
        safe_headers[header_name] = header_value
      end
      
      safe_headers
    end

    ##
    # Extract safe request parameters (filter sensitive data)
    def extract_safe_parameters(request)
      return {} unless request.params
      
      safe_params = {}
      
      request.params.each do |key, value|
        # Skip sensitive parameter names
        next if sensitive_parameter?(key)
        
        # Limit parameter value size
        param_value = value.to_s
        param_value = param_value[0..500] + '...' if param_value.length > 500
        
        safe_params[key] = param_value
      end
      
      safe_params
    end

    ##
    # Check if header contains sensitive information
    def sensitive_header?(header_name)
      sensitive_patterns = %w[
        authorization
        cookie
        x-api-key
        x-auth-token
        x-access-token
        authentication
      ]
      
      sensitive_patterns.any? { |pattern| header_name.include?(pattern) }
    end

    ##
    # Check if parameter contains sensitive information
    def sensitive_parameter?(param_name)
      param_name = param_name.to_s.downcase
      
      sensitive_patterns = %w[
        password
        passwd
        secret
        token
        key
        credential
        auth
        ssn
        credit_card
        cvv
      ]
      
      sensitive_patterns.any? { |pattern| param_name.include?(pattern) }
    end

    ##
    # Check if request body should be captured
    def should_capture_body?(request)
      # Only capture for specific content types
      return false unless request.content_type
      
      safe_content_types = %w[
        application/json
        application/xml
        text/xml
        text/plain
      ]
      
      safe_content_types.any? { |type| request.content_type.include?(type) }
    end

    ##
    # Safely read request body without interfering with Rails
    def safely_read_request_body(request)
      return nil unless request.body
      
      # Read body content
      body_content = request.body.read
      
      # Rewind for Rails to process normally
      request.body.rewind
      
      # Limit body size
      if body_content.length > 1000
        body_content = body_content[0..1000] + '...'
      end
      
      body_content
    rescue => e
      Rails.logger.warn "[ErrorCaptureMiddleware] Failed to read request body: #{e.message}"
      nil
    end

    ##
    # Limit context size to prevent memory issues
    def limit_context_size(context)
      context_json = JSON.generate(context)
      
      if context_json.length > @config[:max_context_size]
        # Remove large fields progressively
        [:headers, :parameters, :request_body].each do |field|
          if context[field] && context_json.length > @config[:max_context_size]
            context[field] = '[TRUNCATED - too large]'
            context_json = JSON.generate(context)
          end
        end
      end
      
      context
    end

    ##
    # Check if error should be sampled based on sample rate
    def should_sample_error?
      return true if @config[:sample_rate] >= 1.0
      
      rand < @config[:sample_rate]
    end

    ##
    # Generate unique correlation ID for request tracking
    def generate_correlation_id
      "req_#{Time.current.to_i}_#{SecureRandom.hex(8)}"
    end
  end
end