# frozen_string_literal: true

module ParlantBridge
  ##
  # Comprehensive Error Handling and Recovery System
  # Provides specialized exception classes, circuit breaker pattern,
  # retry mechanisms, and fallback strategies for robust operation.
  #
  
  ##
  # Base error class for all Parlant Bridge exceptions
  #
  class ParlantBridgeError < StandardError
    attr_reader :operation_id, :context, :timestamp, :recoverable

    def initialize(message, operation_id = nil, context = {}, recoverable = true)
      super(message)
      @operation_id = operation_id
      @context = context || {}
      @timestamp = Time.now
      @recoverable = recoverable
    end

    def recoverable?
      @recoverable
    end

    def to_h
      {
        error_class: self.class.name,
        message: message,
        operation_id: @operation_id,
        context: @context,
        timestamp: @timestamp.iso8601,
        recoverable: @recoverable,
        backtrace: backtrace&.first(10)
      }
    end
  end

  ##
  # Validation specific errors
  #
  class ValidationError < ParlantBridgeError; end
  class ValidationTimeoutError < ValidationError; end
  class ValidationRejectedError < ValidationError; end
  class ValidationConfigurationError < ValidationError; end

  ##
  # Connection and communication errors
  #
  class ConnectionError < ParlantBridgeError; end
  class RequestTimeoutError < ConnectionError; end
  class AuthenticationError < ConnectionError; end
  class RateLimitError < ConnectionError; end

  ##
  # Service availability errors
  #
  class ServiceUnavailableError < ParlantBridgeError; end
  class CircuitBreakerOpenError < ServiceUnavailableError; end
  class MaintenanceModeError < ServiceUnavailableError; end

  ##
  # Configuration and setup errors
  #
  class ConfigurationError < ParlantBridgeError
    def initialize(message, context = {})
      super(message, nil, context, false) # Configuration errors are not recoverable
    end
  end

  ##
  # Cache related errors
  #
  class CacheError < ParlantBridgeError; end
  class CacheCorruptionError < CacheError; end

  ##
  # Session management errors
  #
  class SessionError < ParlantBridgeError; end
  class SessionExpiredError < SessionError; end
  class SessionNotFoundError < SessionError; end

  ##
  # HTTP Response wrapper for error context
  #
  class HttpResponse
    attr_reader :status, :body, :headers, :success

    def initialize(status:, body:, headers: {}, success: false)
      @status = status
      @body = body
      @headers = headers || {}
      @success = success
    end

    def success?
      @success
    end

    def client_error?
      @status >= 400 && @status < 500
    end

    def server_error?
      @status >= 500
    end

    def to_h
      {
        status: @status,
        body: @body,
        headers: @headers,
        success: @success
      }
    end
  end

  ##
  # Circuit Breaker Pattern Implementation
  # Provides fault tolerance by monitoring failures and preventing cascading failures
  #
  class CircuitBreaker
    # Circuit breaker states
    STATE_CLOSED = :closed     # Normal operation
    STATE_OPEN = :open         # Failing fast, blocking requests
    STATE_HALF_OPEN = :half_open # Testing if service has recovered

    attr_reader :failure_threshold, :recovery_timeout, :state, :failure_count,
                :last_failure_time, :logger

    ##
    # Initialize circuit breaker
    #
    # @param failure_threshold [Integer] Number of failures to trigger open state
    # @param recovery_timeout [Integer] Seconds to wait before trying recovery
    # @param logger [Logger] Logger for monitoring
    #
    def initialize(failure_threshold: 5, recovery_timeout: 60, logger: nil)
      @failure_threshold = failure_threshold
      @recovery_timeout = recovery_timeout
      @logger = logger || Logger.new($stdout)
      
      # State management
      @state = STATE_CLOSED
      @failure_count = 0
      @last_failure_time = nil
      @last_success_time = Time.now
      @state_mutex = Mutex.new
      
      # Metrics
      @total_requests = 0
      @successful_requests = 0
      @rejected_requests = 0
      
      @logger.info("CircuitBreaker initialized - Threshold: #{@failure_threshold}, Recovery: #{@recovery_timeout}s")
    end

    ##
    # Execute block with circuit breaker protection
    #
    # @param block [Block] Code to execute
    # @return [Object] Block result
    # @raise [CircuitBreakerOpenError] When circuit is open
    #
    def execute(&block)
      @state_mutex.synchronize { @total_requests += 1 }
      
      if open?
        @state_mutex.synchronize { @rejected_requests += 1 }
        raise CircuitBreakerOpenError, "Circuit breaker is open"
      end
      
      begin
        result = block.call
        record_success
        result
      rescue StandardError => e
        record_failure
        raise e
      end
    end

    ##
    # Record successful operation
    #
    def record_success
      @state_mutex.synchronize do
        @failure_count = 0
        @last_success_time = Time.now
        @successful_requests += 1
        
        if @state == STATE_HALF_OPEN
          @state = STATE_CLOSED
          @logger.info("CircuitBreaker recovered - State: CLOSED")
        end
      end
    end

    ##
    # Record failed operation
    #
    def record_failure
      @state_mutex.synchronize do
        @failure_count += 1
        @last_failure_time = Time.now
        
        if @state == STATE_CLOSED && @failure_count >= @failure_threshold
          @state = STATE_OPEN
          @logger.warn("CircuitBreaker opened - Failures: #{@failure_count}")
        elsif @state == STATE_HALF_OPEN
          @state = STATE_OPEN
          @logger.warn("CircuitBreaker re-opened during recovery attempt")
        end
      end
    end

    ##
    # Check if circuit breaker is open
    #
    # @return [Boolean] True if open
    #
    def open?
      @state_mutex.synchronize do
        if @state == STATE_OPEN && recovery_time_elapsed?
          @state = STATE_HALF_OPEN
          @logger.info("CircuitBreaker attempting recovery - State: HALF_OPEN")
        end
        
        @state == STATE_OPEN
      end
    end

    ##
    # Check if circuit breaker is closed
    #
    # @return [Boolean] True if closed
    #
    def closed?
      @state == STATE_CLOSED
    end

    ##
    # Check if circuit breaker is half-open
    #
    # @return [Boolean] True if half-open
    #
    def half_open?
      @state == STATE_HALF_OPEN
    end

    ##
    # Get current status and metrics
    #
    # @return [Hash] Circuit breaker status
    #
    def status
      @state_mutex.synchronize do
        {
          state: @state.to_s,
          failure_count: @failure_count,
          failure_threshold: @failure_threshold,
          last_failure_time: @last_failure_time&.iso8601,
          last_success_time: @last_success_time.iso8601,
          recovery_timeout: @recovery_timeout,
          metrics: {
            total_requests: @total_requests,
            successful_requests: @successful_requests,
            rejected_requests: @rejected_requests,
            success_rate: calculate_success_rate
          }
        }
      end
    end

    ##
    # Reset circuit breaker to closed state
    #
    def reset!
      @state_mutex.synchronize do
        @state = STATE_CLOSED
        @failure_count = 0
        @last_failure_time = nil
        @logger.info("CircuitBreaker manually reset - State: CLOSED")
      end
    end

    private

    ##
    # Check if enough time has elapsed for recovery attempt
    #
    def recovery_time_elapsed?
      return false unless @last_failure_time
      
      Time.now - @last_failure_time >= @recovery_timeout
    end

    ##
    # Calculate success rate percentage
    #
    def calculate_success_rate
      return 0.0 if @total_requests.zero?
      
      (@successful_requests.to_f / @total_requests * 100).round(2)
    end
  end

  ##
  # Error Handler with Retry Logic and Fallback Strategies
  #
  class ErrorHandler
    DEFAULT_MAX_RETRIES = 3
    DEFAULT_BASE_DELAY = 1.0
    DEFAULT_MAX_DELAY = 30.0
    DEFAULT_BACKOFF_MULTIPLIER = 2.0

    attr_reader :max_retries, :base_delay, :max_delay, :backoff_multiplier, :logger

    ##
    # Initialize error handler
    #
    # @param max_retries [Integer] Maximum retry attempts
    # @param base_delay [Float] Base delay between retries
    # @param max_delay [Float] Maximum delay between retries
    # @param backoff_multiplier [Float] Exponential backoff multiplier
    # @param logger [Logger] Logger instance
    #
    def initialize(max_retries: DEFAULT_MAX_RETRIES, base_delay: DEFAULT_BASE_DELAY,
                   max_delay: DEFAULT_MAX_DELAY, backoff_multiplier: DEFAULT_BACKOFF_MULTIPLIER,
                   logger: nil)
      @max_retries = max_retries
      @base_delay = base_delay
      @max_delay = max_delay
      @backoff_multiplier = backoff_multiplier
      @logger = logger || Logger.new($stdout)
    end

    ##
    # Execute operation with retry logic and error handling
    #
    # @param operation_name [String] Name of operation for logging
    # @param retryable_errors [Array] Array of error classes to retry
    # @param fallback [Proc] Fallback operation if all retries fail
    # @param block [Block] Operation to execute
    # @return [Object] Operation result
    #
    def execute_with_retry(operation_name, retryable_errors: [], fallback: nil, &block)
      attempt = 0
      
      begin
        attempt += 1
        @logger.debug("Executing #{operation_name} - Attempt: #{attempt}")
        
        result = block.call
        
        if attempt > 1
          @logger.info("#{operation_name} succeeded after #{attempt} attempts")
        end
        
        result
        
      rescue StandardError => e
        if should_retry?(e, attempt, retryable_errors)
          delay = calculate_delay(attempt)
          @logger.warn("#{operation_name} failed, retrying in #{delay}s - Attempt: #{attempt}, Error: #{e.message}")
          
          sleep(delay)
          retry
        else
          @logger.error("#{operation_name} failed after #{attempt} attempts - Error: #{e.message}")
          
          if fallback
            @logger.info("Executing fallback for #{operation_name}")
            return execute_fallback(fallback, e, operation_name)
          else
            raise e
          end
        end
      end
    end

    ##
    # Handle specific error types with appropriate strategies
    #
    # @param error [Exception] Error to handle
    # @param operation_context [Hash] Context about the failed operation
    # @return [Hash] Error handling result
    #
    def handle_error(error, operation_context = {})
      error_info = {
        type: error.class.name,
        message: error.message,
        operation_id: operation_context[:operation_id],
        timestamp: Time.now.iso8601,
        recoverable: error.respond_to?(:recoverable?) ? error.recoverable? : true
      }
      
      strategy = determine_error_strategy(error)
      
      case strategy
      when :retry
        error_info[:recommendation] = 'Retry operation with exponential backoff'
        error_info[:max_retries] = @max_retries
        
      when :circuit_breaker
        error_info[:recommendation] = 'Activate circuit breaker protection'
        error_info[:action] = 'Block requests temporarily'
        
      when :fallback
        error_info[:recommendation] = 'Use fallback mechanism'
        error_info[:action] = 'Execute alternative operation'
        
      when :escalate
        error_info[:recommendation] = 'Escalate to manual intervention'
        error_info[:action] = 'Alert administrators'
        
      else
        error_info[:recommendation] = 'Log error and continue'
        error_info[:action] = 'Monitor for patterns'
      end
      
      @logger.error("Error handled - Strategy: #{strategy}, #{error_info}")
      error_info
    end

    ##
    # Create recovery plan for failed operations
    #
    # @param error [Exception] The error that occurred
    # @param operation_context [Hash] Context about the failed operation
    # @return [Hash] Recovery plan
    #
    def create_recovery_plan(error, operation_context = {})
      {
        immediate_actions: determine_immediate_actions(error),
        retry_strategy: create_retry_strategy(error),
        fallback_options: determine_fallback_options(error, operation_context),
        escalation_criteria: determine_escalation_criteria(error),
        monitoring_requirements: create_monitoring_requirements(error),
        estimated_recovery_time: estimate_recovery_time(error)
      }
    end

    private

    ##
    # Determine if error should be retried
    #
    def should_retry?(error, attempt, retryable_errors)
      return false if attempt > @max_retries
      return true if retryable_errors.empty? # Retry all errors if none specified
      
      retryable_errors.any? { |error_class| error.is_a?(error_class) }
    end

    ##
    # Calculate retry delay with exponential backoff
    #
    def calculate_delay(attempt)
      delay = @base_delay * (@backoff_multiplier ** (attempt - 1))
      jitter = rand(0.1..0.3) # Add jitter to prevent thundering herd
      
      [delay + jitter, @max_delay].min
    end

    ##
    # Execute fallback operation safely
    #
    def execute_fallback(fallback, original_error, operation_name)
      fallback.call(original_error)
    rescue StandardError => fallback_error
      @logger.error("Fallback failed for #{operation_name} - Error: #{fallback_error.message}")
      raise original_error # Re-raise original error if fallback fails
    end

    ##
    # Determine error handling strategy
    #
    def determine_error_strategy(error)
      case error
      when RequestTimeoutError, RateLimitError
        :retry
      when ConnectionError, ServiceUnavailableError
        :circuit_breaker
      when ValidationRejectedError, AuthenticationError
        :escalate
      when ConfigurationError
        :escalate
      else
        error.respond_to?(:recoverable?) && error.recoverable? ? :retry : :escalate
      end
    end

    ##
    # Determine immediate actions for error recovery
    #
    def determine_immediate_actions(error)
      actions = ['log_error', 'notify_monitoring']
      
      case error
      when ConnectionError
        actions << 'check_network_connectivity'
        actions << 'verify_service_health'
      when AuthenticationError
        actions << 'refresh_authentication'
        actions << 'verify_credentials'
      when RateLimitError
        actions << 'implement_backoff'
        actions << 'review_rate_limits'
      end
      
      actions
    end

    ##
    # Create retry strategy based on error type
    #
    def create_retry_strategy(error)
      {
        max_attempts: @max_retries,
        base_delay: @base_delay,
        backoff_type: 'exponential',
        jitter: true,
        condition: error.respond_to?(:recoverable?) ? error.recoverable? : true
      }
    end

    ##
    # Determine fallback options
    #
    def determine_fallback_options(error, context)
      options = []
      
      case error
      when ValidationTimeoutError
        options << 'use_cached_validation'
        options << 'allow_with_audit'
      when ConnectionError
        options << 'use_local_validation'
        options << 'queue_for_later'
      when ServiceUnavailableError
        options << 'emergency_bypass'
        options << 'manual_approval'
      end
      
      options
    end

    ##
    # Determine escalation criteria
    #
    def determine_escalation_criteria(error)
      {
        immediate: error.is_a?(ConfigurationError) || !error.respond_to?(:recoverable?) || !error.recoverable?,
        after_retries: error.respond_to?(:recoverable?) && error.recoverable?,
        severity: determine_error_severity(error),
        notify: determine_notification_recipients(error)
      }
    end

    ##
    # Create monitoring requirements
    #
    def create_monitoring_requirements(error)
      {
        metrics: ['error_count', 'error_rate', 'recovery_time'],
        alerts: determine_alert_conditions(error),
        dashboards: ['error_dashboard', 'service_health'],
        retention: '30_days'
      }
    end

    ##
    # Estimate recovery time based on error type
    #
    def estimate_recovery_time(error)
      case error
      when RequestTimeoutError, RateLimitError
        '1-5 minutes'
      when ConnectionError
        '5-15 minutes'
      when ServiceUnavailableError
        '15-60 minutes'
      when ConfigurationError
        '1-24 hours'
      else
        'unknown'
      end
    end

    ##
    # Determine error severity
    #
    def determine_error_severity(error)
      case error
      when ConfigurationError, AuthenticationError
        'critical'
      when ServiceUnavailableError, CircuitBreakerOpenError
        'high'
      when ConnectionError, ValidationTimeoutError
        'medium'
      else
        'low'
      end
    end

    ##
    # Determine notification recipients based on error
    #
    def determine_notification_recipients(error)
      case error
      when ConfigurationError
        ['developers', 'ops_team']
      when ServiceUnavailableError
        ['ops_team', 'on_call']
      when AuthenticationError
        ['security_team', 'ops_team']
      else
        ['ops_team']
      end
    end

    ##
    # Determine alert conditions
    #
    def determine_alert_conditions(error)
      base_conditions = ['error_rate > 10%', 'consecutive_failures > 5']
      
      case error
      when ConfigurationError
        base_conditions + ['immediate_alert']
      when ServiceUnavailableError
        base_conditions + ['service_down > 5min']
      else
        base_conditions
      end
    end
  end
end