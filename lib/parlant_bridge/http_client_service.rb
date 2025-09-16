# frozen_string_literal: true

require 'net/http'
require 'json'
require 'concurrent'
require 'monitor'
require 'logger'

module ParlantBridge
  ##
  # HTTP Bridge Client Service for Parlant Server Communication
  # Provides asynchronous validation request/response patterns with connection pooling,
  # retry mechanisms, and comprehensive error handling for Ruby-Huginn integration.
  #
  # @example Basic usage
  #   client = ParlantBridge::HttpClientService.new(
  #     server_url: 'http://localhost:8080',
  #     pool_size: 10,
  #     timeout: 30
  #   )
  #   
  #   result = client.validate_operation(
  #     function_name: 'send_notification',
  #     parameters: { recipient: 'user@example.com', message: 'Alert' },
  #     user_context: { user_id: 123, role: 'admin' },
  #     security_classification: 'INTERNAL'
  #   )
  #
  class HttpClientService
    include MonitorMixin

    # Configuration constants
    DEFAULT_POOL_SIZE = 10
    DEFAULT_TIMEOUT = 30
    DEFAULT_RETRY_ATTEMPTS = 3
    DEFAULT_BACKOFF_MULTIPLIER = 2
    CIRCUIT_BREAKER_FAILURE_THRESHOLD = 5
    CIRCUIT_BREAKER_RECOVERY_TIMEOUT = 60
    
    # HTTP status codes for retry logic
    RETRYABLE_STATUS_CODES = [429, 502, 503, 504].freeze
    
    attr_reader :server_url, :pool_size, :timeout, :logger, :connection_pool, :cache

    ##
    # Initialize HTTP client service with configuration
    #
    # @param server_url [String] Parlant server base URL
    # @param pool_size [Integer] Maximum concurrent connections
    # @param timeout [Integer] Request timeout in seconds
    # @param logger [Logger] Logger instance for monitoring
    # @param cache_ttl [Integer] Cache TTL in seconds
    # @param enable_circuit_breaker [Boolean] Enable circuit breaker pattern
    #
    def initialize(server_url:, pool_size: DEFAULT_POOL_SIZE, timeout: DEFAULT_TIMEOUT, 
                   logger: nil, cache_ttl: 300, enable_circuit_breaker: true)
      super() # Initialize MonitorMixin
      
      @server_url = validate_server_url(server_url)
      @pool_size = pool_size
      @timeout = timeout
      @logger = logger || Logger.new($stdout, level: Logger::INFO)
      @cache = CacheService.new(ttl: cache_ttl)
      
      # Initialize connection pool
      @connection_pool = Concurrent::ThreadPoolExecutor.new(
        min_threads: 2,
        max_threads: pool_size,
        max_queue: pool_size * 2,
        fallback_policy: :caller_runs
      )
      
      # Circuit breaker state
      @circuit_breaker = enable_circuit_breaker ? initialize_circuit_breaker : nil
      
      # Performance metrics
      @metrics = {
        total_requests: Concurrent::AtomicFixnum.new(0),
        successful_requests: Concurrent::AtomicFixnum.new(0),
        failed_requests: Concurrent::AtomicFixnum.new(0),
        cache_hits: Concurrent::AtomicFixnum.new(0),
        average_response_time: Concurrent::AtomicReference.new(0.0)
      }
      
      @logger.info("ParlantBridge::HttpClientService initialized - Server: #{server_url}, Pool: #{pool_size}")
    end

    ##
    # Validate conversational operation with Parlant server
    # Implements asynchronous validation with caching and retry logic
    #
    # @param function_name [String] Name of function to validate
    # @param parameters [Hash] Function parameters for validation
    # @param user_context [Hash] User context information
    # @param security_classification [String] Security level (PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED, CLASSIFIED)
    # @param conversation_id [String] Optional conversation ID for session continuity
    # @return [ValidationResult] Validation result with approval status
    #
    def validate_operation(function_name:, parameters:, user_context:, 
                         security_classification:, conversation_id: nil)
      operation_id = generate_operation_id
      start_time = Time.now
      
      @logger.info("Starting validation - OpID: #{operation_id}, Function: #{function_name}")
      
      # Check cache first
      cache_key = build_cache_key(function_name, parameters, user_context, security_classification)
      cached_result = @cache.get(cache_key)
      if cached_result
        @metrics[:cache_hits].increment
        @logger.info("Cache hit - OpID: #{operation_id}")
        return ValidationResult.from_cache(cached_result, operation_id)
      end
      
      # Circuit breaker check
      if @circuit_breaker && @circuit_breaker.open?
        raise CircuitBreakerOpenError, "Circuit breaker is open, requests temporarily disabled"
      end
      
      # Prepare validation request
      validation_request = build_validation_request(
        function_name, parameters, user_context, security_classification, conversation_id, operation_id
      )
      
      # Execute validation with retry logic
      result = execute_with_retry(validation_request, operation_id)
      
      # Cache successful validations
      if result.success?
        @cache.set(cache_key, result.to_cache_format, ttl: determine_cache_ttl(security_classification))
      end
      
      # Update metrics
      execution_time = Time.now - start_time
      update_metrics(result.success?, execution_time)
      
      @logger.info("Validation completed - OpID: #{operation_id}, Success: #{result.success?}, Time: #{execution_time}s")
      result
      
    rescue StandardError => e
      @logger.error("Validation failed - OpID: #{operation_id}, Error: #{e.message}")
      @metrics[:failed_requests].increment
      handle_validation_error(e, operation_id)
    end

    ##
    # Create async validation session for streaming operations
    # Supports real-time conversation flows with progress callbacks
    #
    # @param session_config [Hash] Session configuration parameters
    # @param progress_callback [Proc] Optional callback for progress updates
    # @return [AsyncValidationSession] Session object for streaming validation
    #
    def create_async_session(session_config:, progress_callback: nil)
      session_id = generate_session_id
      @logger.info("Creating async session - SessionID: #{session_id}")
      
      AsyncValidationSession.new(
        client: self,
        session_id: session_id,
        config: session_config,
        progress_callback: progress_callback,
        logger: @logger
      )
    end

    ##
    # Get service health metrics and status
    #
    # @return [Hash] Current service health and performance metrics
    #
    def health_check
      synchronize do
        total = @metrics[:total_requests].value
        successful = @metrics[:successful_requests].value
        failed = @metrics[:failed_requests].value
        
        {
          status: determine_health_status,
          metrics: {
            total_requests: total,
            successful_requests: successful,
            failed_requests: failed,
            success_rate: total.zero? ? 0.0 : (successful.to_f / total * 100).round(2),
            cache_hit_rate: calculate_cache_hit_rate,
            average_response_time: @metrics[:average_response_time].value.round(3),
            circuit_breaker_status: @circuit_breaker&.status || 'disabled'
          },
          connection_pool: {
            active_threads: @connection_pool.length,
            queue_length: @connection_pool.queue_length,
            pool_size: @pool_size
          },
          timestamp: Time.now.iso8601
        }
      end
    end

    ##
    # Gracefully shutdown the service
    #
    def shutdown
      @logger.info("Shutting down ParlantBridge::HttpClientService")
      @connection_pool.shutdown
      @connection_pool.wait_for_termination(timeout: 10)
      @cache.clear
    end

    private

    ##
    # Validate server URL format
    #
    def validate_server_url(url)
      uri = URI.parse(url)
      unless uri.is_a?(URI::HTTP) || uri.is_a?(URI::HTTPS)
        raise ArgumentError, "Invalid server URL: #{url}"
      end
      url.chomp('/')
    end

    ##
    # Initialize circuit breaker for fault tolerance
    #
    def initialize_circuit_breaker
      CircuitBreaker.new(
        failure_threshold: CIRCUIT_BREAKER_FAILURE_THRESHOLD,
        recovery_timeout: CIRCUIT_BREAKER_RECOVERY_TIMEOUT,
        logger: @logger
      )
    end

    ##
    # Build validation request payload
    #
    def build_validation_request(function_name, parameters, user_context, 
                               security_classification, conversation_id, operation_id)
      {
        operation_id: operation_id,
        function_name: function_name,
        parameters: parameters,
        user_context: user_context,
        security_classification: security_classification,
        conversation_id: conversation_id,
        timestamp: Time.now.iso8601,
        client_info: {
          service: 'huginn',
          version: defined?(Huginn::VERSION) ? Huginn::VERSION : '1.0.0',
          ruby_version: RUBY_VERSION
        }
      }
    end

    ##
    # Execute HTTP request with retry logic and exponential backoff
    #
    def execute_with_retry(request_payload, operation_id, attempts: 0)
      @metrics[:total_requests].increment
      
      response = execute_http_request('/validate', request_payload, operation_id)
      
      if response.success?
        @metrics[:successful_requests].increment
        @circuit_breaker&.record_success
        ValidationResult.from_response(response, operation_id)
      elsif should_retry?(response, attempts)
        wait_time = calculate_backoff_delay(attempts)
        @logger.warn("Request failed, retrying in #{wait_time}s - OpID: #{operation_id}, Attempt: #{attempts + 1}")
        sleep(wait_time)
        execute_with_retry(request_payload, operation_id, attempts + 1)
      else
        @circuit_breaker&.record_failure
        raise ValidationRequestError.new("Request failed after #{attempts + 1} attempts", response)
      end
    end

    ##
    # Execute actual HTTP request
    #
    def execute_http_request(endpoint, payload, operation_id)
      uri = URI("#{@server_url}#{endpoint}")
      
      future = Concurrent::Future.execute(executor: @connection_pool) do
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = uri.scheme == 'https'
        http.open_timeout = @timeout
        http.read_timeout = @timeout
        
        request = Net::HTTP::Post.new(uri)
        request['Content-Type'] = 'application/json'
        request['X-Operation-ID'] = operation_id
        request['X-Client'] = 'huginn-parlant-bridge'
        request['Accept'] = 'application/json'
        request.body = JSON.generate(payload)
        
        @logger.debug("Sending HTTP request - OpID: #{operation_id}, Endpoint: #{endpoint}")
        response = http.request(request)
        
        HttpResponse.new(
          status: response.code.to_i,
          body: response.body,
          headers: response.to_hash,
          success: response.is_a?(Net::HTTPSuccess)
        )
      end
      
      future.value!(@timeout)
    rescue Concurrent::TimeoutError
      raise RequestTimeoutError, "Request timeout after #{@timeout}s - OpID: #{operation_id}"
    rescue StandardError => e
      raise ConnectionError.new("HTTP request failed: #{e.message}", e)
    end

    ##
    # Determine if request should be retried
    #
    def should_retry?(response, attempts)
      return false if attempts >= DEFAULT_RETRY_ATTEMPTS
      return true if RETRYABLE_STATUS_CODES.include?(response.status)
      false
    end

    ##
    # Calculate exponential backoff delay
    #
    def calculate_backoff_delay(attempts)
      base_delay = 1.0
      max_delay = 30.0
      delay = base_delay * (DEFAULT_BACKOFF_MULTIPLIER ** attempts)
      [delay, max_delay].min + rand(0.1..0.5) # Add jitter
    end

    ##
    # Build cache key for validation requests
    #
    def build_cache_key(function_name, parameters, user_context, security_classification)
      data = {
        function: function_name,
        params: parameters.sort.to_h, # Normalize parameter order
        user: user_context.slice(:user_id, :role), # Only cache based on key user attributes
        classification: security_classification
      }
      Digest::SHA256.hexdigest(JSON.generate(data))
    end

    ##
    # Determine cache TTL based on security classification
    #
    def determine_cache_ttl(classification)
      case classification.upcase
      when 'PUBLIC'
        3600 # 1 hour
      when 'INTERNAL'
        1800 # 30 minutes
      when 'CONFIDENTIAL'
        900  # 15 minutes
      when 'RESTRICTED'
        300  # 5 minutes
      when 'CLASSIFIED'
        60   # 1 minute
      else
        300  # Default 5 minutes
      end
    end

    ##
    # Update performance metrics
    #
    def update_metrics(success, execution_time)
      synchronize do
        if success
          @metrics[:successful_requests].increment
        else
          @metrics[:failed_requests].increment
        end
        
        # Update rolling average response time
        current_avg = @metrics[:average_response_time].value
        total_requests = @metrics[:total_requests].value
        new_avg = ((current_avg * (total_requests - 1)) + execution_time) / total_requests
        @metrics[:average_response_time].set(new_avg)
      end
    end

    ##
    # Calculate cache hit rate percentage
    #
    def calculate_cache_hit_rate
      total = @metrics[:total_requests].value
      hits = @metrics[:cache_hits].value
      total.zero? ? 0.0 : (hits.to_f / total * 100).round(2)
    end

    ##
    # Determine overall service health status
    #
    def determine_health_status
      total = @metrics[:total_requests].value
      return 'healthy' if total < 10 # Not enough data
      
      success_rate = @metrics[:successful_requests].value.to_f / total
      avg_response_time = @metrics[:average_response_time].value
      
      if success_rate >= 0.95 && avg_response_time < 1.0
        'healthy'
      elsif success_rate >= 0.90 && avg_response_time < 3.0
        'warning'
      else
        'critical'
      end
    end

    ##
    # Handle validation errors with appropriate fallback strategies
    #
    def handle_validation_error(error, operation_id)
      case error
      when CircuitBreakerOpenError
        ValidationResult.create_fallback('circuit_breaker_open', operation_id)
      when RequestTimeoutError
        ValidationResult.create_fallback('timeout', operation_id)
      when ConnectionError
        ValidationResult.create_fallback('connection_error', operation_id)
      else
        raise error
      end
    end

    ##
    # Generate unique operation ID
    #
    def generate_operation_id
      "huginn_#{Time.now.to_i}_#{SecureRandom.hex(4)}"
    end

    ##
    # Generate unique session ID
    #
    def generate_session_id
      "session_#{Time.now.to_i}_#{SecureRandom.hex(6)}"
    end
  end
end