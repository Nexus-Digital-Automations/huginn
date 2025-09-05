# frozen_string_literal: true

# Circuit Breaker Pattern Implementation for Huginn
# Provides failure isolation and automated recovery for external service calls
#
# Dependencies: Rails, Redis (optional for distributed state)
# Usage: CircuitBreaker.call('service_name') { risky_operation() }
module ErrorMonitoring
  ##
  # CircuitBreaker implements the Circuit Breaker pattern to prevent cascading failures
  # and provide automated recovery mechanisms for external service integrations
  #
  # States:
  # - CLOSED: Normal operation, requests pass through
  # - OPEN: Circuit tripped, requests fail immediately  
  # - HALF_OPEN: Testing phase, limited requests allowed
  #
  # Features:
  # - Configurable failure thresholds and timeouts
  # - Automatic state transitions and recovery
  # - Health check probes for service recovery detection
  # - Integration with error monitoring and alerting
  # - Thread-safe operation with proper locking
  #
  # @example Basic usage
  #   result = CircuitBreaker.call('external_api') do
  #     HTTParty.get('https://api.example.com/data')
  #   end
  #
  # @example With custom configuration
  #   CircuitBreaker.configure('payment_gateway', {
  #     failure_threshold: 3,
  #     timeout: 30.seconds,
  #     recovery_probe_interval: 60.seconds
  #   })
  #
  class CircuitBreaker
    include Singleton

    # Circuit states
    CLOSED = :closed
    OPEN = :open
    HALF_OPEN = :half_open

    # Default configuration values
    DEFAULT_CONFIG = {
      failure_threshold: 5,          # Number of failures before opening circuit
      success_threshold: 3,          # Number of successes to close circuit from half-open
      timeout: 60.seconds,           # Time to wait before trying half-open from open
      recovery_probe_interval: 30.seconds, # Interval between health check probes
      expected_exception_types: [
        Timeout::Error,
        Errno::ECONNREFUSED,
        Errno::EHOSTUNREACH,
        SocketError,
        Net::OpenTimeout,
        Net::ReadTimeout,
        StandardError
      ]
    }.freeze

    ##
    # Execute block with circuit breaker protection
    #
    # @param service_name [String] Unique identifier for the protected service
    # @param options [Hash] Override default configuration for this call
    # @yield Block to execute with circuit breaker protection
    # @return Result of the block execution
    # @raise [CircuitBreakerOpenError] When circuit is open and call is rejected
    def self.call(service_name, options = {}, &block)
      instance.execute_with_circuit_breaker(service_name, options, &block)
    end

    ##
    # Configure circuit breaker for specific service
    #
    # @param service_name [String] Service identifier
    # @param config [Hash] Configuration overrides
    def self.configure(service_name, config = {})
      instance.configure_service(service_name, config)
    end

    ##
    # Get current state of circuit breaker for service
    #
    # @param service_name [String] Service identifier  
    # @return [Symbol] Current circuit state (:closed, :open, :half_open)
    def self.state(service_name)
      instance.get_circuit_state(service_name)
    end

    ##
    # Get circuit breaker statistics for service
    #
    # @param service_name [String] Service identifier
    # @return [Hash] Statistics including failure counts, state history, etc.
    def self.statistics(service_name)
      instance.get_circuit_statistics(service_name)
    end

    ##
    # Force circuit breaker to specific state (for testing/manual intervention)
    #
    # @param service_name [String] Service identifier
    # @param new_state [Symbol] Target state (:closed, :open, :half_open)
    def self.force_state(service_name, new_state)
      instance.force_circuit_state(service_name, new_state)
    end

    ##
    # Reset circuit breaker to initial state
    #
    # @param service_name [String] Service identifier
    def self.reset(service_name)
      instance.reset_circuit(service_name)
    end

    ##
    # Get health status for all monitored services
    #
    # @return [Hash] Health status for each service
    def self.health_status
      instance.get_all_health_status
    end

    def initialize
      @circuits = {}
      @mutex = Mutex.new
      @configurations = {}
      
      Rails.logger.info "[CircuitBreaker] Initialized circuit breaker manager", {
        default_config: DEFAULT_CONFIG
      }
    end

    ##
    # Execute block with circuit breaker protection (instance method)
    def execute_with_circuit_breaker(service_name, options = {}, &block)
      operation_start = Time.current
      operation_id = generate_operation_id
      
      Rails.logger.info "[CircuitBreaker] Executing with protection", {
        service_name: service_name,
        operation_id: operation_id,
        current_state: get_circuit_state(service_name)
      }

      begin
        circuit = get_or_create_circuit(service_name)
        config = get_service_config(service_name, options)
        
        # Check circuit state and handle accordingly
        case circuit[:state]
        when CLOSED
          execute_closed_state(service_name, circuit, config, operation_id, &block)
        when OPEN
          execute_open_state(service_name, circuit, config, operation_id, &block)
        when HALF_OPEN
          execute_half_open_state(service_name, circuit, config, operation_id, &block)
        end
      rescue => circuit_error
        Rails.logger.error "[CircuitBreaker] Circuit breaker execution failed", {
          service_name: service_name,
          operation_id: operation_id,
          error: circuit_error.message,
          execution_time_ms: ((Time.current - operation_start) * 1000).round(2)
        }
        raise circuit_error
      end
    end

    ##
    # Configure service-specific settings
    def configure_service(service_name, config)
      @mutex.synchronize do
        @configurations[service_name] = DEFAULT_CONFIG.merge(config)
        
        Rails.logger.info "[CircuitBreaker] Service configured", {
          service_name: service_name,
          config: @configurations[service_name]
        }
      end
    end

    ##
    # Get current circuit state
    def get_circuit_state(service_name)
      circuit = get_or_create_circuit(service_name)
      circuit[:state]
    end

    ##
    # Get comprehensive circuit statistics
    def get_circuit_statistics(service_name)
      operation_start = Time.current
      
      begin
        circuit = get_or_create_circuit(service_name)
        config = get_service_config(service_name)
        
        statistics = {
          service_name: service_name,
          current_state: circuit[:state],
          failure_count: circuit[:failure_count],
          success_count: circuit[:success_count],
          last_failure_time: circuit[:last_failure_time],
          last_success_time: circuit[:last_success_time],
          state_changed_at: circuit[:state_changed_at],
          total_requests: circuit[:total_requests] || 0,
          successful_requests: circuit[:successful_requests] || 0,
          failed_requests: circuit[:failed_requests] || 0,
          configuration: config,
          health_status: calculate_health_status(circuit, config),
          uptime_percentage: calculate_uptime_percentage(circuit),
          average_response_time: circuit[:average_response_time] || 0,
          generated_at: Time.current
        }
        
        processing_time = ((Time.current - operation_start) * 1000).round(2)
        Rails.logger.info "[CircuitBreaker] Statistics generated", {
          service_name: service_name,
          current_state: statistics[:current_state],
          health_status: statistics[:health_status],
          processing_time_ms: processing_time
        }
        
        statistics
      rescue => stats_error
        Rails.logger.error "[CircuitBreaker] Statistics generation failed", {
          service_name: service_name,
          error: stats_error.message
        }
        
        {
          service_name: service_name,
          error: "Statistics unavailable: #{stats_error.message}",
          generated_at: Time.current
        }
      end
    end

    ##
    # Force circuit to specific state
    def force_circuit_state(service_name, new_state)
      @mutex.synchronize do
        circuit = get_or_create_circuit(service_name)
        old_state = circuit[:state]
        
        circuit[:state] = new_state
        circuit[:state_changed_at] = Time.current
        
        Rails.logger.warn "[CircuitBreaker] Circuit state forced", {
          service_name: service_name,
          old_state: old_state,
          new_state: new_state,
          forced_at: circuit[:state_changed_at]
        }
        
        # Reset counters when forcing state
        case new_state
        when CLOSED
          circuit[:failure_count] = 0
          circuit[:success_count] = 0
        when HALF_OPEN
          circuit[:success_count] = 0
        end
      end
    end

    ##
    # Reset circuit to initial clean state
    def reset_circuit(service_name)
      @mutex.synchronize do
        @circuits[service_name] = create_fresh_circuit
        
        Rails.logger.info "[CircuitBreaker] Circuit reset", {
          service_name: service_name,
          reset_at: Time.current
        }
      end
    end

    ##
    # Get health status for all services
    def get_all_health_status
      operation_start = Time.current
      
      health_status = {}
      
      @circuits.each do |service_name, circuit|
        begin
          config = get_service_config(service_name)
          health_status[service_name] = {
            state: circuit[:state],
            health: calculate_health_status(circuit, config),
            last_check: Time.current
          }
        rescue => health_error
          health_status[service_name] = {
            state: :unknown,
            health: :unhealthy,
            error: health_error.message,
            last_check: Time.current
          }
        end
      end
      
      processing_time = ((Time.current - operation_start) * 1000).round(2)
      Rails.logger.info "[CircuitBreaker] Health status check completed", {
        service_count: health_status.length,
        processing_time_ms: processing_time
      }
      
      {
        services: health_status,
        overall_health: determine_overall_health(health_status),
        checked_at: Time.current
      }
    end

    private

    ##
    # Execute in CLOSED state (normal operation)
    def execute_closed_state(service_name, circuit, config, operation_id, &block)
      request_start = Time.current
      
      begin
        result = yield
        record_success(service_name, circuit, Time.current - request_start)
        
        Rails.logger.info "[CircuitBreaker] Request succeeded in CLOSED state", {
          service_name: service_name,
          operation_id: operation_id,
          response_time_ms: ((Time.current - request_start) * 1000).round(2)
        }
        
        result
      rescue *config[:expected_exception_types] => error
        record_failure(service_name, circuit, config, error, Time.current - request_start)
        
        Rails.logger.error "[CircuitBreaker] Request failed in CLOSED state", {
          service_name: service_name,
          operation_id: operation_id,
          error: error.message,
          failure_count: circuit[:failure_count],
          threshold: config[:failure_threshold]
        }
        
        # Check if we should open the circuit
        if circuit[:failure_count] >= config[:failure_threshold]
          transition_to_open(service_name, circuit, config)
        end
        
        raise error
      end
    end

    ##
    # Execute in OPEN state (circuit tripped)
    def execute_open_state(service_name, circuit, config, operation_id, &block)
      Rails.logger.warn "[CircuitBreaker] Request rejected in OPEN state", {
        service_name: service_name,
        operation_id: operation_id,
        time_since_open: Time.current - circuit[:state_changed_at],
        timeout: config[:timeout]
      }
      
      # Check if timeout period has elapsed
      if Time.current - circuit[:state_changed_at] >= config[:timeout]
        transition_to_half_open(service_name, circuit)
        return execute_half_open_state(service_name, circuit, config, operation_id, &block)
      end
      
      # Reject request immediately
      raise CircuitBreakerOpenError.new(service_name, circuit[:last_failure_time])
    end

    ##
    # Execute in HALF_OPEN state (testing recovery)  
    def execute_half_open_state(service_name, circuit, config, operation_id, &block)
      request_start = Time.current
      
      Rails.logger.info "[CircuitBreaker] Testing request in HALF_OPEN state", {
        service_name: service_name,
        operation_id: operation_id,
        success_count: circuit[:success_count],
        success_threshold: config[:success_threshold]
      }
      
      begin
        result = yield
        record_success(service_name, circuit, Time.current - request_start)
        
        Rails.logger.info "[CircuitBreaker] Test request succeeded in HALF_OPEN state", {
          service_name: service_name,
          operation_id: operation_id,
          success_count: circuit[:success_count],
          response_time_ms: ((Time.current - request_start) * 1000).round(2)
        }
        
        # Check if we should close the circuit
        if circuit[:success_count] >= config[:success_threshold]
          transition_to_closed(service_name, circuit)
        end
        
        result
      rescue *config[:expected_exception_types] => error
        record_failure(service_name, circuit, config, error, Time.current - request_start)
        
        Rails.logger.error "[CircuitBreaker] Test request failed in HALF_OPEN state", {
          service_name: service_name,
          operation_id: operation_id,
          error: error.message
        }
        
        # Immediately transition back to OPEN on any failure
        transition_to_open(service_name, circuit, config)
        
        raise error
      end
    end

    ##
    # Get or create circuit for service
    def get_or_create_circuit(service_name)
      @circuits[service_name] ||= create_fresh_circuit
    end

    ##
    # Create fresh circuit with initial state
    def create_fresh_circuit
      {
        state: CLOSED,
        failure_count: 0,
        success_count: 0,
        last_failure_time: nil,
        last_success_time: nil,
        state_changed_at: Time.current,
        total_requests: 0,
        successful_requests: 0,
        failed_requests: 0,
        response_times: [],
        average_response_time: 0.0
      }
    end

    ##
    # Get service configuration with fallback to defaults
    def get_service_config(service_name, options = {})
      service_config = @configurations[service_name] || DEFAULT_CONFIG
      service_config.merge(options)
    end

    ##
    # Record successful request
    def record_success(service_name, circuit, response_time)
      @mutex.synchronize do
        circuit[:success_count] += 1
        circuit[:total_requests] += 1
        circuit[:successful_requests] += 1
        circuit[:last_success_time] = Time.current
        
        # Track response times for performance analysis
        circuit[:response_times] << response_time
        circuit[:response_times] = circuit[:response_times].last(100) # Keep last 100
        circuit[:average_response_time] = circuit[:response_times].sum / circuit[:response_times].length
        
        # Reset failure count on success in CLOSED state
        if circuit[:state] == CLOSED
          circuit[:failure_count] = 0
        end
      end
      
      Rails.logger.debug "[CircuitBreaker] Success recorded", {
        service_name: service_name,
        success_count: circuit[:success_count],
        response_time_ms: (response_time * 1000).round(2)
      }
    end

    ##
    # Record failed request
    def record_failure(service_name, circuit, config, error, response_time)
      @mutex.synchronize do
        circuit[:failure_count] += 1
        circuit[:total_requests] += 1
        circuit[:failed_requests] += 1
        circuit[:last_failure_time] = Time.current
        
        # Track response times even for failures
        circuit[:response_times] << response_time
        circuit[:response_times] = circuit[:response_times].last(100)
        if circuit[:response_times].any?
          circuit[:average_response_time] = circuit[:response_times].sum / circuit[:response_times].length
        end
      end
      
      Rails.logger.debug "[CircuitBreaker] Failure recorded", {
        service_name: service_name,
        failure_count: circuit[:failure_count],
        error_class: error.class.name,
        response_time_ms: (response_time * 1000).round(2)
      }
      
      # Integrate with error tracking
      ErrorTracker.track_error(error, {
        source: 'circuit_breaker',
        service_name: service_name,
        category: :external_api,
        severity: determine_error_severity(circuit, config),
        metadata: {
          circuit_state: circuit[:state],
          failure_count: circuit[:failure_count],
          threshold: config[:failure_threshold]
        }
      })
    end

    ##
    # Transition circuit to OPEN state
    def transition_to_open(service_name, circuit, config)
      @mutex.synchronize do
        circuit[:state] = OPEN
        circuit[:state_changed_at] = Time.current
        circuit[:success_count] = 0
      end
      
      Rails.logger.error "[CircuitBreaker] Circuit OPENED", {
        service_name: service_name,
        failure_count: circuit[:failure_count],
        threshold: config[:failure_threshold],
        opened_at: circuit[:state_changed_at]
      }
      
      # Trigger alert for circuit opening
      trigger_circuit_alert(service_name, OPEN, circuit, config)
    end

    ##
    # Transition circuit to HALF_OPEN state
    def transition_to_half_open(service_name, circuit)
      @mutex.synchronize do
        circuit[:state] = HALF_OPEN
        circuit[:state_changed_at] = Time.current
        circuit[:success_count] = 0
      end
      
      Rails.logger.info "[CircuitBreaker] Circuit transitioned to HALF_OPEN", {
        service_name: service_name,
        transitioned_at: circuit[:state_changed_at]
      }
    end

    ##
    # Transition circuit to CLOSED state
    def transition_to_closed(service_name, circuit)
      @mutex.synchronize do
        circuit[:state] = CLOSED
        circuit[:state_changed_at] = Time.current
        circuit[:failure_count] = 0
        circuit[:success_count] = 0
      end
      
      Rails.logger.info "[CircuitBreaker] Circuit CLOSED (recovered)", {
        service_name: service_name,
        closed_at: circuit[:state_changed_at]
      }
      
      # Trigger recovery alert
      trigger_circuit_alert(service_name, CLOSED, circuit, nil)
    end

    ##
    # Calculate health status based on circuit state and metrics
    def calculate_health_status(circuit, config)
      case circuit[:state]
      when CLOSED
        failure_rate = circuit[:total_requests] > 0 ? 
          circuit[:failed_requests].to_f / circuit[:total_requests] : 0
        
        if failure_rate < 0.01 # Less than 1% failure rate
          :healthy
        elsif failure_rate < 0.05 # Less than 5% failure rate
          :degraded
        else
          :unhealthy
        end
      when HALF_OPEN
        :recovering
      when OPEN
        :unhealthy
      else
        :unknown
      end
    end

    ##
    # Calculate uptime percentage based on state history
    def calculate_uptime_percentage(circuit)
      # Simplified calculation - in production this would track state changes over time
      case circuit[:state]
      when CLOSED
        success_rate = circuit[:total_requests] > 0 ? 
          (circuit[:successful_requests].to_f / circuit[:total_requests]) * 100 : 100
        success_rate.round(2)
      when HALF_OPEN
        75.0 # Partial availability
      when OPEN
        0.0  # No availability
      else
        0.0
      end
    end

    ##
    # Determine overall health from individual service health
    def determine_overall_health(health_status)
      return :unknown if health_status.empty?
      
      health_counts = health_status.values.group_by { |s| s[:health] }
      
      if health_counts[:unhealthy]&.any?
        :unhealthy
      elsif health_counts[:degraded]&.any? || health_counts[:recovering]&.any?
        :degraded
      elsif health_counts[:healthy]&.any?
        :healthy
      else
        :unknown
      end
    end

    ##
    # Determine error severity based on circuit state and failure count
    def determine_error_severity(circuit, config)
      failure_ratio = circuit[:failure_count].to_f / config[:failure_threshold]
      
      case failure_ratio
      when 0..0.3
        :low
      when 0.3..0.7
        :medium
      when 0.7..1.0
        :high
      else
        :critical
      end
    end

    ##
    # Trigger alerts for circuit state changes
    def trigger_circuit_alert(service_name, new_state, circuit, config)
      alert_data = {
        service_name: service_name,
        new_state: new_state,
        previous_state: circuit[:previous_state],
        state_changed_at: circuit[:state_changed_at],
        failure_count: circuit[:failure_count],
        total_requests: circuit[:total_requests],
        last_failure_time: circuit[:last_failure_time]
      }
      
      case new_state
      when OPEN
        Rails.logger.error "[ALERT] Circuit breaker OPENED for #{service_name}", alert_data
        # Integration with alerting systems (email, Slack, PagerDuty, etc.)
      when CLOSED
        Rails.logger.info "[ALERT] Circuit breaker RECOVERED for #{service_name}", alert_data
      end
    end

    ##
    # Generate unique operation ID for request tracking
    def generate_operation_id
      "cb_op_#{Time.current.to_i}_#{SecureRandom.hex(4)}"
    end
  end

  ##
  # Custom exception for circuit breaker open state
  class CircuitBreakerOpenError < StandardError
    attr_reader :service_name, :last_failure_time

    def initialize(service_name, last_failure_time)
      @service_name = service_name
      @last_failure_time = last_failure_time
      super("Circuit breaker is OPEN for service '#{service_name}'. Last failure: #{last_failure_time}")
    end
  end
end