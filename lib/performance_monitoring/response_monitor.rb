# frozen_string_literal: true

require 'benchmark'
require 'logger'

module PerformanceMonitoring
  ##
  # ResponseMonitor provides real-time response time monitoring with configurable thresholds.
  # 
  # This class monitors request/response timing for critical application paths and triggers
  # alerts when response times exceed configured thresholds. It integrates with Rails
  # middleware stack and provides detailed performance metrics collection.
  #
  # @example Monitor critical path response times
  #   monitor = PerformanceMonitoring::ResponseMonitor.new
  #   
  #   # Monitor a code block with 200ms threshold
  #   result = monitor.monitor('agent_execution', threshold: 0.2) do
  #     agent.perform_task
  #   end
  #   
  #   # Check if threshold was exceeded
  #   if result.exceeded_threshold?
  #     puts "WARNING: Agent execution took #{result.duration}ms"
  #   end
  #
  # @example Configure critical path monitoring
  #   ResponseMonitor.configure do |config|
  #     config.critical_paths = {
  #       'agent_execution' => { threshold: 0.2, alert_level: :warning },
  #       'user_authentication' => { threshold: 0.1, alert_level: :error },
  #       'api_requests' => { threshold: 0.15, alert_level: :warning }
  #     }
  #   end
  #
  # @author Performance Monitoring Specialist
  # @since 2025-09-05
  class ResponseMonitor
    ##
    # Configuration for response monitoring system
    class Configuration
      attr_accessor :critical_paths, :default_threshold, :logger, :alert_callback,
                    :metrics_storage, :enable_detailed_logging, :sampling_rate

      def initialize
        @critical_paths = {}
        @default_threshold = 0.2 # 200ms default threshold
        @logger = Rails.logger
        @enable_detailed_logging = Rails.env.development?
        @sampling_rate = 1.0 # Monitor 100% of requests by default
        @metrics_storage = :memory # Can be :redis, :database, or :memory
      end
    end

    ##
    # Result object containing timing information and threshold analysis
    class MonitoringResult
      attr_reader :path, :duration, :threshold, :metadata, :timestamp,
                  :memory_before, :memory_after, :gc_stats_before, :gc_stats_after

      def initialize(path:, duration:, threshold:, metadata: {})
        @path = path
        @duration = duration
        @threshold = threshold
        @metadata = metadata
        @timestamp = Time.current
        @memory_before = metadata[:memory_before]
        @memory_after = metadata[:memory_after]
        @gc_stats_before = metadata[:gc_stats_before]
        @gc_stats_after = metadata[:gc_stats_after]
      end

      ##
      # Checks if the response time exceeded the configured threshold
      # @return [Boolean] true if threshold was exceeded
      def exceeded_threshold?
        duration > threshold
      end

      ##
      # Returns the percentage over threshold (if any)
      # @return [Float] percentage over threshold, 0 if under threshold
      def threshold_excess_percentage
        return 0.0 unless exceeded_threshold?
        
        ((duration - threshold) / threshold * 100).round(2)
      end

      ##
      # Returns memory usage delta in bytes
      # @return [Integer] memory usage change during monitoring
      def memory_delta
        return 0 unless memory_before && memory_after
        
        memory_after - memory_before
      end

      ##
      # Returns garbage collection statistics delta
      # @return [Hash] GC statistics changes during monitoring
      def gc_delta
        return {} unless gc_stats_before && gc_stats_after
        
        delta = {}
        gc_stats_after.each do |key, value|
          before_value = gc_stats_before[key] || 0
          delta[key] = value - before_value if value.is_a?(Numeric)
        end
        delta
      end

      ##
      # Formats result as hash for logging/storage
      # @return [Hash] structured result data
      def to_hash
        {
          path: path,
          duration: duration,
          threshold: threshold,
          exceeded: exceeded_threshold?,
          excess_percentage: threshold_excess_percentage,
          memory_delta: memory_delta,
          gc_delta: gc_delta,
          timestamp: timestamp.iso8601,
          metadata: metadata
        }
      end
    end

    class_attribute :configuration
    self.configuration = Configuration.new

    ##
    # Configure the response monitor
    # @yield [Configuration] configuration object for setup
    def self.configure
      yield configuration
    end

    ##
    # Initialize a new response monitor instance
    # @param logger [Logger] custom logger instance (optional)
    def initialize(logger: nil)
      @logger = logger || configuration.logger
      @metrics_store = initialize_metrics_store
    end

    ##
    # Monitor a code block for response time performance
    # 
    # @param path [String] identifier for the monitored path/operation
    # @param threshold [Float] response time threshold in seconds (optional)
    # @param metadata [Hash] additional metadata to include with monitoring
    # @yield block to monitor
    # @return [MonitoringResult] detailed monitoring result
    def monitor(path, threshold: nil, metadata: {})
      return yield unless should_monitor?

      # Determine threshold for this path
      effective_threshold = determine_threshold(path, threshold)
      
      # Capture initial system state
      memory_before = get_memory_usage
      gc_stats_before = GC.stat.dup
      
      # Execute monitoring
      start_time = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      
      begin
        result = yield
      ensure
        end_time = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        duration = end_time - start_time
        
        # Capture final system state
        memory_after = get_memory_usage
        gc_stats_after = GC.stat.dup
        
        # Build complete metadata
        complete_metadata = metadata.merge(
          memory_before: memory_before,
          memory_after: memory_after,
          gc_stats_before: gc_stats_before,
          gc_stats_after: gc_stats_after,
          result_class: result.class.name
        )
        
        # Create monitoring result
        monitoring_result = MonitoringResult.new(
          path: path,
          duration: duration,
          threshold: effective_threshold,
          metadata: complete_metadata
        )
        
        # Process the monitoring result
        process_monitoring_result(monitoring_result)
      end
      
      result
    end

    ##
    # Monitor multiple code blocks in sequence
    # @param monitors [Hash] hash of path => block pairs
    # @return [Hash] hash of path => MonitoringResult pairs
    def monitor_batch(monitors)
      results = {}
      
      monitors.each do |path, block|
        results[path] = monitor(path, &block)
      end
      
      results
    end

    ##
    # Get current performance metrics summary
    # @return [Hash] current metrics summary
    def metrics_summary
      {
        total_requests: @metrics_store[:total_requests] || 0,
        threshold_violations: @metrics_store[:threshold_violations] || 0,
        average_response_time: calculate_average_response_time,
        critical_paths_status: critical_paths_status,
        memory_usage: get_memory_usage,
        gc_stats: GC.stat,
        uptime: Process.clock_gettime(Process::CLOCK_MONOTONIC)
      }
    end

    private

    ##
    # Determine if this request should be monitored based on sampling rate
    # @return [Boolean] true if should monitor
    def should_monitor?
      return false if configuration.sampling_rate <= 0
      return true if configuration.sampling_rate >= 1.0
      
      rand <= configuration.sampling_rate
    end

    ##
    # Determine the effective threshold for a given path
    # @param path [String] monitored path
    # @param explicit_threshold [Float] explicitly provided threshold
    # @return [Float] effective threshold to use
    def determine_threshold(path, explicit_threshold)
      return explicit_threshold if explicit_threshold

      path_config = configuration.critical_paths[path]
      return path_config[:threshold] if path_config&.dig(:threshold)

      configuration.default_threshold
    end

    ##
    # Process monitoring result (logging, alerting, storage)
    # @param result [MonitoringResult] monitoring result to process
    def process_monitoring_result(result)
      # Update metrics store
      update_metrics_store(result)
      
      # Log the result
      log_monitoring_result(result)
      
      # Trigger alerts if threshold exceeded
      handle_threshold_violation(result) if result.exceeded_threshold?
    end

    ##
    # Update internal metrics storage
    # @param result [MonitoringResult] monitoring result
    def update_metrics_store(result)
      @metrics_store[:total_requests] = (@metrics_store[:total_requests] || 0) + 1
      
      if result.exceeded_threshold?
        @metrics_store[:threshold_violations] = (@metrics_store[:threshold_violations] || 0) + 1
      end
      
      # Store recent response times for average calculation
      @metrics_store[:recent_times] ||= []
      @metrics_store[:recent_times] << result.duration
      
      # Keep only last 100 response times for average calculation
      @metrics_store[:recent_times] = @metrics_store[:recent_times].last(100)
    end

    ##
    # Log monitoring result with appropriate level
    # @param result [MonitoringResult] monitoring result to log
    def log_monitoring_result(result)
      return unless @logger

      log_level = result.exceeded_threshold? ? :warn : :info
      
      if configuration.enable_detailed_logging
        @logger.public_send(log_level, format_detailed_log_message(result))
      else
        @logger.public_send(log_level, format_simple_log_message(result))
      end
    end

    ##
    # Format detailed log message for monitoring result
    # @param result [MonitoringResult] monitoring result
    # @return [String] formatted log message
    def format_detailed_log_message(result)
      message = "[PERF] Path: #{result.path}, Duration: #{(result.duration * 1000).round(2)}ms"
      message += ", Threshold: #{(result.threshold * 1000).round(2)}ms"
      
      if result.exceeded_threshold?
        message += " ⚠️  EXCEEDED by #{result.threshold_excess_percentage}%"
      else
        message += " ✅"
      end
      
      if result.memory_delta != 0
        message += ", Memory: #{format_memory_size(result.memory_delta)}"
      end
      
      if result.gc_delta.any?
        gc_info = result.gc_delta.map { |k, v| "#{k}:#{v}" }.join(', ')
        message += ", GC: #{gc_info}"
      end
      
      message
    end

    ##
    # Format simple log message for monitoring result
    # @param result [MonitoringResult] monitoring result
    # @return [String] formatted log message
    def format_simple_log_message(result)
      status = result.exceeded_threshold? ? "SLOW" : "OK"
      "[PERF] #{result.path}: #{(result.duration * 1000).round(2)}ms [#{status}]"
    end

    ##
    # Handle threshold violation with configured alert mechanism
    # @param result [MonitoringResult] monitoring result that exceeded threshold
    def handle_threshold_violation(result)
      path_config = configuration.critical_paths[result.path]
      alert_level = path_config&.dig(:alert_level) || :warning
      
      # Execute configured alert callback if present
      if configuration.alert_callback
        configuration.alert_callback.call(result, alert_level)
      end
      
      # Log critical violations as errors
      if alert_level == :error || alert_level == :critical
        @logger&.error("[CRITICAL PERF] #{result.path} exceeded threshold by #{result.threshold_excess_percentage}%")
      end
    end

    ##
    # Initialize metrics storage based on configuration
    # @return [Hash] metrics storage hash
    def initialize_metrics_store
      case configuration.metrics_storage
      when :redis
        # TODO: Implement Redis-backed metrics storage
        {}
      when :database
        # TODO: Implement database-backed metrics storage
        {}
      else
        # Default in-memory storage
        {}
      end
    end

    ##
    # Get current memory usage in bytes
    # @return [Integer] current memory usage
    def get_memory_usage
      # Use RSS (Resident Set Size) for accurate memory measurement
      `ps -o rss= -p #{Process.pid}`.to_i * 1024
    rescue
      0
    end

    ##
    # Calculate average response time from recent measurements
    # @return [Float] average response time in seconds
    def calculate_average_response_time
      recent_times = @metrics_store[:recent_times] || []
      return 0.0 if recent_times.empty?
      
      recent_times.sum / recent_times.size.to_f
    end

    ##
    # Get status of all critical paths
    # @return [Hash] status information for each critical path
    def critical_paths_status
      status = {}
      
      configuration.critical_paths.each do |path, config|
        status[path] = {
          threshold: config[:threshold],
          alert_level: config[:alert_level],
          monitored: true
        }
      end
      
      status
    end

    ##
    # Format memory size in human-readable format
    # @param bytes [Integer] memory size in bytes
    # @return [String] formatted memory size
    def format_memory_size(bytes)
      return "#{bytes}B" if bytes.abs < 1024
      
      units = %w[KB MB GB TB]
      size = bytes.abs.to_f
      unit_index = 0
      
      while size >= 1024 && unit_index < units.length - 1
        size /= 1024
        unit_index += 1
      end
      
      sign = bytes < 0 ? '-' : '+'
      "#{sign}#{size.round(2)}#{units[unit_index]}"
    end
  end
end