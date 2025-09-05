# frozen_string_literal: true

module PerformanceMonitoring
  ##
  # Middleware provides automatic Rails request performance monitoring integration.
  # 
  # This middleware automatically monitors all HTTP requests, tracks response times,
  # identifies critical paths, and integrates with the performance monitoring system
  # to provide comprehensive request-level performance analysis.
  #
  # @example Add middleware to Rails application
  #   # In config/application.rb
  #   config.middleware.use PerformanceMonitoring::Middleware
  #
  # @example Configure middleware thresholds
  #   PerformanceMonitoring::Middleware.configure do |config|
  #     config.monitor_all_requests = true
  #     config.skip_paths = ['/health', '/assets']
  #     config.critical_controllers = ['AgentsController', 'EventsController']
  #   end
  #
  # @author Performance Monitoring Specialist
  # @since 2025-09-05
  class Middleware
    ##
    # Configuration for middleware monitoring
    class Configuration
      attr_accessor :monitor_all_requests, :skip_paths, :critical_controllers,
                    :critical_actions, :request_id_header, :enable_sql_monitoring,
                    :enable_view_monitoring, :max_sql_queries_threshold,
                    :slow_query_threshold, :memory_tracking_enabled

      def initialize
        @monitor_all_requests = true
        @skip_paths = ['/assets', '/health', '/ping', '/favicon.ico']
        @critical_controllers = %w[AgentsController EventsController]
        @critical_actions = %w[create update destroy check run]
        @request_id_header = 'X-Request-ID'
        @enable_sql_monitoring = true
        @enable_view_monitoring = true
        @max_sql_queries_threshold = 50  # Alert on > 50 SQL queries per request
        @slow_query_threshold = 0.1      # Alert on queries > 100ms
        @memory_tracking_enabled = true
      end
    end

    ##
    # Request performance metrics collected during request processing
    class RequestMetrics
      attr_reader :request_id, :path, :method, :controller, :action,
                  :total_time, :view_time, :db_time, :sql_query_count,
                  :slow_queries, :memory_before, :memory_after,
                  :gc_stats_before, :gc_stats_after, :status_code,
                  :timestamp, :user_id, :request_size, :response_size

      def initialize(request_data)
        @request_id = request_data[:request_id]
        @path = request_data[:path]
        @method = request_data[:method]
        @controller = request_data[:controller]
        @action = request_data[:action]
        @total_time = request_data[:total_time]
        @view_time = request_data[:view_time] || 0.0
        @db_time = request_data[:db_time] || 0.0
        @sql_query_count = request_data[:sql_query_count] || 0
        @slow_queries = request_data[:slow_queries] || []
        @memory_before = request_data[:memory_before] || 0
        @memory_after = request_data[:memory_after] || 0
        @gc_stats_before = request_data[:gc_stats_before] || {}
        @gc_stats_after = request_data[:gc_stats_after] || {}
        @status_code = request_data[:status_code]
        @timestamp = request_data[:timestamp] || Time.current
        @user_id = request_data[:user_id]
        @request_size = request_data[:request_size] || 0
        @response_size = request_data[:response_size] || 0
      end

      ##
      # Get memory usage delta in bytes
      # @return [Integer] memory delta
      def memory_delta
        memory_after - memory_before
      end

      ##
      # Check if request is considered slow based on critical path thresholds
      # @return [Boolean] true if request exceeded threshold
      def slow_request?
        threshold = determine_threshold
        total_time > threshold
      end

      ##
      # Check if request has excessive SQL queries
      # @return [Boolean] true if too many SQL queries
      def excessive_sql_queries?
        sql_query_count > Middleware.configuration.max_sql_queries_threshold
      end

      ##
      # Check if request has slow SQL queries
      # @return [Boolean] true if any queries were slow
      def has_slow_sql_queries?
        slow_queries.any?
      end

      ##
      # Get critical path identifier for this request
      # @return [String] critical path identifier
      def critical_path_identifier
        if controller && action
          "#{controller.underscore.gsub('_controller', '')}_#{action}"
        else
          "#{method.downcase}_#{path.gsub('/', '_')}"
        end
      end

      ##
      # Check if this request represents a critical path
      # @return [Boolean] true if critical path
      def critical_path?
        critical_controllers = Middleware.configuration.critical_controllers
        critical_actions = Middleware.configuration.critical_actions
        
        (critical_controllers.include?(controller) || 
         critical_actions.include?(action)) ||
        path.match?(/\A\/(agents|events|scenarios)/)
      end

      ##
      # Convert metrics to hash for storage/logging
      # @return [Hash] metrics as hash
      def to_hash
        {
          request_id: request_id,
          path: path,
          method: method,
          controller: controller,
          action: action,
          total_time: total_time,
          view_time: view_time,
          db_time: db_time,
          sql_query_count: sql_query_count,
          slow_queries: slow_queries,
          memory_delta: memory_delta,
          status_code: status_code,
          timestamp: timestamp.iso8601,
          user_id: user_id,
          request_size: request_size,
          response_size: response_size,
          critical_path: critical_path?,
          slow_request: slow_request?,
          excessive_sql: excessive_sql_queries?,
          has_slow_sql: has_slow_sql_queries?
        }
      end

      private

      def determine_threshold
        path_id = critical_path_identifier
        critical_paths = ResponseMonitor.configuration.critical_paths
        
        if critical_paths && critical_paths[path_id]
          critical_paths[path_id][:threshold] || critical_paths[path_id]['threshold']
        else
          ResponseMonitor.configuration.default_threshold
        end
      end
    end

    class_attribute :configuration
    self.configuration = Configuration.new

    ##
    # Configure the middleware
    # @yield [Configuration] configuration object
    def self.configure
      yield configuration
    end

    ##
    # Initialize middleware
    # @param app [Object] Rack application
    def initialize(app)
      @app = app
      @response_monitor = ResponseMonitor.new
      @sql_queries = []
      @view_time = 0.0
    end

    ##
    # Process Rack request with performance monitoring
    # @param env [Hash] Rack environment
    # @return [Array] Rack response
    def call(env)
      request = Rack::Request.new(env)
      
      # Skip monitoring for configured paths
      return @app.call(env) if should_skip_monitoring?(request)

      # Generate request ID if not present
      request_id = env[configuration.request_id_header] || 
                   env['HTTP_X_REQUEST_ID'] || 
                   SecureRandom.uuid

      # Set request ID for logging correlation
      env['HTTP_X_REQUEST_ID'] = request_id
      
      # Collect initial metrics
      initial_metrics = collect_initial_metrics(request, request_id)
      
      # Setup SQL query monitoring
      setup_sql_monitoring if configuration.enable_sql_monitoring
      
      # Setup view rendering monitoring
      setup_view_monitoring if configuration.enable_view_monitoring
      
      # Process request with timing
      status, headers, body = nil
      request_time = Benchmark.realtime do
        status, headers, body = @app.call(env)
      end
      
      # Collect final metrics
      final_metrics = collect_final_metrics(request, status, headers, body, request_time, initial_metrics)
      
      # Process performance data
      process_request_metrics(final_metrics)
      
      # Return response
      [status, headers, body]
    ensure
      # Cleanup monitoring subscriptions
      cleanup_monitoring
    end

    private

    ##
    # Check if request should skip monitoring
    # @param request [Rack::Request] HTTP request
    # @return [Boolean] true if should skip
    def should_skip_monitoring?(request)
      return true unless configuration.monitor_all_requests

      skip_paths = configuration.skip_paths
      skip_paths.any? { |path| request.path.start_with?(path) }
    end

    ##
    # Collect initial request metrics
    # @param request [Rack::Request] HTTP request
    # @param request_id [String] unique request identifier
    # @return [Hash] initial metrics
    def collect_initial_metrics(request, request_id)
      {
        request_id: request_id,
        path: request.path,
        method: request.request_method,
        timestamp: Time.current,
        memory_before: get_memory_usage,
        gc_stats_before: GC.stat.dup,
        request_size: request.content_length || 0,
        user_id: extract_user_id(request)
      }
    end

    ##
    # Collect final request metrics after processing
    # @param request [Rack::Request] HTTP request
    # @param status [Integer] HTTP status code
    # @param headers [Hash] response headers
    # @param body [Object] response body
    # @param request_time [Float] total request processing time
    # @param initial_metrics [Hash] initial metrics collected
    # @return [RequestMetrics] complete request metrics
    def collect_final_metrics(request, status, headers, body, request_time, initial_metrics)
      # Extract Rails routing information if available
      controller_name, action_name = extract_rails_routing_info(request)
      
      # Calculate response size
      response_size = calculate_response_size(body, headers)
      
      # Build complete metrics
      metrics_data = initial_metrics.merge(
        controller: controller_name,
        action: action_name,
        total_time: request_time,
        view_time: @view_time,
        db_time: calculate_db_time,
        sql_query_count: @sql_queries.length,
        slow_queries: @sql_queries.select { |q| q[:duration] > configuration.slow_query_threshold },
        memory_after: get_memory_usage,
        gc_stats_after: GC.stat.dup,
        status_code: status,
        response_size: response_size
      )
      
      RequestMetrics.new(metrics_data)
    end

    ##
    # Process request metrics (logging, monitoring, alerting)
    # @param metrics [RequestMetrics] request performance metrics
    def process_request_metrics(metrics)
      # Log request performance
      log_request_metrics(metrics)
      
      # Monitor response time using ResponseMonitor
      path_id = metrics.critical_path_identifier
      @response_monitor.monitor(path_id, metadata: metrics.to_hash) do
        # This block represents the already-completed request
        # We simulate the timing since the request is already processed
        sleep(metrics.total_time) if metrics.total_time > 0
        :request_completed
      end
      
      # Check for performance alerts
      check_performance_alerts(metrics)
      
      # Store metrics for analysis if configured
      store_request_metrics(metrics)
    end

    ##
    # Log request performance metrics
    # @param metrics [RequestMetrics] request metrics to log
    def log_request_metrics(metrics)
      log_level = determine_log_level(metrics)
      message = format_log_message(metrics)
      
      Rails.logger.public_send(log_level, message)
    end

    ##
    # Determine appropriate log level based on metrics
    # @param metrics [RequestMetrics] request metrics
    # @return [Symbol] log level
    def determine_log_level(metrics)
      if metrics.slow_request? || metrics.excessive_sql_queries? || metrics.has_slow_sql_queries?
        :warn
      elsif metrics.critical_path?
        :info
      else
        :debug
      end
    end

    ##
    # Format log message for request metrics
    # @param metrics [RequestMetrics] request metrics
    # @return [String] formatted log message
    def format_log_message(metrics)
      message = "[PERF REQ] #{metrics.method} #{metrics.path} - #{(metrics.total_time * 1000).round(2)}ms"
      
      if metrics.controller && metrics.action
        message += " (#{metrics.controller}##{metrics.action})"
      end
      
      message += " [#{metrics.status_code}]"
      
      # Add performance indicators
      indicators = []
      indicators << "SLOW" if metrics.slow_request?
      indicators << "HIGH SQL" if metrics.excessive_sql_queries?
      indicators << "SLOW SQL" if metrics.has_slow_sql_queries?
      indicators << "CRITICAL" if metrics.critical_path?
      
      message += " #{indicators.join(' ')}" if indicators.any?
      
      # Add detailed metrics in debug/development
      if Rails.env.development? || Rails.logger.level == Logger::DEBUG
        message += " | DB: #{(metrics.db_time * 1000).round(2)}ms"
        message += " | View: #{(metrics.view_time * 1000).round(2)}ms" if metrics.view_time > 0
        message += " | SQL: #{metrics.sql_query_count}" if metrics.sql_query_count > 0
        message += " | Mem: #{format_memory_size(metrics.memory_delta)}" if metrics.memory_delta != 0
        message += " | ReqID: #{metrics.request_id}"
      end
      
      message
    end

    ##
    # Check for performance alerts based on metrics
    # @param metrics [RequestMetrics] request metrics to check
    def check_performance_alerts(metrics)
      alerts = []
      
      # Slow request alert
      if metrics.slow_request?
        alerts << {
          type: :slow_request,
          severity: metrics.critical_path? ? :critical : :warning,
          message: "Slow request: #{metrics.path} took #{(metrics.total_time * 1000).round(2)}ms",
          metrics: metrics.to_hash
        }
      end
      
      # Excessive SQL queries alert
      if metrics.excessive_sql_queries?
        alerts << {
          type: :excessive_sql,
          severity: :warning,
          message: "Excessive SQL queries: #{metrics.sql_query_count} queries in #{metrics.path}",
          metrics: metrics.to_hash
        }
      end
      
      # Slow SQL queries alert
      if metrics.has_slow_sql_queries?
        slow_query_count = metrics.slow_queries.length
        alerts << {
          type: :slow_sql,
          severity: :warning,
          message: "Slow SQL queries: #{slow_query_count} queries > #{configuration.slow_query_threshold}s in #{metrics.path}",
          metrics: metrics.to_hash
        }
      end
      
      # Trigger alerts
      alerts.each { |alert| trigger_performance_alert(alert) }
    end

    ##
    # Trigger performance alert
    # @param alert [Hash] alert information
    def trigger_performance_alert(alert)
      # Log alert
      Rails.logger.warn("[PERF ALERT] #{alert[:message]}")
      
      # TODO: Integrate with alerting system (email, Slack, etc.)
      # This could be extended to send notifications via configured channels
    end

    ##
    # Store request metrics for historical analysis
    # @param metrics [RequestMetrics] request metrics to store
    def store_request_metrics(metrics)
      # TODO: Implement metrics storage (database, Redis, file system, etc.)
      # For now, we rely on logging for persistence
      
      # Could store in database for dashboard/reporting:
      # PerformanceMetric.create!(metrics.to_hash)
      
      # Could store in Redis for real-time dashboards:
      # Redis.current.lpush('performance_metrics', metrics.to_hash.to_json)
    end

    ##
    # Setup SQL query monitoring using ActiveSupport instrumentation
    def setup_sql_monitoring
      @sql_queries = []
      
      @sql_subscription = ActiveSupport::Notifications.subscribe('sql.active_record') do |name, start, finish, id, payload|
        duration = finish - start
        
        # Skip schema queries and very fast queries
        next if payload[:name] == 'SCHEMA' || duration < 0.001
        
        @sql_queries << {
          sql: payload[:sql],
          duration: duration,
          name: payload[:name],
          connection_id: payload[:connection_id]
        }
      end
    end

    ##
    # Setup view rendering monitoring using ActiveSupport instrumentation
    def setup_view_monitoring
      @view_time = 0.0
      
      @view_subscription = ActiveSupport::Notifications.subscribe('render_template.action_view') do |name, start, finish, id, payload|
        @view_time += (finish - start)
      end
      
      @partial_subscription = ActiveSupport::Notifications.subscribe('render_partial.action_view') do |name, start, finish, id, payload|
        @view_time += (finish - start)
      end
    end

    ##
    # Calculate total database time from SQL queries
    # @return [Float] total database time in seconds
    def calculate_db_time
      @sql_queries.sum { |query| query[:duration] }
    end

    ##
    # Extract Rails controller and action from request
    # @param request [Rack::Request] HTTP request
    # @return [Array<String>] controller and action names
    def extract_rails_routing_info(request)
      # Try to get Rails routing info from request environment
      if request.env['action_controller.instance']
        controller_instance = request.env['action_controller.instance']
        controller_name = controller_instance.class.name
        action_name = controller_instance.action_name
      elsif request.env['action_dispatch.request.parameters']
        params = request.env['action_dispatch.request.parameters']
        controller_name = "#{params[:controller].camelize}Controller" if params[:controller]
        action_name = params[:action]
      end
      
      [controller_name, action_name]
    rescue
      [nil, nil]
    end

    ##
    # Extract user ID from request (if authentication is present)
    # @param request [Rack::Request] HTTP request
    # @return [String, nil] user ID if available
    def extract_user_id(request)
      # Try to get user from Warden (Devise)
      if request.env['warden']&.user
        request.env['warden'].user.id
      elsif request.env['rack.session'] && request.env['rack.session']['user_id']
        request.env['rack.session']['user_id']
      end
    rescue
      nil
    end

    ##
    # Calculate response size from body and headers
    # @param body [Object] response body
    # @param headers [Hash] response headers  
    # @return [Integer] response size in bytes
    def calculate_response_size(body, headers)
      # Check Content-Length header first
      if headers['Content-Length']
        return headers['Content-Length'].to_i
      end
      
      # Calculate from body if it's a simple string/array
      case body
      when String
        body.bytesize
      when Array
        body.sum(&:bytesize)
      else
        0
      end
    rescue
      0
    end

    ##
    # Get current memory usage in bytes
    # @return [Integer] memory usage in bytes
    def get_memory_usage
      `ps -o rss= -p #{Process.pid}`.to_i * 1024
    rescue
      0
    end

    ##
    # Format memory size in human-readable format
    # @param bytes [Integer] memory size in bytes
    # @return [String] formatted memory size
    def format_memory_size(bytes)
      return "#{bytes}B" if bytes.abs < 1024
      
      units = %w[KB MB GB]
      size = bytes.abs.to_f
      unit_index = 0
      
      while size >= 1024 && unit_index < units.length - 1
        size /= 1024
        unit_index += 1
      end
      
      sign = bytes < 0 ? '-' : '+'
      "#{sign}#{size.round(2)}#{units[unit_index]}"
    end

    ##
    # Cleanup monitoring subscriptions
    def cleanup_monitoring
      ActiveSupport::Notifications.unsubscribe(@sql_subscription) if @sql_subscription
      ActiveSupport::Notifications.unsubscribe(@view_subscription) if @view_subscription  
      ActiveSupport::Notifications.unsubscribe(@partial_subscription) if @partial_subscription
    end
  end
end