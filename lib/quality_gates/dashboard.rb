# frozen_string_literal: true

require 'json'
require 'net/http'
require 'uri'

module QualityGates
  # Dashboard integration for real-time quality monitoring and metrics visualization
  # Supports multiple dashboard backends (Grafana, internal Rails dashboard, webhooks)
  #
  # Usage:
  #   dashboard = QualityGates::Dashboard.new(configuration)
  #   dashboard.update_quality_metrics(gate_results, report_data)
  #   status = dashboard.get_current_status
  #
  # Features: Real-time updates, historical charts, alerting integration
  # Backends: Internal Rails dashboard, Grafana, Prometheus, generic webhooks
  class Dashboard
    attr_reader :configuration, :backend_type, :dashboard_url, :api_client

    # Supported dashboard backend types
    BACKEND_TYPES = %i[internal grafana prometheus webhook custom].freeze

    # Metric categories for dashboard organization
    METRIC_CATEGORIES = %i[
      quality_scores
      execution_times
      gate_status
      trends
      alerts
      system_health
    ].freeze

    def initialize(configuration)
      @configuration = configuration
      @dashboard_config = configuration.dashboard_config
      @backend_type = determine_backend_type
      @dashboard_url = @dashboard_config[:url]
      @api_client = initialize_api_client
      @metrics_buffer = []
      @last_update = nil

      validate_dashboard_configuration!
    end

    # Update dashboard with latest quality metrics
    # @param gate_results [Hash] - current gate execution results
    # @param report_data [Hash] - comprehensive report data
    # @return [Boolean] - whether update was successful
    def update_quality_metrics(gate_results, report_data)
      return false unless enabled? && healthy?

      metrics_data = compile_metrics_data(gate_results, report_data)
      
      success = case @backend_type
                when :internal
                  update_internal_dashboard(metrics_data)
                when :grafana
                  update_grafana_dashboard(metrics_data)
                when :prometheus
                  update_prometheus_metrics(metrics_data)
                when :webhook
                  send_webhook_update(metrics_data)
                when :custom
                  update_custom_dashboard(metrics_data)
                else
                  false
                end

      @last_update = Time.now if success
      log_update_result(success, metrics_data)
      
      success
    end

    # Update individual gate status in real-time
    # @param gate_name [Symbol] - name of the gate
    # @param gate_result [QualityGates::GateResult] - individual gate result
    # @return [Boolean] - whether update was successful
    def update_individual_gate_status(gate_name, gate_result)
      return false unless enabled? && @dashboard_config[:real_time]

      gate_metrics = {
        gate: gate_name,
        status: gate_result.status,
        execution_time: gate_result.execution_time,
        timestamp: Time.now.iso8601,
        details: sanitize_gate_details(gate_result.details)
      }

      case @backend_type
      when :internal
        update_internal_gate_status(gate_name, gate_metrics)
      when :webhook
        send_real_time_webhook(gate_metrics)
      else
        buffer_metrics_update(gate_metrics)
      end
    end

    # Get current dashboard status and health
    # @return [Hash] - current dashboard status information
    def get_current_status
      {
        backend_type: @backend_type,
        enabled: enabled?,
        healthy: healthy?,
        last_update: @last_update,
        dashboard_url: @dashboard_url,
        real_time_enabled: @dashboard_config[:real_time],
        metrics_buffer_size: @metrics_buffer.size,
        connection_status: check_connection_status
      }
    end

    # Create or update dashboard configuration
    # @param dashboard_config [Hash] - dashboard configuration to apply
    # @return [Boolean] - whether configuration was successfully applied
    def configure_dashboard(dashboard_config = {})
      case @backend_type
      when :internal
        configure_internal_dashboard(dashboard_config)
      when :grafana
        configure_grafana_dashboard(dashboard_config)
      when :prometheus
        configure_prometheus_dashboard(dashboard_config)
      else
        store_dashboard_config(dashboard_config)
      end
    end

    # Generate dashboard URL for viewing quality gates
    # @param view_type [Symbol] - type of view (:overview, :details, :trends)
    # @return [String, nil] - URL to dashboard view
    def get_dashboard_url(view_type = :overview)
      return nil unless @dashboard_url

      case @backend_type
      when :internal
        generate_internal_dashboard_url(view_type)
      when :grafana
        generate_grafana_dashboard_url(view_type)
      else
        @dashboard_url
      end
    end

    # Check if dashboard is healthy and responsive
    # @return [Boolean] - whether dashboard is operational
    def healthy?
      return true if @backend_type == :internal

      begin
        check_dashboard_connectivity
      rescue StandardError => e
        log_error("Dashboard health check failed", error: e.message)
        false
      end
    end

    # Check if dashboard functionality is enabled
    # @return [Boolean] - whether dashboard is enabled
    def enabled?
      @dashboard_config[:enabled] == true
    end

    # Export dashboard configuration for backup/migration
    # @return [Hash] - exportable dashboard configuration
    def export_configuration
      {
        backend_type: @backend_type,
        configuration: @dashboard_config,
        custom_panels: get_custom_panels_config,
        alert_rules: get_alert_rules_config,
        exported_at: Time.now.iso8601
      }
    end

    # Import dashboard configuration from backup
    # @param config_data [Hash] - configuration data to import
    # @return [Boolean] - whether import was successful
    def import_configuration(config_data)
      validate_import_data!(config_data)
      
      case @backend_type
      when :grafana
        import_grafana_configuration(config_data)
      when :internal
        import_internal_configuration(config_data)
      else
        store_imported_configuration(config_data)
      end
    end

    private

    # Determine the appropriate dashboard backend type
    def determine_backend_type
      if @dashboard_config[:type]
        @dashboard_config[:type].to_sym
      elsif @dashboard_config[:grafana_url]
        :grafana
      elsif @dashboard_config[:prometheus_url]
        :prometheus
      elsif @dashboard_config[:webhook_url]
        :webhook
      else
        :internal
      end
    end

    # Initialize API client based on backend type
    def initialize_api_client
      case @backend_type
      when :grafana
        initialize_grafana_client
      when :prometheus
        initialize_prometheus_client
      when :webhook
        initialize_webhook_client
      else
        nil
      end
    end

    # Validate dashboard configuration
    def validate_dashboard_configuration!
      unless BACKEND_TYPES.include?(@backend_type)
        raise ConfigurationError, "Unsupported dashboard backend: #{@backend_type}"
      end

      case @backend_type
      when :grafana
        validate_grafana_configuration!
      when :prometheus
        validate_prometheus_configuration!
      when :webhook
        validate_webhook_configuration!
      end
    end

    # Compile metrics data for dashboard update
    def compile_metrics_data(gate_results, report_data)
      {
        timestamp: Time.now.iso8601,
        execution_id: report_data[:metadata][:execution_id],
        overall_metrics: {
          quality_score: report_data[:executive_summary][:quality_score],
          success_rate: report_data[:executive_summary][:success_rate],
          total_execution_time: report_data[:overall_metrics][:total_execution_time],
          critical_failures: report_data[:executive_summary][:critical_failures]
        },
        gate_metrics: compile_individual_gate_metrics(gate_results),
        trend_data: compile_trend_metrics(report_data),
        alert_data: compile_alert_metrics(gate_results, report_data),
        system_metrics: compile_system_metrics
      }
    end

    # Compile metrics for individual gates
    def compile_individual_gate_metrics(gate_results)
      gate_results.transform_values do |result|
        {
          status: result.status,
          execution_time: result.execution_time,
          weight: @configuration.get_gate_config(result.gate_name)[:weight] || 1,
          critical: @configuration.get_gate_config(result.gate_name)[:critical] || false,
          category: @configuration.get_gate_config(result.gate_name)[:category],
          metrics: result.metrics || {}
        }
      end
    end

    # Compile trend metrics for historical visualization
    def compile_trend_metrics(report_data)
      {
        quality_score_history: get_quality_score_history,
        execution_time_trends: get_execution_time_trends,
        failure_rate_trends: get_failure_rate_trends,
        gate_performance_trends: get_gate_performance_trends
      }
    end

    # Compile alert metrics for dashboard notifications
    def compile_alert_metrics(gate_results, report_data)
      alerts = []

      # Critical gate failures
      gate_results.each do |gate_name, result|
        if result.failed? && @configuration.get_gate_config(gate_name)[:critical]
          alerts << {
            type: :critical_gate_failure,
            gate: gate_name,
            severity: :critical,
            message: "Critical gate #{gate_name} failed",
            timestamp: Time.now.iso8601
          }
        end
      end

      # Quality score alerts
      quality_score = report_data[:executive_summary][:quality_score]
      if quality_score < 70
        alerts << {
          type: :low_quality_score,
          severity: :warning,
          message: "Quality score dropped to #{quality_score}%",
          timestamp: Time.now.iso8601
        }
      end

      alerts
    end

    # Compile system metrics for infrastructure monitoring
    def compile_system_metrics
      {
        memory_usage: get_memory_usage,
        cpu_usage: get_cpu_usage,
        disk_usage: get_disk_usage,
        response_times: get_response_times,
        active_connections: get_active_connections
      }
    end

    # Internal dashboard implementation
    def update_internal_dashboard(metrics_data)
      # Store metrics in Rails cache or database for internal dashboard
      Rails.cache.write('quality_gates:current_metrics', metrics_data, expires_in: 1.hour)
      Rails.cache.write('quality_gates:last_update', Time.now)
      
      # Update real-time metrics if ActionCable is available
      broadcast_real_time_update(metrics_data) if defined?(ActionCable)
      
      true
    rescue StandardError => e
      log_error("Internal dashboard update failed", error: e.message)
      false
    end

    def update_internal_gate_status(gate_name, gate_metrics)
      current_gates = Rails.cache.read('quality_gates:current_gates') || {}
      current_gates[gate_name] = gate_metrics
      Rails.cache.write('quality_gates:current_gates', current_gates, expires_in: 1.hour)
      
      # Broadcast real-time update
      broadcast_gate_update(gate_name, gate_metrics) if defined?(ActionCable)
      
      true
    end

    def configure_internal_dashboard(config)
      # Configure internal Rails dashboard views and routes
      Rails.cache.write('quality_gates:dashboard_config', config, expires_in: 24.hours)
      true
    end

    def generate_internal_dashboard_url(view_type)
      base_path = Rails.application.routes.url_helpers.quality_gates_dashboard_path rescue '/quality_gates/dashboard'
      
      case view_type
      when :details
        "#{base_path}/details"
      when :trends
        "#{base_path}/trends"
      else
        base_path
      end
    end

    # Grafana dashboard implementation
    def initialize_grafana_client
      return nil unless @dashboard_config[:grafana_url]

      {
        base_url: @dashboard_config[:grafana_url],
        api_key: @dashboard_config[:grafana_api_key],
        org_id: @dashboard_config[:grafana_org_id] || 1
      }
    end

    def validate_grafana_configuration!
      unless @dashboard_config[:grafana_url]
        raise ConfigurationError, "Grafana URL is required for Grafana dashboard backend"
      end

      unless @dashboard_config[:grafana_api_key]
        raise ConfigurationError, "Grafana API key is required for Grafana dashboard backend"
      end
    end

    def update_grafana_dashboard(metrics_data)
      return false unless @api_client

      # Send metrics to Grafana via API or through Prometheus
      payload = format_grafana_payload(metrics_data)
      
      uri = URI("#{@api_client[:base_url]}/api/annotations")
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = uri.scheme == 'https'

      request = Net::HTTP::Post.new(uri)
      request['Authorization'] = "Bearer #{@api_client[:api_key]}"
      request['Content-Type'] = 'application/json'
      request.body = payload.to_json

      response = http.request(request)
      response.code.start_with?('2')
    rescue StandardError => e
      log_error("Grafana update failed", error: e.message)
      false
    end

    def format_grafana_payload(metrics_data)
      {
        text: "Quality Gates Execution - Score: #{metrics_data[:overall_metrics][:quality_score]}%",
        tags: ['quality-gates', 'automated'],
        time: Time.now.to_i * 1000,
        data: metrics_data
      }
    end

    def configure_grafana_dashboard(config)
      # Configure Grafana dashboard panels and queries
      dashboard_config = build_grafana_dashboard_config(config)
      create_or_update_grafana_dashboard(dashboard_config)
    end

    def generate_grafana_dashboard_url(view_type)
      dashboard_uid = @dashboard_config[:grafana_dashboard_uid] || 'quality-gates'
      
      case view_type
      when :details
        "#{@api_client[:base_url]}/d/#{dashboard_uid}/quality-gates-details"
      when :trends
        "#{@api_client[:base_url]}/d/#{dashboard_uid}/quality-gates-trends"
      else
        "#{@api_client[:base_url]}/d/#{dashboard_uid}/quality-gates-overview"
      end
    end

    # Prometheus dashboard implementation
    def initialize_prometheus_client
      return nil unless @dashboard_config[:prometheus_url]

      {
        gateway_url: @dashboard_config[:prometheus_gateway_url],
        job_name: @dashboard_config[:prometheus_job_name] || 'quality_gates',
        instance: @dashboard_config[:prometheus_instance] || Socket.gethostname
      }
    end

    def validate_prometheus_configuration!
      unless @dashboard_config[:prometheus_gateway_url]
        raise ConfigurationError, "Prometheus Push Gateway URL is required"
      end
    end

    def update_prometheus_metrics(metrics_data)
      return false unless @api_client

      # Format metrics in Prometheus format and push to gateway
      prometheus_metrics = format_prometheus_metrics(metrics_data)
      
      uri = URI("#{@api_client[:gateway_url]}/metrics/job/#{@api_client[:job_name]}/instance/#{@api_client[:instance]}")
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = uri.scheme == 'https'

      request = Net::HTTP::Post.new(uri)
      request['Content-Type'] = 'text/plain'
      request.body = prometheus_metrics

      response = http.request(request)
      response.code.start_with?('2')
    rescue StandardError => e
      log_error("Prometheus update failed", error: e.message)
      false
    end

    def format_prometheus_metrics(metrics_data)
      timestamp = Time.now.to_i * 1000
      
      metrics = []
      
      # Overall metrics
      metrics << "quality_gates_score #{metrics_data[:overall_metrics][:quality_score]} #{timestamp}"
      metrics << "quality_gates_success_rate #{metrics_data[:overall_metrics][:success_rate]} #{timestamp}"
      metrics << "quality_gates_execution_time #{metrics_data[:overall_metrics][:total_execution_time]} #{timestamp}"
      
      # Individual gate metrics
      metrics_data[:gate_metrics].each do |gate_name, gate_data|
        status_value = gate_data[:status] == :passed ? 1 : 0
        metrics << "quality_gates_gate_status{gate=\"#{gate_name}\"} #{status_value} #{timestamp}"
        metrics << "quality_gates_gate_execution_time{gate=\"#{gate_name}\"} #{gate_data[:execution_time]} #{timestamp}"
      end
      
      metrics.join("\n")
    end

    # Webhook dashboard implementation
    def initialize_webhook_client
      return nil unless @dashboard_config[:webhook_url]

      {
        url: @dashboard_config[:webhook_url],
        headers: @dashboard_config[:webhook_headers] || {},
        auth: @dashboard_config[:webhook_auth]
      }
    end

    def validate_webhook_configuration!
      unless @dashboard_config[:webhook_url]
        raise ConfigurationError, "Webhook URL is required for webhook dashboard backend"
      end
    end

    def send_webhook_update(metrics_data)
      return false unless @api_client

      uri = URI(@api_client[:url])
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = uri.scheme == 'https'

      request = Net::HTTP::Post.new(uri)
      request['Content-Type'] = 'application/json'
      
      # Apply custom headers
      @api_client[:headers].each { |key, value| request[key] = value }
      
      # Apply authentication
      apply_webhook_authentication(request) if @api_client[:auth]
      
      request.body = JSON.generate({
        event: 'quality_gates_update',
        timestamp: Time.now.iso8601,
        data: metrics_data
      })

      response = http.request(request)
      response.code.start_with?('2')
    rescue StandardError => e
      log_error("Webhook update failed", error: e.message)
      false
    end

    def send_real_time_webhook(gate_metrics)
      return false unless @api_client

      payload = {
        event: 'quality_gate_status_update',
        timestamp: Time.now.iso8601,
        data: gate_metrics
      }

      send_webhook_payload(payload)
    end

    def apply_webhook_authentication(request)
      auth_config = @api_client[:auth]
      
      case auth_config[:type]
      when 'basic'
        request.basic_auth(auth_config[:username], auth_config[:password])
      when 'bearer'
        request['Authorization'] = "Bearer #{auth_config[:token]}"
      when 'api_key'
        request[auth_config[:header] || 'X-API-Key'] = auth_config[:key]
      end
    end

    # Utility methods
    def check_connection_status
      case @backend_type
      when :internal
        :connected
      when :webhook
        test_webhook_connectivity
      when :grafana
        test_grafana_connectivity
      when :prometheus
        test_prometheus_connectivity
      else
        :unknown
      end
    end

    def test_webhook_connectivity
      return :no_config unless @api_client

      uri = URI(@api_client[:url])
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = uri.scheme == 'https'
      http.open_timeout = 5
      http.read_timeout = 5

      request = Net::HTTP::Head.new(uri)
      response = http.request(request)
      
      response.code.start_with?('2') || response.code == '405' ? :connected : :error
    rescue StandardError
      :error
    end

    def check_dashboard_connectivity
      case @backend_type
      when :internal
        true
      when :webhook
        test_webhook_connectivity == :connected
      when :grafana, :prometheus
        # Implement specific health checks
        true
      else
        false
      end
    end

    def buffer_metrics_update(metrics)
      @metrics_buffer << {
        timestamp: Time.now,
        data: metrics
      }
      
      # Flush buffer if it gets too large
      flush_metrics_buffer if @metrics_buffer.size > 100
    end

    def flush_metrics_buffer
      return if @metrics_buffer.empty?

      # Process buffered metrics
      @metrics_buffer.clear
    end

    def sanitize_gate_details(details)
      return details unless details.is_a?(Hash)
      
      # Remove sensitive information
      details.except(:credentials, :tokens, :passwords, :keys)
    end

    def broadcast_real_time_update(metrics_data)
      return unless defined?(ActionCable)

      ActionCable.server.broadcast(
        'quality_gates_channel',
        {
          event: 'metrics_update',
          data: metrics_data
        }
      )
    end

    def broadcast_gate_update(gate_name, gate_metrics)
      return unless defined?(ActionCable)

      ActionCable.server.broadcast(
        'quality_gates_channel',
        {
          event: 'gate_update',
          gate: gate_name,
          data: gate_metrics
        }
      )
    end

    # Historical data methods
    def get_quality_score_history
      # Implementation would fetch from time series database
      []
    end

    def get_execution_time_trends
      []
    end

    def get_failure_rate_trends
      []
    end

    def get_gate_performance_trends
      []
    end

    # System metrics methods
    def get_memory_usage
      # Implementation would get actual system metrics
      0
    end

    def get_cpu_usage
      0
    end

    def get_disk_usage
      0
    end

    def get_response_times
      {}
    end

    def get_active_connections
      0
    end

    # Configuration methods
    def get_custom_panels_config
      @dashboard_config[:custom_panels] || []
    end

    def get_alert_rules_config
      @dashboard_config[:alert_rules] || []
    end

    def store_dashboard_config(config)
      # Store configuration in appropriate backend
      true
    end

    def validate_import_data!(config_data)
      required_keys = %w[backend_type configuration]
      required_keys.each do |key|
        unless config_data.key?(key)
          raise ArgumentError, "Import data missing required key: #{key}"
        end
      end
    end

    def store_imported_configuration(config_data)
      # Implementation would store imported configuration
      true
    end

    # Logging helpers
    def log_update_result(success, metrics_data)
      if success
        log_info("Dashboard updated successfully", {
          backend: @backend_type,
          metrics_count: metrics_data.keys.count
        })
      else
        log_error("Dashboard update failed", {
          backend: @backend_type
        })
      end
    end

    def log_info(message, data = {})
      Rails.logger&.info("QualityGates::Dashboard - #{message}: #{data}")
    end

    def log_error(message, data = {})
      Rails.logger&.error("QualityGates::Dashboard - #{message}: #{data}")
    end
  end
end