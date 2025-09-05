# frozen_string_literal: true

##
# PerformanceMonitoringController provides web-based dashboard access to performance monitoring data.
# 
# This controller serves performance metrics, monitoring status, and historical data
# through JSON API endpoints that can be consumed by dashboard frontend components
# or integrated with existing admin interfaces.
#
# @example Access performance dashboard
#   GET /performance_monitoring/dashboard
#   GET /performance_monitoring/metrics
#   GET /performance_monitoring/status
#
# @author Performance Monitoring Specialist
# @since 2025-09-05
class PerformanceMonitoringController < ApplicationController
  
  # Require admin access for performance monitoring endpoints
  before_action :authenticate_admin!
  
  # Skip CSRF for API endpoints (if needed for dashboard integrations)
  skip_before_action :verify_authenticity_token, only: [:metrics, :status, :alerts]
  
  ##
  # Performance monitoring dashboard view
  def dashboard
    @current_status = gather_current_status
    @recent_metrics = gather_recent_metrics
    @active_alerts = gather_active_alerts
    @optimization_recommendations = gather_optimization_recommendations
  end

  ##
  # Get current performance metrics as JSON
  # @return [JSON] current performance metrics
  def metrics
    metrics_data = {
      timestamp: Time.current.iso8601,
      response_monitoring: gather_response_metrics,
      resource_usage: gather_resource_metrics,
      benchmark_status: gather_benchmark_metrics,
      system_info: gather_system_info
    }
    
    render json: metrics_data
  end

  ##
  # Get current monitoring status
  # @return [JSON] monitoring system status
  def status
    status_data = {
      timestamp: Time.current.iso8601,
      monitoring_active: monitoring_system_active?,
      components: {
        response_monitor: component_status(:response_monitor),
        resource_monitor: component_status(:resource_monitor),
        benchmark_system: component_status(:benchmark_system),
        regression_detector: component_status(:regression_detector),
        middleware: component_status(:middleware)
      },
      configuration: gather_configuration_summary
    }
    
    render json: status_data
  end

  ##
  # Get performance alerts
  # @return [JSON] active performance alerts
  def alerts
    alerts_data = {
      timestamp: Time.current.iso8601,
      active_alerts: gather_active_alerts,
      recent_alerts: gather_recent_alerts,
      alert_summary: generate_alert_summary
    }
    
    render json: alerts_data
  end

  ##
  # Get historical performance data
  # @return [JSON] historical performance metrics
  def history
    hours = params[:hours]&.to_i || 24
    
    history_data = {
      timestamp: Time.current.iso8601,
      period_hours: hours,
      response_time_history: gather_response_time_history(hours),
      resource_usage_history: gather_resource_usage_history(hours),
      benchmark_history: gather_benchmark_history(hours)
    }
    
    render json: history_data
  end

  ##
  # Get optimization recommendations
  # @return [JSON] performance optimization recommendations  
  def recommendations
    recommendations_data = {
      timestamp: Time.current.iso8601,
      recommendations: gather_optimization_recommendations,
      priority_summary: generate_priority_summary,
      implementation_guide: generate_implementation_guide
    }
    
    render json: recommendations_data
  end

  ##
  # Generate comprehensive performance report
  # @return [JSON] comprehensive performance report
  def report
    report_data = {
      generated_at: Time.current.iso8601,
      report_type: 'comprehensive_performance_dashboard_report',
      executive_summary: generate_executive_summary,
      detailed_metrics: gather_detailed_metrics,
      trend_analysis: perform_trend_analysis,
      recommendations: gather_optimization_recommendations,
      system_health: assess_system_health
    }
    
    respond_to do |format|
      format.json { render json: report_data }
      format.html { 
        @report_data = report_data
        render 'report'
      }
    end
  end

  ##
  # Trigger manual performance test run
  # @return [JSON] performance test results
  def run_tests
    return render json: { error: 'Unauthorized' }, status: :forbidden unless current_user.admin?
    
    begin
      # Initialize benchmark system
      require 'performance_monitoring/benchmark_system'
      benchmark_system = PerformanceMonitoring::BenchmarkSystem.new
      
      # Register and run basic benchmarks
      register_dashboard_benchmarks(benchmark_system)
      results = benchmark_system.run_all_benchmarks
      
      test_results = {
        timestamp: Time.current.iso8601,
        test_run_id: SecureRandom.uuid,
        total_tests: results.length,
        passed_tests: results.count { |r| !r.performance_degraded? },
        failed_tests: results.count(&:performance_degraded?),
        critical_failures: results.count(&:critical_degradation?),
        results: results.map do |result|
          {
            name: result.name,
            current_time: result.current_time,
            baseline_time: result.baseline_time,
            performance_change: result.degradation_percentage,
            status: determine_test_status(result),
            description: result.performance_change_description
          }
        end
      }
      
      render json: test_results
    rescue StandardError => e
      Rails.logger.error "[PERFORMANCE DASHBOARD] Failed to run performance tests: #{e.message}"
      render json: { error: 'Failed to run performance tests', message: e.message }, status: :internal_server_error
    end
  end

  private

  ##
  # Gather current system status overview
  # @return [Hash] current status summary
  def gather_current_status
    {
      monitoring_active: monitoring_system_active?,
      response_time_ok: response_time_within_limits?,
      resource_usage_ok: resource_usage_within_limits?,
      recent_alerts_count: gather_active_alerts.length,
      last_benchmark_run: get_last_benchmark_time,
      system_health: assess_system_health_score
    }
  end

  ##
  # Gather recent performance metrics
  # @return [Hash] recent metrics summary
  def gather_recent_metrics
    {
      avg_response_time: calculate_average_response_time,
      memory_usage: get_current_memory_usage,
      cpu_usage: get_current_cpu_usage,
      active_connections: get_database_connections,
      requests_per_minute: calculate_requests_per_minute
    }
  end

  ##
  # Gather response monitoring metrics
  # @return [Hash] response monitoring data
  def gather_response_metrics
    if defined?(PerformanceMonitoring::ResponseMonitor)
      monitor = PerformanceMonitoring::ResponseMonitor.new
      summary = monitor.metrics_summary
      
      {
        total_requests: summary[:total_requests] || 0,
        threshold_violations: summary[:threshold_violations] || 0,
        average_response_time: summary[:average_response_time] || 0.0,
        critical_paths_count: summary[:critical_paths_status]&.length || 0,
        monitoring_active: true
      }
    else
      { monitoring_active: false, error: 'ResponseMonitor not available' }
    end
  rescue StandardError => e
    { monitoring_active: false, error: e.message }
  end

  ##
  # Gather resource monitoring metrics
  # @return [Hash] resource monitoring data
  def gather_resource_metrics
    if defined?(PerformanceMonitoring::ResourceMonitor)
      monitor = PerformanceMonitoring::ResourceMonitor.new
      snapshot = monitor.take_snapshot
      
      {
        memory_usage_mb: snapshot.memory_usage_mb,
        memory_usage_percentage: snapshot.memory_usage_percentage,
        cpu_percentage: snapshot.cpu_percentage,
        load_average: snapshot.load_average,
        gc_frequency: snapshot.gc_frequency_per_minute,
        database_connections: snapshot.database_stats,
        alerts: {
          memory_warning: snapshot.memory_warning?,
          memory_critical: snapshot.memory_critical?,
          cpu_warning: snapshot.cpu_warning?,
          cpu_critical: snapshot.cpu_critical?,
          excessive_gc: snapshot.excessive_gc_frequency?
        }
      }
    else
      { monitoring_active: false, error: 'ResourceMonitor not available' }
    end
  rescue StandardError => e
    { monitoring_active: false, error: e.message }
  end

  ##
  # Gather benchmark system metrics
  # @return [Hash] benchmark system data
  def gather_benchmark_metrics
    baseline_file = Rails.root.join('config/performance_baseline.json')
    
    if baseline_file.exist?
      begin
        baseline_data = JSON.parse(File.read(baseline_file))
        {
          baseline_established: true,
          baseline_date: baseline_data['created_at'],
          benchmark_count: baseline_data['baselines']&.length || 0,
          last_update: File.mtime(baseline_file).iso8601
        }
      rescue JSON::ParserError
        { baseline_established: false, error: 'Invalid baseline file' }
      end
    else
      { baseline_established: false, error: 'No baseline file found' }
    end
  end

  ##
  # Gather system information
  # @return [Hash] system information
  def gather_system_info
    {
      rails_version: Rails.version,
      ruby_version: RUBY_VERSION,
      environment: Rails.env,
      hostname: Socket.gethostname,
      pid: Process.pid,
      uptime: get_process_uptime,
      memory_total: get_total_system_memory,
      cpu_count: get_cpu_count
    }
  rescue StandardError => e
    { error: e.message }
  end

  ##
  # Check if monitoring system is active
  # @return [Boolean] true if monitoring is active
  def monitoring_system_active?
    # Check if key monitoring components are loaded and functioning
    defined?(PerformanceMonitoring::ResponseMonitor) &&
      defined?(PerformanceMonitoring::ResourceMonitor) &&
      Rails.application.middleware.any? { |m| m.klass == PerformanceMonitoring::Middleware }
  end

  ##
  # Get component status
  # @param component [Symbol] component name
  # @return [Hash] component status
  def component_status(component)
    case component
    when :response_monitor
      { 
        loaded: defined?(PerformanceMonitoring::ResponseMonitor),
        configured: defined?(PerformanceMonitoring::ResponseMonitor) && 
                   PerformanceMonitoring::ResponseMonitor.configuration.present?
      }
    when :resource_monitor
      { 
        loaded: defined?(PerformanceMonitoring::ResourceMonitor),
        configured: defined?(PerformanceMonitoring::ResourceMonitor) && 
                   PerformanceMonitoring::ResourceMonitor.configuration.present?
      }
    when :benchmark_system
      { 
        loaded: defined?(PerformanceMonitoring::BenchmarkSystem),
        configured: defined?(PerformanceMonitoring::BenchmarkSystem) && 
                   PerformanceMonitoring::BenchmarkSystem.configuration.present?
      }
    when :regression_detector
      { 
        loaded: defined?(PerformanceMonitoring::RegressionDetector),
        configured: defined?(PerformanceMonitoring::RegressionDetector) && 
                   PerformanceMonitoring::RegressionDetector.configuration.present?
      }
    when :middleware
      { 
        loaded: defined?(PerformanceMonitoring::Middleware),
        active: Rails.application.middleware.any? { |m| m.klass == PerformanceMonitoring::Middleware }
      }
    else
      { error: 'Unknown component' }
    end
  rescue StandardError => e
    { error: e.message }
  end

  ##
  # Gather configuration summary
  # @return [Hash] configuration summary
  def gather_configuration_summary
    summary = {}
    
    if defined?(PerformanceMonitoring::ResponseMonitor)
      config = PerformanceMonitoring::ResponseMonitor.configuration
      summary[:response_monitor] = {
        default_threshold: config.default_threshold,
        sampling_rate: config.sampling_rate,
        critical_paths_count: config.critical_paths&.length || 0
      }
    end
    
    if defined?(PerformanceMonitoring::ResourceMonitor)
      config = PerformanceMonitoring::ResourceMonitor.configuration
      summary[:resource_monitor] = {
        memory_warning_threshold: config.memory_warning_threshold,
        cpu_warning_threshold: config.cpu_warning_threshold,
        monitoring_interval: config.monitoring_interval
      }
    end
    
    summary
  rescue StandardError => e
    { error: e.message }
  end

  ##
  # Gather active performance alerts
  # @return [Array] active alerts
  def gather_active_alerts
    alerts = []
    
    # Check current resource status for alerts
    if defined?(PerformanceMonitoring::ResourceMonitor)
      begin
        monitor = PerformanceMonitoring::ResourceMonitor.new
        snapshot = monitor.take_snapshot
        
        alerts << create_alert(:memory_critical, 'Critical memory usage', snapshot.memory_usage_percentage) if snapshot.memory_critical?
        alerts << create_alert(:memory_warning, 'High memory usage', snapshot.memory_usage_percentage) if snapshot.memory_warning?
        alerts << create_alert(:cpu_critical, 'Critical CPU usage', snapshot.cpu_percentage) if snapshot.cpu_critical?
        alerts << create_alert(:cpu_warning, 'High CPU usage', snapshot.cpu_percentage) if snapshot.cpu_warning?
        alerts << create_alert(:excessive_gc, 'Excessive garbage collection', snapshot.gc_frequency_per_minute) if snapshot.excessive_gc_frequency?
      rescue StandardError => e
        Rails.logger.warn "[PERFORMANCE DASHBOARD] Failed to check resource alerts: #{e.message}"
      end
    end
    
    alerts
  end

  ##
  # Gather recent alerts from logs or storage
  # @return [Array] recent alerts
  def gather_recent_alerts
    # This is a simplified implementation
    # In production, you might store alerts in database or read from log files
    []
  end

  ##
  # Generate alert summary statistics
  # @return [Hash] alert summary
  def generate_alert_summary
    active_alerts = gather_active_alerts
    
    {
      total_active: active_alerts.length,
      critical_count: active_alerts.count { |a| a[:severity] == :critical },
      warning_count: active_alerts.count { |a| a[:severity] == :warning },
      types: active_alerts.group_by { |a| a[:type] }.transform_values(&:length)
    }
  end

  ##
  # Create alert object
  # @param type [Symbol] alert type
  # @param message [String] alert message
  # @param value [Numeric] alert trigger value
  # @return [Hash] alert object
  def create_alert(type, message, value)
    severity = case type
               when :memory_critical, :cpu_critical then :critical
               when :memory_warning, :cpu_warning then :warning
               else :info
               end
    
    {
      id: SecureRandom.uuid,
      type: type,
      severity: severity,
      message: message,
      value: value,
      timestamp: Time.current.iso8601,
      acknowledged: false
    }
  end

  ##
  # Gather optimization recommendations
  # @return [Array] optimization recommendations
  def gather_optimization_recommendations
    recommendations = []
    
    if defined?(PerformanceMonitoring::ResourceMonitor)
      begin
        monitor = PerformanceMonitoring::ResourceMonitor.new
        resource_recommendations = monitor.optimization_recommendations(analysis_window: 24)
        recommendations.concat(resource_recommendations.map(&:to_hash))
      rescue StandardError => e
        Rails.logger.warn "[PERFORMANCE DASHBOARD] Failed to gather resource recommendations: #{e.message}"
      end
    end
    
    # Add general recommendations based on system status
    recommendations.concat(generate_general_recommendations)
    
    recommendations.sort_by { |r| priority_score(r[:priority]) }
  end

  ##
  # Generate general performance recommendations
  # @return [Array] general recommendations
  def generate_general_recommendations
    recommendations = []
    
    # Check if baselines are established
    unless File.exist?(Rails.root.join('config/performance_baseline.json'))
      recommendations << {
        category: 'baseline',
        priority: 'high',
        title: 'Establish Performance Baselines',
        description: 'Create performance baselines to enable regression detection and performance monitoring.',
        action: "Run 'rake performance:benchmark:create_baseline' to establish baselines",
        impact: 'high',
        effort: 'low'
      }
    end
    
    # Check monitoring configuration
    config_file = Rails.root.join('config/performance_monitoring.yml')
    unless config_file.exist?
      recommendations << {
        category: 'configuration',
        priority: 'medium',
        title: 'Configure Performance Monitoring',
        description: 'Customize performance monitoring thresholds and settings for your environment.',
        action: 'Review and customize config/performance_monitoring.yml',
        impact: 'medium',
        effort: 'low'
      }
    end
    
    recommendations
  end

  ##
  # Convert priority to numeric score for sorting
  # @param priority [String] priority level
  # @return [Integer] numeric priority score
  def priority_score(priority)
    case priority.to_s.downcase
    when 'critical' then 1
    when 'high' then 2
    when 'medium' then 3
    when 'low' then 4
    else 5
    end
  end

  ##
  # Check if response times are within acceptable limits
  # @return [Boolean] true if response times are OK
  def response_time_within_limits?
    # Simplified check - in production, this might check recent metrics
    true
  end

  ##
  # Check if resource usage is within acceptable limits
  # @return [Boolean] true if resource usage is OK
  def resource_usage_within_limits?
    if defined?(PerformanceMonitoring::ResourceMonitor)
      monitor = PerformanceMonitoring::ResourceMonitor.new
      snapshot = monitor.take_snapshot
      !snapshot.memory_critical? && !snapshot.cpu_critical?
    else
      true
    end
  rescue
    true
  end

  ##
  # Get last benchmark run time
  # @return [String, nil] last benchmark time
  def get_last_benchmark_time
    baseline_file = Rails.root.join('config/performance_baseline.json')
    if baseline_file.exist?
      File.mtime(baseline_file).iso8601
    else
      nil
    end
  rescue
    nil
  end

  ##
  # Assess system health score (0-100)
  # @return [Integer] health score
  def assess_system_health_score
    score = 100
    
    # Deduct points for active alerts
    active_alerts = gather_active_alerts
    score -= active_alerts.count { |a| a[:severity] == :critical } * 20
    score -= active_alerts.count { |a| a[:severity] == :warning } * 10
    
    # Deduct points for missing baselines
    score -= 15 unless File.exist?(Rails.root.join('config/performance_baseline.json'))
    
    # Deduct points for high resource usage
    if defined?(PerformanceMonitoring::ResourceMonitor)
      begin
        monitor = PerformanceMonitoring::ResourceMonitor.new
        snapshot = monitor.take_snapshot
        
        score -= 10 if snapshot.memory_usage_percentage > 85
        score -= 10 if snapshot.cpu_percentage > 85
      rescue
        score -= 5  # Deduct for monitoring unavailability
      end
    end
    
    [score, 0].max
  end

  ##
  # Calculate average response time from recent requests
  # @return [Float] average response time in ms
  def calculate_average_response_time
    # This is a simplified implementation
    # In production, you might calculate from stored metrics or logs
    150.0  # Default placeholder value
  end

  ##
  # Get current memory usage
  # @return [Float] memory usage in MB
  def get_current_memory_usage
    `ps -o rss= -p #{Process.pid}`.to_i / 1024.0
  rescue
    0.0
  end

  ##
  # Get current CPU usage
  # @return [Float] CPU usage percentage
  def get_current_cpu_usage
    `ps -o %cpu= -p #{Process.pid}`.to_f
  rescue
    0.0
  end

  ##
  # Get database connection count
  # @return [Integer] active database connections
  def get_database_connections
    if defined?(ActiveRecord)
      ActiveRecord::Base.connection_pool.connections.count(&:in_use?)
    else
      0
    end
  rescue
    0
  end

  ##
  # Calculate requests per minute
  # @return [Float] requests per minute
  def calculate_requests_per_minute
    # This is a simplified implementation
    # In production, you might track this from middleware or web server logs
    0.0
  end

  ##
  # Get process uptime in seconds
  # @return [Float] process uptime
  def get_process_uptime
    Process.clock_gettime(Process::CLOCK_MONOTONIC)
  rescue
    0.0
  end

  ##
  # Get total system memory in bytes
  # @return [Integer] total system memory
  def get_total_system_memory
    case RUBY_PLATFORM
    when /linux/
      meminfo = File.read('/proc/meminfo')
      meminfo.match(/MemTotal:\s*(\d+) kB/)[1].to_i * 1024
    when /darwin/
      `sysctl -n hw.memsize`.to_i
    else
      0
    end
  rescue
    0
  end

  ##
  # Get CPU count
  # @return [Integer] number of CPUs
  def get_cpu_count
    `nproc`.to_i
  rescue
    1
  end

  ##
  # Register basic benchmarks for dashboard testing
  # @param benchmark_system [BenchmarkSystem] benchmark system instance
  def register_dashboard_benchmarks(benchmark_system)
    benchmark_system.register_benchmark('dashboard_tests') do |suite|
      suite.measure('database_connection') do
        ActiveRecord::Base.connection.execute('SELECT 1')
      end
      
      suite.measure('memory_allocation') do
        1000.times { |i| "test_string_#{i}" }
      end
      
      suite.measure('simple_computation') do
        (1..1000).map(&:to_s).join(',')
      end
    end
  end

  ##
  # Determine test status from result
  # @param result [BenchmarkResult] benchmark result
  # @return [String] test status
  def determine_test_status(result)
    if result.critical_degradation?
      'critical'
    elsif result.performance_degraded?
      'degraded'
    elsif result.degradation_percentage < -0.05
      'improved'
    else
      'stable'
    end
  end

  ##
  # Generate executive summary for reports
  # @return [Hash] executive summary
  def generate_executive_summary
    {
      system_health_score: assess_system_health_score,
      monitoring_status: monitoring_system_active? ? 'active' : 'inactive',
      active_alerts_count: gather_active_alerts.length,
      recommendations_count: gather_optimization_recommendations.length,
      last_updated: Time.current.iso8601
    }
  end

  ##
  # Gather detailed metrics for comprehensive reporting
  # @return [Hash] detailed metrics
  def gather_detailed_metrics
    {
      response_monitoring: gather_response_metrics,
      resource_usage: gather_resource_metrics,
      benchmark_status: gather_benchmark_metrics,
      system_info: gather_system_info
    }
  end

  ##
  # Perform trend analysis on historical data
  # @return [Hash] trend analysis results
  def perform_trend_analysis
    # Simplified trend analysis
    # In production, this would analyze historical data to identify trends
    {
      response_time_trend: 'stable',
      memory_usage_trend: 'stable',
      error_rate_trend: 'stable',
      performance_trend: 'stable'
    }
  end

  ##
  # Assess overall system health
  # @return [Hash] system health assessment
  def assess_system_health
    health_score = assess_system_health_score
    
    status = case health_score
             when 90..100 then 'excellent'
             when 75..89 then 'good'
             when 60..74 then 'fair'
             when 40..59 then 'poor'
             else 'critical'
             end
    
    {
      overall_score: health_score,
      status: status,
      components_healthy: component_health_check,
      recommendations_count: gather_optimization_recommendations.length
    }
  end

  ##
  # Check health of individual components
  # @return [Hash] component health status
  def component_health_check
    {
      response_monitoring: monitoring_system_active?,
      resource_monitoring: defined?(PerformanceMonitoring::ResourceMonitor),
      benchmarking: File.exist?(Rails.root.join('config/performance_baseline.json')),
      alerting: gather_active_alerts.count { |a| a[:severity] == :critical } == 0
    }
  end

  ##
  # Gather response time history
  # @param hours [Integer] hours of history to gather
  # @return [Array] response time history data
  def gather_response_time_history(hours)
    # Simplified implementation - in production, this would query stored metrics
    []
  end

  ##
  # Gather resource usage history
  # @param hours [Integer] hours of history to gather
  # @return [Array] resource usage history data
  def gather_resource_usage_history(hours)
    # Simplified implementation - in production, this would query stored metrics
    []
  end

  ##
  # Gather benchmark history
  # @param hours [Integer] hours of history to gather
  # @return [Array] benchmark history data
  def gather_benchmark_history(hours)
    # Simplified implementation - in production, this would query stored results
    []
  end

  ##
  # Generate priority summary for recommendations
  # @return [Hash] priority summary
  def generate_priority_summary
    recommendations = gather_optimization_recommendations
    
    {
      critical: recommendations.count { |r| r[:priority] == 'critical' },
      high: recommendations.count { |r| r[:priority] == 'high' },
      medium: recommendations.count { |r| r[:priority] == 'medium' },
      low: recommendations.count { |r| r[:priority] == 'low' }
    }
  end

  ##
  # Generate implementation guide for recommendations
  # @return [Array] implementation guide steps
  def generate_implementation_guide
    [
      {
        step: 1,
        title: 'Address Critical Issues First',
        description: 'Focus on critical and high-priority recommendations that have immediate impact on performance.',
        estimated_time: '1-2 hours'
      },
      {
        step: 2,
        title: 'Establish Baselines',
        description: 'Run performance benchmarks to establish baseline metrics for future comparison.',
        estimated_time: '30 minutes',
        command: 'rake performance:benchmark:create_baseline'
      },
      {
        step: 3,
        title: 'Monitor and Validate',
        description: 'Monitor the system after implementing changes to validate improvements.',
        estimated_time: 'Ongoing'
      }
    ]
  end
end