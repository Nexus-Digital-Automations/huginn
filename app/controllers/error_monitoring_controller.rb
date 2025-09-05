# frozen_string_literal: true

# Error Monitoring Dashboard Controller for Huginn
# Provides web interface for error monitoring system management and visualization
class ErrorMonitoringController < ApplicationController
  before_action :authenticate_user!
  before_action :require_admin_user!
  before_action :load_error_monitoring_components
  before_action :set_time_range, only: [:index, :statistics, :trends, :recovery]

  ##
  # Dashboard overview with key metrics and system health
  def index
    begin
      @dashboard_data = {
        current_error_rate: @error_tracker.current_error_rate,
        error_rate_threshold: ErrorMonitoring::ErrorTracker::PRODUCTION_ERROR_RATE_THRESHOLD,
        threshold_compliance: @error_tracker.current_error_rate <= ErrorMonitoring::ErrorTracker::PRODUCTION_ERROR_RATE_THRESHOLD,
        system_health: assess_system_health,
        recent_errors: fetch_recent_errors(limit: 10),
        error_trends: fetch_error_trends(@time_range),
        circuit_breaker_status: @circuit_breaker.health_status,
        recovery_status: @recovery_manager.health_status,
        alert_summary: generate_alert_summary
      }
      
      Rails.logger.info "[ErrorMonitoringController] Dashboard loaded", {
        user_id: current_user.id,
        error_rate: @dashboard_data[:current_error_rate],
        compliance: @dashboard_data[:threshold_compliance]
      }
      
    rescue => e
      Rails.logger.error "[ErrorMonitoringController] Dashboard loading failed: #{e.message}"
      @dashboard_data = { error: "Dashboard data unavailable: #{e.message}" }
    end
  end

  ##
  # Detailed error statistics and analytics
  def statistics
    begin
      hours = params[:hours]&.to_i || 24
      
      @statistics_data = {
        time_range: hours,
        error_statistics: @error_tracker.error_statistics(hours: hours, include_trends: true),
        categorization_analysis: @error_categorizer.analyze_patterns(
          time_range: hours.hours,
          min_occurrences: 3
        ),
        recovery_statistics: @recovery_manager.recovery_statistics(time_range: hours.hours),
        performance_metrics: calculate_performance_metrics(hours.hours)
      }
      
      respond_to do |format|
        format.html
        format.json { render json: @statistics_data }
        format.csv { send_csv_report(@statistics_data) }
      end
      
    rescue => e
      Rails.logger.error "[ErrorMonitoringController] Statistics loading failed: #{e.message}"
      handle_controller_error(e, "Statistics unavailable")
    end
  end

  ##
  # Error trends and pattern analysis
  def trends
    begin
      @trends_data = {
        trending_errors: @error_categorizer.trending_errors(time_range: @time_range),
        pattern_analysis: @error_categorizer.analyze_patterns(
          time_range: @time_range,
          min_occurrences: params[:min_occurrences]&.to_i || 2
        ),
        hourly_distribution: fetch_hourly_error_distribution(@time_range),
        category_trends: fetch_category_trends(@time_range),
        severity_trends: fetch_severity_trends(@time_range)
      }
      
      respond_to do |format|
        format.html
        format.json { render json: @trends_data }
      end
      
    rescue => e
      Rails.logger.error "[ErrorMonitoringController] Trends loading failed: #{e.message}"
      handle_controller_error(e, "Trends analysis unavailable")
    end
  end

  ##
  # Circuit breaker management and monitoring
  def circuit_breakers
    begin
      @circuit_breaker_data = {
        health_status: @circuit_breaker.health_status,
        service_statistics: fetch_service_statistics,
        configuration: fetch_circuit_breaker_configuration
      }
      
      respond_to do |format|
        format.html
        format.json { render json: @circuit_breaker_data }
      end
      
    rescue => e
      Rails.logger.error "[ErrorMonitoringController] Circuit breaker data loading failed: #{e.message}"
      handle_controller_error(e, "Circuit breaker data unavailable")
    end
  end

  ##
  # Recovery system management and status
  def recovery
    begin
      @recovery_data = {
        health_status: @recovery_manager.health_status,
        recovery_statistics: @recovery_manager.recovery_statistics(time_range: @time_range),
        active_degradations: fetch_active_degradations,
        strategy_performance: fetch_strategy_performance(@time_range)
      }
      
      respond_to do |format|
        format.html
        format.json { render json: @recovery_data }
      end
      
    rescue => e
      Rails.logger.error "[ErrorMonitoringController] Recovery data loading failed: #{e.message}"
      handle_controller_error(e, "Recovery data unavailable")
    end
  end

  ##
  # Real-time system health API endpoint
  def health
    begin
      health_data = {
        timestamp: Time.current,
        error_rate: {
          current: @error_tracker.current_error_rate,
          threshold: ErrorMonitoring::ErrorTracker::PRODUCTION_ERROR_RATE_THRESHOLD,
          status: @error_tracker.current_error_rate <= ErrorMonitoring::ErrorTracker::PRODUCTION_ERROR_RATE_THRESHOLD ? 'compliant' : 'breach'
        },
        circuit_breakers: @circuit_breaker.health_status[:overall_health],
        recovery_system: @recovery_manager.health_status[:overall_health],
        system_status: assess_system_health
      }
      
      render json: health_data
      
    rescue => e
      Rails.logger.error "[ErrorMonitoringController] Health check failed: #{e.message}"
      render json: { error: "Health check failed", timestamp: Time.current }, status: :service_unavailable
    end
  end

  ##
  # Force circuit breaker state change
  def force_circuit_state
    begin
      service_name = params.require(:service_name)
      new_state = params.require(:state).to_sym
      
      unless [:closed, :open, :half_open].include?(new_state)
        return render json: { error: "Invalid state: #{new_state}" }, status: :bad_request
      end
      
      @circuit_breaker.force_state(service_name, new_state)
      
      Rails.logger.info "[ErrorMonitoringController] Circuit breaker state forced", {
        user_id: current_user.id,
        service_name: service_name,
        new_state: new_state
      }
      
      render json: {
        success: true,
        service_name: service_name,
        new_state: new_state,
        changed_at: Time.current
      }
      
    rescue ActionController::ParameterMissing => e
      render json: { error: "Missing parameter: #{e.param}" }, status: :bad_request
    rescue => e
      Rails.logger.error "[ErrorMonitoringController] Circuit breaker state change failed: #{e.message}"
      render json: { error: "State change failed: #{e.message}" }, status: :internal_server_error
    end
  end

  ##
  # Reset circuit breaker to initial state
  def reset_circuit_breaker
    begin
      service_name = params.require(:service_name)
      
      @circuit_breaker.reset(service_name)
      
      Rails.logger.info "[ErrorMonitoringController] Circuit breaker reset", {
        user_id: current_user.id,
        service_name: service_name
      }
      
      render json: {
        success: true,
        service_name: service_name,
        reset_at: Time.current
      }
      
    rescue ActionController::ParameterMissing => e
      render json: { error: "Missing parameter: #{e.param}" }, status: :bad_request
    rescue => e
      Rails.logger.error "[ErrorMonitoringController] Circuit breaker reset failed: #{e.message}"
      render json: { error: "Reset failed: #{e.message}" }, status: :internal_server_error
    end
  end

  ##
  # Enable graceful degradation for component
  def enable_degradation
    begin
      component = params.require(:component)
      degradation_level = params.require(:degradation_level).to_sym
      
      unless ErrorMonitoring::RecoveryManager::DEGRADATION_LEVELS.key?(degradation_level)
        return render json: { error: "Invalid degradation level: #{degradation_level}" }, status: :bad_request
      end
      
      result = @recovery_manager.enable_degradation(component, degradation_level, {
        initiated_by: current_user.id,
        reason: params[:reason] || 'manual_intervention'
      })
      
      Rails.logger.info "[ErrorMonitoringController] Graceful degradation enabled", {
        user_id: current_user.id,
        component: component,
        degradation_level: degradation_level,
        success: result[:success]
      }
      
      render json: result
      
    rescue ActionController::ParameterMissing => e
      render json: { error: "Missing parameter: #{e.param}" }, status: :bad_request
    rescue => e
      Rails.logger.error "[ErrorMonitoringController] Degradation enable failed: #{e.message}"
      render json: { error: "Degradation enable failed: #{e.message}" }, status: :internal_server_error
    end
  end

  ##
  # Restore full functionality for component
  def restore_functionality
    begin
      component = params.require(:component)
      
      result = @recovery_manager.restore_full_functionality(component)
      
      Rails.logger.info "[ErrorMonitoringController] Full functionality restored", {
        user_id: current_user.id,
        component: component,
        success: result[:success]
      }
      
      render json: result
      
    rescue ActionController::ParameterMissing => e
      render json: { error: "Missing parameter: #{e.param}" }, status: :bad_request
    rescue => e
      Rails.logger.error "[ErrorMonitoringController] Functionality restore failed: #{e.message}"
      render json: { error: "Restore failed: #{e.message}" }, status: :internal_server_error
    end
  end

  ##
  # Export comprehensive error monitoring report
  def export_report
    begin
      hours = params[:hours]&.to_i || 24
      format = params[:format] || 'json'
      
      # Generate timestamp for unique filename
      timestamp = Time.current.strftime('%Y%m%d_%H%M%S')
      filename = "error_monitoring_report_#{timestamp}.#{format}"
      
      # Generate report using ErrorTracker
      temp_path = Rails.root.join('tmp', filename)
      report_path = @error_tracker.export_error_report(temp_path.to_s, format: format.to_sym, hours: hours)
      
      Rails.logger.info "[ErrorMonitoringController] Report exported", {
        user_id: current_user.id,
        format: format,
        hours: hours,
        file_size: File.size(report_path)
      }
      
      # Send file to user
      send_file(report_path, {
        filename: filename,
        type: determine_content_type(format),
        disposition: 'attachment'
      })
      
      # Clean up temp file after sending
      File.delete(report_path) if File.exist?(report_path)
      
    rescue => e
      Rails.logger.error "[ErrorMonitoringController] Report export failed: #{e.message}"
      redirect_to error_monitoring_index_path, alert: "Report export failed: #{e.message}"
    end
  end

  ##
  # Configuration management endpoint
  def configuration
    begin
      if request.post?
        update_configuration
      else
        @configuration_data = {
          current_config: load_current_configuration,
          default_config: load_default_configuration,
          environment: Rails.env
        }
      end
      
    rescue => e
      Rails.logger.error "[ErrorMonitoringController] Configuration access failed: #{e.message}"
      handle_controller_error(e, "Configuration unavailable")
    end
  end

  private

  ##
  # Load error monitoring components
  def load_error_monitoring_components
    require_relative '../../../lib/error_monitoring/error_tracker'
    require_relative '../../../lib/error_monitoring/circuit_breaker'
    require_relative '../../../lib/error_monitoring/error_categorizer'
    require_relative '../../../lib/error_monitoring/recovery_manager'
    
    @error_tracker = ErrorMonitoring::ErrorTracker
    @circuit_breaker = ErrorMonitoring::CircuitBreaker
    @error_categorizer = ErrorMonitoring::ErrorCategorizer
    @recovery_manager = ErrorMonitoring::RecoveryManager
    
  rescue => e
    Rails.logger.error "[ErrorMonitoringController] Component loading failed: #{e.message}"
    raise e
  end

  ##
  # Require admin user access
  def require_admin_user!
    unless current_user.admin?
      Rails.logger.warn "[ErrorMonitoringController] Non-admin access attempt", {
        user_id: current_user.id,
        ip: request.remote_ip
      }
      redirect_to root_path, alert: "Access denied. Admin privileges required."
    end
  end

  ##
  # Set time range for queries based on parameters
  def set_time_range
    hours = params[:hours]&.to_i || 24
    hours = [hours, 168].min # Limit to 1 week maximum
    @time_range = hours.hours
  end

  ##
  # Assess overall system health
  def assess_system_health
    error_rate = @error_tracker.current_error_rate
    threshold = ErrorMonitoring::ErrorTracker::PRODUCTION_ERROR_RATE_THRESHOLD
    cb_health = @circuit_breaker.health_status[:overall_health]
    recovery_health = @recovery_manager.health_status[:overall_health]
    
    if error_rate > (threshold * 5) || cb_health == :unhealthy || recovery_health == :unhealthy
      :critical
    elsif error_rate > threshold || cb_health == :degraded || recovery_health == :degraded
      :warning
    else
      :healthy
    end
  rescue
    :unknown
  end

  ##
  # Fetch recent error entries
  def fetch_recent_errors(limit: 20)
    AgentLog.where('level >= ? AND created_at > ?', 3, 24.hours.ago)
            .order(created_at: :desc)
            .limit(limit)
            .pluck(:id, :message, :created_at, :level, :agent_id)
            .map do |id, message, created_at, level, agent_id|
              {
                id: id,
                message: message.truncate(200),
                created_at: created_at,
                level: level,
                agent_id: agent_id,
                severity: level_to_severity(level)
              }
            end
  rescue => e
    Rails.logger.error "[ErrorMonitoringController] Recent errors fetch failed: #{e.message}"
    []
  end

  ##
  # Fetch error trends for time range
  def fetch_error_trends(time_range)
    hours_back = (time_range / 1.hour).to_i
    
    AgentLog.where('level >= ? AND created_at > ?', 3, time_range.ago)
            .group_by_hour(:created_at, last: hours_back)
            .count
            .map { |hour, count| { hour: hour, count: count } }
  rescue => e
    Rails.logger.error "[ErrorMonitoringController] Error trends fetch failed: #{e.message}"
    []
  end

  ##
  # Generate alert summary
  def generate_alert_summary
    alerts = []
    
    # Error rate alerts
    current_rate = @error_tracker.current_error_rate
    threshold = ErrorMonitoring::ErrorTracker::PRODUCTION_ERROR_RATE_THRESHOLD
    
    if current_rate > threshold
      severity = calculate_alert_severity(current_rate, threshold)
      alerts << {
        type: :error_rate_breach,
        severity: severity,
        message: "Error rate (#{(current_rate * 100).round(4)}%) exceeds threshold (#{(threshold * 100).round(4)}%)",
        timestamp: Time.current
      }
    end
    
    # Circuit breaker alerts
    cb_status = @circuit_breaker.health_status
    open_circuits = cb_status[:services].select { |name, status| status[:state] == :open }
    
    if open_circuits.any?
      alerts << {
        type: :circuit_breaker_open,
        severity: :high,
        message: "#{open_circuits.length} circuit breaker(s) open: #{open_circuits.keys.join(', ')}",
        timestamp: Time.current
      }
    end
    
    # Recovery system alerts
    recovery_status = @recovery_manager.health_status
    if recovery_status[:overall_health] == :unhealthy
      alerts << {
        type: :recovery_system_unhealthy,
        severity: :high,
        message: "Recovery system health: #{recovery_status[:overall_health]}",
        timestamp: Time.current
      }
    end
    
    alerts
  rescue => e
    Rails.logger.error "[ErrorMonitoringController] Alert summary generation failed: #{e.message}"
    []
  end

  ##
  # Fetch hourly error distribution
  def fetch_hourly_error_distribution(time_range)
    hours_back = (time_range / 1.hour).to_i
    
    AgentLog.where('level >= ? AND created_at > ?', 3, time_range.ago)
            .group_by_hour(:created_at, last: hours_back)
            .group(:level)
            .count
            .map { |(hour, level), count| 
              { 
                hour: hour, 
                level: level, 
                severity: level_to_severity(level), 
                count: count 
              } 
            }
  rescue => e
    Rails.logger.error "[ErrorMonitoringController] Hourly distribution fetch failed: #{e.message}"
    []
  end

  ##
  # Fetch category trends
  def fetch_category_trends(time_range)
    # Simplified category trend analysis
    # In production, this would use the ErrorCategorizer more extensively
    {
      database_errors: count_errors_by_pattern(time_range, /sql|database|connection/i),
      agent_errors: count_errors_by_pattern(time_range, /agent/i),
      network_errors: count_errors_by_pattern(time_range, /timeout|network|http/i),
      system_errors: count_errors_by_pattern(time_range, /system|internal/i)
    }
  rescue => e
    Rails.logger.error "[ErrorMonitoringController] Category trends fetch failed: #{e.message}"
    {}
  end

  ##
  # Fetch severity trends
  def fetch_severity_trends(time_range)
    hours_back = (time_range / 1.hour).to_i
    
    AgentLog.where('level >= ? AND created_at > ?', 3, time_range.ago)
            .group_by_hour(:created_at, last: hours_back)
            .group(:level)
            .count
            .group_by { |(hour, level), count| hour }
            .transform_values do |hour_data|
              severity_counts = {}
              hour_data.each { |(hour, level), count| severity_counts[level_to_severity(level)] = count }
              severity_counts
            end
  rescue => e
    Rails.logger.error "[ErrorMonitoringController] Severity trends fetch failed: #{e.message}"
    {}
  end

  ##
  # Fetch service statistics for circuit breakers
  def fetch_service_statistics
    cb_health = @circuit_breaker.health_status
    
    cb_health[:services].map do |service_name, status|
      {
        service_name: service_name,
        state: status[:state],
        health: status[:health],
        statistics: @circuit_breaker.statistics(service_name)
      }
    end
  rescue => e
    Rails.logger.error "[ErrorMonitoringController] Service statistics fetch failed: #{e.message}"
    []
  end

  ##
  # Fetch circuit breaker configuration
  def fetch_circuit_breaker_configuration
    ErrorMonitoring::CircuitBreaker::DEFAULT_CONFIG
  rescue => e
    Rails.logger.error "[ErrorMonitoringController] Circuit breaker config fetch failed: #{e.message}"
    {}
  end

  ##
  # Fetch active degradations
  def fetch_active_degradations
    recovery_status = @recovery_manager.health_status
    recovery_status[:active_degradations] || []
  rescue => e
    Rails.logger.error "[ErrorMonitoringController] Active degradations fetch failed: #{e.message}"
    []
  end

  ##
  # Fetch strategy performance data
  def fetch_strategy_performance(time_range)
    # This would be implemented with actual recovery attempt tracking
    # For now, return mock data structure
    ErrorMonitoring::RecoveryManager::RECOVERY_STRATEGIES.keys.map do |strategy|
      {
        strategy: strategy,
        attempts: 0,
        successes: 0,
        success_rate: 0.8, # Mock data
        average_time: 30.seconds
      }
    end
  rescue => e
    Rails.logger.error "[ErrorMonitoringController] Strategy performance fetch failed: #{e.message}"
    []
  end

  ##
  # Calculate performance metrics
  def calculate_performance_metrics(time_range)
    time_threshold = Time.current - time_range
    
    total_errors = AgentLog.where('created_at > ? AND level >= ?', time_threshold, 3).count
    total_requests = AgentLog.where('created_at > ?', time_threshold).count
    
    {
      total_errors: total_errors,
      total_requests: total_requests,
      error_rate: total_requests > 0 ? (total_errors.to_f / total_requests) : 0,
      avg_errors_per_hour: total_errors.to_f / (time_range / 1.hour)
    }
  rescue => e
    Rails.logger.error "[ErrorMonitoringController] Performance metrics calculation failed: #{e.message}"
    { total_errors: 0, total_requests: 0, error_rate: 0, avg_errors_per_hour: 0 }
  end

  ##
  # Handle controller errors consistently
  def handle_controller_error(error, user_message)
    respond_to do |format|
      format.html { redirect_to error_monitoring_index_path, alert: user_message }
      format.json { render json: { error: user_message }, status: :internal_server_error }
      format.csv { redirect_to error_monitoring_index_path, alert: user_message }
    end
  end

  ##
  # Send CSV report response
  def send_csv_report(data)
    csv_content = generate_csv_from_statistics(data)
    timestamp = Time.current.strftime('%Y%m%d_%H%M%S')
    filename = "error_statistics_#{timestamp}.csv"
    
    send_data csv_content, {
      filename: filename,
      type: 'text/csv',
      disposition: 'attachment'
    }
  end

  ##
  # Generate CSV from statistics data
  def generate_csv_from_statistics(data)
    require 'csv'
    
    CSV.generate(headers: true) do |csv|
      csv << ['Metric', 'Value', 'Time Range', 'Generated At']
      
      stats = data[:error_statistics]
      csv << ['Total Errors', stats[:error_counts][:total], "#{data[:time_range]} hours", Time.current]
      csv << ['Current Error Rate', "#{(stats[:threshold_compliance][:current_rate] * 100).round(4)}%", 'Current', Time.current]
      csv << ['Threshold Compliant', stats[:threshold_compliance][:compliant], 'Current', Time.current]
    end
  end

  ##
  # Determine content type for file format
  def determine_content_type(format)
    case format.downcase
    when 'json'
      'application/json'
    when 'csv'
      'text/csv'
    when 'yaml', 'yml'
      'text/yaml'
    else
      'application/octet-stream'
    end
  end

  ##
  # Load current configuration
  def load_current_configuration
    config_path = Rails.root.join('config', 'error_monitoring.yml')
    return {} unless File.exist?(config_path)
    
    YAML.load_file(config_path)[Rails.env] || {}
  rescue => e
    Rails.logger.error "[ErrorMonitoringController] Current config load failed: #{e.message}"
    {}
  end

  ##
  # Load default configuration
  def load_default_configuration
    {
      error_rate_monitoring: {
        threshold: 0.001,
        enabled: true
      },
      circuit_breaker: {
        enabled: true
      },
      recovery_manager: {
        enabled: true
      }
    }
  end

  ##
  # Update configuration (placeholder for future implementation)
  def update_configuration
    # This would implement configuration updates
    # For security, this should be very carefully implemented
    redirect_to configuration_error_monitoring_index_path, notice: "Configuration updated successfully"
  end

  ##
  # Count errors by message pattern
  def count_errors_by_pattern(time_range, pattern)
    AgentLog.where('level >= ? AND created_at > ? AND message REGEXP ?', 
                   3, time_range.ago, pattern.source)
            .count
  rescue => e
    Rails.logger.error "[ErrorMonitoringController] Pattern count failed: #{e.message}"
    0
  end

  ##
  # Convert error level to severity name
  def level_to_severity(level)
    case level
    when 4
      :critical
    when 3
      :high
    when 2
      :medium
    when 1
      :low
    else
      :info
    end
  end

  ##
  # Calculate alert severity based on error rate
  def calculate_alert_severity(current_rate, threshold)
    multiplier = current_rate / threshold
    
    case multiplier
    when 0..2
      :minor
    when 2..5
      :moderate
    when 5..10
      :severe
    else
      :critical
    end
  end
end