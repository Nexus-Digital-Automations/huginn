# frozen_string_literal: true

# Helper methods for Error Monitoring Dashboard views
module ErrorMonitoringHelper
  ##
  # Determine CSS color class based on system health status
  def health_status_color(status)
    case status
    when :healthy
      'success'
    when :warning, :degraded
      'warning'
    when :critical, :unhealthy
      'danger'
    else
      'secondary'
    end
  end

  ##
  # Determine CSS color class for circuit breaker status
  def circuit_breaker_color(status)
    case status
    when :healthy
      'success'
    when :degraded, :recovering
      'warning'
    when :unhealthy
      'danger'
    else
      'secondary'
    end
  end

  ##
  # Determine CSS color class for recovery system status
  def recovery_system_color(status)
    case status
    when :healthy
      'success'
    when :degraded, :recovering
      'warning'
    when :unhealthy
      'danger'
    else
      'secondary'
    end
  end

  ##
  # Determine CSS color class for alert severity
  def alert_severity_color(severity)
    case severity
    when :critical
      'danger'
    when :severe, :high
      'warning'
    when :moderate, :medium
      'info'
    when :minor, :low
      'secondary'
    else
      'light'
    end
  end

  ##
  # Determine CSS color class for error severity
  def severity_color(severity)
    case severity
    when :critical
      'danger'
    when :high
      'warning'
    when :medium
      'info'
    when :low
      'secondary'
    else
      'light'
    end
  end

  ##
  # Calculate system uptime based on dashboard data
  def calculate_system_uptime(dashboard_data)
    # Simplified uptime calculation based on error rate compliance
    if dashboard_data[:threshold_compliance]
      uptime_percentage = 99.9 - (dashboard_data[:current_error_rate] * 100)
      "#{uptime_percentage.round(2)}%"
    else
      # Calculate based on breach severity
      breach_multiplier = dashboard_data[:current_error_rate] / dashboard_data[:error_rate_threshold]
      uptime_percentage = [99.9 - (breach_multiplier * 10), 95.0].max
      "#{uptime_percentage.round(2)}%"
    end
  end

  ##
  # Format error rate as percentage with appropriate precision
  def format_error_rate(rate)
    if rate < 0.0001
      "< 0.01%"
    else
      number_to_percentage(rate * 100, precision: 4)
    end
  end

  ##
  # Format duration in human-readable format
  def format_duration(seconds)
    if seconds < 60
      "#{seconds.round}s"
    elsif seconds < 3600
      "#{(seconds / 60).round}m"
    elsif seconds < 86400
      "#{(seconds / 3600).round(1)}h"
    else
      "#{(seconds / 86400).round(1)}d"
    end
  end

  ##
  # Generate status icon based on boolean condition
  def status_icon(condition, success_icon: 'check-circle', failure_icon: 'exclamation-triangle')
    if condition
      content_tag(:i, '', class: "fa fa-#{success_icon} text-success")
    else
      content_tag(:i, '', class: "fa fa-#{failure_icon} text-danger")
    end
  end

  ##
  # Generate trend arrow icon based on trend direction
  def trend_arrow(direction)
    case direction
    when :increasing, :up
      content_tag(:i, '', class: "fa fa-arrow-up text-danger", title: "Increasing")
    when :decreasing, :down
      content_tag(:i, '', class: "fa fa-arrow-down text-success", title: "Decreasing")
    when :stable, :neutral
      content_tag(:i, '', class: "fa fa-minus text-muted", title: "Stable")
    else
      content_tag(:i, '', class: "fa fa-question text-secondary", title: "Unknown")
    end
  end

  ##
  # Format large numbers with appropriate units
  def format_metric_number(number)
    case number
    when 0...1_000
      number.to_s
    when 1_000...1_000_000
      "#{(number / 1_000.0).round(1)}K"
    when 1_000_000...1_000_000_000
      "#{(number / 1_000_000.0).round(1)}M"
    else
      "#{(number / 1_000_000_000.0).round(1)}B"
    end
  end

  ##
  # Generate progress bar for success rates
  def success_rate_progress_bar(rate, options = {})
    percentage = (rate * 100).round(1)
    color_class = case percentage
                  when 90..100
                    'success'
                  when 70...90
                    'warning'
                  else
                    'danger'
                  end

    content_tag(:div, class: "progress #{options[:class]}") do
      content_tag(:div, "#{percentage}%", 
                  class: "progress-bar bg-#{color_class}",
                  style: "width: #{percentage}%",
                  role: "progressbar",
                  'aria-valuenow': percentage,
                  'aria-valuemin': 0,
                  'aria-valuemax': 100)
    end
  end

  ##
  # Generate sparkline data for Chart.js
  def sparkline_data(data_points, options = {})
    {
      labels: Array.new(data_points.length) { |i| i + 1 },
      datasets: [{
        data: data_points,
        borderColor: options[:color] || '#007bff',
        backgroundColor: options[:background_color] || 'rgba(0, 123, 255, 0.1)',
        borderWidth: options[:border_width] || 2,
        pointRadius: options[:point_radius] || 0,
        tension: options[:tension] || 0.4,
        fill: options[:fill] || true
      }]
    }.to_json.html_safe
  end

  ##
  # Generate time range options for select boxes
  def time_range_options
    [
      ['Last 1 hour', 1],
      ['Last 6 hours', 6],
      ['Last 24 hours', 24],
      ['Last 3 days', 72],
      ['Last 7 days', 168],
      ['Last 30 days', 720]
    ]
  end

  ##
  # Generate export format options
  def export_format_options
    [
      ['JSON Format', 'json'],
      ['CSV Format', 'csv'],
      ['YAML Format', 'yaml'],
      ['PDF Format', 'pdf']
    ]
  end

  ##
  # Determine if a circuit breaker state is healthy
  def circuit_breaker_healthy?(state)
    state == :closed
  end

  ##
  # Format circuit breaker state with appropriate styling
  def format_circuit_state(state)
    color_class = case state
                  when :closed
                    'success'
                  when :half_open
                    'warning'
                  when :open
                    'danger'
                  else
                    'secondary'
                  end

    content_tag(:span, state.to_s.humanize, class: "badge badge-#{color_class}")
  end

  ##
  # Format recovery strategy with description
  def format_recovery_strategy(strategy)
    strategy_descriptions = {
      simple_retry: "Simple Retry with Linear Backoff",
      exponential_backoff: "Exponential Backoff Retry",
      circuit_breaker_reset: "Circuit Breaker Reset",
      credential_refresh: "Credential Refresh",
      connection_pool_reset: "Database Connection Pool Reset",
      agent_restart: "Agent Restart",
      graceful_degradation: "Graceful Service Degradation",
      resource_scaling: "Resource Scaling"
    }

    description = strategy_descriptions[strategy] || strategy.to_s.humanize
    
    content_tag(:div) do
      content_tag(:strong, strategy.to_s.humanize) +
      content_tag(:br) +
      content_tag(:small, description, class: "text-muted")
    end
  end

  ##
  # Generate alert badge with count
  def alert_count_badge(count, severity = :info)
    return '' if count.zero?

    color_class = alert_severity_color(severity)
    content_tag(:span, count, class: "badge badge-#{color_class} ml-1")
  end

  ##
  # Format degradation level with impact description
  def format_degradation_level(level)
    level_descriptions = {
      none: "Full functionality available",
      minimal: "Slight performance reduction",
      moderate: "Noticeable feature limitations",
      significant: "Major functionality restricted",
      severe: "Emergency mode - critical functions only"
    }

    description = level_descriptions[level] || "Unknown degradation level"
    color_class = case level
                  when :none
                    'success'
                  when :minimal
                    'info'
                  when :moderate
                    'warning'
                  when :significant, :severe
                    'danger'
                  else
                    'secondary'
                  end

    content_tag(:div) do
      content_tag(:span, level.to_s.humanize, class: "badge badge-#{color_class}") +
      content_tag(:br) +
      content_tag(:small, description, class: "text-muted")
    end
  end

  ##
  # Generate health check indicator
  def health_indicator(status, label = nil)
    color_class = health_status_color(status)
    icon_class = case status
                 when :healthy
                   'check-circle'
                 when :warning, :degraded
                   'exclamation-triangle'
                 when :critical, :unhealthy
                   'times-circle'
                 else
                   'question-circle'
                 end

    content_tag(:div, class: "health-indicator") do
      content_tag(:i, '', class: "fa fa-#{icon_class} text-#{color_class} mr-2") +
      (label || status.to_s.humanize)
    end
  end

  ##
  # Format timestamp with relative time
  def format_timestamp_with_relative(timestamp)
    content_tag(:div) do
      content_tag(:div, l(timestamp, format: :short)) +
      content_tag(:small, "(#{time_ago_in_words(timestamp)} ago)", class: "text-muted")
    end
  end

  ##
  # Generate metric comparison indicator
  def metric_comparison_indicator(current, previous, higher_is_better: false)
    return content_tag(:span, '—', class: 'text-muted') if previous.nil? || previous.zero?

    change_percentage = ((current - previous) / previous.to_f * 100).round(1)
    
    if change_percentage > 0
      icon = 'arrow-up'
      color = higher_is_better ? 'success' : 'danger'
      prefix = '+'
    elsif change_percentage < 0
      icon = 'arrow-down'
      color = higher_is_better ? 'danger' : 'success'
      prefix = ''
    else
      icon = 'minus'
      color = 'muted'
      prefix = ''
    end

    content_tag(:span, class: "text-#{color}") do
      content_tag(:i, '', class: "fa fa-#{icon} mr-1") +
      "#{prefix}#{change_percentage}%"
    end
  end

  ##
  # Generate configuration status indicator
  def config_status_indicator(config_valid)
    if config_valid
      content_tag(:span, class: 'text-success') do
        content_tag(:i, '', class: 'fa fa-check-circle mr-1') + 'Valid'
      end
    else
      content_tag(:span, class: 'text-danger') do
        content_tag(:i, '', class: 'fa fa-exclamation-triangle mr-1') + 'Invalid'
      end
    end
  end

  ##
  # Generate action buttons for error monitoring operations
  def error_monitoring_action_button(action, path, options = {})
    default_options = {
      class: 'btn btn-sm',
      method: :post,
      confirm: options.delete(:confirm)
    }

    button_config = {
      reset: {
        class: 'btn btn-sm btn-warning',
        icon: 'sync-alt',
        text: 'Reset'
      },
      enable: {
        class: 'btn btn-sm btn-success',
        icon: 'play',
        text: 'Enable'
      },
      disable: {
        class: 'btn btn-sm btn-danger',
        icon: 'pause',
        text: 'Disable'
      },
      force_open: {
        class: 'btn btn-sm btn-danger',
        icon: 'lock-open',
        text: 'Force Open'
      },
      force_close: {
        class: 'btn btn-sm btn-success',
        icon: 'lock',
        text: 'Force Close'
      }
    }

    config = button_config[action] || {}
    merged_options = default_options.merge(config).merge(options)

    link_to(path, merged_options) do
      content_tag(:i, '', class: "fa fa-#{config[:icon]} mr-1") + config[:text]
    end
  end
end