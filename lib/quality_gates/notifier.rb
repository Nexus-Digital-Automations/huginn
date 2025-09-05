# frozen_string_literal: true

require 'net/http'
require 'uri'
require 'json'
require 'mail'

module QualityGates
  # Notification and alerting system for quality gate failures and important events
  # Supports multiple notification channels with intelligent routing and throttling
  #
  # Usage:
  #   notifier = QualityGates::Notifier.new(configuration)
  #   notifier.notify_quality_gate_failures(execution_result, gate_results)
  #   notifier.send_summary_notification(report_data)
  #
  # Channels: Email, Slack, Webhook, SMS (Twilio), Microsoft Teams, Discord
  # Features: Message templating, throttling, escalation, channel failover
  class Notifier
    attr_reader :configuration, :notification_config, :enabled_channels

    # Supported notification channels
    NOTIFICATION_CHANNELS = {
      email: QualityGates::NotificationChannels::EmailChannel,
      slack: QualityGates::NotificationChannels::SlackChannel,
      webhook: QualityGates::NotificationChannels::WebhookChannel,
      sms: QualityGates::NotificationChannels::SmsChannel,
      teams: QualityGates::NotificationChannels::TeamsChannel,
      discord: QualityGates::NotificationChannels::DiscordChannel
    }.freeze

    # Notification severity levels
    SEVERITY_LEVELS = %i[info warning error critical].freeze

    # Notification types
    NOTIFICATION_TYPES = %i[
      quality_gate_failure
      critical_failure
      execution_complete
      quality_improvement
      quality_degradation
      system_health
    ].freeze

    def initialize(configuration)
      @configuration = configuration
      @notification_config = configuration.notification_config
      @enabled_channels = load_enabled_channels
      @notification_history = []
      @throttle_cache = {}
      
      validate_notification_configuration!
    end

    # Notify about quality gate failures
    # @param execution_result [QualityGates::ExecutionResult] - execution results
    # @param gate_results [Hash] - individual gate results
    # @return [Boolean] - whether notifications were sent successfully
    def notify_quality_gate_failures(execution_result, gate_results)
      return true unless should_notify_failures?

      failed_gates = gate_results.select { |_, result| result.failed? }
      critical_failures = failed_gates.select do |gate_name, _|
        @configuration.get_gate_config(gate_name)[:critical]
      end

      notifications_sent = 0

      # Send critical failure notifications immediately
      if critical_failures.any?
        message_data = build_critical_failure_message(critical_failures, execution_result)
        notifications_sent += send_notification(:critical_failure, :critical, message_data)
      end

      # Send general failure notification if there are non-critical failures
      non_critical_failures = failed_gates.reject { |gate_name, _| critical_failures.key?(gate_name) }
      if non_critical_failures.any?
        message_data = build_failure_message(non_critical_failures, execution_result)
        notifications_sent += send_notification(:quality_gate_failure, :error, message_data)
      end

      log_notification_result(:failure_notifications, notifications_sent > 0, {
        total_failed_gates: failed_gates.count,
        critical_failures: critical_failures.count,
        notifications_sent: notifications_sent
      })

      notifications_sent > 0
    end

    # Send execution completion notification
    # @param execution_result [QualityGates::ExecutionResult] - execution results
    # @param report_data [Hash] - comprehensive report data
    # @return [Boolean] - whether notification was sent successfully
    def send_completion_notification(execution_result, report_data)
      return true unless should_notify_completion?

      message_data = build_completion_message(execution_result, report_data)
      severity = execution_result.success? ? :info : :warning
      
      success = send_notification(:execution_complete, severity, message_data)
      
      log_notification_result(:completion_notification, success, {
        execution_success: execution_result.success?,
        quality_score: report_data[:executive_summary][:quality_score]
      })

      success > 0
    end

    # Send quality improvement notification
    # @param improvements [Array] - list of quality improvements detected
    # @param comparison_data [Hash] - comparison with previous execution
    # @return [Boolean] - whether notification was sent successfully
    def notify_quality_improvements(improvements, comparison_data)
      return true unless improvements.any? && should_notify_improvements?

      message_data = build_improvement_message(improvements, comparison_data)
      success = send_notification(:quality_improvement, :info, message_data)
      
      log_notification_result(:improvement_notification, success, {
        improvements_count: improvements.count
      })

      success > 0
    end

    # Send quality degradation alert
    # @param regressions [Array] - list of quality regressions detected
    # @param comparison_data [Hash] - comparison with previous execution
    # @return [Boolean] - whether notification was sent successfully
    def notify_quality_degradation(regressions, comparison_data)
      return true unless regressions.any?

      message_data = build_degradation_message(regressions, comparison_data)
      success = send_notification(:quality_degradation, :warning, message_data)
      
      log_notification_result(:degradation_notification, success, {
        regressions_count: regressions.count
      })

      success > 0
    end

    # Send system health alert
    # @param health_data [Hash] - system health information
    # @return [Boolean] - whether notification was sent successfully
    def notify_system_health(health_data)
      return true unless health_data[:alerts]&.any?

      message_data = build_health_message(health_data)
      severity = determine_health_severity(health_data)
      success = send_notification(:system_health, severity, message_data)
      
      log_notification_result(:health_notification, success, {
        alert_count: health_data[:alerts]&.count || 0
      })

      success > 0
    end

    # Test notification channels
    # @param channels [Array<Symbol>] - specific channels to test (nil for all)
    # @return [Hash] - test results for each channel
    def test_channels(channels = nil)
      test_channels = channels || @enabled_channels.keys
      results = {}

      test_channels.each do |channel_name|
        channel = @enabled_channels[channel_name]
        next unless channel

        begin
          test_message = build_test_message
          success = channel.send_notification(test_message)
          results[channel_name] = { success: success, error: nil }
        rescue StandardError => e
          results[channel_name] = { success: false, error: e.message }
        end
      end

      log_notification_result(:channel_test, results.values.any? { |r| r[:success] }, {
        channels_tested: results.keys,
        successful_channels: results.select { |_, r| r[:success] }.keys
      })

      results
    end

    # Check if notification channels are available
    # @return [Boolean] - whether any notification channels are operational
    def channels_available?
      @enabled_channels.any? { |_, channel| channel.available? }
    end

    # Get notification history
    # @param limit [Integer] - maximum number of entries to return
    # @return [Array<Hash>] - recent notification history
    def get_notification_history(limit = 50)
      @notification_history.last(limit).map do |entry|
        entry.except(:raw_data) # Remove potentially large raw data
      end
    end

    # Clear notification history
    def clear_notification_history
      @notification_history.clear
      @throttle_cache.clear
    end

    private

    # Load and initialize enabled notification channels
    def load_enabled_channels
      channels = {}
      
      @notification_config[:channels].each do |channel_name, channel_config|
        next unless channel_config[:enabled]
        
        channel_class = NOTIFICATION_CHANNELS[channel_name.to_sym]
        next unless channel_class

        begin
          channels[channel_name.to_sym] = channel_class.new(channel_config, @configuration)
        rescue StandardError => e
          log_error("Failed to initialize #{channel_name} channel", error: e.message)
        end
      end

      channels
    end

    # Validate notification configuration
    def validate_notification_configuration!
      unless @notification_config.is_a?(Hash)
        raise ConfigurationError, "Notification configuration must be a hash"
      end

      unless @notification_config[:channels].is_a?(Hash)
        raise ConfigurationError, "Notification channels configuration must be a hash"
      end

      # Validate individual channel configurations
      @notification_config[:channels].each do |channel_name, config|
        next unless config[:enabled]
        
        validate_channel_configuration(channel_name, config)
      end
    end

    # Validate individual channel configuration
    def validate_channel_configuration(channel_name, config)
      channel_class = NOTIFICATION_CHANNELS[channel_name.to_sym]
      return unless channel_class

      channel_class.validate_configuration!(config)
    rescue StandardError => e
      raise ConfigurationError, "Invalid #{channel_name} configuration: #{e.message}"
    end

    # Determine whether to notify based on settings and throttling
    def should_notify_failures?
      @notification_config[:on_failure] != false && !throttled?(:failure)
    end

    def should_notify_completion?
      @notification_config[:on_completion] == true && !throttled?(:completion)
    end

    def should_notify_improvements?
      @notification_config[:on_improvement] == true && !throttled?(:improvement)
    end

    # Check if notifications are throttled for a specific type
    def throttled?(notification_type)
      throttle_key = "#{notification_type}_#{Date.current}"
      throttle_limit = get_throttle_limit(notification_type)
      
      return false if throttle_limit.zero?

      current_count = @throttle_cache[throttle_key] || 0
      current_count >= throttle_limit
    end

    # Get throttle limit for notification type
    def get_throttle_limit(notification_type)
      @notification_config.dig(:throttling, notification_type, :daily_limit) || 0
    end

    # Update throttle cache
    def update_throttle_cache(notification_type)
      throttle_key = "#{notification_type}_#{Date.current}"
      @throttle_cache[throttle_key] = (@throttle_cache[throttle_key] || 0) + 1
    end

    # Send notification to all enabled channels
    def send_notification(notification_type, severity, message_data)
      return 0 if @enabled_channels.empty?

      notifications_sent = 0
      channels_to_use = determine_channels_for_notification(notification_type, severity)

      channels_to_use.each do |channel_name|
        channel = @enabled_channels[channel_name]
        next unless channel&.available?

        begin
          formatted_message = channel.format_message(message_data, notification_type, severity)
          success = channel.send_notification(formatted_message)
          
          if success
            notifications_sent += 1
            record_successful_notification(channel_name, notification_type, severity, message_data)
          else
            record_failed_notification(channel_name, notification_type, severity, "Send failed")
          end
        rescue StandardError => e
          record_failed_notification(channel_name, notification_type, severity, e.message)
          log_error("Notification failed for #{channel_name}", error: e.message)
        end
      end

      update_throttle_cache(notification_type) if notifications_sent > 0
      notifications_sent
    end

    # Determine which channels to use for a notification
    def determine_channels_for_notification(notification_type, severity)
      # Critical notifications go to all channels
      return @enabled_channels.keys if severity == :critical

      # Use channel routing configuration
      routing_config = @notification_config.dig(:routing, notification_type)
      return @enabled_channels.keys unless routing_config

      channels = routing_config[:channels] || @enabled_channels.keys
      
      # Filter by minimum severity
      min_severity = routing_config[:min_severity] || :info
      return [] unless severity_meets_minimum?(severity, min_severity)

      channels & @enabled_channels.keys
    end

    # Check if severity meets minimum requirement
    def severity_meets_minimum?(current_severity, min_severity)
      current_index = SEVERITY_LEVELS.index(current_severity) || 0
      min_index = SEVERITY_LEVELS.index(min_severity) || 0
      current_index >= min_index
    end

    # Build message for critical failures
    def build_critical_failure_message(critical_failures, execution_result)
      {
        title: "🔴 Critical Quality Gates Failed",
        summary: "#{critical_failures.count} critical quality gates failed in execution #{execution_result.execution_id}",
        details: {
          execution_id: execution_result.execution_id,
          timestamp: Time.now.iso8601,
          environment: @configuration.environment,
          failed_gates: critical_failures.keys,
          failure_details: critical_failures.transform_values { |result| result.primary_failure_reason }
        },
        actions: [
          "Review failed gates immediately",
          "Check gate configuration and dependencies",
          "Contact development team if needed"
        ],
        severity: :critical,
        priority: :high
      }
    end

    # Build message for general failures
    def build_failure_message(failed_gates, execution_result)
      {
        title: "⚠️  Quality Gates Failed",
        summary: "#{failed_gates.count} quality gates failed in execution #{execution_result.execution_id}",
        details: {
          execution_id: execution_result.execution_id,
          timestamp: Time.now.iso8601,
          environment: @configuration.environment,
          failed_gates: failed_gates.keys,
          success_rate: calculate_success_rate(execution_result),
          total_execution_time: calculate_total_execution_time(failed_gates.values)
        },
        actions: [
          "Review failed gate details",
          "Check for configuration issues",
          "Monitor for recurring failures"
        ],
        severity: :error,
        priority: :medium
      }
    end

    # Build completion notification message
    def build_completion_message(execution_result, report_data)
      status_emoji = execution_result.success? ? "✅" : "⚠️"
      
      {
        title: "#{status_emoji} Quality Gates Execution Complete",
        summary: "Quality gates execution #{execution_result.execution_id} completed with #{report_data[:executive_summary][:success_rate]}% success rate",
        details: {
          execution_id: execution_result.execution_id,
          timestamp: Time.now.iso8601,
          environment: @configuration.environment,
          overall_status: execution_result.success? ? :passed : :failed,
          quality_score: report_data[:executive_summary][:quality_score],
          success_rate: report_data[:executive_summary][:success_rate],
          total_gates: report_data[:executive_summary][:total_gates],
          execution_time: report_data[:overall_metrics][:total_execution_time]
        },
        metrics: extract_key_metrics(report_data),
        severity: execution_result.success? ? :info : :warning,
        priority: :low
      }
    end

    # Build improvement notification message
    def build_improvement_message(improvements, comparison_data)
      {
        title: "📈 Quality Improvements Detected",
        summary: "#{improvements.count} quality improvements identified",
        details: {
          timestamp: Time.now.iso8601,
          environment: @configuration.environment,
          improvements: improvements.map do |improvement|
            {
              gate: improvement[:gate],
              type: improvement[:type],
              description: improvement[:description]
            }
          end,
          quality_score_change: comparison_data.dig(:current_summary, :quality_score) - 
                               comparison_data.dig(:previous_summary, :quality_score)
        },
        severity: :info,
        priority: :low
      }
    end

    # Build degradation notification message
    def build_degradation_message(regressions, comparison_data)
      {
        title: "📉 Quality Degradation Alert",
        summary: "#{regressions.count} quality regressions detected",
        details: {
          timestamp: Time.now.iso8601,
          environment: @configuration.environment,
          regressions: regressions.map do |regression|
            {
              gate: regression[:gate],
              type: regression[:type],
              description: regression[:description]
            }
          end,
          quality_score_change: comparison_data.dig(:current_summary, :quality_score) - 
                               comparison_data.dig(:previous_summary, :quality_score)
        },
        actions: [
          "Review recent changes",
          "Check for configuration drift",
          "Investigate root cause"
        ],
        severity: :warning,
        priority: :medium
      }
    end

    # Build system health message
    def build_health_message(health_data)
      {
        title: "🏥 System Health Alert",
        summary: "Quality gates system health issues detected",
        details: {
          timestamp: Time.now.iso8601,
          environment: @configuration.environment,
          alerts: health_data[:alerts],
          overall_health: health_data[:overall_health],
          affected_components: health_data[:affected_components]
        },
        actions: [
          "Check system resources",
          "Verify service connectivity",
          "Review system logs"
        ],
        severity: determine_health_severity(health_data),
        priority: :high
      }
    end

    # Build test message
    def build_test_message
      {
        title: "🧪 Quality Gates Notification Test",
        summary: "This is a test notification to verify channel configuration",
        details: {
          timestamp: Time.now.iso8601,
          environment: @configuration.environment,
          test_id: SecureRandom.hex(8)
        },
        severity: :info,
        priority: :low
      }
    end

    # Determine severity for health notifications
    def determine_health_severity(health_data)
      critical_alerts = health_data[:alerts]&.count { |alert| alert[:severity] == :critical } || 0
      warning_alerts = health_data[:alerts]&.count { |alert| alert[:severity] == :warning } || 0

      if critical_alerts > 0
        :critical
      elsif warning_alerts > 2
        :error
      elsif warning_alerts > 0
        :warning
      else
        :info
      end
    end

    # Extract key metrics for notifications
    def extract_key_metrics(report_data)
      {
        quality_score: report_data[:executive_summary][:quality_score],
        success_rate: report_data[:executive_summary][:success_rate],
        critical_failures: report_data[:executive_summary][:critical_failures],
        execution_time: report_data[:overall_metrics][:total_execution_time]
      }
    end

    # Calculate success rate from execution result
    def calculate_success_rate(execution_result)
      return 100 if execution_result.total_gates.zero?
      
      ((execution_result.passed_gates.count.to_f / execution_result.total_gates) * 100).round(2)
    end

    # Calculate total execution time
    def calculate_total_execution_time(gate_results)
      gate_results.sum(&:execution_time).round(2)
    end

    # Record successful notification
    def record_successful_notification(channel, notification_type, severity, message_data)
      @notification_history << {
        timestamp: Time.now,
        channel: channel,
        notification_type: notification_type,
        severity: severity,
        status: :success,
        title: message_data[:title],
        execution_id: message_data.dig(:details, :execution_id)
      }
      
      # Keep history limited
      @notification_history = @notification_history.last(1000) if @notification_history.size > 1000
    end

    # Record failed notification
    def record_failed_notification(channel, notification_type, severity, error_message)
      @notification_history << {
        timestamp: Time.now,
        channel: channel,
        notification_type: notification_type,
        severity: severity,
        status: :failed,
        error: error_message
      }
    end

    # Logging helpers
    def log_notification_result(operation, success, data = {})
      if success
        log_info("#{operation} completed successfully", data)
      else
        log_error("#{operation} failed", data)
      end
    end

    def log_info(message, data = {})
      Rails.logger&.info("QualityGates::Notifier - #{message}: #{data}")
    end

    def log_error(message, data = {})
      Rails.logger&.error("QualityGates::Notifier - #{message}: #{data}")
    end
  end
end

# Load notification channel implementations
require_relative 'notification_channels/base_channel'
require_relative 'notification_channels/email_channel'
require_relative 'notification_channels/slack_channel'
require_relative 'notification_channels/webhook_channel'
require_relative 'notification_channels/sms_channel'
require_relative 'notification_channels/teams_channel'
require_relative 'notification_channels/discord_channel'