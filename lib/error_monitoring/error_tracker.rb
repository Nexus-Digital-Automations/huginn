# frozen_string_literal: true

# Error Rate Monitoring System for Huginn
# Enforces <0.1% production error rate with comprehensive tracking and alerting
#
# Dependencies: Rails, ActiveRecord, AgentLog model
# Usage: ErrorTracker.track_error(error, context) -> monitors and alerts on error rate thresholds
module ErrorMonitoring
  ##
  # ErrorTracker provides comprehensive error rate monitoring with <0.1% production enforcement
  # 
  # Features:
  # - Real-time error rate calculation and trending
  # - Automated threshold breach detection and alerting  
  # - Error categorization and impact assessment
  # - Integration with existing AgentLog system
  # - Performance metrics and bottleneck identification
  #
  # @example Basic error tracking
  #   ErrorTracker.track_error(StandardError.new("Connection failed"), {
  #     agent_id: 123,
  #     category: :database_connection,
  #     severity: :high
  #   })
  #
  # @example Error rate monitoring
  #   current_rate = ErrorTracker.current_error_rate
  #   ErrorTracker.check_threshold_breach if current_rate > 0.001
  #
  class ErrorTracker
    include Singleton

    # Error rate threshold for production (0.1%)
    PRODUCTION_ERROR_RATE_THRESHOLD = 0.001

    # Time windows for error rate calculation (in seconds)
    TIME_WINDOWS = {
      immediate: 300,    # 5 minutes
      short_term: 1800,  # 30 minutes  
      medium_term: 3600, # 1 hour
      long_term: 86400   # 24 hours
    }.freeze

    # Error severity levels with impact weights
    SEVERITY_LEVELS = {
      critical: 4,
      high: 3,
      medium: 2,
      low: 1,
      info: 0
    }.freeze

    # Error categories for classification and trending
    ERROR_CATEGORIES = %w[
      agent_execution
      database_connection
      database_query
      external_api
      authentication
      authorization
      background_job
      validation
      network
      system
      unknown
    ].freeze

    ##
    # Track error occurrence and update metrics
    #
    # @param error [Exception] The error that occurred
    # @param context [Hash] Additional context for error categorization
    # @option context [Integer] :agent_id Agent ID if error is agent-related
    # @option context [Symbol] :category Error category for classification
    # @option context [Symbol] :severity Error severity level
    # @option context [String] :source Source system/component that generated error
    # @option context [Hash] :metadata Additional metadata for debugging
    #
    # @return [ErrorTracker::ErrorRecord] Created error record
    def self.track_error(error, context = {})
      operation_start = Time.current
      
      Rails.logger.error "[ErrorTracker] Tracking error: #{error.class} - #{error.message}", {
        error: error.class.name,
        message: error.message,
        context: context,
        operation_id: generate_operation_id
      }

      begin
        error_record = create_error_record(error, context)
        update_error_metrics(error_record)
        check_threshold_breach(error_record)
        
        processing_time = ((Time.current - operation_start) * 1000).round(2)
        Rails.logger.info "[ErrorTracker] Error tracking completed", {
          error_id: error_record.id,
          processing_time_ms: processing_time,
          current_error_rate: current_error_rate
        }
        
        error_record
      rescue => tracking_error
        Rails.logger.error "[ErrorTracker] Failed to track error: #{tracking_error.message}", {
          original_error: error.message,
          tracking_error: tracking_error.message,
          stack_trace: tracking_error.backtrace&.first(5)
        }
        nil
      end
    end

    ##
    # Calculate current error rate across different time windows
    #
    # @param window [Symbol] Time window for calculation (:immediate, :short_term, :medium_term, :long_term)
    # @return [Float] Error rate as decimal (0.001 = 0.1%)
    def self.current_error_rate(window: :immediate)
      operation_start = Time.current
      
      begin
        time_threshold = Time.current - TIME_WINDOWS[window]
        
        # Count errors in time window
        error_count = AgentLog.where('created_at > ? AND level >= ?', time_threshold, 4).count
        
        # Count total operations (approximate using all agent logs as proxy for activity)
        total_operations = AgentLog.where('created_at > ?', time_threshold).count
        
        # Calculate error rate with fallback to prevent division by zero
        error_rate = total_operations > 0 ? (error_count.to_f / total_operations) : 0.0
        
        processing_time = ((Time.current - operation_start) * 1000).round(2)
        Rails.logger.info "[ErrorTracker] Error rate calculated", {
          window: window,
          error_count: error_count,
          total_operations: total_operations,
          error_rate: error_rate,
          error_rate_percentage: (error_rate * 100).round(4),
          processing_time_ms: processing_time
        }
        
        error_rate
      rescue => calculation_error
        Rails.logger.error "[ErrorTracker] Error rate calculation failed: #{calculation_error.message}", {
          window: window,
          error: calculation_error.message
        }
        1.0 # Return high error rate on calculation failure to trigger alerts
      end
    end

    ##
    # Check if error rate exceeds threshold and trigger alerts
    #
    # @param error_record [ErrorTracker::ErrorRecord] Optional specific error record that triggered check
    # @return [Boolean] True if threshold was breached
    def self.check_threshold_breach(error_record = nil)
      operation_start = Time.current
      
      begin
        current_rate = current_error_rate(:immediate)
        threshold_breached = current_rate > PRODUCTION_ERROR_RATE_THRESHOLD
        
        if threshold_breached
          Rails.logger.error "[ErrorTracker] ERROR RATE THRESHOLD BREACHED", {
            current_rate: current_rate,
            threshold: PRODUCTION_ERROR_RATE_THRESHOLD,
            breach_severity: calculate_breach_severity(current_rate),
            trigger_error_id: error_record&.id
          }
          
          # Trigger immediate alert mechanisms
          trigger_error_rate_alerts(current_rate, error_record)
          
          # Log breach to AgentLog for visibility
          log_threshold_breach(current_rate, error_record)
        end
        
        processing_time = ((Time.current - operation_start) * 1000).round(2)
        Rails.logger.info "[ErrorTracker] Threshold check completed", {
          current_rate: current_rate,
          threshold_breached: threshold_breached,
          processing_time_ms: processing_time
        }
        
        threshold_breached
      rescue => check_error
        Rails.logger.error "[ErrorTracker] Threshold check failed: #{check_error.message}", {
          error: check_error.message,
          stack_trace: check_error.backtrace&.first(3)
        }
        false
      end
    end

    ##
    # Get error statistics and trends for dashboard display
    #
    # @param options [Hash] Options for statistics generation
    # @option options [Integer] :hours Number of hours to analyze (default: 24)
    # @option options [Boolean] :include_trends Include trending data
    # @option options [Array<String>] :categories Filter by specific error categories
    #
    # @return [Hash] Comprehensive error statistics
    def self.error_statistics(options = {})
      operation_start = Time.current
      hours = options[:hours] || 24
      time_threshold = Time.current - hours.hours
      
      Rails.logger.info "[ErrorTracker] Generating error statistics", {
        hours: hours,
        include_trends: options[:include_trends],
        categories: options[:categories]
      }
      
      begin
        base_query = AgentLog.where('created_at > ? AND level >= ?', time_threshold, 4)
        
        statistics = {
          time_period: {
            hours: hours,
            start_time: time_threshold,
            end_time: Time.current
          },
          error_rates: calculate_error_rates_for_windows,
          error_counts: {
            total: base_query.count,
            by_level: base_query.group(:level).count,
            by_hour: base_query.group_by_hour(:created_at, last: hours).count
          },
          top_error_sources: analyze_error_sources(base_query),
          error_trends: options[:include_trends] ? calculate_error_trends(hours) : nil,
          threshold_compliance: {
            current_rate: current_error_rate(:immediate),
            threshold: PRODUCTION_ERROR_RATE_THRESHOLD,
            compliant: current_error_rate(:immediate) <= PRODUCTION_ERROR_RATE_THRESHOLD,
            breach_count_24h: count_threshold_breaches(24.hours)
          },
          generated_at: Time.current
        }
        
        processing_time = ((Time.current - operation_start) * 1000).round(2)
        Rails.logger.info "[ErrorTracker] Error statistics generated", {
          total_errors: statistics[:error_counts][:total],
          current_rate: statistics[:threshold_compliance][:current_rate],
          compliant: statistics[:threshold_compliance][:compliant],
          processing_time_ms: processing_time
        }
        
        statistics
      rescue => stats_error
        Rails.logger.error "[ErrorTracker] Statistics generation failed: #{stats_error.message}", {
          error: stats_error.message,
          hours: hours
        }
        
        # Return minimal statistics on failure
        {
          error: "Statistics generation failed: #{stats_error.message}",
          current_rate: current_error_rate(:immediate),
          threshold: PRODUCTION_ERROR_RATE_THRESHOLD,
          generated_at: Time.current
        }
      end
    end

    ##
    # Export error monitoring report to file
    #
    # @param output_path [String] Path where to save the report
    # @param format [Symbol] Report format (:json, :csv, :txt)
    # @param options [Hash] Additional options for report generation
    #
    # @return [String] Path to generated report file
    def self.export_error_report(output_path, format: :json, options: {})
      operation_start = Time.current
      
      Rails.logger.info "[ErrorTracker] Exporting error report", {
        output_path: output_path,
        format: format,
        options: options
      }
      
      begin
        statistics = error_statistics(options.merge(include_trends: true))
        
        # Generate report content based on format
        report_content = case format
        when :json
          JSON.pretty_generate(statistics)
        when :csv
          generate_csv_report(statistics)
        when :txt
          generate_text_report(statistics)
        else
          raise ArgumentError, "Unsupported format: #{format}"
        end
        
        # Write report to file
        File.write(output_path, report_content)
        
        processing_time = ((Time.current - operation_start) * 1000).round(2)
        Rails.logger.info "[ErrorTracker] Error report exported", {
          output_path: output_path,
          format: format,
          file_size_bytes: File.size(output_path),
          processing_time_ms: processing_time
        }
        
        output_path
      rescue => export_error
        Rails.logger.error "[ErrorTracker] Report export failed: #{export_error.message}", {
          output_path: output_path,
          format: format,
          error: export_error.message
        }
        raise export_error
      end
    end

    private

    ##
    # Create error record with comprehensive context
    def self.create_error_record(error, context)
      AgentLog.create!({
        message: format_error_message(error, context),
        level: determine_error_level(error, context[:severity]),
        agent_id: context[:agent_id],
        created_at: Time.current
      })
    end

    ##
    # Update error metrics and counters
    def self.update_error_metrics(error_record)
      # This could integrate with external metrics systems like StatsD, DataDog, etc.
      Rails.logger.info "[ErrorTracker] Error metrics updated", {
        error_id: error_record.id,
        level: error_record.level,
        agent_id: error_record.agent_id
      }
    end

    ##
    # Format error message with comprehensive context
    def self.format_error_message(error, context)
      message_parts = []
      message_parts << "[ERROR_MONITOR]"
      message_parts << "#{error.class}: #{error.message}"
      
      if context[:category]
        message_parts << "Category: #{context[:category]}"
      end
      
      if context[:source]
        message_parts << "Source: #{context[:source]}"  
      end
      
      if context[:metadata]
        message_parts << "Metadata: #{context[:metadata].to_json}"
      end
      
      if error.backtrace
        message_parts << "Backtrace: #{error.backtrace.first(3).join(' | ')}"
      end
      
      message_parts.join(" | ")
    end

    ##
    # Determine error level based on exception type and severity
    def self.determine_error_level(error, severity)
      return SEVERITY_LEVELS[severity] if severity && SEVERITY_LEVELS.key?(severity)
      
      # Auto-classify based on exception type
      case error
      when SecurityError, ArgumentError
        4 # Critical
      when ActiveRecord::ConnectionNotEstablished, Timeout::Error
        4 # Critical  
      when ActiveRecord::RecordNotFound, NoMethodError
        3 # High
      when StandardError
        3 # High
      else
        2 # Medium
      end
    end

    ##
    # Calculate error rates for all time windows
    def self.calculate_error_rates_for_windows
      TIME_WINDOWS.transform_values { |_| current_error_rate(_1) }
    end

    ##
    # Analyze top error sources from query results
    def self.analyze_error_sources(query)
      query.joins(:agent)
           .group('agents.type', 'agents.name')
           .limit(10)
           .count
           .map { |key, count| { agent_type: key[0], agent_name: key[1], error_count: count } }
    end

    ##
    # Calculate error trends over time period
    def self.calculate_error_trends(hours)
      {
        hourly_rates: calculate_hourly_error_rates(hours),
        trend_direction: determine_trend_direction(hours),
        peak_error_hour: find_peak_error_hour(hours)
      }
    end

    ##
    # Count threshold breaches in time period
    def self.count_threshold_breaches(time_period)
      # This would require a separate breach log table in a full implementation
      # For now, approximate by checking high error rate periods
      threshold_time = Time.current - time_period
      high_error_periods = AgentLog.where('created_at > ? AND level >= ?', threshold_time, 4)
                                  .group_by_hour(:created_at)
                                  .count
                                  .select { |_hour, count| count > 10 } # Approximate threshold
      
      high_error_periods.count
    end

    ##
    # Calculate hourly error rates for trending
    def self.calculate_hourly_error_rates(hours)
      (0...hours).map do |hour_offset|
        hour_start = Time.current - (hour_offset + 1).hours
        hour_end = Time.current - hour_offset.hours
        
        error_count = AgentLog.where('created_at BETWEEN ? AND ? AND level >= ?', 
                                   hour_start, hour_end, 4).count
        total_count = AgentLog.where('created_at BETWEEN ? AND ?', 
                                   hour_start, hour_end).count
        
        {
          hour: hour_start.strftime('%Y-%m-%d %H:00'),
          error_rate: total_count > 0 ? (error_count.to_f / total_count) : 0.0,
          error_count: error_count,
          total_operations: total_count
        }
      end.reverse
    end

    ##
    # Determine overall trend direction
    def self.determine_trend_direction(hours)
      hourly_rates = calculate_hourly_error_rates(hours)
      return :stable if hourly_rates.length < 2
      
      recent_rate = hourly_rates.last(3).map { |h| h[:error_rate] }.sum / 3.0
      earlier_rate = hourly_rates.first(3).map { |h| h[:error_rate] }.sum / 3.0
      
      if recent_rate > earlier_rate * 1.2
        :increasing
      elsif recent_rate < earlier_rate * 0.8
        :decreasing  
      else
        :stable
      end
    end

    ##
    # Find hour with peak error rate
    def self.find_peak_error_hour(hours)
      hourly_rates = calculate_hourly_error_rates(hours)
      peak_hour = hourly_rates.max_by { |h| h[:error_rate] }
      
      {
        hour: peak_hour[:hour],
        error_rate: peak_hour[:error_rate],
        error_count: peak_hour[:error_count]
      }
    end

    ##
    # Calculate severity of threshold breach
    def self.calculate_breach_severity(current_rate)
      multiplier = current_rate / PRODUCTION_ERROR_RATE_THRESHOLD
      
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

    ##
    # Trigger error rate alert mechanisms
    def self.trigger_error_rate_alerts(current_rate, error_record)
      severity = calculate_breach_severity(current_rate)
      
      Rails.logger.error "[ALERT] ERROR RATE THRESHOLD BREACHED", {
        alert_level: severity,
        current_rate: current_rate,
        threshold: PRODUCTION_ERROR_RATE_THRESHOLD,
        breach_multiplier: (current_rate / PRODUCTION_ERROR_RATE_THRESHOLD).round(2),
        trigger_error_id: error_record&.id,
        timestamp: Time.current.iso8601
      }
      
      # Integration points for external alerting systems
      # - Email notifications via SystemMailer
      # - Slack/Discord webhooks
      # - PagerDuty/Opsgenie integration
      # - SMS alerts for critical breaches
      
      case severity
      when :critical
        send_critical_alert(current_rate, error_record)
      when :severe
        send_severe_alert(current_rate, error_record)
      when :moderate
        send_moderate_alert(current_rate, error_record)
      when :minor
        send_minor_alert(current_rate, error_record)
      end
    end

    ##
    # Log threshold breach to AgentLog for visibility
    def self.log_threshold_breach(current_rate, error_record)
      breach_message = "ERROR RATE THRESHOLD BREACHED: #{(current_rate * 100).round(4)}% " \
                      "(threshold: #{(PRODUCTION_ERROR_RATE_THRESHOLD * 100).round(4)}%)"
                      
      AgentLog.create!({
        message: breach_message,
        level: 4, # Error level
        agent_id: error_record&.agent_id,
        created_at: Time.current
      })
    end

    ##
    # Send critical severity alerts
    def self.send_critical_alert(current_rate, error_record)
      Rails.logger.error "[CRITICAL ALERT] Immediate intervention required", {
        current_rate: current_rate,
        error_rate_percentage: (current_rate * 100).round(4)
      }
      
      # Immediate escalation protocols would be implemented here
    end

    ##
    # Send severe severity alerts  
    def self.send_severe_alert(current_rate, error_record)
      Rails.logger.error "[SEVERE ALERT] Urgent attention needed", {
        current_rate: current_rate,
        error_rate_percentage: (current_rate * 100).round(4)
      }
    end

    ##
    # Send moderate severity alerts
    def self.send_moderate_alert(current_rate, error_record)
      Rails.logger.warn "[MODERATE ALERT] Error rate elevated", {
        current_rate: current_rate,
        error_rate_percentage: (current_rate * 100).round(4)
      }
    end

    ##
    # Send minor severity alerts
    def self.send_minor_alert(current_rate, error_record)
      Rails.logger.warn "[MINOR ALERT] Error rate above threshold", {
        current_rate: current_rate,
        error_rate_percentage: (current_rate * 100).round(4)
      }
    end

    ##
    # Generate CSV format error report
    def self.generate_csv_report(statistics)
      require 'csv'
      
      CSV.generate(headers: true) do |csv|
        csv << ['Time Period', 'Error Count', 'Error Rate', 'Compliant', 'Generated At']
        csv << [
          "#{statistics[:time_period][:hours]} hours",
          statistics[:error_counts][:total],
          statistics[:threshold_compliance][:current_rate],
          statistics[:threshold_compliance][:compliant],
          statistics[:generated_at]
        ]
        
        if statistics[:error_trends]
          csv << []
          csv << ['Hour', 'Error Rate', 'Error Count', 'Total Operations']
          statistics[:error_trends][:hourly_rates].each do |hour_data|
            csv << [hour_data[:hour], hour_data[:error_rate], hour_data[:error_count], hour_data[:total_operations]]
          end
        end
      end
    end

    ##
    # Generate text format error report
    def self.generate_text_report(statistics)
      report = []
      report << "Huginn Error Monitoring Report"
      report << "=" * 40
      report << ""
      report << "Generated: #{statistics[:generated_at]}"
      report << "Time Period: #{statistics[:time_period][:hours]} hours"
      report << ""
      report << "THRESHOLD COMPLIANCE"
      report << "Current Error Rate: #{(statistics[:threshold_compliance][:current_rate] * 100).round(4)}%"
      report << "Threshold: #{(PRODUCTION_ERROR_RATE_THRESHOLD * 100).round(4)}%"
      report << "Status: #{statistics[:threshold_compliance][:compliant] ? 'COMPLIANT' : 'BREACH'}"
      report << ""
      report << "ERROR SUMMARY"
      report << "Total Errors: #{statistics[:error_counts][:total]}"
      
      if statistics[:error_trends]
        report << ""
        report << "TRENDS"
        report << "Direction: #{statistics[:error_trends][:trend_direction].to_s.upcase}"
        report << "Peak Hour: #{statistics[:error_trends][:peak_error_hour][:hour]}"
        report << "Peak Rate: #{(statistics[:error_trends][:peak_error_hour][:error_rate] * 100).round(4)}%"
      end
      
      report.join("\n")
    end

    ##
    # Generate unique operation ID for tracking
    def self.generate_operation_id
      "error_track_#{Time.current.to_i}_#{SecureRandom.hex(4)}"
    end
  end
end