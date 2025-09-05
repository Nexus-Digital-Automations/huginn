# frozen_string_literal: true

# Error Categorization and Classification System for Huginn
# Provides intelligent error classification, impact assessment, and pattern recognition
#
# Dependencies: Rails, ActiveRecord
# Usage: ErrorCategorizer.categorize(error, context) -> returns detailed classification
module ErrorMonitoring
  ##
  # ErrorCategorizer provides intelligent error classification and pattern recognition
  # to enable better error handling, alerting, and resolution strategies
  #
  # Features:
  # - Multi-dimensional error classification (type, severity, impact, source)
  # - Pattern recognition for recurring error types
  # - Impact assessment based on affected systems and users
  # - Root cause analysis suggestions
  # - Integration with existing AgentLog and monitoring systems
  # - Machine learning-ready feature extraction
  #
  # @example Basic error categorization
  #   classification = ErrorCategorizer.categorize(error, {
  #     agent_id: 123,
  #     context: 'data_processing'
  #   })
  #
  # @example Pattern analysis
  #   patterns = ErrorCategorizer.analyze_patterns(time_range: 24.hours)
  #   puts patterns[:trending_errors]
  #
  class ErrorCategorizer
    include Singleton

    # Primary error categories for classification
    PRIMARY_CATEGORIES = {
      agent_execution: {
        patterns: [/agent.*execution/, /agent.*run/, /agent.*process/],
        severity_base: :medium,
        impact_scope: :single_agent,
        recovery_strategy: :retry_with_backoff
      },
      database_connection: {
        patterns: [/connection.*refused/, /connection.*timeout/, /database.*unavailable/],
        severity_base: :critical,
        impact_scope: :system_wide,
        recovery_strategy: :circuit_breaker
      },
      database_query: {
        patterns: [/sql.*error/, /query.*timeout/, /deadlock/, /lock.*timeout/],
        severity_base: :high,
        impact_scope: :feature_specific,
        recovery_strategy: :query_optimization
      },
      external_api: {
        patterns: [/http.*error/, /api.*error/, /remote.*error/, /timeout.*error/],
        severity_base: :medium,
        impact_scope: :integration_specific,
        recovery_strategy: :circuit_breaker
      },
      authentication: {
        patterns: [/auth.*failed/, /unauthorized/, /forbidden/, /token.*invalid/],
        severity_base: :high,
        impact_scope: :user_specific,
        recovery_strategy: :credential_refresh
      },
      authorization: {
        patterns: [/permission.*denied/, /access.*denied/, /not.*authorized/],
        severity_base: :medium,
        impact_scope: :user_specific,
        recovery_strategy: :permission_check
      },
      background_job: {
        patterns: [/job.*failed/, /worker.*error/, /queue.*error/, /delayed.*job/],
        severity_base: :medium,
        impact_scope: :background_processing,
        recovery_strategy: :job_retry
      },
      validation: {
        patterns: [/validation.*failed/, /invalid.*input/, /bad.*request/],
        severity_base: :low,
        impact_scope: :user_input,
        recovery_strategy: :input_sanitization
      },
      network: {
        patterns: [/network.*error/, /dns.*error/, /connection.*reset/, /host.*unreachable/],
        severity_base: :medium,
        impact_scope: :connectivity,
        recovery_strategy: :network_retry
      },
      system: {
        patterns: [/system.*error/, /internal.*error/, /server.*error/],
        severity_base: :high,
        impact_scope: :system_wide,
        recovery_strategy: :system_restart
      },
      resource: {
        patterns: [/memory.*error/, /disk.*full/, /cpu.*overload/, /resource.*exhausted/],
        severity_base: :critical,
        impact_scope: :system_wide,
        recovery_strategy: :resource_scaling
      },
      configuration: {
        patterns: [/config.*error/, /setting.*invalid/, /parameter.*missing/],
        severity_base: :medium,
        impact_scope: :configuration_dependent,
        recovery_strategy: :config_validation
      }
    }.freeze

    # Exception type mappings for automatic classification
    EXCEPTION_TYPE_MAPPINGS = {
      'ActiveRecord::ConnectionNotEstablished' => :database_connection,
      'ActiveRecord::StatementTimeout' => :database_query,
      'ActiveRecord::Deadlocked' => :database_query,
      'ActiveRecord::RecordNotFound' => :validation,
      'Net::OpenTimeout' => :network,
      'Net::ReadTimeout' => :network,
      'Timeout::Error' => :network,
      'SocketError' => :network,
      'Errno::ECONNREFUSED' => :network,
      'Errno::EHOSTUNREACH' => :network,
      'SecurityError' => :authentication,
      'ArgumentError' => :validation,
      'NoMethodError' => :system,
      'StandardError' => :system
    }.freeze

    # Severity levels with impact weights and response times
    SEVERITY_LEVELS = {
      critical: {
        weight: 4,
        max_response_time: 15.minutes,
        escalation_required: true,
        auto_recovery: false
      },
      high: {
        weight: 3,
        max_response_time: 1.hour,
        escalation_required: true,
        auto_recovery: true
      },
      medium: {
        weight: 2,
        max_response_time: 4.hours,
        escalation_required: false,
        auto_recovery: true
      },
      low: {
        weight: 1,
        max_response_time: 24.hours,
        escalation_required: false,
        auto_recovery: true
      },
      info: {
        weight: 0,
        max_response_time: nil,
        escalation_required: false,
        auto_recovery: true
      }
    }.freeze

    ##
    # Categorize error with comprehensive classification
    #
    # @param error [Exception] The error to categorize
    # @param context [Hash] Additional context for classification
    # @option context [Integer] :agent_id Agent ID if error is agent-related
    # @option context [String] :source Source system/component
    # @option context [Hash] :metadata Additional metadata
    # @option context [String] :user_id User ID if user-related error
    # @option context [String] :operation Operation being performed when error occurred
    #
    # @return [Hash] Comprehensive error classification
    def self.categorize(error, context = {})
      instance.perform_categorization(error, context)
    end

    ##
    # Analyze error patterns over time period
    #
    # @param options [Hash] Analysis options
    # @option options [ActiveSupport::Duration] :time_range Time range to analyze (default: 24.hours)
    # @option options [Integer] :min_occurrences Minimum occurrences to consider a pattern (default: 3)
    # @option options [Array<String>] :categories Filter by specific categories
    #
    # @return [Hash] Pattern analysis results
    def self.analyze_patterns(options = {})
      instance.perform_pattern_analysis(options)
    end

    ##
    # Get trending errors and emerging issues
    #
    # @param time_range [ActiveSupport::Duration] Time range for trend analysis
    # @return [Hash] Trending error information
    def self.trending_errors(time_range: 24.hours)
      instance.identify_trending_errors(time_range)
    end

    ##
    # Suggest root cause and resolution strategies
    #
    # @param error_classification [Hash] Output from categorize method
    # @param historical_context [Hash] Historical error context
    # @return [Hash] Root cause analysis and suggestions
    def self.suggest_resolution(error_classification, historical_context = {})
      instance.generate_resolution_suggestions(error_classification, historical_context)
    end

    ##
    # Export error categorization report
    #
    # @param output_path [String] Path for report file
    # @param options [Hash] Report options
    # @return [String] Path to generated report
    def self.export_categorization_report(output_path, options = {})
      instance.generate_categorization_report(output_path, options)
    end

    def initialize
      @classification_cache = {}
      @pattern_cache = {}
      @cache_mutex = Mutex.new
      
      Rails.logger.info "[ErrorCategorizer] Initialized error categorization system", {
        categories: PRIMARY_CATEGORIES.keys,
        exception_mappings: EXCEPTION_TYPE_MAPPINGS.keys.length
      }
    end

    ##
    # Perform comprehensive error categorization
    def perform_categorization(error, context = {})
      operation_start = Time.current
      operation_id = generate_operation_id
      
      Rails.logger.info "[ErrorCategorizer] Categorizing error", {
        error_class: error.class.name,
        error_message: error.message,
        context: context,
        operation_id: operation_id
      }

      begin
        classification = {
          operation_id: operation_id,
          timestamp: Time.current,
          error_details: extract_error_details(error),
          primary_category: determine_primary_category(error, context),
          secondary_categories: determine_secondary_categories(error, context),
          severity: determine_severity(error, context),
          impact_assessment: assess_impact(error, context),
          affected_systems: identify_affected_systems(error, context),
          user_impact: assess_user_impact(error, context),
          frequency_analysis: analyze_frequency(error, context),
          contextual_factors: extract_contextual_factors(error, context),
          recovery_strategies: suggest_recovery_strategies(error, context),
          similar_errors: find_similar_errors(error, context),
          classification_confidence: calculate_confidence(error, context)
        }

        processing_time = ((Time.current - operation_start) * 1000).round(2)
        Rails.logger.info "[ErrorCategorizer] Categorization completed", {
          operation_id: operation_id,
          primary_category: classification[:primary_category],
          severity: classification[:severity],
          confidence: classification[:classification_confidence],
          processing_time_ms: processing_time
        }

        classification
      rescue => categorization_error
        Rails.logger.error "[ErrorCategorizer] Categorization failed", {
          operation_id: operation_id,
          original_error: error.message,
          categorization_error: categorization_error.message,
          stack_trace: categorization_error.backtrace&.first(3)
        }

        # Return minimal classification on failure
        {
          operation_id: operation_id,
          timestamp: Time.current,
          error_details: { class: error.class.name, message: error.message },
          primary_category: :unknown,
          severity: :medium,
          classification_confidence: 0.0,
          error: "Categorization failed: #{categorization_error.message}"
        }
      end
    end

    ##
    # Perform pattern analysis over time period
    def perform_pattern_analysis(options = {})
      operation_start = Time.current
      time_range = options[:time_range] || 24.hours
      min_occurrences = options[:min_occurrences] || 3
      
      Rails.logger.info "[ErrorCategorizer] Analyzing error patterns", {
        time_range: time_range,
        min_occurrences: min_occurrences,
        categories: options[:categories]
      }

      begin
        time_threshold = Time.current - time_range
        base_query = AgentLog.where('created_at > ? AND level >= ?', time_threshold, 3)
        
        # Apply category filter if specified
        if options[:categories].present?
          category_patterns = options[:categories].map { |cat| PRIMARY_CATEGORIES[cat.to_sym][:patterns] }.flatten
          pattern_regex = Regexp.union(category_patterns)
          base_query = base_query.where('message REGEXP ?', pattern_regex.source)
        end

        patterns = {
          time_period: { 
            range: time_range,
            start_time: time_threshold,
            end_time: Time.current 
          },
          recurring_patterns: identify_recurring_patterns(base_query, min_occurrences),
          error_clusters: cluster_similar_errors(base_query),
          temporal_patterns: analyze_temporal_patterns(base_query),
          category_distribution: analyze_category_distribution(base_query),
          severity_trends: analyze_severity_trends(base_query),
          agent_error_profiles: analyze_agent_error_profiles(base_query),
          correlation_analysis: analyze_error_correlations(base_query),
          anomaly_detection: detect_error_anomalies(base_query),
          generated_at: Time.current
        }

        processing_time = ((Time.current - operation_start) * 1000).round(2)
        Rails.logger.info "[ErrorCategorizer] Pattern analysis completed", {
          recurring_patterns: patterns[:recurring_patterns].length,
          error_clusters: patterns[:error_clusters].length,
          processing_time_ms: processing_time
        }

        patterns
      rescue => analysis_error
        Rails.logger.error "[ErrorCategorizer] Pattern analysis failed", {
          error: analysis_error.message,
          time_range: time_range
        }

        {
          error: "Pattern analysis failed: #{analysis_error.message}",
          time_period: { range: time_range },
          generated_at: Time.current
        }
      end
    end

    ##
    # Identify trending errors
    def identify_trending_errors(time_range)
      operation_start = Time.current
      
      Rails.logger.info "[ErrorCategorizer] Identifying trending errors", {
        time_range: time_range
      }

      begin
        current_period = Time.current - time_range
        previous_period = current_period - time_range
        
        current_errors = AgentLog.where('created_at > ? AND level >= ?', current_period, 3)
                                .group('SUBSTRING(message, 1, 100)')
                                .count
                                
        previous_errors = AgentLog.where('created_at BETWEEN ? AND ? AND level >= ?', 
                                        previous_period, current_period, 3)
                                 .group('SUBSTRING(message, 1, 100)')
                                 .count

        trends = calculate_error_trends(current_errors, previous_errors)
        
        processing_time = ((Time.current - operation_start) * 1000).round(2)
        Rails.logger.info "[ErrorCategorizer] Trending analysis completed", {
          trending_up: trends[:increasing].length,
          trending_down: trends[:decreasing].length,
          new_errors: trends[:new].length,
          processing_time_ms: processing_time
        }

        {
          time_range: time_range,
          trends: trends,
          analysis_period: {
            current_start: current_period,
            previous_start: previous_period
          },
          generated_at: Time.current
        }
      rescue => trend_error
        Rails.logger.error "[ErrorCategorizer] Trend analysis failed", {
          error: trend_error.message,
          time_range: time_range
        }

        {
          error: "Trend analysis failed: #{trend_error.message}",
          time_range: time_range,
          generated_at: Time.current
        }
      end
    end

    ##
    # Generate resolution suggestions
    def generate_resolution_suggestions(classification, historical_context = {})
      operation_start = Time.current
      
      Rails.logger.info "[ErrorCategorizer] Generating resolution suggestions", {
        primary_category: classification[:primary_category],
        severity: classification[:severity]
      }

      begin
        category_config = PRIMARY_CATEGORIES[classification[:primary_category]]
        
        suggestions = {
          immediate_actions: generate_immediate_actions(classification, category_config),
          recovery_strategies: generate_recovery_strategies(classification, category_config),
          preventive_measures: generate_preventive_measures(classification, historical_context),
          monitoring_recommendations: generate_monitoring_recommendations(classification),
          escalation_path: determine_escalation_path(classification),
          estimated_resolution_time: estimate_resolution_time(classification, historical_context),
          success_probability: calculate_success_probability(classification, historical_context),
          resource_requirements: assess_resource_requirements(classification),
          related_documentation: find_related_documentation(classification),
          generated_at: Time.current
        }

        processing_time = ((Time.current - operation_start) * 1000).round(2)
        Rails.logger.info "[ErrorCategorizer] Resolution suggestions generated", {
          immediate_actions: suggestions[:immediate_actions].length,
          recovery_strategies: suggestions[:recovery_strategies].length,
          processing_time_ms: processing_time
        }

        suggestions
      rescue => suggestion_error
        Rails.logger.error "[ErrorCategorizer] Suggestion generation failed", {
          error: suggestion_error.message,
          primary_category: classification[:primary_category]
        }

        {
          error: "Suggestion generation failed: #{suggestion_error.message}",
          generated_at: Time.current
        }
      end
    end

    ##
    # Generate categorization report
    def generate_categorization_report(output_path, options = {})
      operation_start = Time.current
      hours = options[:hours] || 24
      
      Rails.logger.info "[ErrorCategorizer] Generating categorization report", {
        output_path: output_path,
        hours: hours
      }

      begin
        patterns = perform_pattern_analysis(time_range: hours.hours, include_trends: true)
        trending = identify_trending_errors(hours.hours)
        
        report_data = {
          report_metadata: {
            generated_at: Time.current,
            time_period_hours: hours,
            report_type: 'error_categorization'
          },
          executive_summary: generate_executive_summary(patterns, trending),
          pattern_analysis: patterns,
          trending_analysis: trending,
          recommendations: generate_system_recommendations(patterns, trending),
          appendix: {
            category_definitions: PRIMARY_CATEGORIES,
            severity_levels: SEVERITY_LEVELS
          }
        }

        # Write report in JSON format
        File.write(output_path, JSON.pretty_generate(report_data))
        
        processing_time = ((Time.current - operation_start) * 1000).round(2)
        Rails.logger.info "[ErrorCategorizer] Report generated", {
          output_path: output_path,
          file_size: File.size(output_path),
          processing_time_ms: processing_time
        }

        output_path
      rescue => report_error
        Rails.logger.error "[ErrorCategorizer] Report generation failed", {
          output_path: output_path,
          error: report_error.message
        }
        raise report_error
      end
    end

    private

    ##
    # Extract detailed error information
    def extract_error_details(error)
      {
        class: error.class.name,
        message: error.message,
        backtrace: error.backtrace&.first(5),
        cause: error.cause&.message,
        fingerprint: generate_error_fingerprint(error)
      }
    end

    ##
    # Determine primary error category
    def determine_primary_category(error, context)
      # Check exception type mapping first
      if EXCEPTION_TYPE_MAPPINGS.key?(error.class.name)
        return EXCEPTION_TYPE_MAPPINGS[error.class.name]
      end

      # Check error message patterns
      error_text = "#{error.class.name} #{error.message}".downcase
      
      PRIMARY_CATEGORIES.each do |category, config|
        config[:patterns].each do |pattern|
          return category if error_text.match?(pattern)
        end
      end

      # Check context hints
      if context[:agent_id] && context[:operation]&.include?('agent')
        return :agent_execution
      end

      :unknown
    end

    ##
    # Determine secondary categories
    def determine_secondary_categories(error, context)
      secondary = []
      error_text = "#{error.class.name} #{error.message}".downcase
      
      PRIMARY_CATEGORIES.each do |category, config|
        config[:patterns].each do |pattern|
          if error_text.match?(pattern)
            secondary << category
          end
        end
      end
      
      secondary.uniq.first(3) # Limit to top 3 secondary categories
    end

    ##
    # Determine error severity
    def determine_severity(error, context)
      primary_category = determine_primary_category(error, context)
      base_severity = PRIMARY_CATEGORIES[primary_category]&.dig(:severity_base) || :medium
      
      # Adjust severity based on context
      severity_adjustments = 0
      
      # Critical system errors
      severity_adjustments += 1 if error.is_a?(SystemExit) || error.is_a?(SecurityError)
      
      # Database connection issues
      severity_adjustments += 1 if error.message.match?(/connection.*refused|database.*unavailable/)
      
      # High frequency errors (if this error has occurred frequently recently)
      recent_count = count_recent_similar_errors(error, 1.hour)
      severity_adjustments += 1 if recent_count > 10
      
      # Apply adjustments
      severity_levels = SEVERITY_LEVELS.keys
      current_index = severity_levels.index(base_severity) || 2
      adjusted_index = [current_index + severity_adjustments, severity_levels.length - 1].min
      
      severity_levels[adjusted_index]
    end

    ##
    # Assess impact of error
    def assess_impact(error, context)
      primary_category = determine_primary_category(error, context)
      base_impact = PRIMARY_CATEGORIES[primary_category]&.dig(:impact_scope) || :unknown
      
      {
        scope: base_impact,
        affected_users: estimate_affected_users(error, context),
        affected_agents: estimate_affected_agents(error, context),
        system_availability: assess_system_availability_impact(error, context),
        data_integrity: assess_data_integrity_impact(error, context),
        business_impact: assess_business_impact(error, context)
      }
    end

    ##
    # Identify affected systems
    def identify_affected_systems(error, context)
      systems = []
      
      # Agent system
      systems << 'agent_execution' if context[:agent_id] || error.message.match?(/agent/)
      
      # Database system
      systems << 'database' if error.is_a?(ActiveRecord::ActiveRecordError) || 
                               error.message.match?(/sql|database|connection/)
      
      # External APIs
      systems << 'external_apis' if error.message.match?(/http|api|remote|timeout/)
      
      # Authentication system
      systems << 'authentication' if error.message.match?(/auth|unauthorized|forbidden/)
      
      # Background jobs
      systems << 'background_jobs' if error.message.match?(/job|worker|queue/)
      
      systems.uniq
    end

    ##
    # Assess user impact
    def assess_user_impact(error, context)
      {
        severity: determine_user_impact_severity(error, context),
        estimated_affected_users: estimate_affected_users(error, context),
        functionality_impacted: identify_impacted_functionality(error, context),
        workaround_available: assess_workaround_availability(error, context)
      }
    end

    ##
    # Analyze error frequency
    def analyze_frequency(error, context)
      fingerprint = generate_error_fingerprint(error)
      
      {
        first_occurrence: find_first_occurrence(fingerprint),
        last_occurrence: Time.current,
        frequency_1h: count_recent_similar_errors(error, 1.hour),
        frequency_24h: count_recent_similar_errors(error, 24.hours),
        frequency_7d: count_recent_similar_errors(error, 7.days),
        is_recurring: is_recurring_error?(fingerprint),
        trend: analyze_error_frequency_trend(fingerprint)
      }
    end

    ##
    # Extract contextual factors
    def extract_contextual_factors(error, context)
      factors = {}
      
      # Time-based factors
      factors[:time_of_day] = Time.current.hour
      factors[:day_of_week] = Time.current.wday
      factors[:is_weekend] = Time.current.weekend?
      
      # System load factors
      factors[:system_load] = estimate_system_load
      
      # Agent-specific factors
      if context[:agent_id]
        factors[:agent_type] = get_agent_type(context[:agent_id])
        factors[:agent_last_success] = get_agent_last_success(context[:agent_id])
      end
      
      # User-specific factors
      if context[:user_id]
        factors[:user_error_history] = get_user_error_history(context[:user_id])
      end
      
      factors
    end

    ##
    # Suggest recovery strategies
    def suggest_recovery_strategies(error, context)
      primary_category = determine_primary_category(error, context)
      base_strategy = PRIMARY_CATEGORIES[primary_category]&.dig(:recovery_strategy) || :manual_investigation
      
      strategies = [base_strategy]
      
      # Add additional strategies based on error characteristics
      strategies << :circuit_breaker if error.message.match?(/timeout|connection/)
      strategies << :retry_with_backoff if error.is_a?(StandardError) && !error.is_a?(ArgumentError)
      strategies << :credential_refresh if error.message.match?(/auth|unauthorized/)
      strategies << :resource_scaling if error.message.match?(/memory|resource/)
      
      strategies.uniq
    end

    ##
    # Find similar errors
    def find_similar_errors(error, context)
      fingerprint = generate_error_fingerprint(error)
      
      AgentLog.where('created_at > ? AND level >= ? AND message LIKE ?', 
                     24.hours.ago, 3, "%#{fingerprint}%")
             .order(created_at: :desc)
             .limit(5)
             .pluck(:id, :message, :created_at)
             .map { |id, message, created_at| 
               { id: id, message: message, occurred_at: created_at }
             }
    end

    ##
    # Calculate classification confidence
    def calculate_confidence(error, context)
      confidence = 0.0
      
      # Exception type mapping confidence
      if EXCEPTION_TYPE_MAPPINGS.key?(error.class.name)
        confidence += 0.4
      end
      
      # Pattern matching confidence
      error_text = "#{error.class.name} #{error.message}".downcase
      PRIMARY_CATEGORIES.each do |_category, config|
        config[:patterns].each do |pattern|
          if error_text.match?(pattern)
            confidence += 0.3
            break
          end
        end
      end
      
      # Context information confidence
      confidence += 0.2 if context[:agent_id]
      confidence += 0.1 if context[:operation]
      
      [confidence, 1.0].min.round(2)
    end

    # Additional helper methods for pattern analysis...
    
    def identify_recurring_patterns(query, min_occurrences)
      # Group similar errors and find patterns that occur frequently
      patterns = query.group('SUBSTRING(message, 1, 200)')
                     .having('COUNT(*) >= ?', min_occurrences)
                     .count
                     .map { |message, count| 
                       {
                         pattern: message,
                         occurrences: count,
                         category: determine_primary_category_from_message(message),
                         last_occurrence: query.where('message LIKE ?', "#{message}%")
                                               .maximum(:created_at)
                       }
                     }
                     
      patterns.sort_by { |p| -p[:occurrences] }
    end

    def cluster_similar_errors(query)
      # Simple clustering based on error message similarity
      # In production, this could use more sophisticated NLP techniques
      error_groups = {}
      
      query.find_each do |log|
        key_words = extract_key_words(log.message)
        cluster_key = key_words.sort.join('_')
        
        error_groups[cluster_key] ||= []
        error_groups[cluster_key] << {
          id: log.id,
          message: log.message,
          created_at: log.created_at
        }
      end
      
      # Return clusters with more than one error
      error_groups.select { |_key, errors| errors.length > 1 }
                  .map { |key, errors| 
                    {
                      cluster_id: key,
                      error_count: errors.length,
                      representative_message: errors.first[:message],
                      first_occurrence: errors.map { |e| e[:created_at] }.min,
                      last_occurrence: errors.map { |e| e[:created_at] }.max
                    }
                  }
    end

    def analyze_temporal_patterns(query)
      hourly_distribution = query.group_by_hour(:created_at, last: 24).count
      daily_distribution = query.group_by_day(:created_at, last: 7).count
      
      {
        hourly_distribution: hourly_distribution,
        daily_distribution: daily_distribution,
        peak_hour: hourly_distribution.max_by { |_hour, count| count }&.first,
        peak_day: daily_distribution.max_by { |_day, count| count }&.first
      }
    end

    def analyze_category_distribution(query)
      category_counts = {}
      
      query.find_each do |log|
        category = determine_primary_category_from_message(log.message)
        category_counts[category] ||= 0
        category_counts[category] += 1
      end
      
      total_errors = category_counts.values.sum
      
      category_counts.transform_values { |count| 
        {
          count: count,
          percentage: total_errors > 0 ? (count.to_f / total_errors * 100).round(2) : 0
        }
      }
    end

    def analyze_severity_trends(query)
      severity_by_hour = query.group_by_hour(:created_at, last: 24)
                             .group(:level)
                             .count
                             
      # Convert to more readable format
      hourly_severity = {}
      severity_by_hour.each do |(hour, level), count|
        hourly_severity[hour] ||= {}
        hourly_severity[hour][level] = count
      end
      
      hourly_severity
    end

    def analyze_agent_error_profiles(query)
      agent_errors = query.joins(:agent)
                          .group('agents.type', 'agents.name')
                          .count
                          
      agent_errors.map { |(agent_type, agent_name), count|
        {
          agent_type: agent_type,
          agent_name: agent_name,
          error_count: count,
          error_rate: calculate_agent_error_rate(agent_name, count)
        }
      }.sort_by { |profile| -profile[:error_count] }
    end

    # Additional utility methods...

    def generate_error_fingerprint(error)
      # Create a unique fingerprint for error matching
      "#{error.class.name}:#{error.message&.gsub(/\d+/, 'N')&.first(100)}"
    end

    def determine_primary_category_from_message(message)
      message_lower = message.downcase
      
      PRIMARY_CATEGORIES.each do |category, config|
        config[:patterns].each do |pattern|
          return category if message_lower.match?(pattern)
        end
      end
      
      :unknown
    end

    def extract_key_words(message)
      # Extract meaningful words from error message for clustering
      words = message.downcase
                    .gsub(/[^\w\s]/, ' ')
                    .split
                    .reject { |word| word.length < 3 }
                    .reject { |word| %w[the and for with from error failed].include?(word) }
                    
      words.uniq.first(5) # Limit to top 5 key words
    end

    def count_recent_similar_errors(error, time_range)
      fingerprint = generate_error_fingerprint(error)
      time_threshold = Time.current - time_range
      
      AgentLog.where('created_at > ? AND level >= ? AND message LIKE ?', 
                     time_threshold, 3, "%#{fingerprint.split(':').last}%")
             .count
    end

    def generate_operation_id
      "error_cat_#{Time.current.to_i}_#{SecureRandom.hex(4)}"
    end

    # Placeholder methods for additional functionality
    # These would be fully implemented based on specific requirements
    
    def estimate_affected_users(error, context); 0; end
    def estimate_affected_agents(error, context); 0; end
    def assess_system_availability_impact(error, context); :minimal; end
    def assess_data_integrity_impact(error, context); :none; end
    def assess_business_impact(error, context); :low; end
    def determine_user_impact_severity(error, context); :low; end
    def identify_impacted_functionality(error, context); []; end
    def assess_workaround_availability(error, context); true; end
    def find_first_occurrence(fingerprint); 24.hours.ago; end
    def is_recurring_error?(fingerprint); false; end
    def analyze_error_frequency_trend(fingerprint); :stable; end
    def estimate_system_load; :normal; end
    def get_agent_type(agent_id); 'unknown'; end
    def get_agent_last_success(agent_id); nil; end
    def get_user_error_history(user_id); []; end
    def calculate_agent_error_rate(agent_name, error_count); 0.0; end
    def calculate_error_trends(current, previous); { increasing: [], decreasing: [], new: [] }; end
    def generate_immediate_actions(classification, config); []; end
    def generate_recovery_strategies(classification, config); []; end
    def generate_preventive_measures(classification, historical); []; end
    def generate_monitoring_recommendations(classification); []; end
    def determine_escalation_path(classification); []; end
    def estimate_resolution_time(classification, historical); '1 hour'; end
    def calculate_success_probability(classification, historical); 0.8; end
    def assess_resource_requirements(classification); { cpu: :low, memory: :low, network: :medium }; end
    def find_related_documentation(classification); []; end
    def generate_executive_summary(patterns, trending); {}; end
    def generate_system_recommendations(patterns, trending); []; end
    def analyze_error_correlations(query); {}; end
    def detect_error_anomalies(query); []; end
  end
end