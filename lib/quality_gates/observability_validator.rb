# frozen_string_literal: true

require_relative 'utils'

module QualityGates
  # Validates observability built-in patterns for metrics, logs, and traces
  # Ensures comprehensive monitoring and debugging capabilities are integrated from the start
  class ObservabilityValidator
    include Utils

    attr_reader :project_root, :logger

    def initialize(project_root = Rails.root)
      @project_root = Pathname.new(project_root)
      @logger = setup_logger
    end

    # Main validation entry point
    # @return [ValidationResult] Results of observability validation
    def validate
      log_operation_start('Observability built-in validation')
      start_time = Time.now

      errors = []
      warnings = []
      details = {
        logging: validate_logging_implementation,
        metrics: validate_metrics_collection,
        tracing: validate_distributed_tracing,
        health_checks: validate_health_monitoring,
        error_tracking: validate_error_tracking,
        performance_monitoring: validate_performance_monitoring,
        alerting: validate_alerting_setup,
        dashboards: validate_dashboard_configuration
      }

      # Analyze each validation area
      details.each do |area, result|
        if result[:errors].any?
          errors.concat(result[:errors].map { |e| "#{area.to_s.humanize}: #{e}" })
        end
        
        if result[:warnings].any?
          warnings.concat(result[:warnings].map { |w| "#{area.to_s.humanize}: #{w}" })
        end
      end

      # Overall observability readiness assessment
      observability_score = calculate_observability_score(details)
      details[:overall_observability_score] = observability_score

      if observability_score < 70
        errors << "Overall observability score too low: #{observability_score}% (minimum: 70%)"
      elsif observability_score < 85
        warnings << "Observability could be enhanced: #{observability_score}% (target: 85%+)"
      end

      result = ValidationResult.new(
        passed: errors.empty?,
        errors: errors,
        warnings: warnings,
        details: details
      )

      log_validation_completion('Observability validation', start_time, result)
      result
    end

    private

    def setup_logger
      Logger.new($stdout).tap do |logger|
        logger.level = Logger::INFO
        logger.formatter = proc do |severity, datetime, progname, msg|
          "[#{datetime.strftime('%H:%M:%S')}] [ObservabilityValidator] #{severity}: #{msg}\n"
        end
      end
    end

    def log_operation_start(operation)
      logger.info("📊 Starting: #{operation}")
    end

    def log_validation_completion(operation, start_time, result)
      duration = ((Time.now - start_time) * 1000).round(2)
      status = result.passed? ? '✅ PASSED' : '❌ FAILED'
      logger.info("🏁 Completed: #{operation} in #{duration}ms - #{status}")
    end

    # Validate logging implementation and patterns
    def validate_logging_implementation
      errors = []
      warnings = []
      details = {
        logging_configuration: analyze_logging_configuration,
        structured_logging: validate_structured_logging,
        log_levels: validate_log_levels_usage,
        log_rotation: check_log_rotation_setup,
        contextual_logging: analyze_contextual_logging,
        log_aggregation: check_log_aggregation_setup
      }

      # Check basic logging setup
      unless details[:logging_configuration][:has_custom_logging_config]
        warnings << "Using default logging configuration - consider custom setup for production"
      end

      # Validate structured logging
      if details[:structured_logging][:structured_percentage] < 60
        warnings << "Low structured logging usage: #{details[:structured_logging][:structured_percentage]}% (target: 60%+)"
      end

      # Check log rotation
      unless details[:log_rotation][:has_log_rotation]
        warnings << "No log rotation configured - logs may grow unbounded"
      end

      { errors: errors, warnings: warnings, details: details }
    end

    # Analyze logging configuration
    def analyze_logging_configuration
      config_files = find_configuration_files
      has_custom_config = false
      logging_libraries = []

      # Check for custom logging configuration
      config_files.each do |file_path|
        content = File.read(file_path)
        
        if content.match?(/config\.log_level|Rails\.logger|Logger\./i)
          has_custom_config = true
        end

        # Detect logging libraries
        if content.match?(lograge|semantic_logger|rails_semantic_logger/i)
          logging_libraries << extract_logging_gems(content)
        end
      end

      # Check Gemfile for logging gems
      gemfile_path = project_root.join('Gemfile')
      if gemfile_path.exist?
        gemfile_content = gemfile_path.read
        logging_gems = detect_logging_gems(gemfile_content)
        logging_libraries.concat(logging_gems)
      end

      {
        has_custom_logging_config: has_custom_config,
        logging_libraries: logging_libraries.flatten.uniq,
        config_files_checked: config_files.length
      }
    end

    # Find configuration files
    def find_configuration_files
      patterns = %w[
        config/**/*.rb
        config/**/*.yml
        initializers/**/*.rb
      ]

      found_files = []
      patterns.each do |pattern|
        found_files.concat(Dir.glob(project_root.join(pattern)))
      end

      found_files
    end

    # Extract logging gems from content
    def extract_logging_gems(content)
      logging_patterns = %w[lograge semantic_logger rails_semantic_logger amazing_print]
      logging_patterns.select { |gem| content.include?(gem) }
    end

    # Detect logging gems in Gemfile
    def detect_logging_gems(gemfile_content)
      logging_gems = %w[
        lograge semantic_logger rails_semantic_logger amazing_print
        logstash-event logstash-logger fluentd syslog-logger
      ]
      
      logging_gems.select { |gem| gemfile_content.include?(gem) }
    end

    # Validate structured logging usage
    def validate_structured_logging
      ruby_files = find_ruby_files
      structured_logging_count = 0
      total_logging_statements = 0

      ruby_files.each do |file_path|
        content = File.read(file_path)
        
        # Count logging statements
        logging_statements = content.scan(/(?:Rails\.)?logger\.(?:debug|info|warn|error|fatal)/).length
        total_logging_statements += logging_statements

        # Count structured logging (JSON, hash parameters)
        structured_statements = content.scan(/logger\.(?:info|debug|warn|error)\s*\([^)]*\{.*?\}/m).length
        structured_statements += content.scan(/logger\.(?:info|debug|warn|error)\s*.*?\.to_json/m).length
        structured_logging_count += structured_statements
      end

      structured_percentage = total_logging_statements.zero? ? 0 : 
                             (structured_logging_count.to_f / total_logging_statements * 100).round(2)

      {
        total_logging_statements: total_logging_statements,
        structured_logging_statements: structured_logging_count,
        structured_percentage: structured_percentage,
        files_analyzed: ruby_files.length
      }
    end

    # Find Ruby files for analysis
    def find_ruby_files
      patterns = %w[app/**/*.rb lib/**/*.rb]
      patterns.flat_map { |pattern| Dir.glob(project_root.join(pattern)) }
               .select { |path| File.file?(path) }
    end

    # Validate log levels usage
    def validate_log_levels_usage
      ruby_files = find_ruby_files
      log_level_usage = {
        debug: 0, info: 0, warn: 0, error: 0, fatal: 0
      }

      ruby_files.each do |file_path|
        content = File.read(file_path)
        
        log_level_usage.each_key do |level|
          log_level_usage[level] += content.scan(/logger\.#{level}/).length
        end
      end

      total_log_statements = log_level_usage.values.sum
      
      {
        log_level_distribution: log_level_usage,
        total_log_statements: total_log_statements,
        balanced_usage: check_balanced_log_usage(log_level_usage, total_log_statements)
      }
    end

    # Check if log levels are used in a balanced way
    def check_balanced_log_usage(usage, total)
      return true if total.zero?

      # Check if error/warn logs are present (important for debugging)
      error_warn_ratio = (usage[:error] + usage[:warn]).to_f / total
      
      # Check if info logs dominate (good for operational visibility)
      info_ratio = usage[:info].to_f / total
      
      error_warn_ratio > 0.1 && info_ratio > 0.3
    end

    # Check log rotation setup
    def check_log_rotation_setup
      config_files = find_configuration_files
      has_rotation = false

      config_files.each do |file_path|
        content = File.read(file_path)
        if content.match?(daily|weekly|size|rotate/i)
          has_rotation = true
          break
        end
      end

      # Check for logrotate configuration
      logrotate_configs = Dir.glob(project_root.join('config/**/*logrotate*'))
      has_logrotate = logrotate_configs.any?

      {
        has_log_rotation: has_rotation || has_logrotate,
        logrotate_configs: logrotate_configs.length,
        config_files_checked: config_files.length
      }
    end

    # Analyze contextual logging patterns
    def analyze_contextual_logging
      ruby_files = find_ruby_files
      contextual_logging_indicators = 0
      context_patterns = %w[
        request_id user_id session_id transaction_id
        correlation_id trace_id span_id
      ]

      ruby_files.each do |file_path|
        content = File.read(file_path)
        
        context_patterns.each do |pattern|
          contextual_logging_indicators += content.scan(/logger.*#{pattern}/i).length
        end
      end

      {
        contextual_logging_statements: contextual_logging_indicators,
        context_patterns_detected: context_patterns.select do |pattern|
          ruby_files.any? { |file| File.read(file).match?(/logger.*#{pattern}/i) }
        end
      }
    end

    # Check log aggregation setup
    def check_log_aggregation_setup
      gemfile_path = project_root.join('Gemfile')
      aggregation_gems = []

      if gemfile_path.exist?
        gemfile_content = gemfile_path.read
        log_aggregation_tools = %w[
          fluentd logstash elastic-apm newrelic_rpm
          datadog scout_apm skylight
        ]
        
        aggregation_gems = log_aggregation_tools.select { |gem| gemfile_content.include?(gem) }
      end

      config_files = find_configuration_files
      has_aggregation_config = config_files.any? do |file|
        content = File.read(file)
        content.match?(fluentd|logstash|elasticsearch|datadog|newrelic/i)
      end

      {
        aggregation_gems: aggregation_gems,
        has_aggregation_config: has_aggregation_config
      }
    end

    # Validate metrics collection implementation
    def validate_metrics_collection
      errors = []
      warnings = []
      details = {
        metrics_libraries: detect_metrics_libraries,
        custom_metrics: analyze_custom_metrics,
        business_metrics: analyze_business_metrics,
        system_metrics: validate_system_metrics,
        metrics_endpoints: check_metrics_endpoints
      }

      # Check for metrics collection setup
      if details[:metrics_libraries][:libraries].empty?
        warnings << "No metrics collection libraries detected - consider adding application metrics"
      end

      # Validate custom metrics implementation
      if details[:custom_metrics][:custom_metrics_count] == 0
        warnings << "No custom metrics found - consider tracking business-specific metrics"
      end

      { errors: errors, warnings: warnings, details: details }
    end

    # Detect metrics collection libraries
    def detect_metrics_libraries
      gemfile_path = project_root.join('Gemfile')
      libraries = []

      if gemfile_path.exist?
        gemfile_content = gemfile_path.read
        metrics_gems = %w[
          prometheus-client statsd-ruby datadog newrelic_rpm
          scout_apm skylight elastic-apm yabeda
        ]
        
        libraries = metrics_gems.select { |gem| gemfile_content.include?(gem) }
      end

      config_files = find_configuration_files
      configured_libraries = []

      config_files.each do |file_path|
        content = File.read(file_path)
        metrics_tools = %w[prometheus statsd datadog newrelic scout]
        
        metrics_tools.each do |tool|
          configured_libraries << tool if content.downcase.include?(tool)
        end
      end

      {
        libraries: libraries,
        configured_tools: configured_libraries.uniq,
        total_detected: (libraries + configured_libraries).uniq.length
      }
    end

    # Analyze custom metrics implementation
    def analyze_custom_metrics
      ruby_files = find_ruby_files
      custom_metrics_patterns = []
      metrics_count = 0

      ruby_files.each do |file_path|
        content = File.read(file_path)
        relative_path = Pathname.new(file_path).relative_path_from(project_root).to_s
        
        # Look for metrics instrumentation patterns
        metrics_calls = content.scan(/(?:increment|decrement|histogram|gauge|timer|measure)/).length
        prometheus_metrics = content.scan(/prometheus.*?(?:counter|gauge|histogram|summary)/i).length
        statsd_metrics = content.scan(/statsd.*?(?:increment|decrement|gauge|timing)/i).length
        
        total_metrics = metrics_calls + prometheus_metrics + statsd_metrics
        if total_metrics > 0
          custom_metrics_patterns << {
            file: relative_path,
            metrics_count: total_metrics,
            types: {
              general: metrics_calls,
              prometheus: prometheus_metrics,
              statsd: statsd_metrics
            }
          }
          metrics_count += total_metrics
        end
      end

      {
        custom_metrics_count: metrics_count,
        files_with_metrics: custom_metrics_patterns.length,
        metrics_patterns: custom_metrics_patterns
      }
    end

    # Analyze business metrics tracking
    def analyze_business_metrics
      ruby_files = find_ruby_files
      business_metrics = []

      # Common business metric patterns
      business_patterns = [
        { name: 'user_activity', patterns: %w[user_login user_signup user_action] },
        { name: 'agent_performance', patterns: %w[agent_check agent_receive event_created] },
        { name: 'system_health', patterns: %w[response_time error_rate throughput] },
        { name: 'feature_usage', patterns: %w[feature_enabled feature_used conversion] }
      ]

      ruby_files.each do |file_path|
        content = File.read(file_path)
        
        business_patterns.each do |category|
          matching_patterns = category[:patterns].select do |pattern|
            content.downcase.include?(pattern)
          end
          
          if matching_patterns.any?
            business_metrics << {
              category: category[:name],
              file: Pathname.new(file_path).relative_path_from(project_root).to_s,
              patterns_found: matching_patterns
            }
          end
        end
      end

      {
        business_metrics_found: business_metrics.length,
        metrics_by_category: business_patterns.map do |category|
          matches = business_metrics.select { |m| m[:category] == category[:name] }
          { category: category[:name], count: matches.length }
        end,
        detailed_metrics: business_metrics
      }
    end

    # Validate system metrics collection
    def validate_system_metrics
      # Check for system-level metrics collection
      config_files = find_configuration_files
      system_metrics_config = false

      config_files.each do |file_path|
        content = File.read(file_path)
        if content.match?(memory|cpu|disk|network|gc|database_pool/i)
          system_metrics_config = true
          break
        end
      end

      # Check for Rails built-in metrics
      rails_metrics = check_rails_metrics_setup

      {
        has_system_metrics_config: system_metrics_config,
        rails_metrics: rails_metrics,
        recommended_metrics: %w[
          response_time request_count error_rate
          memory_usage cpu_usage database_connections
          background_job_queue_size cache_hit_rate
        ]
      }
    end

    # Check Rails metrics setup
    def check_rails_metrics_setup
      config_files = Dir.glob(project_root.join('config/**/*.rb'))
      
      rails_metrics_indicators = {
        action_controller_metrics: false,
        active_record_metrics: false,
        cache_metrics: false,
        job_metrics: false
      }

      config_files.each do |file_path|
        content = File.read(file_path)
        
        rails_metrics_indicators[:action_controller_metrics] = true if content.include?('ActionController')
        rails_metrics_indicators[:active_record_metrics] = true if content.include?('ActiveRecord')
        rails_metrics_indicators[:cache_metrics] = true if content.include?('cache')
        rails_metrics_indicators[:job_metrics] = true if content.include?('ActiveJob')
      end

      rails_metrics_indicators
    end

    # Check metrics endpoints
    def check_metrics_endpoints
      routes_file = project_root.join('config/routes.rb')
      has_metrics_endpoint = false
      metrics_paths = []

      if routes_file.exist?
        routes_content = routes_file.read
        
        # Look for common metrics endpoints
        metrics_endpoints = %w[/metrics /health /status /prometheus]
        metrics_endpoints.each do |endpoint|
          if routes_content.include?(endpoint)
            has_metrics_endpoint = true
            metrics_paths << endpoint
          end
        end
      end

      {
        has_metrics_endpoint: has_metrics_endpoint,
        metrics_paths: metrics_paths
      }
    end

    # Validate distributed tracing implementation
    def validate_distributed_tracing
      errors = []
      warnings = []
      details = {
        tracing_libraries: detect_tracing_libraries,
        trace_instrumentation: analyze_trace_instrumentation,
        correlation_ids: check_correlation_id_usage,
        span_creation: analyze_span_creation_patterns
      }

      # Check for tracing setup
      if details[:tracing_libraries][:libraries].empty?
        warnings << "No distributed tracing libraries detected - consider adding for microservices debugging"
      end

      # Validate trace instrumentation
      if details[:trace_instrumentation][:instrumented_files] == 0
        warnings << "No manual trace instrumentation found - consider adding for critical paths"
      end

      { errors: errors, warnings: warnings, details: details }
    end

    # Detect distributed tracing libraries
    def detect_tracing_libraries
      gemfile_path = project_root.join('Gemfile')
      libraries = []

      if gemfile_path.exist?
        gemfile_content = gemfile_path.read
        tracing_gems = %w[
          jaeger-client zipkin-tracer opentelemetry-sdk
          elastic-apm datadog ddtrace newrelic_rpm
        ]
        
        libraries = tracing_gems.select { |gem| gemfile_content.include?(gem) }
      end

      {
        libraries: libraries,
        total_detected: libraries.length
      }
    end

    # Analyze trace instrumentation
    def analyze_trace_instrumentation
      ruby_files = find_ruby_files
      instrumented_files = 0
      instrumentation_patterns = []

      ruby_files.each do |file_path|
        content = File.read(file_path)
        relative_path = Pathname.new(file_path).relative_path_from(project_root).to_s
        
        # Look for tracing patterns
        trace_patterns = %w[
          span trace start_span with_span
          tracer Jaeger Zipkin OpenTelemetry
        ]
        
        found_patterns = trace_patterns.select { |pattern| content.include?(pattern) }
        
        if found_patterns.any?
          instrumented_files += 1
          instrumentation_patterns << {
            file: relative_path,
            patterns: found_patterns
          }
        end
      end

      {
        instrumented_files: instrumented_files,
        total_files_analyzed: ruby_files.length,
        instrumentation_coverage: ruby_files.empty? ? 0 : 
                                 (instrumented_files.to_f / ruby_files.length * 100).round(2),
        patterns_found: instrumentation_patterns
      }
    end

    # Check correlation ID usage
    def check_correlation_id_usage
      ruby_files = find_ruby_files
      correlation_usage = 0
      correlation_patterns = %w[
        correlation_id request_id trace_id
        x-correlation-id x-request-id x-trace-id
      ]

      ruby_files.each do |file_path|
        content = File.read(file_path)
        correlation_usage += correlation_patterns.sum { |pattern| content.scan(/#{pattern}/i).length }
      end

      {
        correlation_id_usage: correlation_usage,
        patterns_searched: correlation_patterns
      }
    end

    # Analyze span creation patterns
    def analyze_span_creation_patterns
      ruby_files = find_ruby_files
      span_patterns = []

      ruby_files.each do |file_path|
        content = File.read(file_path)
        
        # Look for manual span creation
        span_creations = content.scan(/(?:start_span|with_span)\s*\(['"]([^'"]*)['"]\)/).flatten
        
        if span_creations.any?
          span_patterns << {
            file: Pathname.new(file_path).relative_path_from(project_root).to_s,
            span_names: span_creations
          }
        end
      end

      {
        files_with_spans: span_patterns.length,
        span_patterns: span_patterns
      }
    end

    # Validate health monitoring setup
    def validate_health_monitoring
      errors = []
      warnings = []
      details = {
        health_check_endpoints: check_health_endpoints,
        dependency_checks: analyze_dependency_health_checks,
        readiness_probes: check_readiness_probes,
        liveness_probes: check_liveness_probes
      }

      # Check for basic health endpoints
      unless details[:health_check_endpoints][:has_health_endpoint]
        errors << "No health check endpoint found - required for container orchestration"
      end

      # Validate dependency checks
      if details[:dependency_checks][:dependency_checks_count] == 0
        warnings << "No dependency health checks found - consider monitoring external services"
      end

      { errors: errors, warnings: warnings, details: details }
    end

    # Check health check endpoints
    def check_health_endpoints
      routes_file = project_root.join('config/routes.rb')
      health_endpoints = []

      if routes_file.exist?
        routes_content = routes_file.read
        
        # Common health check patterns
        health_patterns = %w[/health /status /ping /ready /alive /healthcheck]
        health_endpoints = health_patterns.select { |pattern| routes_content.include?(pattern) }
      end

      # Check for health check controllers
      controller_files = Dir.glob(project_root.join('app/controllers/**/*health*.rb'))
      controller_files.concat(Dir.glob(project_root.join('app/controllers/**/*status*.rb')))

      {
        has_health_endpoint: health_endpoints.any? || controller_files.any?,
        health_endpoints: health_endpoints,
        health_controllers: controller_files.map { |f| File.basename(f) }
      }
    end

    # Analyze dependency health checks
    def analyze_dependency_health_checks
      ruby_files = find_ruby_files
      dependency_checks = []
      
      # Common dependency check patterns
      dependency_patterns = %w[
        database redis cache queue
        external_api third_party_service
        elasticsearch mongodb postgresql mysql
      ]

      ruby_files.each do |file_path|
        content = File.read(file_path)
        
        # Look for health check methods
        if content.match?(/def.*?health|def.*?status|def.*?check/)
          found_dependencies = dependency_patterns.select do |dep|
            content.downcase.include?(dep)
          end
          
          if found_dependencies.any?
            dependency_checks << {
              file: Pathname.new(file_path).relative_path_from(project_root).to_s,
              dependencies: found_dependencies
            }
          end
        end
      end

      {
        dependency_checks_count: dependency_checks.length,
        dependency_patterns: dependency_checks
      }
    end

    # Check readiness probes setup
    def check_readiness_probes
      # Look for Kubernetes readiness probe configuration
      k8s_files = Dir.glob(project_root.join('**/*.{yml,yaml}'))
      
      readiness_probe_configs = k8s_files.select do |file_path|
        content = File.read(file_path)
        content.include?('readinessProbe')
      end

      # Check application-level readiness logic
      ruby_files = find_ruby_files
      readiness_logic = ruby_files.any? do |file_path|
        content = File.read(file_path)
        content.match?(/ready\?|readiness|ready.*?check/i)
      end

      {
        kubernetes_readiness_configs: readiness_probe_configs.length,
        application_readiness_logic: readiness_logic
      }
    end

    # Check liveness probes setup
    def check_liveness_probes
      # Look for Kubernetes liveness probe configuration
      k8s_files = Dir.glob(project_root.join('**/*.{yml,yaml}'))
      
      liveness_probe_configs = k8s_files.select do |file_path|
        content = File.read(file_path)
        content.include?('livenessProbe')
      end

      # Check application-level liveness logic
      ruby_files = find_ruby_files
      liveness_logic = ruby_files.any? do |file_path|
        content = File.read(file_path)
        content.match?(/alive\?|liveness|live.*?check/i)
      end

      {
        kubernetes_liveness_configs: liveness_probe_configs.length,
        application_liveness_logic: liveness_logic
      }
    end

    # Validate error tracking implementation
    def validate_error_tracking
      errors = []
      warnings = []
      details = {
        error_tracking_services: detect_error_tracking_services,
        exception_handling: analyze_exception_handling_patterns,
        error_context: check_error_context_capture,
        error_alerts: validate_error_alerting
      }

      # Check for error tracking setup
      if details[:error_tracking_services][:services].empty?
        warnings << "No error tracking services detected - consider Sentry, Bugsnag, or similar"
      end

      # Validate exception context
      if details[:error_context][:context_capture_usage] == 0
        warnings << "No error context capture found - consider adding user/request context to errors"
      end

      { errors: errors, warnings: warnings, details: details }
    end

    # Detect error tracking services
    def detect_error_tracking_services
      gemfile_path = project_root.join('Gemfile')
      services = []

      if gemfile_path.exist?
        gemfile_content = gemfile_path.read
        error_tracking_gems = %w[
          sentry-ruby bugsnag rollbar airbrake
          exception_notification honeybadger
        ]
        
        services = error_tracking_gems.select { |gem| gemfile_content.include?(gem) }
      end

      # Check for service configuration
      config_files = find_configuration_files
      configured_services = []

      config_files.each do |file_path|
        content = File.read(file_path)
        error_services = %w[sentry bugsnag rollbar airbrake]
        
        error_services.each do |service|
          configured_services << service if content.downcase.include?(service)
        end
      end

      {
        services: services,
        configured_services: configured_services.uniq,
        total_services: (services + configured_services).uniq.length
      }
    end

    # Analyze exception handling patterns
    def analyze_exception_handling_patterns
      ruby_files = find_ruby_files
      exception_patterns = []

      ruby_files.each do |file_path|
        content = File.read(file_path)
        relative_path = Pathname.new(file_path).relative_path_from(project_root).to_s
        
        # Count exception handling patterns
        rescue_blocks = content.scan(/rescue\s+(\w+(?:::\w+)*)?/).length
        error_notifications = content.scan(/notify|report.*?error|capture.*?exception/i).length
        
        if rescue_blocks > 0 || error_notifications > 0
          exception_patterns << {
            file: relative_path,
            rescue_blocks: rescue_blocks,
            error_notifications: error_notifications
          }
        end
      end

      {
        files_with_exception_handling: exception_patterns.length,
        exception_patterns: exception_patterns,
        total_rescue_blocks: exception_patterns.sum { |p| p[:rescue_blocks] },
        total_error_notifications: exception_patterns.sum { |p| p[:error_notifications] }
      }
    end

    # Check error context capture
    def check_error_context_capture
      ruby_files = find_ruby_files
      context_usage = 0

      ruby_files.each do |file_path|
        content = File.read(file_path)
        
        # Look for error context patterns
        context_patterns = %w[
          extra user_id session_id request_id
          tags context fingerprint
        ]
        
        context_patterns.each do |pattern|
          context_usage += content.scan(/#{pattern}.*?error|error.*?#{pattern}/i).length
        end
      end

      {
        context_capture_usage: context_usage
      }
    end

    # Validate error alerting setup
    def validate_error_alerting
      config_files = find_configuration_files
      has_alerting = false

      config_files.each do |file_path|
        content = File.read(file_path)
        if content.match?(/alert|notification|webhook|email.*?error/i)
          has_alerting = true
          break
        end
      end

      {
        has_error_alerting: has_alerting
      }
    end

    # Validate performance monitoring
    def validate_performance_monitoring
      errors = []
      warnings = []
      details = {
        apm_tools: detect_apm_tools,
        performance_instrumentation: analyze_performance_instrumentation,
        database_monitoring: check_database_performance_monitoring,
        cache_monitoring: check_cache_performance_monitoring
      }

      # Check for APM tools
      if details[:apm_tools][:tools].empty?
        warnings << "No APM tools detected - consider New Relic, Datadog, or similar for performance monitoring"
      end

      { errors: errors, warnings: warnings, details: details }
    end

    # Detect APM (Application Performance Monitoring) tools
    def detect_apm_tools
      gemfile_path = project_root.join('Gemfile')
      tools = []

      if gemfile_path.exist?
        gemfile_content = gemfile_path.read
        apm_gems = %w[
          newrelic_rpm datadog scout_apm skylight
          elastic-apm appsignal
        ]
        
        tools = apm_gems.select { |gem| gemfile_content.include?(gem) }
      end

      {
        tools: tools,
        total_apm_tools: tools.length
      }
    end

    # Analyze performance instrumentation
    def analyze_performance_instrumentation
      ruby_files = find_ruby_files
      instrumentation_patterns = []

      ruby_files.each do |file_path|
        content = File.read(file_path)
        relative_path = Pathname.new(file_path).relative_path_from(project_root).to_s
        
        # Look for performance instrumentation
        perf_patterns = %w[
          benchmark measure time duration
          ActiveSupport::Notifications instrument
        ]
        
        found_patterns = perf_patterns.select { |pattern| content.downcase.include?(pattern.downcase) }
        
        if found_patterns.any?
          instrumentation_patterns << {
            file: relative_path,
            patterns: found_patterns
          }
        end
      end

      {
        instrumented_files: instrumentation_patterns.length,
        instrumentation_patterns: instrumentation_patterns
      }
    end

    # Check database performance monitoring
    def check_database_performance_monitoring
      config_files = find_configuration_files
      db_monitoring = false

      config_files.each do |file_path|
        content = File.read(file_path)
        if content.match?(/query.*?log|slow.*?query|database.*?log/i)
          db_monitoring = true
          break
        end
      end

      {
        has_database_monitoring: db_monitoring
      }
    end

    # Check cache performance monitoring
    def check_cache_performance_monitoring
      ruby_files = find_ruby_files
      cache_monitoring = 0

      ruby_files.each do |file_path|
        content = File.read(file_path)
        cache_monitoring += content.scan(/cache.*?hit|cache.*?miss|cache.*?performance/i).length
      end

      {
        cache_monitoring_usage: cache_monitoring
      }
    end

    # Validate alerting setup
    def validate_alerting_setup
      errors = []
      warnings = []
      details = {
        alerting_tools: detect_alerting_tools,
        alert_rules: analyze_alert_rules,
        notification_channels: check_notification_channels
      }

      # Check for alerting infrastructure
      if details[:alerting_tools][:tools].empty?
        warnings << "No alerting tools detected - consider setting up alerts for critical metrics"
      end

      { errors: errors, warnings: warnings, details: details }
    end

    # Detect alerting tools
    def detect_alerting_tools
      config_files = find_configuration_files
      tools = []

      config_files.each do |file_path|
        content = File.read(file_path)
        alerting_services = %w[
          pagerduty slack webhook email
          prometheus grafana datadog newrelic
        ]
        
        alerting_services.each do |service|
          tools << service if content.downcase.include?(service)
        end
      end

      {
        tools: tools.uniq,
        total_alerting_tools: tools.uniq.length
      }
    end

    # Analyze alert rules
    def analyze_alert_rules
      config_files = Dir.glob(project_root.join('**/*.{yml,yaml}'))
      alert_rules = []

      config_files.each do |file_path|
        content = File.read(file_path)
        
        if content.match?(alert|rule|threshold/i)
          alert_indicators = content.scan(/(?:error_rate|response_time|memory|cpu) > [\d.]+/i)
          if alert_indicators.any?
            alert_rules << {
              file: Pathname.new(file_path).relative_path_from(project_root).to_s,
              rules: alert_indicators
            }
          end
        end
      end

      {
        files_with_alert_rules: alert_rules.length,
        alert_rules: alert_rules
      }
    end

    # Check notification channels
    def check_notification_channels
      config_files = find_configuration_files
      channels = []

      config_files.each do |file_path|
        content = File.read(file_path)
        notification_types = %w[email slack webhook sms pagerduty]
        
        notification_types.each do |type|
          channels << type if content.downcase.include?(type)
        end
      end

      {
        notification_channels: channels.uniq,
        total_channels: channels.uniq.length
      }
    end

    # Validate dashboard configuration
    def validate_dashboard_configuration
      errors = []
      warnings = []
      details = {
        dashboard_tools: detect_dashboard_tools,
        dashboard_configs: find_dashboard_configurations,
        visualization_setup: check_visualization_setup
      }

      # Check for dashboard tools
      if details[:dashboard_tools][:tools].empty?
        warnings << "No dashboard tools detected - consider Grafana, Datadog, or similar for observability"
      end

      { errors: errors, warnings: warnings, details: details }
    end

    # Detect dashboard tools
    def detect_dashboard_tools
      config_files = find_configuration_files
      gemfile_path = project_root.join('Gemfile')
      tools = []

      # Check configuration files
      config_files.each do |file_path|
        content = File.read(file_path)
        dashboard_services = %w[grafana kibana datadog newrelic prometheus]
        
        dashboard_services.each do |service|
          tools << service if content.downcase.include?(service)
        end
      end

      # Check Gemfile for dashboard-related gems
      if gemfile_path.exist?
        gemfile_content = gemfile_path.read
        dashboard_gems = %w[grafana prometheus-client]
        tools.concat(dashboard_gems.select { |gem| gemfile_content.include?(gem) })
      end

      {
        tools: tools.uniq,
        total_dashboard_tools: tools.uniq.length
      }
    end

    # Find dashboard configuration files
    def find_dashboard_configurations
      dashboard_patterns = %w[
        **/*grafana*
        **/*dashboard*
        **/prometheus*
        **/*kibana*
      ]

      config_files = []
      dashboard_patterns.each do |pattern|
        config_files.concat(Dir.glob(project_root.join(pattern)))
      end

      config_files.map { |file| Pathname.new(file).relative_path_from(project_root).to_s }
    end

    # Check visualization setup
    def check_visualization_setup
      config_files = find_dashboard_configurations
      has_visualizations = false

      config_files.each do |file_path|
        full_path = project_root.join(file_path)
        next unless full_path.exist?

        content = full_path.read
        if content.match?(chart|graph|panel|widget|visualization/i)
          has_visualizations = true
          break
        end
      end

      {
        has_visualizations: has_visualizations,
        config_files_checked: config_files.length
      }
    end

    # Calculate overall observability score
    def calculate_observability_score(details)
      score = 100
      
      # Logging (20 points)
      logging_score = 0
      logging_score += 5 if details[:logging][:details][:logging_configuration][:has_custom_logging_config]
      logging_score += 5 if details[:logging][:details][:structured_logging][:structured_percentage] > 60
      logging_score += 5 if details[:logging][:details][:log_rotation][:has_log_rotation]
      logging_score += 5 if details[:logging][:details][:log_aggregation][:aggregation_gems].any?
      score -= (20 - logging_score)
      
      # Metrics (20 points)
      metrics_score = 0
      metrics_score += 10 if details[:metrics][:details][:metrics_libraries][:total_detected] > 0
      metrics_score += 5 if details[:metrics][:details][:custom_metrics][:custom_metrics_count] > 0
      metrics_score += 5 if details[:metrics][:details][:metrics_endpoints][:has_metrics_endpoint]
      score -= (20 - metrics_score)
      
      # Tracing (15 points)
      tracing_score = 0
      tracing_score += 10 if details[:tracing][:details][:tracing_libraries][:total_detected] > 0
      tracing_score += 5 if details[:tracing][:details][:trace_instrumentation][:instrumented_files] > 0
      score -= (15 - tracing_score)
      
      # Health checks (15 points)
      health_score = 0
      health_score += 10 if details[:health_checks][:details][:health_check_endpoints][:has_health_endpoint]
      health_score += 5 if details[:health_checks][:details][:dependency_checks][:dependency_checks_count] > 0
      score -= (15 - health_score)
      
      # Error tracking (15 points)
      error_score = 0
      error_score += 10 if details[:error_tracking][:details][:error_tracking_services][:total_services] > 0
      error_score += 5 if details[:error_tracking][:details][:error_context][:context_capture_usage] > 0
      score -= (15 - error_score)
      
      # Performance monitoring (10 points)
      perf_score = 0
      perf_score += 10 if details[:performance_monitoring][:details][:apm_tools][:total_apm_tools] > 0
      score -= (10 - perf_score)
      
      # Alerting (5 points)
      alert_score = 0
      alert_score += 5 if details[:alerting][:details][:alerting_tools][:total_alerting_tools] > 0
      score -= (5 - alert_score)

      [score, 0].max
    end
  end
end