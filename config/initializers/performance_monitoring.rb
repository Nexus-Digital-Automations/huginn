# frozen_string_literal: true

# Performance Monitoring System Initializer
# 
# This initializer sets up the comprehensive performance monitoring system for Huginn.
# It configures response time monitoring, resource monitoring, benchmarking, and 
# regression detection based on the configuration in config/performance_monitoring.yml.

require 'yaml'

# Only initialize in Rails application context
if defined?(Rails) && Rails.application
  
  # Load performance monitoring configuration
  config_file = Rails.root.join('config/performance_monitoring.yml')
  perf_config = {}
  
  if config_file.exist?
    full_config = YAML.load_file(config_file)
    perf_config = full_config[Rails.env] || full_config['default'] || {}
    Rails.logger.info "[PERFORMANCE] Loaded configuration for #{Rails.env} environment"
  else
    Rails.logger.warn "[PERFORMANCE] Configuration file not found: #{config_file}"
  end

  # Require performance monitoring components
  begin
    require 'performance_monitoring/response_monitor'
    require 'performance_monitoring/resource_monitor'
    require 'performance_monitoring/benchmark_system'
    require 'performance_monitoring/regression_detector'
    require 'performance_monitoring/middleware'
    
    Rails.logger.info "[PERFORMANCE] Performance monitoring components loaded successfully"
  rescue LoadError => e
    Rails.logger.error "[PERFORMANCE] Failed to load monitoring components: #{e.message}"
  end

  Rails.application.configure do
    
    # Configure Response Monitor
    if defined?(PerformanceMonitoring::ResponseMonitor)
      PerformanceMonitoring::ResponseMonitor.configure do |config|
        response_config = perf_config['response_monitor'] || {}
        
        config.default_threshold = response_config['default_threshold'] || 0.2
        config.sampling_rate = response_config['sampling_rate'] || 1.0
        config.enable_detailed_logging = response_config['enable_detailed_logging'] || Rails.env.development?
        config.metrics_storage = (response_config['metrics_storage'] || :memory).to_sym
        
        # Configure critical paths
        if response_config['critical_paths']
          config.critical_paths = {}
          response_config['critical_paths'].each do |path, path_config|
            config.critical_paths[path.to_s] = {
              threshold: path_config['threshold'],
              alert_level: (path_config['alert_level'] || :warning).to_sym,
              description: path_config['description']
            }
          end
          
          Rails.logger.info "[PERFORMANCE] Configured #{config.critical_paths.length} critical paths"
        end
        
        # Setup alert callback if configured
        alerting_config = perf_config['alerting'] || {}
        if alerting_config['enabled'] != false
          config.alert_callback = proc do |result, alert_level|
            message = "[PERF ALERT] #{alert_level.upcase}: #{result.path} exceeded threshold by #{result.threshold_excess_percentage}%"
            
            case alert_level
            when :critical, :error
              Rails.logger.error(message)
            when :warning
              Rails.logger.warn(message)
            else
              Rails.logger.info(message)
            end
            
            # TODO: Integrate with email/Slack/webhook alerting
            # This could be extended based on alerting_config settings
          end
        end
      end
      
      Rails.logger.info "[PERFORMANCE] Response monitor configured"
    end

    # Configure Benchmark System
    if defined?(PerformanceMonitoring::BenchmarkSystem)
      PerformanceMonitoring::BenchmarkSystem.configure do |config|
        benchmark_config = perf_config['benchmark_system'] || {}
        
        config.performance_degradation_threshold = benchmark_config['performance_degradation_threshold'] || 0.08
        config.critical_degradation_threshold = benchmark_config['critical_degradation_threshold'] || 0.20
        
        # Set file paths
        config.baseline_file = Rails.root.join(benchmark_config['baseline_file'] || 'config/performance_baseline.json')
        config.results_directory = Rails.root.join(benchmark_config['results_directory'] || 'development/reports/benchmarks')
        
        # Benchmark execution settings
        config.warmup_iterations = benchmark_config['warmup_iterations'] || 3
        config.benchmark_iterations = benchmark_config['benchmark_iterations'] || 10
        config.auto_update_baseline = benchmark_config['auto_update_baseline'] || false
        
        # Setup alert callback
        alerting_config = perf_config['alerting'] || {}
        if alerting_config['enabled'] != false
          config.alert_callback = proc do |result, alert_level|
            message = "[BENCHMARK ALERT] #{alert_level.upcase}: #{result.name} performance degraded by #{(result.degradation_percentage * 100).round(1)}%"
            
            case alert_level
            when :critical, :error
              Rails.logger.error(message)
            when :warning
              Rails.logger.warn(message)
            else
              Rails.logger.info(message)
            end
          end
        end
      end
      
      Rails.logger.info "[PERFORMANCE] Benchmark system configured"
    end

    # Configure Resource Monitor  
    if defined?(PerformanceMonitoring::ResourceMonitor)
      PerformanceMonitoring::ResourceMonitor.configure do |config|
        resource_config = perf_config['resource_monitor'] || {}
        
        # Threshold configuration
        config.memory_warning_threshold = resource_config['memory_warning_threshold'] || 75
        config.memory_critical_threshold = resource_config['memory_critical_threshold'] || 90
        config.cpu_warning_threshold = resource_config['cpu_warning_threshold'] || 80
        config.cpu_critical_threshold = resource_config['cpu_critical_threshold'] || 95
        config.gc_frequency_threshold = resource_config['gc_frequency_threshold'] || 50
        config.database_connection_threshold = resource_config['database_connection_threshold'] || 80
        
        # Monitoring settings
        config.monitoring_interval = resource_config['monitoring_interval'] || 60
        config.history_retention_days = resource_config['history_retention_days'] || 7
        
        # Storage configuration
        if resource_config['storage_directory']
          config.storage_directory = Rails.root.join(resource_config['storage_directory'])
        end
        
        # Setup alert callback
        alerting_config = perf_config['alerting'] || {}
        if alerting_config['enabled'] != false
          config.alert_callback = proc do |alert, snapshot|
            message = "[RESOURCE ALERT] #{alert[:level].upcase} #{alert[:type]}: #{alert[:value]}"
            
            case alert[:level]
            when :critical
              Rails.logger.error(message)
            when :warning
              Rails.logger.warn(message)
            else
              Rails.logger.info(message)
            end
          end
        end
      end
      
      Rails.logger.info "[PERFORMANCE] Resource monitor configured"
    end

    # Configure Regression Detector
    if defined?(PerformanceMonitoring::RegressionDetector)
      PerformanceMonitoring::RegressionDetector.configure do |config|
        regression_config = perf_config['regression_detector'] || {}
        
        # Regression detection thresholds
        config.regression_threshold = regression_config['regression_threshold'] || 0.08
        config.critical_regression_threshold = regression_config['critical_regression_threshold'] || 0.20
        config.improvement_threshold = regression_config['improvement_threshold'] || 0.05
        
        # Statistical analysis settings
        config.minimum_sample_size = regression_config['minimum_sample_size'] || 3
        config.confidence_level = regression_config['confidence_level'] || 0.90
        
        statistical_method = regression_config['statistical_test_method'] || 'welch_t_test'
        config.statistical_test_method = statistical_method.to_sym
        
        config.outlier_detection_enabled = regression_config['outlier_detection_enabled'] != false
        
        # Test execution settings
        config.warmup_runs = regression_config['warmup_runs'] || 2
        config.measurement_runs = regression_config['measurement_runs'] || 5
        
        # Storage paths
        if regression_config['baseline_storage_path']
          config.baseline_storage_path = Rails.root.join(regression_config['baseline_storage_path'])
        end
        
        if regression_config['results_storage_path']
          config.results_storage_path = Rails.root.join(regression_config['results_storage_path'])
        end
        
        # Ensure storage directories exist
        [config.baseline_storage_path, config.results_storage_path].each do |path|
          FileUtils.mkdir_p(path) if path && !path.exist?
        end
      end
      
      Rails.logger.info "[PERFORMANCE] Regression detector configured"
    end

    # Configure Middleware
    if defined?(PerformanceMonitoring::Middleware)
      PerformanceMonitoring::Middleware.configure do |config|
        response_config = perf_config['response_monitor'] || {}
        
        config.monitor_all_requests = response_config['monitor_all_requests'] != false
        config.skip_paths = response_config['skip_paths'] || ['/assets', '/health', '/ping', '/favicon.ico']
        
        # Critical paths for middleware monitoring
        if response_config['critical_paths']
          config.critical_controllers = []
          config.critical_actions = []
          
          response_config['critical_paths'].each do |path_name, path_config|
            # Extract controller/action patterns from path names
            if path_name.include?('_')
              parts = path_name.split('_')
              if parts.length >= 2
                controller = "#{parts.first.camelize}Controller"
                action = parts.last
                config.critical_controllers << controller unless config.critical_controllers.include?(controller)
                config.critical_actions << action unless config.critical_actions.include?(action)
              end
            end
          end
        end
        
        # SQL monitoring settings
        config.enable_sql_monitoring = response_config['enable_sql_monitoring'] != false
        config.enable_view_monitoring = response_config['enable_view_monitoring'] != false
        config.max_sql_queries_threshold = response_config['max_sql_queries_threshold'] || 50
        config.slow_query_threshold = response_config['slow_query_threshold'] || 0.1
        config.memory_tracking_enabled = response_config['memory_tracking_enabled'] != false
      end
      
      # Add middleware to Rails application
      config.middleware.use PerformanceMonitoring::Middleware
      Rails.logger.info "[PERFORMANCE] Middleware configured and added to stack"
    end
  end

  # Initialize monitoring on application startup
  Rails.application.config.after_initialize do
    
    # Create necessary directories
    directories_to_create = [
      'development/reports',
      'development/reports/benchmarks', 
      'development/reports/resource_monitoring',
      'development/reports/regression_detection',
      'config/performance_baselines'
    ]
    
    directories_to_create.each do |dir|
      path = Rails.root.join(dir)
      FileUtils.mkdir_p(path) unless path.exist?
    end
    
    # Start resource monitoring if configured
    resource_config = perf_config['resource_monitor'] || {}
    if resource_config['auto_start_monitoring'] && defined?(PerformanceMonitoring::ResourceMonitor)
      begin
        resource_monitor = PerformanceMonitoring::ResourceMonitor.new
        resource_monitor.start_monitoring
        Rails.logger.info "[PERFORMANCE] Auto-started resource monitoring"
      rescue StandardError => e
        Rails.logger.warn "[PERFORMANCE] Failed to auto-start resource monitoring: #{e.message}"
      end
    end
    
    # Log successful initialization
    Rails.logger.info "[PERFORMANCE] Performance monitoring system initialized successfully"
    Rails.logger.info "[PERFORMANCE] Available rake tasks:"
    Rails.logger.info "[PERFORMANCE]   rake performance:setup - Initialize performance monitoring"
    Rails.logger.info "[PERFORMANCE]   rake performance:status - Show monitoring status"
    Rails.logger.info "[PERFORMANCE]   rake performance:benchmark:run - Run performance benchmarks"
    Rails.logger.info "[PERFORMANCE]   rake performance:monitor:start - Start resource monitoring"
    Rails.logger.info "[PERFORMANCE]   rake performance:report - Generate performance report"
    
    # Log configuration summary
    if Rails.logger.level <= Logger::INFO
      config_summary = {
        response_monitoring: PerformanceMonitoring::ResponseMonitor.configuration.default_threshold,
        critical_paths: PerformanceMonitoring::ResponseMonitor.configuration.critical_paths&.length || 0,
        resource_monitoring_interval: PerformanceMonitoring::ResourceMonitor.configuration.monitoring_interval,
        benchmark_threshold: PerformanceMonitoring::BenchmarkSystem.configuration.performance_degradation_threshold,
        regression_threshold: PerformanceMonitoring::RegressionDetector.configuration.regression_threshold
      }
      
      Rails.logger.info "[PERFORMANCE] Configuration summary: #{config_summary}"
    end
  end

  # Handle graceful shutdown
  at_exit do
    # Stop any running resource monitoring
    if defined?(PerformanceMonitoring::ResourceMonitor) && PerformanceMonitoring::ResourceMonitor.instance_variable_defined?(:@instance)
      monitor_instance = PerformanceMonitoring::ResourceMonitor.instance_variable_get(:@instance)
      if monitor_instance&.monitoring_active?
        monitor_instance.stop_monitoring
        Rails.logger.info "[PERFORMANCE] Stopped resource monitoring on shutdown"
      end
    end
  end

else
  # Running outside of Rails context
  puts "Performance monitoring system requires Rails application context"
end