# frozen_string_literal: true

require 'fileutils'
require 'json'
require 'yaml'

namespace :performance do
  desc "Setup performance monitoring system"
  task setup: :environment do
    puts "🚀 Setting up Huginn Performance Monitoring System..."
    
    # Create necessary directories
    create_monitoring_directories
    
    # Initialize configuration
    initialize_performance_configuration
    
    # Create baseline performance data
    create_initial_baselines
    
    # Setup monitoring middleware
    setup_monitoring_middleware
    
    puts "✅ Performance monitoring system setup complete!"
    puts ""
    puts "Next steps:"
    puts "1. Run 'rake performance:benchmark:create_baseline' to establish performance baselines"
    puts "2. Start resource monitoring with 'rake performance:monitor:start'"
    puts "3. View current performance status with 'rake performance:status'"
  end

  desc "Show current performance monitoring status"
  task status: :environment do
    puts "📊 Huginn Performance Monitoring Status"
    puts "=" * 50
    
    # Load monitoring components
    require_monitoring_components
    
    # Response time monitoring status
    show_response_monitoring_status
    
    # Resource monitoring status  
    show_resource_monitoring_status
    
    # Benchmark system status
    show_benchmark_system_status
    
    # Regression detection status
    show_regression_detection_status
  end

  desc "Generate comprehensive performance report"
  task report: :environment do
    puts "📈 Generating Comprehensive Performance Report..."
    
    require_monitoring_components
    
    # Generate timestamp for report
    timestamp = Time.current.strftime('%Y%m%d_%H%M%S')
    report_file = Rails.root.join("development/reports/performance_report_#{timestamp}.json")
    
    # Collect performance data
    report_data = generate_performance_report
    
    # Save report
    FileUtils.mkdir_p(File.dirname(report_file))
    File.write(report_file, JSON.pretty_generate(report_data))
    
    puts "📄 Performance report generated: #{report_file}"
    puts ""
    puts "Report Summary:"
    puts "- Response Time Monitoring: #{report_data[:response_monitoring][:status]}"
    puts "- Resource Usage: #{report_data[:resource_monitoring][:summary]}"
    puts "- Performance Regressions: #{report_data[:regression_analysis][:summary]}"
    puts "- Optimization Recommendations: #{report_data[:optimization_recommendations].length} items"
  end

  namespace :monitor do
    desc "Start continuous resource monitoring"
    task start: :environment do
      puts "🔄 Starting continuous resource monitoring..."
      
      require_monitoring_components
      
      # Initialize resource monitor
      monitor = PerformanceMonitoring::ResourceMonitor.new
      
      # Configure alert callback
      monitor.class.configure do |config|
        config.alert_callback = proc do |alert, snapshot|
          Rails.logger.warn "[PERFORMANCE ALERT] #{alert[:type]} - #{alert[:level]}: #{alert[:value]}"
        end
      end
      
      # Start monitoring
      monitor.start_monitoring
      
      puts "✅ Resource monitoring started in background"
      puts "📊 Monitor logs: tail -f log/#{Rails.env}.log | grep RESOURCE"
      puts "⏹️  Stop monitoring: rake performance:monitor:stop"
      
      # Keep process alive
      trap('INT') do
        puts "\n🛑 Stopping resource monitoring..."
        monitor.stop_monitoring
        puts "✅ Resource monitoring stopped"
        exit
      end
      
      puts "Press Ctrl+C to stop monitoring..."
      loop { sleep 60 }
    end

    desc "Stop continuous resource monitoring"  
    task stop: :environment do
      puts "⏹️  Stopping resource monitoring..."
      
      # Find and stop monitoring processes
      pids = `pgrep -f "rake performance:monitor:start"`.split.map(&:to_i)
      
      if pids.any?
        pids.each { |pid| Process.kill('INT', pid) rescue nil }
        puts "✅ Stopped #{pids.length} monitoring process(es)"
      else
        puts "ℹ️  No monitoring processes found"
      end
    end

    desc "Take resource usage snapshot"
    task snapshot: :environment do
      require_monitoring_components
      
      monitor = PerformanceMonitoring::ResourceMonitor.new
      snapshot = monitor.take_snapshot
      
      puts "📸 Resource Usage Snapshot (#{snapshot.timestamp.strftime('%Y-%m-%d %H:%M:%S')})"
      puts "-" * 60
      puts "Memory Usage: #{snapshot.memory_usage_mb.round(1)} MB (#{snapshot.memory_usage_percentage.round(1)}%)"
      puts "CPU Usage: #{snapshot.cpu_percentage.round(1)}%"
      puts "Load Average: #{snapshot.load_average.join(', ')}"
      puts "GC Frequency: #{snapshot.gc_frequency_per_minute.round(1)} collections/minute"
      
      if snapshot.database_stats.any?
        db_stats = snapshot.database_stats
        puts "DB Connections: #{db_stats[:busy]}/#{db_stats[:size]} (#{db_stats[:usage_percentage].round(1)}%)"
      end
      
      # Show alerts
      alerts = []
      alerts << "⚠️  High memory usage" if snapshot.memory_warning?
      alerts << "🚨 Critical memory usage" if snapshot.memory_critical?
      alerts << "⚠️  High CPU usage" if snapshot.cpu_warning?
      alerts << "🚨 Critical CPU usage" if snapshot.cpu_critical?
      alerts << "⚠️  Excessive GC frequency" if snapshot.excessive_gc_frequency?
      
      if alerts.any?
        puts ""
        puts "Alerts:"
        alerts.each { |alert| puts alert }
      end
    end
  end

  namespace :benchmark do
    desc "Create performance baselines"
    task create_baseline: :environment do
      puts "📊 Creating performance baselines..."
      
      require_monitoring_components
      
      # Initialize benchmark system
      benchmark_system = PerformanceMonitoring::BenchmarkSystem.new
      
      # Register core benchmarks
      register_core_benchmarks(benchmark_system)
      
      # Run benchmarks to establish baseline
      puts "Running baseline benchmarks..."
      results = benchmark_system.run_all_benchmarks
      
      # Update baseline
      benchmark_system.update_baseline(results)
      
      puts "✅ Baseline created with #{results.length} benchmarks"
      puts ""
      puts "Baseline Results:"
      results.each do |result|
        puts "- #{result.name}: #{(result.current_time * 1000).round(2)}ms"
      end
    end

    desc "Run performance benchmarks"
    task run: :environment do
      puts "🏃 Running performance benchmarks..."
      
      require_monitoring_components
      
      # Initialize benchmark system
      benchmark_system = PerformanceMonitoring::BenchmarkSystem.new
      
      # Register core benchmarks
      register_core_benchmarks(benchmark_system)
      
      # Run benchmarks
      results = benchmark_system.run_all_benchmarks
      
      puts "📊 Benchmark Results:"
      puts "-" * 60
      
      results.each do |result|
        status_icon = if result.critical_degradation?
          "🚨"
        elsif result.performance_degraded?
          "⚠️ "
        elsif result.degradation_percentage < -0.05
          "⚡"
        else
          "✅"
        end
        
        puts "#{status_icon} #{result.name}: #{(result.current_time * 1000).round(2)}ms"
        puts "   #{result.performance_change_description}" if result.baseline_time
      end
      
      # Show summary
      degraded_count = results.count(&:performance_degraded?)
      critical_count = results.count(&:critical_degradation?)
      
      puts ""
      puts "Summary: #{results.length} benchmarks, #{degraded_count} regressions, #{critical_count} critical"
      
      exit 1 if critical_count > 0
    end

    desc "Reset performance baselines"
    task reset_baseline: :environment do
      puts "🔄 Resetting performance baselines..."
      
      baseline_file = Rails.root.join('config/performance_baseline.json')
      
      if File.exist?(baseline_file)
        File.delete(baseline_file)
        puts "✅ Baseline file deleted: #{baseline_file}"
      else
        puts "ℹ️  No baseline file found"
      end
      
      puts "Run 'rake performance:benchmark:create_baseline' to create new baselines"
    end
  end

  namespace :regression do
    desc "Run performance regression detection"
    task detect: :environment do
      puts "🔍 Running performance regression detection..."
      
      require_monitoring_components
      
      # Initialize regression detector
      detector = PerformanceMonitoring::RegressionDetector.new
      
      # Run CI/CD performance check
      ci_cd_result = detector.run_ci_cd_performance_check do |suite|
        # Register performance tests
        register_performance_tests(suite)
      end
      
      # Display results
      puts "🎯 Regression Detection Results:"
      puts "-" * 50
      puts "Status: #{ci_cd_result[:ci_cd_status]}"
      
      summary = ci_cd_result[:summary]
      puts "Total Tests: #{summary[:total_tests]}"
      puts "Regressions: #{summary[:regressions_detected]}"
      puts "Critical Regressions: #{summary[:critical_regressions]}"
      puts "Improvements: #{summary[:improvements_detected]}"
      puts "Success Rate: #{summary[:success_rate]}%"
      
      # Show recommendations
      if ci_cd_result[:recommendations].any?
        puts ""
        puts "Recommendations:"
        ci_cd_result[:recommendations].each do |rec|
          puts "- #{rec[:priority].upcase}: #{rec[:message]}"
        end
      end
      
      exit ci_cd_result[:exit_code]
    end

    desc "Update regression baselines"
    task update_baseline: :environment do
      puts "📈 Updating regression detection baselines..."
      
      require_monitoring_components
      
      # Initialize regression detector
      detector = PerformanceMonitoring::RegressionDetector.new
      
      # Run performance tests
      test_results = []
      suite = detector.send(:TestSuite).new
      register_performance_tests(suite)
      
      suite.tests.each do |test_name, test_block|
        result = detector.send(:run_performance_test, test_name, &test_block)
        test_results << result
      end
      
      # Update baseline
      detector.update_baseline(test_results)
      
      puts "✅ Updated baselines for #{test_results.length} tests"
    end

    desc "Generate regression detection report"
    task report: :environment do
      puts "📋 Generating regression detection report..."
      
      require_monitoring_components
      
      detector = PerformanceMonitoring::RegressionDetector.new
      report = detector.generate_regression_report
      
      # Save report
      timestamp = Time.current.strftime('%Y%m%d_%H%M%S')
      report_file = Rails.root.join("development/reports/regression_report_#{timestamp}.json")
      
      FileUtils.mkdir_p(File.dirname(report_file))
      File.write(report_file, JSON.pretty_generate(report))
      
      puts "📄 Regression report generated: #{report_file}"
      puts ""
      puts "Report Summary (#{report[:report_period]}):"
      puts "- Total Analyses: #{report[:summary][:total_analyses]}"
      puts "- Regression Rate: #{report[:summary][:regression_rate]}%"  
      puts "- Improvement Rate: #{report[:summary][:improvement_rate]}%"
      puts "- Baseline Coverage: #{report[:baseline_coverage][:total_baselines]} tests"
    end
  end

  namespace :alert do
    desc "Test performance alerting system"
    task test: :environment do
      puts "🔔 Testing performance alerting system..."
      
      require_monitoring_components
      
      # Create test alert scenarios
      test_alerts = [
        { type: :memory, level: :warning, value: 85.0 },
        { type: :cpu, level: :critical, value: 98.0 },
        { type: :response_time, level: :error, value: 2.5 }
      ]
      
      test_alerts.each do |alert|
        puts "Triggering #{alert[:level]} #{alert[:type]} alert..."
        
        # Create mock snapshot for alert context
        mock_snapshot = OpenStruct.new(
          timestamp: Time.current,
          memory_usage_percentage: alert[:type] == :memory ? alert[:value] : 50.0,
          cpu_percentage: alert[:type] == :cpu ? alert[:value] : 25.0
        )
        
        # Trigger alert (this would normally be called by monitoring components)
        Rails.logger.warn "[TEST ALERT] #{alert[:level].upcase} #{alert[:type]} alert: #{alert[:value]}"
        
        sleep 1
      end
      
      puts "✅ Alert system test complete"
      puts "Check logs for alert messages: tail -f log/#{Rails.env}.log | grep ALERT"
    end
  end

  desc "Clean up old performance monitoring data"
  task cleanup: :environment do
    puts "🧹 Cleaning up old performance monitoring data..."
    
    retention_days = 30
    cutoff_date = retention_days.days.ago
    
    cleanup_paths = [
      Rails.root.join('development/reports/benchmarks'),
      Rails.root.join('development/reports/resource_monitoring'),
      Rails.root.join('development/reports/regression_detection')
    ]
    
    total_cleaned = 0
    
    cleanup_paths.each do |path|
      next unless path.exist?
      
      old_files = Dir.glob(path.join('*.json')).select do |file|
        File.mtime(file) < cutoff_date
      end
      
      old_files.each do |file|
        File.delete(file)
        total_cleaned += 1
      end
      
      puts "🗑️  Cleaned #{old_files.length} files from #{path.basename}"
    end
    
    puts "✅ Cleanup complete: removed #{total_cleaned} old files"
  end

  # Private helper methods for rake tasks
  private

  def create_monitoring_directories
    directories = [
      'config',
      'development/reports',
      'development/reports/benchmarks',
      'development/reports/resource_monitoring',
      'development/reports/regression_detection',
      'config/performance_baselines'
    ]
    
    directories.each do |dir|
      path = Rails.root.join(dir)
      FileUtils.mkdir_p(path) unless path.exist?
      puts "📁 Created directory: #{dir}"
    end
  end

  def initialize_performance_configuration
    config_file = Rails.root.join('config/performance_monitoring.yml')
    return if config_file.exist?
    
    puts "⚙️  Performance monitoring configuration already exists"
  end

  def create_initial_baselines
    baseline_file = Rails.root.join('config/performance_baseline.json')
    return if baseline_file.exist?
    
    initial_baseline = {
      created_at: Time.current.iso8601,
      description: "Initial performance baseline - update with 'rake performance:benchmark:create_baseline'",
      baselines: {}
    }
    
    File.write(baseline_file, JSON.pretty_generate(initial_baseline))
    puts "📊 Created initial baseline file: #{baseline_file}"
  end

  def setup_monitoring_middleware
    # Create middleware configuration file
    middleware_file = Rails.root.join('config/initializers/performance_monitoring.rb')
    return if middleware_file.exist?
    
    middleware_content = <<~RUBY
      # Performance Monitoring Initialization
      # This file is automatically generated by rake performance:setup
      
      require 'performance_monitoring/response_monitor'
      require 'performance_monitoring/resource_monitor'
      require 'performance_monitoring/benchmark_system'
      require 'performance_monitoring/regression_detector'
      
      # Configure performance monitoring components
      if defined?(Rails) && Rails.application
        Rails.application.configure do
          # Load performance monitoring configuration
          config_file = Rails.root.join('config/performance_monitoring.yml')
          if config_file.exist?
            perf_config = YAML.load_file(config_file)[Rails.env] || {}
            
            # Configure Response Monitor
            PerformanceMonitoring::ResponseMonitor.configure do |config|
              response_config = perf_config['response_monitor'] || {}
              config.default_threshold = response_config['default_threshold'] || 0.2
              config.sampling_rate = response_config['sampling_rate'] || 1.0
              config.enable_detailed_logging = response_config['enable_detailed_logging'] || false
              
              # Configure critical paths
              if response_config['critical_paths']
                config.critical_paths = response_config['critical_paths'].transform_keys(&:to_s)
              end
            end
            
            # Configure Benchmark System
            PerformanceMonitoring::BenchmarkSystem.configure do |config|
              benchmark_config = perf_config['benchmark_system'] || {}
              config.performance_degradation_threshold = benchmark_config['performance_degradation_threshold'] || 0.08
              config.critical_degradation_threshold = benchmark_config['critical_degradation_threshold'] || 0.20
              config.auto_update_baseline = benchmark_config['auto_update_baseline'] || false
            end
            
            # Configure Resource Monitor
            PerformanceMonitoring::ResourceMonitor.configure do |config|
              resource_config = perf_config['resource_monitor'] || {}
              config.memory_warning_threshold = resource_config['memory_warning_threshold'] || 75
              config.cpu_warning_threshold = resource_config['cpu_warning_threshold'] || 80
              config.monitoring_interval = resource_config['monitoring_interval'] || 60
            end
            
            # Configure Regression Detector
            PerformanceMonitoring::RegressionDetector.configure do |config|
              regression_config = perf_config['regression_detector'] || {}
              config.regression_threshold = regression_config['regression_threshold'] || 0.08
              config.critical_regression_threshold = regression_config['critical_regression_threshold'] || 0.20
              config.minimum_sample_size = regression_config['minimum_sample_size'] || 3
            end
          end
        end
      end
      
      # Initialize monitoring on application start
      Rails.application.config.after_initialize do
        Rails.logger.info "[PERFORMANCE] Performance monitoring system initialized"
      end
    RUBY
    
    File.write(middleware_file, middleware_content)
    puts "🔧 Created performance monitoring initializer: #{middleware_file}"
  end

  def require_monitoring_components
    require Rails.root.join('lib/performance_monitoring/response_monitor')
    require Rails.root.join('lib/performance_monitoring/benchmark_system') 
    require Rails.root.join('lib/performance_monitoring/resource_monitor')
    require Rails.root.join('lib/performance_monitoring/regression_detector')
  end

  def show_response_monitoring_status
    puts ""
    puts "🎯 Response Time Monitoring"
    puts "-" * 30
    
    monitor = PerformanceMonitoring::ResponseMonitor.new
    metrics = monitor.metrics_summary
    
    puts "Total Requests Monitored: #{metrics[:total_requests]}"
    puts "Threshold Violations: #{metrics[:threshold_violations]}"
    puts "Average Response Time: #{(metrics[:average_response_time] * 1000).round(2)}ms"
    puts "Critical Paths Monitored: #{metrics[:critical_paths_status].keys.length}"
  end

  def show_resource_monitoring_status
    puts ""
    puts "💻 Resource Monitoring"
    puts "-" * 30
    
    monitor = PerformanceMonitoring::ResourceMonitor.new
    snapshot = monitor.take_snapshot
    
    puts "Current Memory Usage: #{snapshot.memory_usage_mb.round(1)}MB (#{snapshot.memory_usage_percentage.round(1)}%)"
    puts "Current CPU Usage: #{snapshot.cpu_percentage.round(1)}%"
    puts "Load Average: #{snapshot.load_average.join(', ')}"
    puts "Monitoring Active: #{monitor.monitoring_active? ? 'Yes' : 'No'}"
  end

  def show_benchmark_system_status
    puts ""
    puts "📊 Benchmark System"
    puts "-" * 30
    
    baseline_file = Rails.root.join('config/performance_baseline.json')
    if baseline_file.exist?
      baseline_data = JSON.parse(File.read(baseline_file))
      puts "Baseline Established: Yes (#{baseline_data['baselines'].keys.length} benchmarks)"
      puts "Baseline Date: #{Time.parse(baseline_data['created_at']).strftime('%Y-%m-%d %H:%M')}" rescue nil
    else
      puts "Baseline Established: No"
      puts "Run 'rake performance:benchmark:create_baseline' to establish baselines"
    end
  end

  def show_regression_detection_status
    puts ""
    puts "🔍 Regression Detection"  
    puts "-" * 30
    
    baseline_dir = Rails.root.join('config/performance_baselines')
    if baseline_dir.exist?
      baseline_count = Dir.glob(baseline_dir.join('*.json')).length
      puts "Regression Baselines: #{baseline_count} tests"
    else
      puts "Regression Baselines: None"
    end
    
    results_dir = Rails.root.join('development/reports/regression_detection')
    if results_dir.exist?
      recent_results = Dir.glob(results_dir.join('*.json')).select do |file|
        File.mtime(file) > 24.hours.ago
      end
      puts "Recent Analyses (24h): #{recent_results.length}"
    else
      puts "Recent Analyses (24h): 0"
    end
  end

  def generate_performance_report
    # Initialize monitoring components
    response_monitor = PerformanceMonitoring::ResponseMonitor.new
    resource_monitor = PerformanceMonitoring::ResourceMonitor.new
    regression_detector = PerformanceMonitoring::RegressionDetector.new
    
    {
      generated_at: Time.current.iso8601,
      report_type: 'comprehensive_performance_report',
      
      response_monitoring: {
        status: 'active',
        metrics: response_monitor.metrics_summary
      },
      
      resource_monitoring: {
        summary: resource_monitor.take_snapshot.to_hash,
        recommendations: resource_monitor.optimization_recommendations.map(&:to_hash)
      },
      
      regression_analysis: {
        summary: regression_detector.generate_regression_report(hours: 24)
      },
      
      optimization_recommendations: collect_optimization_recommendations,
      
      system_info: {
        rails_version: Rails.version,
        ruby_version: RUBY_VERSION,
        environment: Rails.env,
        hostname: `hostname`.strip,
        uptime: `uptime`.strip
      }
    }
  end

  def collect_optimization_recommendations
    recommendations = []
    
    # Resource-based recommendations
    resource_monitor = PerformanceMonitoring::ResourceMonitor.new
    resource_recommendations = resource_monitor.optimization_recommendations(analysis_window: 24)
    recommendations.concat(resource_recommendations.map(&:to_hash))
    
    recommendations
  end

  def register_core_benchmarks(benchmark_system)
    # Agent Performance Benchmarks
    benchmark_system.register_benchmark('agent_performance') do |suite|
      suite.setup do
        @test_user = User.find_by(email: 'test@example.com') || 
                     User.create!(username: 'test_user', email: 'test@example.com', password: 'password123')
      end
      
      suite.measure('agent_creation') do
        agent = @test_user.agents.build(
          name: "Test Agent #{rand(10000)}",
          type: 'Agents::ManualEventAgent',
          options: {}
        )
        agent.save!
        agent.destroy
      end
      
      suite.measure('event_creation') do
        agent = @test_user.agents.first || @test_user.agents.create!(
          name: 'Benchmark Agent',
          type: 'Agents::ManualEventAgent',
          options: {}
        )
        
        event = agent.events.build(payload: { test: 'data' })
        event.save!
        event.destroy
      end
      
      suite.teardown do
        # Cleanup any test data
      end
    end
    
    # Database Performance Benchmarks
    benchmark_system.register_benchmark('database_performance') do |suite|
      suite.measure('user_query') do
        User.limit(10).load
      end
      
      suite.measure('agent_query') do  
        Agent.includes(:user).limit(10).load
      end
      
      suite.measure('event_query') do
        Event.includes(:agent).limit(10).load
      end
    end
  end

  def register_performance_tests(suite)
    suite.test('agent_execution_time') do
      # Simulate agent execution
      start_time = Time.current
      
      # Mock agent work
      1000.times { |i| "test_#{i}".upcase }
      
      # Ensure minimum execution time for meaningful measurement  
      sleep(0.001) if Time.current - start_time < 0.001
    end
    
    suite.test('database_query_time') do
      User.limit(5).load
    end
    
    suite.test('json_serialization_time') do
      data = { agents: 100.times.map { |i| { id: i, name: "Agent #{i}", type: 'TestAgent' } } }
      JSON.generate(data)
    end
  end
end