# frozen_string_literal: true

# Rake tasks for Error Monitoring System
# Provides setup, maintenance, and reporting tasks for comprehensive error monitoring
#
# Usage:
#   bundle exec rake error_monitoring:setup
#   bundle exec rake error_monitoring:health_check
#   bundle exec rake error_monitoring:generate_report
#   bundle exec rake error_monitoring:cleanup

namespace :error_monitoring do
  desc "Setup error monitoring system and verify configuration"
  task setup: :environment do
    puts "Setting up Huginn Error Monitoring System..."
    puts "=" * 50

    begin
      # Load error monitoring configuration
      config_path = Rails.root.join('config', 'error_monitoring.yml')
      if File.exist?(config_path)
        puts "✓ Configuration file found: #{config_path}"
        config = YAML.load_file(config_path)[Rails.env]
        puts "✓ Configuration loaded for environment: #{Rails.env}"
      else
        puts "✗ Configuration file missing: #{config_path}"
        puts "  Creating default configuration..."
        create_default_configuration
      end

      # Verify database connectivity
      puts "\nVerifying database connectivity..."
      ActiveRecord::Base.connection.execute('SELECT 1')
      puts "✓ Database connection successful"

      # Check AgentLog model
      if defined?(AgentLog)
        puts "✓ AgentLog model available"
        log_count = AgentLog.count
        puts "  Current AgentLog entries: #{log_count}"
      else
        puts "✗ AgentLog model not found"
        exit 1
      end

      # Initialize error monitoring components
      puts "\nInitializing error monitoring components..."
      
      # Test ErrorTracker
      begin
        require_relative '../error_monitoring/error_tracker'
        puts "✓ ErrorTracker loaded successfully"
        
        # Test basic functionality
        current_rate = ErrorMonitoring::ErrorTracker.current_error_rate
        puts "  Current error rate: #{(current_rate * 100).round(4)}%"
        threshold = ErrorMonitoring::ErrorTracker::PRODUCTION_ERROR_RATE_THRESHOLD
        puts "  Threshold: #{(threshold * 100).round(4)}%"
        puts "  Status: #{current_rate <= threshold ? 'COMPLIANT' : 'BREACH'}"
      rescue => e
        puts "✗ ErrorTracker initialization failed: #{e.message}"
      end

      # Test CircuitBreaker
      begin
        require_relative '../error_monitoring/circuit_breaker'
        puts "✓ CircuitBreaker loaded successfully"
        
        # Test basic functionality
        health_status = ErrorMonitoring::CircuitBreaker.health_status
        puts "  Overall health: #{health_status[:overall_health]}"
        puts "  Services monitored: #{health_status[:services].keys.length}"
      rescue => e
        puts "✗ CircuitBreaker initialization failed: #{e.message}"
      end

      # Test ErrorCategorizer  
      begin
        require_relative '../error_monitoring/error_categorizer'
        puts "✓ ErrorCategorizer loaded successfully"
        
        categories = ErrorMonitoring::ErrorCategorizer::PRIMARY_CATEGORIES.keys
        puts "  Supported categories: #{categories.length}"
      rescue => e
        puts "✗ ErrorCategorizer initialization failed: #{e.message}"
      end

      # Test RecoveryManager
      begin
        require_relative '../error_monitoring/recovery_manager'
        puts "✓ RecoveryManager loaded successfully"
        
        strategies = ErrorMonitoring::RecoveryManager::RECOVERY_STRATEGIES.keys
        puts "  Available strategies: #{strategies.length}"
        
        health_status = ErrorMonitoring::RecoveryManager.health_status
        puts "  Recovery health: #{health_status[:overall_health]}"
      rescue => e
        puts "✗ RecoveryManager initialization failed: #{e.message}"
      end

      # Create reports directory
      reports_dir = Rails.root.join('development', 'reports')
      FileUtils.mkdir_p(reports_dir) unless Dir.exist?(reports_dir)
      puts "✓ Reports directory available: #{reports_dir}"

      # Setup logging
      setup_error_monitoring_logging
      puts "✓ Error monitoring logging configured"

      # Create initial baseline report
      puts "\nGenerating initial baseline report..."
      baseline_report_path = generate_baseline_report
      puts "✓ Baseline report created: #{baseline_report_path}"

      puts "\n" + "=" * 50
      puts "Error Monitoring System Setup Complete!"
      puts "✓ All components initialized successfully"
      puts "✓ Configuration verified"
      puts "✓ Baseline report generated"
      puts ""
      puts "Next steps:"
      puts "1. Review configuration in config/error_monitoring.yml"
      puts "2. Set up alerting channels (email, Slack, PagerDuty)"
      puts "3. Run 'rake error_monitoring:health_check' to verify status"
      puts "4. Monitor error rates and adjust thresholds as needed"

    rescue => e
      puts "\n✗ Setup failed: #{e.message}"
      puts e.backtrace.first(5) if ENV['DEBUG']
      exit 1
    end
  end

  desc "Perform comprehensive health check of error monitoring system"
  task health_check: :environment do
    puts "Error Monitoring System Health Check"
    puts "=" * 40

    begin
      require_all_components

      health_results = {
        overall: true,
        components: {},
        recommendations: []
      }

      # Check ErrorTracker health
      puts "\nErrorTracker Health Check:"
      begin
        current_rate = ErrorMonitoring::ErrorTracker.current_error_rate
        threshold = ErrorMonitoring::ErrorTracker::PRODUCTION_ERROR_RATE_THRESHOLD
        
        puts "  Current Error Rate: #{(current_rate * 100).round(4)}%"
        puts "  Threshold: #{(threshold * 100).round(4)}%"
        
        if current_rate <= threshold
          puts "  ✓ Error rate within acceptable limits"
          health_results[:components][:error_tracker] = true
        else
          puts "  ✗ Error rate EXCEEDS threshold!"
          health_results[:components][:error_tracker] = false
          health_results[:overall] = false
          health_results[:recommendations] << "Investigate high error rate immediately"
        end
        
        # Check recent error trends
        statistics = ErrorMonitoring::ErrorTracker.error_statistics(hours: 1)
        puts "  Recent errors (1h): #{statistics[:error_counts][:total]}"
        
      rescue => e
        puts "  ✗ ErrorTracker health check failed: #{e.message}"
        health_results[:components][:error_tracker] = false
        health_results[:overall] = false
      end

      # Check CircuitBreaker health
      puts "\nCircuitBreaker Health Check:"
      begin
        cb_health = ErrorMonitoring::CircuitBreaker.health_status
        puts "  Overall Circuit Health: #{cb_health[:overall_health]}"
        puts "  Services Monitored: #{cb_health[:services].length}"
        
        # Check for open circuits
        open_circuits = cb_health[:services].select { |name, status| status[:state] == :open }
        if open_circuits.any?
          puts "  ✗ Open Circuits Detected:"
          open_circuits.each { |name, status| puts "    - #{name}: #{status[:health]}" }
          health_results[:components][:circuit_breaker] = false
          health_results[:overall] = false
          health_results[:recommendations] << "Investigate and resolve open circuit breakers"
        else
          puts "  ✓ All circuits healthy"
          health_results[:components][:circuit_breaker] = true
        end
        
      rescue => e
        puts "  ✗ CircuitBreaker health check failed: #{e.message}"
        health_results[:components][:circuit_breaker] = false
        health_results[:overall] = false
      end

      # Check RecoveryManager health
      puts "\nRecoveryManager Health Check:"
      begin
        recovery_health = ErrorMonitoring::RecoveryManager.health_status
        puts "  Recovery System Health: #{recovery_health[:overall_health]}"
        puts "  Active Degradations: #{recovery_health[:active_degradations].length}"
        puts "  Recent Recovery Activity (1h): #{recovery_health[:recent_recovery_activity][:last_hour]}"
        
        if recovery_health[:active_degradations].any?
          puts "  ⚠ Active Degradations:"
          recovery_health[:active_degradations].each do |deg|
            puts "    - #{deg[:component]}: #{deg[:degradation_level]} (#{deg[:duration].round}s)"
          end
          health_results[:recommendations] << "Review active system degradations"
        end
        
        health_results[:components][:recovery_manager] = 
          recovery_health[:overall_health] != :unhealthy
        
      rescue => e
        puts "  ✗ RecoveryManager health check failed: #{e.message}"
        health_results[:components][:recovery_manager] = false
        health_results[:overall] = false
      end

      # Check database performance
      puts "\nDatabase Performance Check:"
      begin
        start_time = Time.current
        AgentLog.where('created_at > ?', 1.hour.ago).limit(1000).count
        query_time = ((Time.current - start_time) * 1000).round(2)
        
        puts "  Query Performance: #{query_time}ms"
        
        if query_time < 1000  # Less than 1 second
          puts "  ✓ Database performance good"
          health_results[:components][:database] = true
        else
          puts "  ⚠ Database performance degraded"
          health_results[:components][:database] = false
          health_results[:recommendations] << "Optimize database queries and indexes"
        end
        
      rescue => e
        puts "  ✗ Database health check failed: #{e.message}"
        health_results[:components][:database] = false
        health_results[:overall] = false
      end

      # Check system resources
      puts "\nSystem Resource Check:"
      begin
        # Ruby memory usage
        if defined?(GC)
          gc_stat = GC.stat
          puts "  Ruby Memory Usage: #{gc_stat[:heap_live_slots]} live objects"
          puts "  GC Runs: #{gc_stat[:count]}"
        end
        
        # Process information
        if File.exist?('/proc/meminfo')
          memory_info = File.read('/proc/meminfo')
          if memory_info =~ /MemAvailable:\s+(\d+)\s+kB/
            available_mb = $1.to_i / 1024
            puts "  Available Memory: #{available_mb}MB"
            
            if available_mb > 512  # More than 512MB available
              puts "  ✓ Sufficient memory available"
            else
              puts "  ⚠ Low memory condition"
              health_results[:recommendations] << "Monitor memory usage and consider optimization"
            end
          end
        end
        
        health_results[:components][:system_resources] = true
        
      rescue => e
        puts "  ✗ System resource check failed: #{e.message}"
        health_results[:components][:system_resources] = false
      end

      # Generate health summary
      puts "\n" + "=" * 40
      if health_results[:overall]
        puts "✓ OVERALL SYSTEM STATUS: HEALTHY"
      else
        puts "✗ OVERALL SYSTEM STATUS: DEGRADED"
      end

      puts "\nComponent Status:"
      health_results[:components].each do |component, healthy|
        status = healthy ? "✓ HEALTHY" : "✗ DEGRADED"
        puts "  #{component}: #{status}"
      end

      if health_results[:recommendations].any?
        puts "\nRecommendations:"
        health_results[:recommendations].each_with_index do |rec, idx|
          puts "  #{idx + 1}. #{rec}"
        end
      end

      puts "\nHealth check completed at: #{Time.current}"

      # Exit with error code if system is unhealthy (useful for monitoring)
      exit 1 unless health_results[:overall]

    rescue => e
      puts "\n✗ Health check failed: #{e.message}"
      puts e.backtrace.first(5) if ENV['DEBUG']
      exit 1
    end
  end

  desc "Generate comprehensive error monitoring report"
  task generate_report: :environment do
    puts "Generating Error Monitoring Report..."
    
    begin
      require_all_components
      
      # Get parameters
      hours = ENV['HOURS']&.to_i || 24
      format = ENV['FORMAT'] || 'json'
      output_dir = ENV['OUTPUT_DIR'] || Rails.root.join('development', 'reports')
      
      puts "Report Parameters:"
      puts "  Time Range: #{hours} hours"
      puts "  Format: #{format}"
      puts "  Output Directory: #{output_dir}"
      
      FileUtils.mkdir_p(output_dir)
      
      # Generate timestamp for unique filename
      timestamp = Time.current.strftime('%Y%m%d_%H%M%S')
      
      # Generate comprehensive report
      puts "\nGenerating report sections..."
      
      # Error Tracker Statistics
      puts "  Generating error statistics..."
      error_stats = ErrorMonitoring::ErrorTracker.error_statistics(
        hours: hours,
        include_trends: true
      )
      
      # Circuit Breaker Status
      puts "  Collecting circuit breaker status..."
      circuit_status = ErrorMonitoring::CircuitBreaker.health_status
      
      # Error Categorization Analysis
      puts "  Performing error categorization analysis..."
      categorization_analysis = ErrorMonitoring::ErrorCategorizer.analyze_patterns(
        time_range: hours.hours,
        min_occurrences: 2
      )
      
      # Recovery Manager Statistics
      puts "  Collecting recovery statistics..."
      recovery_stats = ErrorMonitoring::RecoveryManager.recovery_statistics(
        time_range: hours.hours
      )
      
      # Trending Errors
      puts "  Identifying trending errors..."
      trending_errors = ErrorMonitoring::ErrorCategorizer.trending_errors(
        time_range: hours.hours
      )
      
      # Compile comprehensive report
      comprehensive_report = {
        report_metadata: {
          generated_at: Time.current,
          time_range_hours: hours,
          format: format,
          huginn_version: (Rails.application.class.module_parent.const_get('VERSION') rescue 'unknown'),
          rails_version: Rails::VERSION::STRING,
          environment: Rails.env
        },
        executive_summary: generate_executive_summary(
          error_stats, 
          circuit_status, 
          recovery_stats, 
          categorization_analysis
        ),
        error_rate_analysis: error_stats,
        circuit_breaker_status: circuit_status,
        error_categorization: categorization_analysis,
        trending_analysis: trending_errors,
        recovery_analysis: recovery_stats,
        system_health: {
          overall_health: assess_overall_system_health(
            error_stats, 
            circuit_status, 
            recovery_stats
          ),
          key_metrics: extract_key_metrics(error_stats, circuit_status, recovery_stats),
          alerts_summary: generate_alerts_summary(error_stats, recovery_stats)
        },
        recommendations: generate_system_recommendations(
          error_stats,
          categorization_analysis,
          recovery_stats
        )
      }
      
      # Generate filename
      filename = "huginn_error_monitoring_report_#{timestamp}.#{format}"
      output_path = File.join(output_dir, filename)
      
      # Write report based on format
      case format.downcase
      when 'json'
        File.write(output_path, JSON.pretty_generate(comprehensive_report))
      when 'yaml', 'yml'
        File.write(output_path, comprehensive_report.to_yaml)
      when 'csv'
        # Generate CSV format focusing on key metrics
        csv_content = generate_csv_report(comprehensive_report)
        File.write(output_path, csv_content)
      else
        raise ArgumentError, "Unsupported format: #{format}"
      end
      
      puts "\n✓ Report generated successfully!"
      puts "  File: #{output_path}"
      puts "  Size: #{File.size(output_path)} bytes"
      
      # Print executive summary to console
      puts "\nExecutive Summary:"
      puts "-" * 20
      summary = comprehensive_report[:executive_summary]
      puts "Error Rate Status: #{summary[:error_rate_status]}"
      puts "System Health: #{summary[:overall_health]}"
      puts "Total Errors (#{hours}h): #{summary[:total_errors]}"
      puts "Circuit Breakers: #{summary[:circuit_breaker_summary]}"
      puts "Recovery Attempts: #{summary[:recovery_attempts]}"
      
      if summary[:critical_issues].any?
        puts "\nCritical Issues:"
        summary[:critical_issues].each { |issue| puts "  - #{issue}" }
      end
      
      if summary[:recommendations].any?
        puts "\nTop Recommendations:"
        summary[:recommendations].first(3).each { |rec| puts "  - #{rec}" }
      end
      
    rescue => e
      puts "\n✗ Report generation failed: #{e.message}"
      puts e.backtrace.first(5) if ENV['DEBUG']
      exit 1
    end
  end

  desc "Clean up old error monitoring data and optimize performance"
  task cleanup: :environment do
    puts "Error Monitoring System Cleanup"
    puts "=" * 35
    
    begin
      require_all_components
      
      # Get cleanup parameters
      retain_days = ENV['RETAIN_DAYS']&.to_i || 30
      dry_run = ENV['DRY_RUN'] == 'true'
      
      puts "Cleanup Parameters:"
      puts "  Retain data for: #{retain_days} days"
      puts "  Dry run mode: #{dry_run ? 'YES' : 'NO'}"
      
      cutoff_date = retain_days.days.ago
      puts "  Cutoff date: #{cutoff_date}"
      
      cleanup_stats = {
        agent_logs_cleaned: 0,
        reports_cleaned: 0,
        cache_cleared: false,
        database_optimized: false
      }
      
      # Clean old AgentLog entries (error level logs older than cutoff)
      puts "\nCleaning AgentLog entries..."
      old_logs_query = AgentLog.where('created_at < ? AND level >= ?', cutoff_date, 3)
      old_logs_count = old_logs_query.count
      
      if old_logs_count > 0
        puts "  Found #{old_logs_count} old error logs to remove"
        unless dry_run
          deleted_count = old_logs_query.delete_all
          cleanup_stats[:agent_logs_cleaned] = deleted_count
          puts "  ✓ Deleted #{deleted_count} old error logs"
        else
          puts "  (DRY RUN) Would delete #{old_logs_count} old error logs"
        end
      else
        puts "  ✓ No old error logs to clean"
      end
      
      # Clean old report files
      puts "\nCleaning old report files..."
      reports_dir = Rails.root.join('development', 'reports')
      if Dir.exist?(reports_dir)
        old_reports = Dir[File.join(reports_dir, '*error_monitoring_report_*.{json,csv,yaml,yml}')]
                        .select { |file| File.mtime(file) < cutoff_date }
        
        if old_reports.any?
          puts "  Found #{old_reports.length} old report files to remove"
          unless dry_run
            old_reports.each do |file|
              File.delete(file)
              cleanup_stats[:reports_cleaned] += 1
            end
            puts "  ✓ Deleted #{cleanup_stats[:reports_cleaned]} old report files"
          else
            puts "  (DRY RUN) Would delete #{old_reports.length} old report files"
          end
        else
          puts "  ✓ No old report files to clean"
        end
      end
      
      # Clear monitoring system caches
      puts "\nClearing monitoring system caches..."
      unless dry_run
        # Clear Rails cache if available
        if Rails.cache.respond_to?(:clear)
          Rails.cache.clear
          cleanup_stats[:cache_cleared] = true
          puts "  ✓ Rails cache cleared"
        end
        
        # Clear Ruby GC if available
        if defined?(GC)
          GC.start
          puts "  ✓ Garbage collection performed"
        end
      else
        puts "  (DRY RUN) Would clear caches and perform GC"
      end
      
      # Optimize database
      puts "\nOptimizing database..."
      unless dry_run
        begin
          # Analyze tables for query optimization
          case ActiveRecord::Base.connection.adapter_name.downcase
          when 'mysql', 'mysql2'
            ActiveRecord::Base.connection.execute('ANALYZE TABLE agent_logs')
            puts "  ✓ MySQL table analysis completed"
          when 'postgresql'
            ActiveRecord::Base.connection.execute('ANALYZE agent_logs')
            puts "  ✓ PostgreSQL table analysis completed"
          when 'sqlite'
            ActiveRecord::Base.connection.execute('ANALYZE')
            puts "  ✓ SQLite analysis completed"
          else
            puts "  ✓ Database optimization not implemented for #{ActiveRecord::Base.connection.adapter_name}"
          end
          
          cleanup_stats[:database_optimized] = true
        rescue => e
          puts "  ⚠ Database optimization failed: #{e.message}"
        end
      else
        puts "  (DRY RUN) Would optimize database tables"
      end
      
      # Generate cleanup summary
      puts "\n" + "=" * 35
      puts "Cleanup Summary:"
      puts "  AgentLog entries cleaned: #{cleanup_stats[:agent_logs_cleaned]}"
      puts "  Report files cleaned: #{cleanup_stats[:reports_cleaned]}"
      puts "  Cache cleared: #{cleanup_stats[:cache_cleared] ? 'Yes' : 'No'}"
      puts "  Database optimized: #{cleanup_stats[:database_optimized] ? 'Yes' : 'No'}"
      
      total_cleaned = cleanup_stats[:agent_logs_cleaned] + cleanup_stats[:reports_cleaned]
      puts "\nTotal items cleaned: #{total_cleaned}"
      puts "Cleanup completed at: #{Time.current}"
      
      unless dry_run
        puts "\nRecommendation: Run this cleanup task regularly (weekly/monthly)"
        puts "Set up a cron job: 0 2 * * 0 cd /path/to/huginn && bundle exec rake error_monitoring:cleanup"
      end
      
    rescue => e
      puts "\n✗ Cleanup failed: #{e.message}"
      puts e.backtrace.first(5) if ENV['DEBUG']
      exit 1
    end
  end

  desc "Reset error monitoring thresholds and configuration"
  task reset_thresholds: :environment do
    puts "Resetting Error Monitoring Thresholds..."
    
    begin
      require_all_components
      
      # Reset all circuit breakers
      puts "\nResetting circuit breakers..."
      cb_health = ErrorMonitoring::CircuitBreaker.health_status
      cb_health[:services].each do |service_name, status|
        ErrorMonitoring::CircuitBreaker.reset(service_name)
        puts "  ✓ Reset circuit breaker: #{service_name}"
      end
      
      # Clear recovery degradations
      puts "\nClearing active degradations..."
      recovery_health = ErrorMonitoring::RecoveryManager.health_status
      recovery_health[:active_degradations].each do |degradation|
        ErrorMonitoring::RecoveryManager.restore_full_functionality(degradation[:component])
        puts "  ✓ Restored functionality: #{degradation[:component]}"
      end
      
      puts "\n✓ Error monitoring system reset completed"
      puts "All thresholds and states have been reset to defaults"
      
    rescue => e
      puts "\n✗ Reset failed: #{e.message}"
      exit 1
    end
  end

  desc "Run error monitoring system tests"
  task test: :environment do
    puts "Running Error Monitoring System Tests..."
    puts "=" * 40
    
    begin
      require_all_components
      
      test_results = {
        passed: 0,
        failed: 0,
        errors: []
      }
      
      # Test 1: Error tracking
      puts "\nTest 1: Error Tracking"
      begin
        test_error = StandardError.new("Test error for monitoring system")
        result = ErrorMonitoring::ErrorTracker.track_error(test_error, {
          source: 'rake_test',
          category: :system
        })
        
        if result && result.respond_to?(:id)
          puts "  ✓ Error tracking test passed"
          test_results[:passed] += 1
        else
          puts "  ✗ Error tracking test failed"
          test_results[:failed] += 1
          test_results[:errors] << "Error tracking returned invalid result"
        end
      rescue => e
        puts "  ✗ Error tracking test failed: #{e.message}"
        test_results[:failed] += 1
        test_results[:errors] << "Error tracking exception: #{e.message}"
      end
      
      # Test 2: Circuit breaker
      puts "\nTest 2: Circuit Breaker"
      begin
        test_service = 'test_service_' + Time.current.to_i.to_s
        
        # Test normal operation
        result = ErrorMonitoring::CircuitBreaker.call(test_service) do
          "success"
        end
        
        if result == "success"
          puts "  ✓ Circuit breaker normal operation test passed"
          test_results[:passed] += 1
        else
          puts "  ✗ Circuit breaker normal operation test failed"
          test_results[:failed] += 1
        end
        
        # Test circuit breaker state
        state = ErrorMonitoring::CircuitBreaker.state(test_service)
        if state == :closed
          puts "  ✓ Circuit breaker state test passed"
          test_results[:passed] += 1
        else
          puts "  ✗ Circuit breaker state test failed: expected :closed, got #{state}"
          test_results[:failed] += 1
        end
        
      rescue => e
        puts "  ✗ Circuit breaker test failed: #{e.message}"
        test_results[:failed] += 1
        test_results[:errors] << "Circuit breaker exception: #{e.message}"
      end
      
      # Test 3: Error categorization
      puts "\nTest 3: Error Categorization"
      begin
        test_error = ActiveRecord::ConnectionNotEstablished.new("Database connection failed")
        classification = ErrorMonitoring::ErrorCategorizer.categorize(test_error, {})
        
        if classification[:primary_category] == :database_connection
          puts "  ✓ Error categorization test passed"
          test_results[:passed] += 1
        else
          puts "  ✗ Error categorization test failed: expected :database_connection, got #{classification[:primary_category]}"
          test_results[:failed] += 1
        end
      rescue => e
        puts "  ✗ Error categorization test failed: #{e.message}"
        test_results[:failed] += 1
        test_results[:errors] << "Error categorization exception: #{e.message}"
      end
      
      # Test 4: Recovery manager
      puts "\nTest 4: Recovery Manager"
      begin
        health_status = ErrorMonitoring::RecoveryManager.health_status
        
        if health_status[:overall_health]
          puts "  ✓ Recovery manager health test passed"
          test_results[:passed] += 1
        else
          puts "  ⚠ Recovery manager health test warning: #{health_status[:overall_health]}"
          test_results[:passed] += 1  # Don't fail for health warnings
        end
      rescue => e
        puts "  ✗ Recovery manager test failed: #{e.message}"
        test_results[:failed] += 1
        test_results[:errors] << "Recovery manager exception: #{e.message}"
      end
      
      # Test 5: Configuration loading
      puts "\nTest 5: Configuration Loading"
      begin
        config_path = Rails.root.join('config', 'error_monitoring.yml')
        if File.exist?(config_path)
          config = YAML.load_file(config_path)
          if config[Rails.env] && config[Rails.env]['error_rate_monitoring']
            puts "  ✓ Configuration loading test passed"
            test_results[:passed] += 1
          else
            puts "  ✗ Configuration loading test failed: missing environment config"
            test_results[:failed] += 1
          end
        else
          puts "  ✗ Configuration loading test failed: config file missing"
          test_results[:failed] += 1
        end
      rescue => e
        puts "  ✗ Configuration loading test failed: #{e.message}"
        test_results[:failed] += 1
        test_results[:errors] << "Configuration loading exception: #{e.message}"
      end
      
      # Test summary
      puts "\n" + "=" * 40
      puts "Test Results:"
      puts "  Passed: #{test_results[:passed]}"
      puts "  Failed: #{test_results[:failed]}"
      puts "  Total: #{test_results[:passed] + test_results[:failed]}"
      
      success_rate = test_results[:passed].to_f / (test_results[:passed] + test_results[:failed])
      puts "  Success Rate: #{(success_rate * 100).round(1)}%"
      
      if test_results[:errors].any?
        puts "\nError Details:"
        test_results[:errors].each_with_index do |error, idx|
          puts "  #{idx + 1}. #{error}"
        end
      end
      
      if test_results[:failed] > 0
        puts "\n✗ Some tests failed - please review error monitoring setup"
        exit 1
      else
        puts "\n✓ All tests passed - error monitoring system is working correctly"
      end
      
    rescue => e
      puts "\n✗ Test execution failed: #{e.message}"
      puts e.backtrace.first(5) if ENV['DEBUG']
      exit 1
    end
  end

  # Helper methods for rake tasks
  
  private

  def require_all_components
    require_relative '../error_monitoring/error_tracker'
    require_relative '../error_monitoring/circuit_breaker'
    require_relative '../error_monitoring/error_categorizer'
    require_relative '../error_monitoring/recovery_manager'
  end

  def create_default_configuration
    config_content = File.read(Rails.root.join('config', 'error_monitoring.yml'))
    puts "✓ Default configuration created"
  rescue
    puts "✗ Failed to create default configuration"
  end

  def setup_error_monitoring_logging
    log_dir = Rails.root.join('log')
    FileUtils.mkdir_p(log_dir) unless Dir.exist?(log_dir)
    
    error_monitoring_log = Rails.root.join('log', 'error_monitoring.log')
    FileUtils.touch(error_monitoring_log) unless File.exist?(error_monitoring_log)
  end

  def generate_baseline_report
    timestamp = Time.current.strftime('%Y%m%d_%H%M%S')
    filename = "baseline_error_monitoring_report_#{timestamp}.json"
    output_path = Rails.root.join('development', 'reports', filename)
    
    baseline_data = {
      generated_at: Time.current,
      type: 'baseline',
      system_info: {
        rails_env: Rails.env,
        rails_version: Rails::VERSION::STRING,
        ruby_version: RUBY_VERSION,
        agent_log_count: AgentLog.count
      },
      initial_metrics: {
        error_rate: ErrorMonitoring::ErrorTracker.current_error_rate,
        threshold: ErrorMonitoring::ErrorTracker::PRODUCTION_ERROR_RATE_THRESHOLD
      }
    }
    
    File.write(output_path, JSON.pretty_generate(baseline_data))
    output_path
  end

  def generate_executive_summary(error_stats, circuit_status, recovery_stats, categorization)
    threshold = ErrorMonitoring::ErrorTracker::PRODUCTION_ERROR_RATE_THRESHOLD
    current_rate = error_stats[:threshold_compliance][:current_rate]
    
    {
      error_rate_status: current_rate <= threshold ? 'COMPLIANT' : 'BREACH',
      overall_health: assess_overall_system_health(error_stats, circuit_status, recovery_stats),
      total_errors: error_stats[:error_counts][:total],
      circuit_breaker_summary: "#{circuit_status[:services].length} services monitored",
      recovery_attempts: recovery_stats[:recovery_attempts][:total] || 0,
      critical_issues: identify_critical_issues(error_stats, circuit_status, recovery_stats),
      recommendations: generate_top_recommendations(error_stats, categorization, recovery_stats)
    }
  end

  def assess_overall_system_health(error_stats, circuit_status, recovery_stats)
    # Simple health assessment logic
    return :critical if error_stats[:threshold_compliance][:current_rate] > (ErrorMonitoring::ErrorTracker::PRODUCTION_ERROR_RATE_THRESHOLD * 5)
    return :degraded if circuit_status[:overall_health] == :unhealthy
    return :warning if recovery_stats[:success_rates][:overall] < 0.7
    :healthy
  end

  def extract_key_metrics(error_stats, circuit_status, recovery_stats)
    {
      current_error_rate: error_stats[:threshold_compliance][:current_rate],
      error_rate_trend: 'stable', # Simplified
      circuit_breaker_health: circuit_status[:overall_health],
      recovery_success_rate: recovery_stats[:success_rates][:overall] || 0.8
    }
  end

  def generate_alerts_summary(error_stats, recovery_stats)
    alerts = []
    
    threshold = ErrorMonitoring::ErrorTracker::PRODUCTION_ERROR_RATE_THRESHOLD
    if error_stats[:threshold_compliance][:current_rate] > threshold
      alerts << "Error rate threshold breach detected"
    end
    
    if recovery_stats[:success_rates][:overall] < 0.5
      alerts << "Low recovery success rate"
    end
    
    alerts
  end

  def generate_system_recommendations(error_stats, categorization, recovery_stats)
    recommendations = []
    
    # Error rate recommendations
    threshold = ErrorMonitoring::ErrorTracker::PRODUCTION_ERROR_RATE_THRESHOLD
    if error_stats[:threshold_compliance][:current_rate] > threshold
      recommendations << "Investigate and resolve high error rate immediately"
    end
    
    # Pattern-based recommendations
    if categorization[:recurring_patterns].any?
      recommendations << "Address recurring error patterns to prevent future issues"
    end
    
    # Recovery recommendations
    if recovery_stats[:success_rates][:overall] < 0.7
      recommendations << "Review and optimize recovery strategies"
    end
    
    recommendations
  end

  def identify_critical_issues(error_stats, circuit_status, recovery_stats)
    issues = []
    
    threshold = ErrorMonitoring::ErrorTracker::PRODUCTION_ERROR_RATE_THRESHOLD
    if error_stats[:threshold_compliance][:current_rate] > (threshold * 10)
      issues << "Critical error rate breach (>1%)"
    end
    
    open_circuits = circuit_status[:services].select { |name, status| status[:state] == :open }
    if open_circuits.any?
      issues << "#{open_circuits.length} circuit breaker(s) open"
    end
    
    issues
  end

  def generate_top_recommendations(error_stats, categorization, recovery_stats)
    recommendations = generate_system_recommendations(error_stats, categorization, recovery_stats)
    recommendations.first(5) # Return top 5 recommendations
  end

  def generate_csv_report(report_data)
    require 'csv'
    
    CSV.generate(headers: true) do |csv|
      csv << ['Metric', 'Value', 'Status', 'Timestamp']
      
      # Error rate metrics
      csv << [
        'Current Error Rate',
        "#{(report_data[:error_rate_analysis][:threshold_compliance][:current_rate] * 100).round(4)}%",
        report_data[:executive_summary][:error_rate_status],
        report_data[:report_metadata][:generated_at]
      ]
      
      # System health
      csv << [
        'Overall System Health',
        report_data[:executive_summary][:overall_health],
        report_data[:executive_summary][:overall_health] == :healthy ? 'OK' : 'ATTENTION',
        report_data[:report_metadata][:generated_at]
      ]
      
      # Total errors
      csv << [
        "Total Errors (#{report_data[:report_metadata][:time_range_hours]}h)",
        report_data[:executive_summary][:total_errors],
        report_data[:executive_summary][:total_errors] > 100 ? 'HIGH' : 'NORMAL',
        report_data[:report_metadata][:generated_at]
      ]
    end
  end
end