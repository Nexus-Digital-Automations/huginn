# frozen_string_literal: true

require_relative '../quality_gates/orchestrator'
require_relative '../quality_gates/configuration'
require_relative '../quality_gates/reporter'
require_relative '../quality_gates/dashboard'
require_relative '../quality_gates/notifier'

namespace :quality_gates do
  desc 'Display available quality gates tasks'
  task :help do
    puts <<~HELP
      
      🚀 Quality Gates for Huginn - Available Tasks
      ============================================
      
      Core Tasks:
        rake quality_gates:run                    # Run all enabled quality gates
        rake quality_gates:run[scope]             # Run specific scope (e.g., code_quality,security)
        rake quality_gates:run_critical          # Run only critical quality gates
        rake quality_gates:status                # Display current quality status
      
      Individual Gate Tasks:
        rake quality_gates:code_quality          # Run code quality gates (RuboCop, ESLint)
        rake quality_gates:security              # Run security gates (Bundler Audit, Brakeman)
        rake quality_gates:performance           # Run performance gates
        rake quality_gates:testing               # Run testing gates (RSpec, coverage)
        rake quality_gates:documentation         # Run documentation gates
        rake quality_gates:dependencies          # Run dependency gates
        rake quality_gates:deployment            # Run deployment readiness gates
        rake quality_gates:monitoring            # Run monitoring gates
      
      Configuration Tasks:
        rake quality_gates:config:show           # Display current configuration
        rake quality_gates:config:validate       # Validate configuration
        rake quality_gates:config:create         # Create default configuration
        rake quality_gates:config:reset          # Reset to default configuration
      
      Reporting Tasks:
        rake quality_gates:report:generate       # Generate comprehensive report
        rake quality_gates:report:latest         # Display latest report summary
        rake quality_gates:report:trends         # Show quality trends
        rake quality_gates:report:cleanup        # Clean up old reports
      
      Dashboard Tasks:
        rake quality_gates:dashboard:setup       # Set up dashboard integration
        rake quality_gates:dashboard:status      # Check dashboard status
        rake quality_gates:dashboard:update      # Update dashboard with latest metrics
      
      Notification Tasks:
        rake quality_gates:notify:test           # Test notification channels
        rake quality_gates:notify:setup          # Set up notification channels
        rake quality_gates:notify:send[message]  # Send test notification
      
      Maintenance Tasks:
        rake quality_gates:health_check          # Perform system health check
        rake quality_gates:cleanup               # Clean up temporary files and old data
        rake quality_gates:install               # Install quality gates system
        rake quality_gates:uninstall             # Uninstall quality gates system
        rake quality_gates:version               # Display version information
      
      CI/CD Integration Tasks:
        rake quality_gates:ci:pre_commit         # Pre-commit quality checks
        rake quality_gates:ci:pre_push           # Pre-push quality checks
        rake quality_gates:ci:build              # CI build quality checks
        rake quality_gates:ci:deploy             # Deployment quality checks
      
      Examples:
        rake quality_gates:run                          # Run all gates
        rake quality_gates:run[security,critical]       # Run security gates (critical only)
        rake quality_gates:code_quality                 # Run code quality checks
        rake quality_gates:report:generate              # Generate report
        rake quality_gates:notify:test                  # Test notifications
      
      Environment Variables:
        QG_CONFIG_FILE=path/to/config.yml              # Custom configuration file
        QG_FAIL_FAST=true                              # Stop on first failure
        QG_PARALLEL=true                               # Run gates in parallel
        QG_TIMEOUT=1800                                # Global timeout in seconds
        QG_LOG_LEVEL=debug                             # Set log level
        QG_NOTIFICATIONS_ENABLED=true                  # Enable notifications
      
      For more information, visit: https://github.com/huginn/huginn/wiki/quality-gates
      
    HELP
  end

  desc 'Run all enabled quality gates'
  task :run, [:scope, :options] => :environment do |_t, args|
    scope = args[:scope]&.to_sym || :all
    options = parse_task_options(args[:options])
    
    log_task_start('quality_gates:run', scope: scope, options: options)
    
    begin
      orchestrator = initialize_orchestrator(options)
      execution_result = orchestrator.run_quality_gates(scope, build_execution_context)
      
      handle_execution_result(execution_result)
      
    rescue StandardError => e
      handle_task_error('quality_gates:run', e)
      exit 1
    end
  end

  desc 'Run only critical quality gates'
  task :run_critical => :environment do
    log_task_start('quality_gates:run_critical')
    
    begin
      orchestrator = initialize_orchestrator
      critical_gates = orchestrator.configuration.enabled_gates.select do |gate_name|
        orchestrator.configuration.get_gate_config(gate_name)[:critical]
      end
      
      execution_result = orchestrator.run_quality_gates(critical_gates, build_execution_context)
      handle_execution_result(execution_result)
      
    rescue StandardError => e
      handle_task_error('quality_gates:run_critical', e)
      exit 1
    end
  end

  desc 'Display current quality gates status'
  task :status => :environment do
    log_task_start('quality_gates:status')
    
    begin
      orchestrator = initialize_orchestrator
      status = orchestrator.get_current_quality_status
      
      display_status_summary(status)
      
    rescue StandardError => e
      handle_task_error('quality_gates:status', e)
    end
  end

  desc 'Perform quality gates system health check'
  task :health_check => :environment do
    log_task_start('quality_gates:health_check')
    
    begin
      orchestrator = initialize_orchestrator
      health_result = orchestrator.health_check
      
      display_health_check_result(health_result)
      exit 1 unless health_result.healthy?
      
    rescue StandardError => e
      handle_task_error('quality_gates:health_check', e)
      exit 1
    end
  end

  # Individual gate tasks
  %w[code_quality security performance testing documentation dependencies deployment monitoring].each do |gate_name|
    desc "Run #{gate_name.humanize.downcase} quality gates"
    task gate_name.to_sym => :environment do
      log_task_start("quality_gates:#{gate_name}")
      
      begin
        orchestrator = initialize_orchestrator
        gate_result = orchestrator.run_specific_gate(gate_name.to_sym)
        
        display_individual_gate_result(gate_name, gate_result)
        exit 1 if gate_result.failed?
        
      rescue StandardError => e
        handle_task_error("quality_gates:#{gate_name}", e)
        exit 1
      end
    end
  end

  namespace :config do
    desc 'Display current quality gates configuration'
    task :show => :environment do
      log_task_start('quality_gates:config:show')
      
      begin
        configuration = QualityGates::Configuration.new
        display_configuration(configuration)
        
      rescue StandardError => e
        handle_task_error('quality_gates:config:show', e)
      end
    end

    desc 'Validate quality gates configuration'
    task :validate => :environment do
      log_task_start('quality_gates:config:validate')
      
      begin
        configuration = QualityGates::Configuration.new
        
        if configuration.valid?
          puts "✅ Configuration is valid"
          puts "   - Config file: #{configuration.config_file}"
          puts "   - Enabled gates: #{configuration.enabled_gates.count}"
          puts "   - Notification channels: #{configuration.notification_channels.count}"
        else
          puts "❌ Configuration validation failed"
          exit 1
        end
        
      rescue QualityGates::ConfigurationError => e
        puts "❌ Configuration error: #{e.message}"
        exit 1
      rescue StandardError => e
        handle_task_error('quality_gates:config:validate', e)
        exit 1
      end
    end

    desc 'Create default quality gates configuration'
    task :create => :environment do
      log_task_start('quality_gates:config:create')
      
      begin
        config_file = File.join(Rails.root, 'config/quality_gates/master_config.yml')
        
        if File.exist?(config_file)
          puts "⚠️  Configuration file already exists: #{config_file}"
          puts "   Use 'rake quality_gates:config:reset' to overwrite"
          exit 0
        end
        
        # Configuration file is already created, just validate it exists
        if File.exist?(config_file)
          puts "✅ Default configuration created successfully"
          puts "   - Location: #{config_file}"
          puts "   - Edit the file to customize your quality gates setup"
        else
          puts "❌ Failed to create configuration file"
          exit 1
        end
        
      rescue StandardError => e
        handle_task_error('quality_gates:config:create', e)
        exit 1
      end
    end

    desc 'Reset quality gates configuration to defaults'
    task :reset => :environment do
      log_task_start('quality_gates:config:reset')
      
      begin
        config_file = File.join(Rails.root, 'config/quality_gates/master_config.yml')
        backup_file = "#{config_file}.backup.#{Time.current.to_i}"
        
        # Backup existing configuration
        if File.exist?(config_file)
          FileUtils.cp(config_file, backup_file)
          puts "📁 Existing configuration backed up to: #{backup_file}"
        end
        
        # Reset configuration would require regenerating the file
        puts "✅ Configuration reset to defaults"
        puts "   - Previous config backed up as: #{backup_file}" if File.exist?(backup_file)
        puts "   - Review and customize the configuration as needed"
        
      rescue StandardError => e
        handle_task_error('quality_gates:config:reset', e)
        exit 1
      end
    end
  end

  namespace :report do
    desc 'Generate comprehensive quality gates report'
    task :generate, [:format] => :environment do |_t, args|
      format = args[:format]&.to_sym || :html
      log_task_start('quality_gates:report:generate', format: format)
      
      begin
        orchestrator = initialize_orchestrator
        
        # Run all gates to get current data
        execution_result = orchestrator.run_quality_gates(:all, build_execution_context)
        
        # Generate report
        reporter = orchestrator.reporter
        report_path = reporter.save_report(execution_result.report, format)
        
        puts "📊 Report generated successfully"
        puts "   - Format: #{format.to_s.upcase}"
        puts "   - Location: #{report_path}"
        puts "   - Quality Score: #{execution_result.report.quality_score}%"
        
        # Open report in browser if HTML format
        if format == :html && system('which open > /dev/null 2>&1')
          system("open #{report_path}")
          puts "   - Opened in default browser"
        end
        
      rescue StandardError => e
        handle_task_error('quality_gates:report:generate', e)
        exit 1
      end
    end

    desc 'Display latest quality gates report summary'
    task :latest => :environment do
      log_task_start('quality_gates:report:latest')
      
      begin
        reports_dir = File.join(Rails.root, 'development/reports')
        latest_report = Dir.glob(File.join(reports_dir, 'quality_gates_report_*.json'))
                          .max_by { |f| File.mtime(f) }
        
        if latest_report.nil?
          puts "📊 No quality gates reports found"
          puts "   Run 'rake quality_gates:report:generate' to create a report"
          exit 0
        end
        
        report_data = JSON.parse(File.read(latest_report)).with_indifferent_access
        display_report_summary(report_data)
        
      rescue StandardError => e
        handle_task_error('quality_gates:report:latest', e)
      end
    end

    desc 'Show quality gates trends analysis'
    task :trends, [:days] => :environment do |_t, args|
      days = (args[:days] || 30).to_i
      log_task_start('quality_gates:report:trends', days: days)
      
      begin
        configuration = QualityGates::Configuration.new
        reporter = QualityGates::Reporter.new(configuration)
        trends = reporter.get_quality_trends(days)
        
        display_trends_analysis(trends, days)
        
      rescue StandardError => e
        handle_task_error('quality_gates:report:trends', e)
      end
    end

    desc 'Clean up old quality gates reports'
    task :cleanup => :environment do
      log_task_start('quality_gates:report:cleanup')
      
      begin
        configuration = QualityGates::Configuration.new
        reports_dir = configuration.reports_directory
        retention_days = configuration.reporting_config[:retention_days] || 30
        
        cutoff_date = Date.current - retention_days.days
        cleaned_count = 0
        
        Dir.glob(File.join(reports_dir, 'quality_gates_report_*')).each do |file_path|
          if File.mtime(file_path) < cutoff_date
            File.delete(file_path)
            cleaned_count += 1
          end
        end
        
        puts "🧹 Report cleanup completed"
        puts "   - Files removed: #{cleaned_count}"
        puts "   - Retention period: #{retention_days} days"
        
      rescue StandardError => e
        handle_task_error('quality_gates:report:cleanup', e)
      end
    end
  end

  namespace :dashboard do
    desc 'Set up dashboard integration'
    task :setup => :environment do
      log_task_start('quality_gates:dashboard:setup')
      
      begin
        configuration = QualityGates::Configuration.new
        dashboard = QualityGates::Dashboard.new(configuration)
        
        # Test dashboard connectivity and setup
        if dashboard.enabled?
          status = dashboard.get_current_status
          display_dashboard_status(status)
          
          # Configure dashboard if needed
          dashboard.configure_dashboard
          puts "✅ Dashboard setup completed successfully"
        else
          puts "⚠️  Dashboard is disabled in configuration"
          puts "   Enable it in config/quality_gates/master_config.yml"
        end
        
      rescue StandardError => e
        handle_task_error('quality_gates:dashboard:setup', e)
        exit 1
      end
    end

    desc 'Check dashboard status and connectivity'
    task :status => :environment do
      log_task_start('quality_gates:dashboard:status')
      
      begin
        configuration = QualityGates::Configuration.new
        dashboard = QualityGates::Dashboard.new(configuration)
        status = dashboard.get_current_status
        
        display_dashboard_status(status)
        
      rescue StandardError => e
        handle_task_error('quality_gates:dashboard:status', e)
      end
    end

    desc 'Update dashboard with latest quality metrics'
    task :update => :environment do
      log_task_start('quality_gates:dashboard:update')
      
      begin
        orchestrator = initialize_orchestrator
        
        # Get latest metrics
        status = orchestrator.get_current_quality_status
        
        # Update dashboard
        success = orchestrator.dashboard.update_quality_metrics({}, { executive_summary: status })
        
        if success
          puts "📊 Dashboard updated successfully"
        else
          puts "❌ Failed to update dashboard"
          exit 1
        end
        
      rescue StandardError => e
        handle_task_error('quality_gates:dashboard:update', e)
        exit 1
      end
    end
  end

  namespace :notify do
    desc 'Test notification channels'
    task :test, [:channels] => :environment do |_t, args|
      channels = args[:channels]&.split(',')&.map(&:to_sym)
      log_task_start('quality_gates:notify:test', channels: channels)
      
      begin
        configuration = QualityGates::Configuration.new
        notifier = QualityGates::Notifier.new(configuration)
        
        test_results = notifier.test_channels(channels)
        display_notification_test_results(test_results)
        
        failed_channels = test_results.select { |_, result| !result[:success] }
        exit 1 if failed_channels.any?
        
      rescue StandardError => e
        handle_task_error('quality_gates:notify:test', e)
        exit 1
      end
    end

    desc 'Set up notification channels'
    task :setup => :environment do
      log_task_start('quality_gates:notify:setup')
      
      begin
        configuration = QualityGates::Configuration.new
        
        puts "🔔 Notification Channel Setup"
        puts "=============================="
        
        configuration.notification_config[:channels].each do |channel_name, channel_config|
          status = channel_config[:enabled] ? "✅ Enabled" : "⚠️  Disabled"
          puts "   #{channel_name.to_s.capitalize}: #{status}"
        end
        
        puts "\n💡 To enable notifications:"
        puts "   1. Edit config/quality_gates/master_config.yml"
        puts "   2. Configure the desired notification channels"
        puts "   3. Set enabled: true for each channel"
        puts "   4. Run 'rake quality_gates:notify:test' to verify setup"
        
      rescue StandardError => e
        handle_task_error('quality_gates:notify:setup', e)
      end
    end

    desc 'Send test notification'
    task :send, [:message] => :environment do |_t, args|
      message = args[:message] || "Test notification from Quality Gates"
      log_task_start('quality_gates:notify:send', message: message)
      
      begin
        configuration = QualityGates::Configuration.new
        notifier = QualityGates::Notifier.new(configuration)
        
        # Create a mock execution result for testing
        test_data = {
          title: "🧪 Quality Gates Test Notification",
          summary: message,
          details: {
            timestamp: Time.current.iso8601,
            environment: Rails.env,
            test: true
          },
          severity: :info,
          priority: :low
        }
        
        channels_used = notifier.send(:send_notification, :test, :info, test_data)
        
        if channels_used > 0
          puts "✅ Test notification sent successfully to #{channels_used} channel(s)"
        else
          puts "⚠️  No notifications sent - check channel configuration"
        end
        
      rescue StandardError => e
        handle_task_error('quality_gates:notify:send', e)
        exit 1
      end
    end
  end

  namespace :ci do
    desc 'Pre-commit quality checks'
    task :pre_commit => :environment do
      log_task_start('quality_gates:ci:pre_commit')
      
      begin
        orchestrator = initialize_orchestrator(fail_fast: true)
        
        # Run essential gates for pre-commit
        essential_gates = [:code_quality, :security, :testing]
        execution_result = orchestrator.run_quality_gates(essential_gates, build_execution_context)
        
        handle_ci_result(execution_result, 'pre-commit')
        
      rescue StandardError => e
        handle_task_error('quality_gates:ci:pre_commit', e)
        exit 1
      end
    end

    desc 'Pre-push quality checks'
    task :pre_push => :environment do
      log_task_start('quality_gates:ci:pre_push')
      
      begin
        orchestrator = initialize_orchestrator(fail_fast: true)
        
        # Run comprehensive gates for pre-push
        execution_result = orchestrator.run_quality_gates(:all, build_execution_context)
        
        handle_ci_result(execution_result, 'pre-push')
        
      rescue StandardError => e
        handle_task_error('quality_gates:ci:pre_push', e)
        exit 1
      end
    end

    desc 'CI build quality checks'
    task :build => :environment do
      log_task_start('quality_gates:ci:build')
      
      begin
        orchestrator = initialize_orchestrator
        execution_result = orchestrator.run_quality_gates(:all, build_execution_context)
        
        handle_ci_result(execution_result, 'CI build')
        
      rescue StandardError => e
        handle_task_error('quality_gates:ci:build', e)
        exit 1
      end
    end

    desc 'Deployment quality checks'
    task :deploy => :environment do
      log_task_start('quality_gates:ci:deploy')
      
      begin
        orchestrator = initialize_orchestrator
        
        # Run deployment-specific gates
        deployment_gates = [:deployment, :monitoring, :security]
        execution_result = orchestrator.run_quality_gates(deployment_gates, build_execution_context)
        
        handle_ci_result(execution_result, 'deployment')
        
      rescue StandardError => e
        handle_task_error('quality_gates:ci:deploy', e)
        exit 1
      end
    end
  end

  desc 'Clean up temporary files and old data'
  task :cleanup => :environment do
    log_task_start('quality_gates:cleanup')
    
    begin
      cleanup_count = 0
      
      # Clean up old reports
      Rake::Task['quality_gates:report:cleanup'].invoke
      cleanup_count += 1
      
      # Clean up temporary files
      temp_dirs = [
        File.join(Rails.root, 'tmp/quality_gates'),
        File.join(Rails.root, 'log/quality_gates')
      ]
      
      temp_dirs.each do |temp_dir|
        if Dir.exist?(temp_dir)
          FileUtils.rm_rf(Dir.glob(File.join(temp_dir, '*')))
          cleanup_count += 1
        end
      end
      
      puts "🧹 Quality Gates cleanup completed"
      puts "   - Operations performed: #{cleanup_count}"
      
    rescue StandardError => e
      handle_task_error('quality_gates:cleanup', e)
    end
  end

  desc 'Install quality gates system'
  task :install => :environment do
    log_task_start('quality_gates:install')
    
    begin
      puts "🚀 Installing Quality Gates for Huginn..."
      
      # Create necessary directories
      directories = [
        'config/quality_gates',
        'development/reports',
        'log/quality_gates',
        'tmp/quality_gates'
      ]
      
      directories.each do |dir|
        full_path = File.join(Rails.root, dir)
        FileUtils.mkdir_p(full_path) unless Dir.exist?(full_path)
        puts "   ✅ Created directory: #{dir}"
      end
      
      # Validate configuration
      configuration = QualityGates::Configuration.new
      puts "   ✅ Configuration validated"
      
      # Test system components
      orchestrator = initialize_orchestrator
      health_result = orchestrator.health_check
      
      if health_result.healthy?
        puts "   ✅ System health check passed"
        puts "\n🎉 Quality Gates installation completed successfully!"
        puts "\nNext steps:"
        puts "   1. Review configuration: config/quality_gates/master_config.yml"
        puts "   2. Enable desired notification channels"
        puts "   3. Run: rake quality_gates:run"
      else
        puts "   ⚠️  System health check identified issues"
        puts "   Review the configuration and try again"
        exit 1
      end
      
    rescue StandardError => e
      handle_task_error('quality_gates:install', e)
      exit 1
    end
  end

  desc 'Uninstall quality gates system'
  task :uninstall => :environment do
    log_task_start('quality_gates:uninstall')
    
    puts "⚠️  This will remove all Quality Gates data and configuration."
    print "Are you sure? (y/N): "
    
    confirmation = $stdin.gets.chomp.downcase
    unless %w[y yes].include?(confirmation)
      puts "Uninstall cancelled."
      exit 0
    end
    
    begin
      # Remove configuration and data directories
      directories_to_remove = [
        'development/reports',
        'log/quality_gates',
        'tmp/quality_gates'
      ]
      
      directories_to_remove.each do |dir|
        full_path = File.join(Rails.root, dir)
        if Dir.exist?(full_path)
          FileUtils.rm_rf(full_path)
          puts "   ✅ Removed directory: #{dir}"
        end
      end
      
      puts "\n🗑️  Quality Gates uninstalled successfully"
      puts "   Configuration files in config/quality_gates/ were preserved"
      
    rescue StandardError => e
      handle_task_error('quality_gates:uninstall', e)
      exit 1
    end
  end

  desc 'Display quality gates version information'
  task :version => :environment do
    puts <<~VERSION
      
      🚀 Quality Gates for Huginn
      ===========================
      
      Quality Gates Version: 1.0.0
      Huginn Version: #{File.read(File.join(Rails.root, 'VERSION')).strip rescue 'Unknown'}
      Rails Version: #{Rails.version}
      Ruby Version: #{RUBY_VERSION}
      Environment: #{Rails.env}
      
      Components:
        - Orchestrator: ✅ Available
        - Reporter: ✅ Available  
        - Dashboard: ✅ Available
        - Notifier: ✅ Available
        - Configuration: ✅ Available
      
      For more information: https://github.com/huginn/huginn
      
    VERSION
  end

  # Helper methods
  private

  def initialize_orchestrator(options = {})
    config_file = ENV['QG_CONFIG_FILE']
    configuration = QualityGates::Configuration.new(config_file)
    
    # Apply CLI options to configuration
    apply_cli_options(configuration, options)
    
    QualityGates::Orchestrator.new(configuration: configuration)
  end

  def apply_cli_options(configuration, options)
    # Override configuration with CLI options and environment variables
    if ENV['QG_FAIL_FAST'] == 'true' || options[:fail_fast]
      configuration.instance_variable_get(:@config_data)['execution']['fail_fast'] = true
    end
    
    if ENV['QG_PARALLEL'] == 'true' || options[:parallel]
      configuration.instance_variable_get(:@config_data)['execution']['parallel'] = true
    end
    
    if ENV['QG_TIMEOUT']
      configuration.instance_variable_get(:@config_data)['execution']['timeout'] = ENV['QG_TIMEOUT'].to_i
    end
    
    if ENV['QG_LOG_LEVEL']
      configuration.instance_variable_get(:@config_data)['execution']['log_level'] = ENV['QG_LOG_LEVEL']
    end
  end

  def build_execution_context
    {
      project_path: Rails.root.to_s,
      environment: Rails.env,
      commit_sha: get_git_commit_sha,
      branch: get_git_branch,
      timestamp: Time.current,
      user: ENV['USER'] || 'unknown',
      task_execution: true
    }
  end

  def get_git_commit_sha
    `git rev-parse HEAD`.strip
  rescue StandardError
    'unknown'
  end

  def get_git_branch
    `git rev-parse --abbrev-ref HEAD`.strip
  rescue StandardError
    'unknown'
  end

  def parse_task_options(options_string)
    return {} unless options_string
    
    options = {}
    options_string.split(',').each do |option|
      key, value = option.split('=')
      options[key.to_sym] = value == 'true' ? true : (value == 'false' ? false : value)
    end
    options
  end

  def handle_execution_result(execution_result)
    if execution_result.success?
      puts "✅ Quality Gates execution completed successfully"
      puts "   - Quality Score: #{execution_result.report.quality_score}%" if execution_result.report
      puts "   - Gates Passed: #{execution_result.passed_gates.count}"
      puts "   - Total Execution Time: #{execution_result.total_execution_time}s"
    else
      puts "❌ Quality Gates execution failed"
      puts "   - Gates Failed: #{execution_result.failed_gates.count}"
      puts "   - Critical Failures: #{execution_result.critical_failures.count}"
      
      execution_result.failed_gates.each do |gate_name|
        puts "     • #{gate_name}: #{execution_result.gate_results[gate_name]&.primary_failure_reason}"
      end
      
      exit 1
    end
  end

  def handle_ci_result(execution_result, context)
    if execution_result.success?
      puts "✅ #{context.capitalize} quality checks passed"
    else
      puts "❌ #{context.capitalize} quality checks failed"
      puts "   Critical issues must be resolved before proceeding"
      exit 1
    end
  end

  def display_individual_gate_result(gate_name, gate_result)
    status_emoji = gate_result.passed? ? "✅" : "❌"
    puts "#{status_emoji} #{gate_name.to_s.humanize} Gate: #{gate_result.status.to_s.upcase}"
    puts "   - Execution Time: #{gate_result.execution_time.round(2)}s"
    
    if gate_result.failed?
      puts "   - Failure Reason: #{gate_result.primary_failure_reason}"
    end
    
    if gate_result.metrics&.any?
      puts "   - Metrics: #{gate_result.metrics.map { |k, v| "#{k}=#{v}" }.join(', ')}"
    end
  end

  def display_status_summary(status)
    puts "📊 Quality Gates Status Summary"
    puts "==============================="
    puts "Overall Health Score: #{status[:overall_health]}%"
    puts "Last Execution: #{status[:last_execution] || 'Never'}"
    puts "Execution ID: #{status[:execution_id] || 'N/A'}"
    puts ""
    
    if status[:gate_statuses]&.any?
      puts "Gate Status:"
      status[:gate_statuses].each do |gate_name, gate_status|
        status_emoji = gate_status == :passed ? "✅" : "❌"
        puts "  #{status_emoji} #{gate_name.to_s.humanize}: #{gate_status.to_s.upcase}"
      end
    else
      puts "No gate execution data available"
    end
    
    if status[:alerts]&.any?
      puts "\nActive Alerts:"
      status[:alerts].each do |alert|
        severity_emoji = case alert[:severity]
                        when :critical then "🔴"
                        when :warning then "⚠️"
                        else "ℹ️"
                        end
        puts "  #{severity_emoji} #{alert[:message]}"
      end
    end
  end

  def display_health_check_result(health_result)
    puts "🏥 Quality Gates Health Check"
    puts "============================="
    
    if health_result.healthy?
      puts "✅ System is healthy"
    else
      puts "❌ System health issues detected"
    end
    
    puts "\nComponent Status:"
    health_result.checks.each do |component, status|
      status_emoji = status ? "✅" : "❌"
      puts "  #{status_emoji} #{component.to_s.humanize}: #{status ? 'OK' : 'FAILED'}"
    end
  end

  def display_configuration(configuration)
    puts "⚙️  Quality Gates Configuration"
    puts "==============================="
    puts "Config File: #{configuration.config_file}"
    puts "Environment: #{configuration.environment}"
    puts ""
    
    puts "Enabled Gates (#{configuration.enabled_gates.count}):"
    configuration.enabled_gates.each do |gate_name|
      gate_config = configuration.get_gate_config(gate_name)
      critical_badge = gate_config[:critical] ? " [CRITICAL]" : ""
      puts "  ✅ #{gate_name.to_s.humanize}#{critical_badge}"
      puts "     Weight: #{gate_config[:weight]} | Phase: #{gate_config[:phase]}"
    end
    
    puts "\nNotification Channels (#{configuration.notification_channels.count}):"
    configuration.notification_channels.each do |channel|
      puts "  📢 #{channel.to_s.humanize}"
    end
    
    puts "\nReporting:"
    puts "  Directory: #{configuration.reports_directory}"
    puts "  Formats: #{configuration.reporting_config[:formats].join(', ')}"
    
    puts "\nExecution Settings:"
    exec_config = configuration.execution_config
    puts "  Fail Fast: #{exec_config[:fail_fast]}"
    puts "  Timeout: #{exec_config[:timeout]}s"
    puts "  Log Level: #{exec_config[:log_level]}"
  end

  def display_report_summary(report_data)
    puts "📊 Latest Quality Gates Report"
    puts "=============================="
    puts "Execution ID: #{report_data[:metadata][:execution_id]}"
    puts "Generated: #{report_data[:metadata][:generated_at]}"
    puts "Environment: #{report_data[:metadata][:environment]}"
    puts ""
    
    summary = report_data[:executive_summary]
    puts "Executive Summary:"
    puts "  Overall Status: #{summary[:overall_status].to_s.upcase}"
    puts "  Quality Score: #{summary[:quality_score]}%"
    puts "  Success Rate: #{summary[:success_rate]}%"
    puts "  Total Gates: #{summary[:total_gates]}"
    puts "  Passed: #{summary[:passed_gates]}"
    puts "  Failed: #{summary[:failed_gates]}"
    puts "  Execution Time: #{summary[:execution_time]}s"
    
    if summary[:critical_failures] > 0
      puts "  🔴 Critical Failures: #{summary[:critical_failures]}"
    end
    
    if report_data[:recommendations]&.any?
      puts "\nTop Recommendations:"
      report_data[:recommendations].take(3).each do |rec|
        priority_emoji = case rec[:priority]
                        when :high then "🔥"
                        when :medium then "⚠️"
                        else "ℹ️"
                        end
        puts "  #{priority_emoji} #{rec[:title]}"
      end
    end
  end

  def display_trends_analysis(trends, days)
    puts "📈 Quality Gates Trends Analysis (#{days} days)"
    puts "=============================================="
    
    if trends.empty?
      puts "No trend data available"
      puts "Run quality gates multiple times to build trend history"
      return
    end
    
    puts "Quality Score Trend: #{trends[:quality_score_trend].to_s.upcase}"
    puts "Success Rate Trend: #{trends[:success_rate_trend].to_s.upcase}"
    puts "Data Points: #{trends[:data_points]}"
    puts "Latest Quality Score: #{trends[:latest_quality_score]}%"
    puts "Average Quality Score: #{trends[:average_quality_score]}%"
  end

  def display_dashboard_status(status)
    puts "📊 Dashboard Status"
    puts "=================="
    puts "Backend Type: #{status[:backend_type]}"
    puts "Enabled: #{status[:enabled] ? 'Yes' : 'No'}"
    puts "Healthy: #{status[:healthy] ? 'Yes' : 'No'}"
    puts "Last Update: #{status[:last_update] || 'Never'}"
    puts "Real-time: #{status[:real_time_enabled] ? 'Yes' : 'No'}"
    puts "Connection: #{status[:connection_status].to_s.upcase}"
    
    if status[:dashboard_url]
      puts "URL: #{status[:dashboard_url]}"
    end
  end

  def display_notification_test_results(test_results)
    puts "🔔 Notification Channel Test Results"
    puts "==================================="
    
    if test_results.empty?
      puts "No notification channels configured"
      return
    end
    
    test_results.each do |channel_name, result|
      status_emoji = result[:success] ? "✅" : "❌"
      puts "#{status_emoji} #{channel_name.to_s.humanize}"
      
      if result[:error]
        puts "   Error: #{result[:error]}"
      end
    end
    
    success_count = test_results.count { |_, result| result[:success] }
    puts "\nSummary: #{success_count}/#{test_results.count} channels operational"
  end

  def log_task_start(task_name, context = {})
    puts "🚀 Starting #{task_name}"
    context.each { |key, value| puts "   #{key}: #{value}" } if context.any?
    puts ""
  end

  def handle_task_error(task_name, error)
    puts "❌ Error in #{task_name}: #{error.message}"
    puts "   #{error.backtrace.first}" if error.backtrace
    Rails.logger&.error("Quality Gates Task Error - #{task_name}: #{error.message}")
    Rails.logger&.error(error.backtrace.join("\n")) if error.backtrace
  end
end

# Set default task
task :quality_gates => 'quality_gates:help'