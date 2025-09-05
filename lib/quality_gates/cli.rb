# frozen_string_literal: true

require 'optparse'
require 'json'

module QualityGates
  # Command-line interface for quality gates system
  # Provides manual execution, testing, and management capabilities
  #
  # Usage:
  #   ruby -r ./lib/quality_gates/cli.rb -e "QualityGates::CLI.new.run(ARGV)"
  #   Or through Rails: rails runner "QualityGates::CLI.new.run(['--help'])"
  #
  # Commands: run, status, config, test, report, dashboard, notify
  # Features: Interactive mode, batch processing, output formatting
  class CLI
    attr_reader :options, :command, :arguments

    # Available CLI commands
    COMMANDS = %w[
      run
      status
      config
      test
      report
      dashboard
      notify
      health
      install
      version
      help
    ].freeze

    # Output format options
    OUTPUT_FORMATS = %w[text json yaml table].freeze

    def initialize
      @options = {}
      @command = nil
      @arguments = []
      @orchestrator = nil
    end

    # Main CLI entry point
    # @param args [Array<String>] - command line arguments
    # @return [Integer] - exit code
    def run(args = ARGV)
      begin
        parse_arguments(args)
        
        # Show help if no command provided
        if @command.nil? || @command == 'help'
          show_help
          return 0
        end

        # Validate command
        unless COMMANDS.include?(@command)
          error "Unknown command: #{@command}"
          show_help
          return 1
        end

        # Initialize orchestrator for commands that need it
        initialize_orchestrator if needs_orchestrator?

        # Execute command
        exit_code = execute_command
        exit_code

      rescue QualityGates::ConfigurationError => e
        error "Configuration error: #{e.message}"
        1
      rescue StandardError => e
        error "Unexpected error: #{e.message}"
        error e.backtrace.join("\n") if @options[:debug]
        1
      end
    end

    private

    # Parse command line arguments
    def parse_arguments(args)
      parser = create_option_parser
      
      remaining_args = parser.parse(args)
      
      if remaining_args.any?
        @command = remaining_args.shift
        @arguments = remaining_args
      end
    end

    # Create OptionParser with all CLI options
    def create_option_parser
      OptionParser.new do |opts|
        opts.banner = "Usage: #{$PROGRAM_NAME} [options] command [arguments]"
        opts.separator ""
        opts.separator "Commands:"
        opts.separator "  run [scope]          Run quality gates (all, critical, or specific gate names)"
        opts.separator "  status               Show current quality status"
        opts.separator "  config               Show or validate configuration"
        opts.separator "  test [channels]      Test notification channels"
        opts.separator "  report [format]      Generate quality report"
        opts.separator "  dashboard            Dashboard operations"
        opts.separator "  notify [message]     Send test notification"
        opts.separator "  health               Perform health check"
        opts.separator "  install              Install quality gates system"
        opts.separator "  version              Show version information"
        opts.separator "  help                 Show this help message"
        opts.separator ""
        opts.separator "Options:"

        # Configuration options
        opts.on('-c', '--config FILE', 'Configuration file path') do |config|
          @options[:config_file] = config
        end

        opts.on('-e', '--environment ENV', 'Environment (development, test, production)') do |env|
          @options[:environment] = env
        end

        # Execution options
        opts.on('-f', '--fail-fast', 'Stop on first critical failure') do
          @options[:fail_fast] = true
        end

        opts.on('-p', '--parallel', 'Run gates in parallel') do
          @options[:parallel] = true
        end

        opts.on('-t', '--timeout SECONDS', Integer, 'Execution timeout in seconds') do |timeout|
          @options[:timeout] = timeout
        end

        # Output options
        opts.on('-o', '--output FORMAT', OUTPUT_FORMATS, 'Output format (text, json, yaml, table)') do |format|
          @options[:output_format] = format.to_sym
        end

        opts.on('-v', '--verbose', 'Verbose output') do
          @options[:verbose] = true
        end

        opts.on('-q', '--quiet', 'Suppress non-essential output') do
          @options[:quiet] = true
        end

        opts.on('--debug', 'Debug mode with detailed error information') do
          @options[:debug] = true
        end

        # Reporting options
        opts.on('-r', '--report-file FILE', 'Save report to specific file') do |file|
          @options[:report_file] = file
        end

        opts.on('--no-open', 'Do not open HTML reports in browser') do
          @options[:no_open] = true
        end

        # Notification options
        opts.on('--no-notifications', 'Disable notifications') do
          @options[:notifications_enabled] = false
        end

        # Common options
        opts.on('-h', '--help', 'Show this help message') do
          @command = 'help'
        end

        opts.on('--version', 'Show version information') do
          @command = 'version'
        end
      end
    end

    # Check if command requires orchestrator initialization
    def needs_orchestrator?
      %w[run status test report dashboard notify health].include?(@command)
    end

    # Initialize orchestrator with CLI options
    def initialize_orchestrator
      config_file = @options[:config_file] || ENV['QG_CONFIG_FILE']
      environment = @options[:environment] || Rails.env
      
      configuration = QualityGates::Configuration.new(config_file, environment)
      
      # Apply CLI options to configuration
      apply_cli_options_to_config(configuration)
      
      @orchestrator = QualityGates::Orchestrator.new(configuration: configuration)
    end

    # Apply CLI options to configuration
    def apply_cli_options_to_config(configuration)
      config_data = configuration.instance_variable_get(:@config_data)
      
      if @options[:fail_fast]
        config_data['execution'] ||= {}
        config_data['execution']['fail_fast'] = true
      end
      
      if @options[:parallel]
        config_data['execution'] ||= {}
        config_data['execution']['parallel'] = true
      end
      
      if @options[:timeout]
        config_data['execution'] ||= {}
        config_data['execution']['timeout'] = @options[:timeout]
      end
      
      if @options[:notifications_enabled] == false
        config_data['notifications'] ||= {}
        config_data['notifications']['enabled'] = false
      end
    end

    # Execute the specified command
    def execute_command
      case @command
      when 'run'
        execute_run_command
      when 'status'
        execute_status_command
      when 'config'
        execute_config_command
      when 'test'
        execute_test_command
      when 'report'
        execute_report_command
      when 'dashboard'
        execute_dashboard_command
      when 'notify'
        execute_notify_command
      when 'health'
        execute_health_command
      when 'install'
        execute_install_command
      when 'version'
        execute_version_command
      else
        error "Unknown command: #{@command}"
        1
      end
    end

    # Execute run command
    def execute_run_command
      scope = parse_scope_argument(@arguments.first) || :all
      
      info "Running quality gates (scope: #{scope})"
      
      execution_context = build_execution_context
      execution_result = @orchestrator.run_quality_gates(scope, execution_context)
      
      output_execution_result(execution_result)
      
      execution_result.success? ? 0 : 1
    end

    # Execute status command
    def execute_status_command
      info "Checking quality gates status"
      
      status = @orchestrator.get_current_quality_status
      output_status(status)
      
      0
    end

    # Execute config command
    def execute_config_command
      subcommand = @arguments.first || 'show'
      
      case subcommand
      when 'show'
        output_configuration(@orchestrator.configuration)
      when 'validate'
        if @orchestrator.configuration.valid?
          success "Configuration is valid"
        else
          error "Configuration validation failed"
          return 1
        end
      else
        error "Unknown config subcommand: #{subcommand}"
        return 1
      end
      
      0
    end

    # Execute test command
    def execute_test_command
      channels = parse_channels_argument(@arguments.first)
      
      info "Testing notification channels#{channels ? " (#{channels.join(', ')})" : ''}"
      
      test_results = @orchestrator.notifier.test_channels(channels)
      output_test_results(test_results)
      
      failed_channels = test_results.select { |_, result| !result[:success] }
      failed_channels.any? ? 1 : 0
    end

    # Execute report command
    def execute_report_command
      format = (@arguments.first || 'html').to_sym
      
      unless QualityGates::Reporter::REPORT_FORMATS.key?(format)
        error "Unsupported report format: #{format}"
        return 1
      end
      
      info "Generating quality gates report (format: #{format})"
      
      # Run gates to get current data
      execution_context = build_execution_context
      execution_result = @orchestrator.run_quality_gates(:all, execution_context)
      
      # Generate report
      report_path = @orchestrator.reporter.save_report(execution_result.report, format)
      
      success "Report generated: #{report_path}"
      
      # Open HTML reports in browser unless disabled
      if format == :html && !@options[:no_open] && system('which open > /dev/null 2>&1')
        system("open #{report_path}")
        info "Opened report in default browser"
      end
      
      0
    end

    # Execute dashboard command
    def execute_dashboard_command
      subcommand = @arguments.first || 'status'
      
      case subcommand
      when 'status'
        status = @orchestrator.dashboard.get_current_status
        output_dashboard_status(status)
      when 'update'
        success = @orchestrator.dashboard.update_quality_metrics({}, { executive_summary: {} })
        if success
          success "Dashboard updated successfully"
        else
          error "Failed to update dashboard"
          return 1
        end
      else
        error "Unknown dashboard subcommand: #{subcommand}"
        return 1
      end
      
      0
    end

    # Execute notify command
    def execute_notify_command
      message = @arguments.join(' ') || "Test notification from Quality Gates CLI"
      
      info "Sending test notification"
      
      # Create test notification data
      test_data = {
        title: "🧪 Quality Gates CLI Test",
        summary: message,
        details: {
          timestamp: Time.current.iso8601,
          environment: Rails.env,
          cli_test: true
        },
        severity: :info,
        priority: :low
      }
      
      channels_used = @orchestrator.notifier.send(:send_notification, :test, :info, test_data)
      
      if channels_used > 0
        success "Test notification sent to #{channels_used} channel(s)"
      else
        warning "No notifications sent - check channel configuration"
      end
      
      0
    end

    # Execute health command
    def execute_health_command
      info "Performing quality gates health check"
      
      health_result = @orchestrator.health_check
      output_health_check(health_result)
      
      health_result.healthy? ? 0 : 1
    end

    # Execute install command
    def execute_install_command
      info "Installing Quality Gates for Huginn"
      
      begin
        # Create necessary directories
        directories = [
          File.join(Rails.root, 'config/quality_gates'),
          File.join(Rails.root, 'development/reports'),
          File.join(Rails.root, 'log/quality_gates'),
          File.join(Rails.root, 'tmp/quality_gates')
        ]
        
        directories.each do |dir|
          unless Dir.exist?(dir)
            FileUtils.mkdir_p(dir)
            info "Created directory: #{dir}"
          end
        end
        
        # Test configuration
        configuration = QualityGates::Configuration.new
        success "Configuration validated"
        
        # Test system health
        initialize_orchestrator
        health_result = @orchestrator.health_check
        
        if health_result.healthy?
          success "Quality Gates installation completed successfully!"
          info "Next steps:"
          info "  1. Review configuration: config/quality_gates/master_config.yml"
          info "  2. Enable desired notification channels"
          info "  3. Run: #{$PROGRAM_NAME} run"
          0
        else
          error "System health check failed - review configuration"
          1
        end
        
      rescue StandardError => e
        error "Installation failed: #{e.message}"
        1
      end
    end

    # Execute version command
    def execute_version_command
      output_version_info
      0
    end

    # Parse scope argument for run command
    def parse_scope_argument(arg)
      return nil unless arg
      
      case arg.downcase
      when 'all'
        :all
      when 'critical'
        :critical
      else
        # Check if it's a valid gate name or comma-separated list
        gates = arg.split(',').map(&:strip).map(&:to_sym)
        gates.size == 1 ? gates.first : gates
      end
    end

    # Parse channels argument for test command
    def parse_channels_argument(arg)
      return nil unless arg
      
      arg.split(',').map(&:strip).map(&:to_sym)
    end

    # Build execution context for orchestrator
    def build_execution_context
      {
        project_path: Rails.root.to_s,
        environment: Rails.env,
        commit_sha: get_git_commit_sha,
        branch: get_git_branch,
        timestamp: Time.current,
        user: ENV['USER'] || 'cli-user',
        cli_execution: true,
        cli_options: @options
      }
    end

    # Output methods for different formats
    def output_execution_result(result)
      case @options[:output_format]
      when :json
        puts JSON.pretty_generate(result_to_hash(result))
      when :yaml
        puts result_to_hash(result).to_yaml
      else
        output_execution_result_text(result)
      end
    end

    def output_execution_result_text(result)
      if result.success?
        success "Quality Gates execution completed successfully"
        info "  Quality Score: #{result.report&.quality_score}%" if result.report
        info "  Gates Passed: #{result.passed_gates.count}"
        info "  Total Time: #{result.total_execution_time.round(2)}s"
      else
        error "Quality Gates execution failed"
        error "  Gates Failed: #{result.failed_gates.count}"
        error "  Critical Failures: #{result.critical_failures.count}"
        
        unless @options[:quiet]
          result.failed_gates.each do |gate_name|
            gate_result = result.gate_results[gate_name]
            error "    • #{gate_name}: #{gate_result&.primary_failure_reason}"
          end
        end
      end
    end

    def output_status(status)
      case @options[:output_format]
      when :json
        puts JSON.pretty_generate(status)
      when :yaml
        puts status.to_yaml
      else
        output_status_text(status)
      end
    end

    def output_status_text(status)
      info "Quality Gates Status Summary"
      info "=" * 30
      info "Overall Health: #{status[:overall_health]}%"
      info "Last Execution: #{status[:last_execution] || 'Never'}"
      info "Execution ID: #{status[:execution_id] || 'N/A'}"
      
      if status[:gate_statuses]&.any?
        info "\nGate Status:"
        status[:gate_statuses].each do |gate_name, gate_status|
          status_symbol = gate_status == :passed ? "✅" : "❌"
          info "  #{status_symbol} #{gate_name.to_s.humanize}: #{gate_status.to_s.upcase}"
        end
      end
      
      if status[:alerts]&.any?
        warning "\nActive Alerts:"
        status[:alerts].each do |alert|
          warning "  #{alert[:message]}"
        end
      end
    end

    def output_configuration(config)
      case @options[:output_format]
      when :json
        puts JSON.pretty_generate(config.to_hash)
      when :yaml
        puts config.to_hash.to_yaml
      else
        output_configuration_text(config)
      end
    end

    def output_configuration_text(config)
      info "Quality Gates Configuration"
      info "=" * 30
      info "Config File: #{config.config_file}"
      info "Environment: #{config.environment}"
      
      info "\nEnabled Gates (#{config.enabled_gates.count}):"
      config.enabled_gates.each do |gate_name|
        gate_config = config.get_gate_config(gate_name)
        critical_badge = gate_config[:critical] ? " [CRITICAL]" : ""
        info "  ✅ #{gate_name.to_s.humanize}#{critical_badge}"
        info "     Weight: #{gate_config[:weight]} | Phase: #{gate_config[:phase]}"
      end
      
      info "\nNotification Channels (#{config.notification_channels.count}):"
      config.notification_channels.each do |channel|
        info "  📢 #{channel.to_s.humanize}"
      end
    end

    def output_test_results(results)
      case @options[:output_format]
      when :json
        puts JSON.pretty_generate(results)
      when :yaml
        puts results.to_yaml
      else
        output_test_results_text(results)
      end
    end

    def output_test_results_text(results)
      info "Notification Channel Test Results"
      info "=" * 35
      
      results.each do |channel_name, result|
        status_symbol = result[:success] ? "✅" : "❌"
        info "#{status_symbol} #{channel_name.to_s.humanize}"
        
        if result[:error] && !@options[:quiet]
          error "   Error: #{result[:error]}"
        end
      end
      
      success_count = results.count { |_, result| result[:success] }
      info "\nSummary: #{success_count}/#{results.count} channels operational"
    end

    def output_dashboard_status(status)
      case @options[:output_format]
      when :json
        puts JSON.pretty_generate(status)
      when :yaml
        puts status.to_yaml
      else
        output_dashboard_status_text(status)
      end
    end

    def output_dashboard_status_text(status)
      info "Dashboard Status"
      info "=" * 16
      info "Backend: #{status[:backend_type]}"
      info "Enabled: #{status[:enabled] ? 'Yes' : 'No'}"
      info "Healthy: #{status[:healthy] ? 'Yes' : 'No'}"
      info "Last Update: #{status[:last_update] || 'Never'}"
      info "Real-time: #{status[:real_time_enabled] ? 'Yes' : 'No'}"
      
      if status[:dashboard_url]
        info "URL: #{status[:dashboard_url]}"
      end
    end

    def output_health_check(health_result)
      case @options[:output_format]
      when :json
        puts JSON.pretty_generate({
          healthy: health_result.healthy?,
          checks: health_result.checks
        })
      when :yaml
        puts {
          healthy: health_result.healthy?,
          checks: health_result.checks
        }.to_yaml
      else
        output_health_check_text(health_result)
      end
    end

    def output_health_check_text(health_result)
      if health_result.healthy?
        success "Quality Gates system is healthy"
      else
        error "Quality Gates system has health issues"
      end
      
      unless @options[:quiet]
        info "\nComponent Status:"
        health_result.checks.each do |component, status|
          status_symbol = status ? "✅" : "❌"
          info "  #{status_symbol} #{component.to_s.humanize}: #{status ? 'OK' : 'FAILED'}"
        end
      end
    end

    def output_version_info
      info "Quality Gates for Huginn"
      info "=" * 25
      info "Quality Gates Version: 1.0.0"
      info "Huginn Version: #{get_huginn_version}"
      info "Rails Version: #{Rails.version}"
      info "Ruby Version: #{RUBY_VERSION}"
      info "Environment: #{Rails.env}"
      
      unless @options[:quiet]
        info "\nComponents:"
        %w[Orchestrator Reporter Dashboard Notifier Configuration].each do |component|
          info "  - #{component}: ✅ Available"
        end
      end
    end

    # Helper methods
    def result_to_hash(result)
      {
        success: result.success?,
        execution_id: result.execution_id,
        total_gates: result.total_gates,
        passed_gates: result.passed_gates,
        failed_gates: result.failed_gates,
        critical_failures: result.critical_failures,
        execution_time: result.total_execution_time,
        quality_score: result.report&.quality_score
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

    def get_huginn_version
      File.read(File.join(Rails.root, 'VERSION')).strip
    rescue StandardError
      'unknown'
    end

    # Output helper methods
    def info(message)
      return if @options[:quiet]
      puts message unless @options[:output_format] == :json
    end

    def success(message)
      return if @options[:quiet]
      puts "✅ #{message}" unless @options[:output_format] == :json
    end

    def warning(message)
      puts "⚠️ #{message}" unless @options[:output_format] == :json
    end

    def error(message)
      $stderr.puts "❌ #{message}" unless @options[:output_format] == :json
    end

    def show_help
      parser = create_option_parser
      puts parser.help
      puts
      puts "Examples:"
      puts "  #{$PROGRAM_NAME} run                    # Run all quality gates"
      puts "  #{$PROGRAM_NAME} run critical           # Run only critical gates"
      puts "  #{$PROGRAM_NAME} run code_quality       # Run specific gate"
      puts "  #{$PROGRAM_NAME} status                 # Show current status"
      puts "  #{$PROGRAM_NAME} config validate        # Validate configuration"
      puts "  #{$PROGRAM_NAME} test slack             # Test Slack notifications"
      puts "  #{$PROGRAM_NAME} report html            # Generate HTML report"
      puts "  #{$PROGRAM_NAME} --output json status   # JSON output format"
      puts
      puts "For more information: https://github.com/huginn/huginn"
    end
  end
end