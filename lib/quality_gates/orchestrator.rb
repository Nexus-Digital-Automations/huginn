# frozen_string_literal: true

require 'logger'
require 'yaml'
require 'json'

module QualityGates
  # Central orchestrator that coordinates all quality gate components and provides
  # unified management for quality validation phases across the Huginn application
  #
  # Usage:
  #   orchestrator = QualityGates::Orchestrator.new
  #   result = orchestrator.run_quality_gates(:all)
  #   puts result.success? ? "All gates passed" : "Failures: #{result.failures}"
  #
  # Dependencies: reporter, configuration, dashboard, notifier
  # Outputs: Structured quality reports, notifications, dashboard updates
  class Orchestrator
    attr_reader :configuration, :reporter, :dashboard, :notifier, :logger

    # Quality gate execution phases
    PHASES = %i[pre_implementation during_implementation completion monitoring].freeze
    
    # Quality gate categories for validation
    CATEGORIES = %i[
      code_quality 
      security 
      performance 
      testing 
      documentation 
      dependencies 
      deployment 
      monitoring
    ].freeze

    def initialize(options = {})
      @configuration = options[:configuration] || Configuration.new
      @reporter = options[:reporter] || Reporter.new(@configuration)
      @dashboard = options[:dashboard] || Dashboard.new(@configuration)
      @notifier = options[:notifier] || Notifier.new(@configuration)
      @logger = setup_logger
      @execution_context = {}
      @gate_results = {}
      
      log_info("Quality Gates Orchestrator initialized", {
        config_file: @configuration.config_file,
        enabled_gates: @configuration.enabled_gates.count,
        notification_channels: @configuration.notification_channels.count
      })
    end

    # Execute quality gates for specified phase or category
    # @param scope [Symbol, Array<Symbol>] - phase/category or array of them (:all for everything)
    # @param context [Hash] - execution context (project_path, commit_sha, etc.)
    # @return [QualityGates::ExecutionResult] - comprehensive results object
    def run_quality_gates(scope = :all, context = {})
      start_time = Time.now
      @execution_context = context.merge(
        execution_id: generate_execution_id,
        started_at: start_time,
        orchestrator_version: '1.0.0'
      )

      log_info("Starting quality gates execution", {
        scope: scope,
        execution_id: @execution_context[:execution_id],
        context_keys: context.keys
      })

      # Initialize execution tracking
      @gate_results = {}
      gates_to_run = determine_gates_to_run(scope)

      # Validate prerequisites
      validate_prerequisites(gates_to_run)

      # Execute gates in dependency order
      execution_result = execute_gates_sequentially(gates_to_run)

      # Generate comprehensive reports
      report_data = @reporter.generate_comprehensive_report(@gate_results, @execution_context)

      # Update dashboard with latest metrics
      @dashboard.update_quality_metrics(@gate_results, report_data)

      # Send notifications for any failures
      if execution_result.has_failures?
        @notifier.notify_quality_gate_failures(execution_result, @gate_results)
      end

      # Log completion metrics
      execution_time = Time.now - start_time
      log_info("Quality gates execution completed", {
        execution_id: @execution_context[:execution_id],
        total_gates: gates_to_run.count,
        passed: execution_result.passed_gates.count,
        failed: execution_result.failed_gates.count,
        execution_time_seconds: execution_time.round(2),
        overall_success: execution_result.success?
      })

      execution_result
    end

    # Execute specific quality gate by name
    # @param gate_name [Symbol] - name of the specific gate to run
    # @param gate_config [Hash] - specific configuration for this gate
    # @return [QualityGates::GateResult] - individual gate result
    def run_specific_gate(gate_name, gate_config = {})
      log_info("Executing specific quality gate", { gate: gate_name })
      
      gate_context = @execution_context.merge(
        gate_name: gate_name,
        gate_config: gate_config,
        execution_type: 'individual'
      )

      gate_result = execute_individual_gate(gate_name, gate_config, gate_context)
      @gate_results[gate_name] = gate_result

      # Update dashboard with individual gate result
      @dashboard.update_individual_gate_status(gate_name, gate_result)

      gate_result
    end

    # Get current quality status across all gates
    # @return [Hash] - current status summary
    def get_current_quality_status
      {
        overall_health: calculate_overall_health_score,
        gate_statuses: @gate_results.transform_values(&:status),
        last_execution: @execution_context[:started_at],
        execution_id: @execution_context[:execution_id],
        trending: calculate_quality_trends,
        alerts: get_active_quality_alerts
      }
    end

    # Validate system health and quality gate readiness
    # @return [QualityGates::HealthCheck] - system health status
    def health_check
      log_info("Performing quality gates health check")

      health_result = HealthCheck.new
      
      # Check configuration validity
      health_result.add_check(:configuration, @configuration.valid?)
      
      # Check reporter availability
      health_result.add_check(:reporter, @reporter.available?)
      
      # Check dashboard connectivity
      health_result.add_check(:dashboard, @dashboard.healthy?)
      
      # Check notifier channels
      health_result.add_check(:notifications, @notifier.channels_available?)
      
      # Check file system access
      health_result.add_check(:file_system, check_file_system_access)
      
      # Check external dependencies
      health_result.add_check(:dependencies, check_external_dependencies)

      log_info("Health check completed", {
        overall_healthy: health_result.healthy?,
        passed_checks: health_result.passed_checks.count,
        failed_checks: health_result.failed_checks.count
      })

      health_result
    end

    private

    # Set up structured logging for orchestrator operations
    def setup_logger
      logger = Logger.new($stdout)
      logger.level = @configuration.log_level || Logger::INFO
      logger.formatter = proc do |severity, datetime, progname, msg|
        log_entry = {
          timestamp: datetime.iso8601,
          level: severity,
          component: 'QualityGates::Orchestrator',
          message: msg.is_a?(Hash) ? msg[:message] : msg.to_s
        }
        
        # Add structured data if message is a hash
        log_entry.merge!(msg) if msg.is_a?(Hash) && msg[:message]
        
        "#{JSON.generate(log_entry)}\n"
      end
      logger
    end

    # Generate unique execution identifier for tracking
    def generate_execution_id
      "qg_#{Time.now.to_i}_#{SecureRandom.hex(4)}"
    end

    # Determine which quality gates to run based on scope
    def determine_gates_to_run(scope)
      case scope
      when :all
        @configuration.enabled_gates
      when Symbol
        gates_for_scope(scope)
      when Array
        scope.flat_map { |s| gates_for_scope(s) }.uniq
      else
        raise ArgumentError, "Invalid scope: #{scope}. Must be Symbol, Array, or :all"
      end
    end

    # Get gates for a specific scope (phase or category)
    def gates_for_scope(scope)
      if PHASES.include?(scope)
        @configuration.gates_for_phase(scope)
      elsif CATEGORIES.include?(scope)
        @configuration.gates_for_category(scope)
      else
        [@configuration.get_gate_config(scope)].compact
      end
    end

    # Validate that all prerequisites for gate execution are met
    def validate_prerequisites(gates_to_run)
      log_info("Validating prerequisites for gate execution", { gate_count: gates_to_run.count })

      gates_to_run.each do |gate_name|
        gate_config = @configuration.get_gate_config(gate_name)
        
        if gate_config[:dependencies]
          validate_gate_dependencies(gate_name, gate_config[:dependencies])
        end
        
        if gate_config[:prerequisites]
          validate_gate_prerequisites(gate_name, gate_config[:prerequisites])
        end
      end
    end

    # Validate dependencies for a specific gate
    def validate_gate_dependencies(gate_name, dependencies)
      dependencies.each do |dependency|
        unless @configuration.gate_enabled?(dependency)
          raise QualityGates::DependencyError, 
                "Gate '#{gate_name}' requires '#{dependency}' but it's not enabled"
        end
      end
    end

    # Validate prerequisites for a specific gate
    def validate_gate_prerequisites(gate_name, prerequisites)
      prerequisites.each do |prerequisite, requirement|
        case prerequisite
        when 'file_exists'
          unless File.exist?(requirement)
            raise QualityGates::PrerequisiteError,
                  "Gate '#{gate_name}' requires file '#{requirement}' but it doesn't exist"
          end
        when 'command_available'
          unless system("which #{requirement} > /dev/null 2>&1")
            raise QualityGates::PrerequisiteError,
                  "Gate '#{gate_name}' requires command '#{requirement}' but it's not available"
          end
        when 'environment_variable'
          unless ENV[requirement]
            raise QualityGates::PrerequisiteError,
                  "Gate '#{gate_name}' requires environment variable '#{requirement}'"
          end
        end
      end
    end

    # Execute gates in proper dependency order
    def execute_gates_sequentially(gates_to_run)
      execution_result = ExecutionResult.new(@execution_context)
      
      # Sort gates by dependency order
      ordered_gates = sort_gates_by_dependencies(gates_to_run)

      ordered_gates.each do |gate_name|
        gate_config = @configuration.get_gate_config(gate_name)
        
        log_info("Executing quality gate", { gate: gate_name })
        
        gate_result = execute_individual_gate(gate_name, gate_config, @execution_context)
        @gate_results[gate_name] = gate_result
        execution_result.add_gate_result(gate_name, gate_result)

        # Stop execution if critical gate fails and fail_fast is enabled
        if gate_result.failed? && gate_config[:critical] && @configuration.fail_fast?
          log_info("Critical gate failed, stopping execution", { gate: gate_name })
          break
        end
      end

      execution_result
    end

    # Execute an individual quality gate
    def execute_individual_gate(gate_name, gate_config, context)
      start_time = Time.now
      
      begin
        # Load and instantiate gate validator
        validator_class = load_gate_validator(gate_name, gate_config)
        validator = validator_class.new(gate_config, context)

        # Execute the gate validation
        validation_result = validator.validate

        # Create gate result with metrics
        gate_result = GateResult.new(
          gate_name: gate_name,
          status: validation_result.success? ? :passed : :failed,
          execution_time: Time.now - start_time,
          details: validation_result.details,
          metrics: validation_result.metrics,
          context: context
        )

        log_info("Gate execution completed", {
          gate: gate_name,
          status: gate_result.status,
          execution_time: gate_result.execution_time.round(3),
          has_metrics: !gate_result.metrics.empty?
        })

        gate_result

      rescue StandardError => e
        log_error("Gate execution failed with error", {
          gate: gate_name,
          error: e.message,
          backtrace: e.backtrace.first(5)
        })

        GateResult.new(
          gate_name: gate_name,
          status: :error,
          execution_time: Time.now - start_time,
          details: { error: e.message, backtrace: e.backtrace },
          metrics: {},
          context: context
        )
      end
    end

    # Load the appropriate validator class for a gate
    def load_gate_validator(gate_name, gate_config)
      validator_name = gate_config[:validator] || "#{gate_name.to_s.camelize}Validator"
      
      begin
        "QualityGates::Validators::#{validator_name}".constantize
      rescue NameError
        # Fall back to a generic validator if specific one doesn't exist
        QualityGates::Validators::GenericValidator
      end
    end

    # Sort gates by their dependency relationships
    def sort_gates_by_dependencies(gates)
      # Simple topological sort implementation
      sorted = []
      remaining = gates.dup
      
      while remaining.any?
        gates_without_deps = remaining.select do |gate|
          deps = @configuration.get_gate_config(gate)[:dependencies] || []
          (deps & remaining).empty?
        end
        
        if gates_without_deps.empty?
          # Circular dependency detected, add remaining gates as-is
          sorted.concat(remaining)
          break
        end
        
        sorted.concat(gates_without_deps)
        remaining -= gates_without_deps
      end
      
      sorted
    end

    # Calculate overall health score based on gate results
    def calculate_overall_health_score
      return 100 if @gate_results.empty?

      total_weight = 0
      weighted_score = 0

      @gate_results.each do |gate_name, result|
        gate_config = @configuration.get_gate_config(gate_name)
        weight = gate_config[:weight] || 1
        
        total_weight += weight
        weighted_score += weight * (result.passed? ? 100 : 0)
      end

      (weighted_score.to_f / total_weight).round(2)
    end

    # Calculate quality trends based on historical data
    def calculate_quality_trends
      # This would integrate with historical reporting data
      {
        trend_direction: :stable, # :improving, :declining, :stable
        score_change: 0,
        period: '24h'
      }
    end

    # Get current active quality alerts
    def get_active_quality_alerts
      alerts = []
      
      @gate_results.each do |gate_name, result|
        if result.failed?
          gate_config = @configuration.get_gate_config(gate_name)
          
          alerts << {
            gate: gate_name,
            severity: gate_config[:critical] ? :critical : :warning,
            message: result.primary_failure_reason,
            timestamp: result.context[:started_at]
          }
        end
      end

      alerts
    end

    # Check file system access for reports and logs
    def check_file_system_access
      begin
        test_file = File.join(@configuration.reports_directory, '.health_check')
        File.write(test_file, 'test')
        File.delete(test_file)
        true
      rescue StandardError
        false
      end
    end

    # Check external dependencies availability
    def check_external_dependencies
      # Check common external tools availability
      dependencies = %w[git ruby bundle]
      dependencies.all? { |dep| system("which #{dep} > /dev/null 2>&1") }
    end

    # Structured logging helpers
    def log_info(message, data = {})
      @logger.info(data.merge(message: message))
    end

    def log_error(message, data = {})
      @logger.error(data.merge(message: message))
    end
  end
end