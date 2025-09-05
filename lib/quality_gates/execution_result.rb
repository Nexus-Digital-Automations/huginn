# frozen_string_literal: true

module QualityGates
  # Container for execution results from quality gates orchestrator
  # Provides comprehensive information about gate execution outcomes
  class ExecutionResult
    attr_reader :execution_context, :gate_results, :started_at, :completed_at

    def initialize(execution_context)
      @execution_context = execution_context
      @gate_results = {}
      @started_at = Time.now
      @completed_at = nil
    end

    # Add result from individual gate execution
    def add_gate_result(gate_name, gate_result)
      @gate_results[gate_name] = gate_result
    end

    # Mark execution as completed
    def complete!
      @completed_at = Time.now
    end

    # Check if execution was successful (no critical failures)
    def success?
      critical_failures.empty?
    end

    # Check if execution has any failures
    def has_failures?
      !failed_gates.empty?
    end

    # Get list of passed gates
    def passed_gates
      @gate_results.select { |_, result| result.passed? }.keys
    end

    # Get list of failed gates
    def failed_gates
      @gate_results.select { |_, result| result.failed? }.keys
    end

    # Get critical failures (failed gates marked as critical)
    def critical_failures
      failed_gates.select do |gate_name|
        # Would need configuration reference to check if gate is critical
        # For now, assume any failure could be critical
        true
      end
    end

    # Get total number of gates executed
    def total_gates
      @gate_results.count
    end

    # Get total execution time
    def total_execution_time
      return 0 unless @completed_at && @started_at
      @completed_at - @started_at
    end

    # Get execution ID
    def execution_id
      @execution_context[:execution_id]
    end

    # Get report data
    def report
      return nil unless @gate_results.any?
      
      # Create a simple report object
      OpenStruct.new(
        quality_score: calculate_quality_score,
        execution_id: execution_id,
        success?: success?
      )
    end

    private

    def calculate_quality_score
      return 100 if @gate_results.empty?
      
      passed = passed_gates.count
      total = total_gates
      
      ((passed.to_f / total) * 100).round(2)
    end
  end

  # Individual gate execution result
  class GateResult
    attr_reader :gate_name, :status, :execution_time, :details, :metrics, :context

    def initialize(gate_name:, status:, execution_time:, details: {}, metrics: {}, context: {})
      @gate_name = gate_name
      @status = status.to_sym
      @execution_time = execution_time
      @details = details || {}
      @metrics = metrics || {}
      @context = context || {}
    end

    def passed?
      @status == :passed
    end

    def failed?
      @status != :passed
    end

    def primary_failure_reason
      return nil if passed?
      
      @details[:error] || 
      @details[:message] ||
      @details.dig(:errors, 0) ||
      "Gate execution failed"
    end

    def recommendations
      @details[:recommendations] || []
    end

    def has_improvement_suggestions?
      @details[:improvements]&.any? || false
    end

    def improvement_suggestions
      @details[:improvements] || []
    end
  end

  # Health check result container
  class HealthCheck
    def initialize
      @checks = {}
    end

    def add_check(component, status)
      @checks[component] = status
    end

    def healthy?
      @checks.values.all?
    end

    def checks
      @checks
    end

    def passed_checks
      @checks.select { |_, status| status }
    end

    def failed_checks
      @checks.select { |_, status| !status }
    end
  end
end