# frozen_string_literal: true

require_relative 'completeness_validator'
require_relative 'integration_tester'
require_relative 'performance_validator'
require_relative 'security_validator'
require_relative 'rollback_validator'

module QualityGates
  # Pre-Completion Validation System
  #
  # This class orchestrates comprehensive validation before feature completion,
  # ensuring all acceptance criteria are met, performance targets achieved,
  # security requirements satisfied, and deployment readiness verified.
  #
  # @example Basic usage
  #   validator = QualityGates::PreCompletion.new(
  #     feature_name: 'User Authentication',
  #     acceptance_criteria: ['Login works', 'Logout works', 'Session management'],
  #     performance_targets: { response_time: 200 }
  #   )
  #   result = validator.validate_all
  #   puts result.success? ? "Ready for deployment" : "Issues found: #{result.failures}"
  #
  # @author Claude Code Assistant
  # @since 2025-09-05
  class PreCompletion
    # Validation configuration structure
    ValidationConfig = Struct.new(
      :feature_name,
      :acceptance_criteria,
      :performance_targets,
      :security_requirements,
      :rollback_strategy,
      :integration_tests,
      keyword_init: true
    )

    # Validation result structure
    ValidationResult = Struct.new(
      :success,
      :completeness_result,
      :integration_result,
      :performance_result,
      :security_result,
      :rollback_result,
      :failures,
      :execution_time,
      keyword_init: true
    ) do
      def success?
        success
      end

      def failure_summary
        failures.map { |f| "#{f[:validator]}: #{f[:message]}" }.join(', ')
      end
    end

    attr_reader :config, :logger, :report_dir

    # Initialize Pre-Completion Validation
    #
    # @param config [Hash] Validation configuration
    # @option config [String] :feature_name Name of the feature being validated
    # @option config [Array<String>] :acceptance_criteria List of acceptance criteria
    # @option config [Hash] :performance_targets Performance thresholds (response_time, memory_usage)
    # @option config [Hash] :security_requirements Security validation requirements
    # @option config [Hash] :rollback_strategy Deployment rollback configuration
    # @option config [Array<String>] :integration_tests List of integration test patterns
    def initialize(config = {})
      @config = ValidationConfig.new(config)
      @logger = setup_logger
      @report_dir = File.join(Rails.root, 'development', 'reports')
      ensure_report_directory
      
      @logger.info "[PreCompletion] Initialized validation for feature: #{@config.feature_name}"
    end

    # Execute comprehensive pre-completion validation
    #
    # Orchestrates all validation phases in the correct order:
    # 1. Feature Completeness Validation
    # 2. Integration Testing
    # 3. Performance Verification
    # 4. Security Validation
    # 5. Rollback Readiness Testing
    #
    # @return [ValidationResult] Comprehensive validation results
    def validate_all
      start_time = Time.now
      @logger.info "[PreCompletion] Starting comprehensive validation for #{@config.feature_name}"

      result = ValidationResult.new(
        success: true,
        failures: [],
        execution_time: nil
      )

      # Phase 1: Feature Completeness Validation
      @logger.info "[PreCompletion] Phase 1: Feature Completeness Validation"
      result.completeness_result = validate_completeness
      add_failures(result, result.completeness_result, 'Completeness')

      # Phase 2: Integration Testing
      @logger.info "[PreCompletion] Phase 2: Integration Testing"
      result.integration_result = validate_integration
      add_failures(result, result.integration_result, 'Integration')

      # Phase 3: Performance Verification
      @logger.info "[PreCompletion] Phase 3: Performance Verification"
      result.performance_result = validate_performance
      add_failures(result, result.performance_result, 'Performance')

      # Phase 4: Security Validation
      @logger.info "[PreCompletion] Phase 4: Security Validation"
      result.security_result = validate_security
      add_failures(result, result.security_result, 'Security')

      # Phase 5: Rollback Readiness Testing
      @logger.info "[PreCompletion] Phase 5: Rollback Readiness Testing"
      result.rollback_result = validate_rollback_readiness
      add_failures(result, result.rollback_result, 'Rollback')

      result.execution_time = Time.now - start_time
      result.success = result.failures.empty?

      log_final_results(result)
      generate_validation_report(result)

      result
    end

    # Execute only feature completeness validation
    #
    # @return [Hash] Completeness validation result
    def validate_completeness
      @logger.info "[PreCompletion] Executing feature completeness validation"
      
      validator = CompletenessValidator.new(
        feature_name: @config.feature_name,
        acceptance_criteria: @config.acceptance_criteria || [],
        logger: @logger
      )
      
      validator.validate
    end

    # Execute only integration testing
    #
    # @return [Hash] Integration testing result
    def validate_integration
      @logger.info "[PreCompletion] Executing integration testing"
      
      tester = IntegrationTester.new(
        feature_name: @config.feature_name,
        integration_tests: @config.integration_tests || [],
        logger: @logger
      )
      
      tester.run_tests
    end

    # Execute only performance validation
    #
    # @return [Hash] Performance validation result
    def validate_performance
      @logger.info "[PreCompletion] Executing performance validation"
      
      validator = PerformanceValidator.new(
        feature_name: @config.feature_name,
        performance_targets: @config.performance_targets || {},
        logger: @logger
      )
      
      validator.validate
    end

    # Execute only security validation
    #
    # @return [Hash] Security validation result
    def validate_security
      @logger.info "[PreCompletion] Executing security validation"
      
      validator = SecurityValidator.new(
        feature_name: @config.feature_name,
        security_requirements: @config.security_requirements || {},
        logger: @logger
      )
      
      validator.validate
    end

    # Execute only rollback readiness validation
    #
    # @return [Hash] Rollback validation result
    def validate_rollback_readiness
      @logger.info "[PreCompletion] Executing rollback readiness validation"
      
      validator = RollbackValidator.new(
        feature_name: @config.feature_name,
        rollback_strategy: @config.rollback_strategy || {},
        logger: @logger
      )
      
      validator.validate
    end

    # Generate comprehensive validation report
    #
    # @param result [ValidationResult] Validation results to report
    # @return [String] Path to generated report file
    def generate_validation_report(result)
      timestamp = Time.now.strftime('%Y%m%d_%H%M%S')
      report_file = File.join(
        @report_dir,
        "pre_completion_validation_#{@config.feature_name&.parameterize || 'unknown'}_#{timestamp}.md"
      )

      File.open(report_file, 'w') do |f|
        f.write(build_report_content(result))
      end

      @logger.info "[PreCompletion] Validation report generated: #{report_file}"
      report_file
    end

    private

    # Set up structured logging for validation process
    #
    # @return [Logger] Configured logger instance
    def setup_logger
      logger = Logger.new($stdout)
      logger.level = Logger::INFO
      logger.formatter = proc do |severity, datetime, _progname, msg|
        "[#{datetime.strftime('%Y-%m-%d %H:%M:%S')}] #{severity}: #{msg}\n"
      end
      logger
    end

    # Ensure report directory exists
    def ensure_report_directory
      FileUtils.mkdir_p(@report_dir) unless Dir.exist?(@report_dir)
    end

    # Add validation failures to the result
    #
    # @param result [ValidationResult] Main result object
    # @param validation_result [Hash] Individual validation result
    # @param validator_name [String] Name of the validator
    def add_failures(result, validation_result, validator_name)
      return if validation_result[:success]

      validation_result[:failures]&.each do |failure|
        result.failures << {
          validator: validator_name,
          message: failure,
          timestamp: Time.now
        }
      end
    end

    # Log final validation results
    #
    # @param result [ValidationResult] Validation results
    def log_final_results(result)
      if result.success?
        @logger.info "[PreCompletion] ✅ All validations passed for #{@config.feature_name}"
        @logger.info "[PreCompletion] Execution time: #{result.execution_time.round(2)}s"
      else
        @logger.error "[PreCompletion] ❌ Validation failures detected for #{@config.feature_name}"
        @logger.error "[PreCompletion] Failure count: #{result.failures.length}"
        @logger.error "[PreCompletion] Summary: #{result.failure_summary}"
      end
    end

    # Build comprehensive validation report content
    #
    # @param result [ValidationResult] Validation results
    # @return [String] Formatted report content
    def build_report_content(result)
      <<~MARKDOWN
        # Pre-Completion Validation Report

        **Feature:** #{@config.feature_name || 'Unknown'}  
        **Timestamp:** #{Time.now.strftime('%Y-%m-%d %H:%M:%S')}  
        **Execution Time:** #{result.execution_time&.round(2)}s  
        **Overall Status:** #{result.success? ? '✅ PASSED' : '❌ FAILED'}

        ## Summary

        #{result.success? ? 'All validation phases completed successfully. Feature is ready for deployment.' : "Validation failed with #{result.failures.length} issue(s) requiring attention before deployment."}

        ## Validation Phases

        ### 1. Feature Completeness
        **Status:** #{result.completeness_result&.dig(:success) ? '✅ PASSED' : '❌ FAILED'}
        #{format_phase_details(result.completeness_result)}

        ### 2. Integration Testing  
        **Status:** #{result.integration_result&.dig(:success) ? '✅ PASSED' : '❌ FAILED'}
        #{format_phase_details(result.integration_result)}

        ### 3. Performance Validation
        **Status:** #{result.performance_result&.dig(:success) ? '✅ PASSED' : '❌ FAILED'}
        #{format_phase_details(result.performance_result)}

        ### 4. Security Validation
        **Status:** #{result.security_result&.dig(:success) ? '✅ PASSED' : '❌ FAILED'}
        #{format_phase_details(result.security_result)}

        ### 5. Rollback Readiness
        **Status:** #{result.rollback_result&.dig(:success) ? '✅ PASSED' : '❌ FAILED'}
        #{format_phase_details(result.rollback_result)}

        ## Failure Details

        #{format_failures(result.failures)}

        ## Recommendations

        #{generate_recommendations(result)}

        ---
        *Report generated by Huginn Pre-Completion Validation System*
      MARKDOWN
    end

    # Format phase details for report
    #
    # @param phase_result [Hash] Phase validation result
    # @return [String] Formatted phase details
    def format_phase_details(phase_result)
      return "No details available" unless phase_result

      details = []
      details << "- **Checks Run:** #{phase_result[:checks_run] || 0}"
      details << "- **Duration:** #{phase_result[:execution_time]&.round(2)}s" if phase_result[:execution_time]
      details << "- **Details:** #{phase_result[:details]}" if phase_result[:details]

      details.join("\n")
    end

    # Format failure details for report
    #
    # @param failures [Array<Hash>] List of validation failures
    # @return [String] Formatted failure list
    def format_failures(failures)
      return "No failures detected." if failures.empty?

      failures.map.with_index(1) do |failure, index|
        "#{index}. **#{failure[:validator]}:** #{failure[:message]}"
      end.join("\n")
    end

    # Generate recommendations based on validation results
    #
    # @param result [ValidationResult] Validation results
    # @return [String] Formatted recommendations
    def generate_recommendations(result)
      return "Feature is ready for deployment. No additional actions required." if result.success?

      recommendations = []
      recommendations << "1. Address all validation failures listed above before deployment"
      recommendations << "2. Re-run validation after fixes to ensure all issues are resolved"
      recommendations << "3. Consider reviewing feature requirements if multiple phases failed"
      recommendations << "4. Consult with security team if security validation failed"
      recommendations << "5. Verify rollback procedures are properly documented and tested"

      recommendations.join("\n")
    end
  end
end