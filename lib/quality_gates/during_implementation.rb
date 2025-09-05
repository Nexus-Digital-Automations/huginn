# frozen_string_literal: true

require_relative 'utils'
require_relative 'interface_validator'
require_relative 'error_boundary_validator'
require_relative 'integration_validator'
require_relative 'documentation_validator'
require_relative 'observability_validator'
require_relative '../security_validation/vulnerability_scanner'
require_relative '../security_validation/auth_validator'
require_relative '../security_validation/data_protection_validator'
require_relative '../security_validation/compliance_checker'

module QualityGates
  # Main orchestrator for during-implementation quality gates
  # Coordinates all validation systems to ensure code quality during development
  class DuringImplementation
    include Utils

    attr_reader :project_root, :validation_results, :logger

    def initialize(project_root = Rails.root)
      @project_root = Pathname.new(project_root)
      @validation_results = {}
      @logger = setup_logger
      log_operation_start('DuringImplementation validation system initialized')
    end

    # Run all during-implementation validation checks
    # @return [ValidationResult] Combined results from all validators
    def validate_all
      log_operation_start('Running comprehensive during-implementation validation')
      start_time = Time.now

      validators = {
        interface: InterfaceValidator.new(project_root),
        error_boundary: ErrorBoundaryValidator.new(project_root),
        integration: IntegrationValidator.new(project_root),
        documentation: DocumentationValidator.new(project_root),
        observability: ObservabilityValidator.new(project_root),
        security_vulnerability: SecurityValidation::VulnerabilityScanner.new(project_root),
        security_auth: SecurityValidation::AuthValidator.new(project_root),
        security_data_protection: SecurityValidation::DataProtectionValidator.new(project_root),
        security_compliance: SecurityValidation::ComplianceChecker.new(project_root)
      }

      validation_results = {}
      validators.each do |name, validator|
        begin
          log_operation_step("Running #{name} validation")
          
          # Call appropriate validation method based on validator type
          case name
          when :security_vulnerability
            validation_results[name] = validator.scan_all_vulnerabilities
          when :security_auth
            validation_results[name] = validator.validate_authentication_security
          when :security_data_protection
            validation_results[name] = validator.validate_data_protection
          when :security_compliance
            validation_results[name] = validator.validate_security_compliance
          else
            validation_results[name] = validator.validate
          end
          
          log_validation_summary(name, validation_results[name])
        rescue StandardError => e
          log_validation_error(name, e)
          validation_results[name] = create_error_result(name, e)
        end
      end

      combined_result = combine_validation_results(validation_results)
      log_operation_completion('During-implementation validation', start_time, combined_result)

      combined_result
    end

    # Run validation for specific component types
    # @param component_types [Array<Symbol>] List of component types to validate
    def validate_components(component_types = [])
      log_operation_start("Running targeted validation for: #{component_types.join(', ')}")
      
      results = {}
      component_types.each do |type|
        validator = create_validator_for_type(type)
        next unless validator

        log_operation_step("Validating #{type} components")
        results[type] = validator.validate
      end

      combine_validation_results(results)
    end

    # Validate specific files or directories
    # @param paths [Array<String>] Paths to validate
    def validate_paths(paths)
      log_operation_start("Validating specific paths: #{paths.join(', ')}")
      
      results = {}
      paths.each do |path|
        file_path = project_root.join(path)
        next unless file_path.exist?

        log_operation_step("Validating path: #{path}")
        results[path] = validate_single_path(file_path)
      end

      combine_validation_results(results)
    end

    # Generate comprehensive validation report
    def generate_report(results = nil)
      results ||= validate_all
      
      log_operation_start('Generating validation report')
      
      report = {
        timestamp: Time.now.iso8601,
        project_root: project_root.to_s,
        overall_status: results.passed? ? 'PASSED' : 'FAILED',
        summary: generate_summary_stats(results),
        detailed_results: results.detailed_results,
        recommendations: generate_recommendations(results),
        metrics: calculate_quality_metrics(results)
      }

      log_operation_completion('Report generation', Time.now - 1.second, results)
      report
    end

    private

    # Set up structured logger for validation operations
    def setup_logger
      logger = Logger.new($stdout)
      logger.level = Logger::INFO
      logger.formatter = proc do |severity, datetime, progname, msg|
        "[#{datetime.strftime('%Y-%m-%d %H:%M:%S')}] [QualityGates] #{severity}: #{msg}\n"
      end
      logger
    end

    # Log the start of a validation operation
    def log_operation_start(operation)
      logger.info("🚀 Starting: #{operation}")
    end

    # Log a validation step
    def log_operation_step(step)
      logger.info("⚙️  Step: #{step}")
    end

    # Log operation completion with timing and results
    def log_operation_completion(operation, start_time, result)
      duration = ((Time.now - start_time) * 1000).round(2)
      status = result.passed? ? '✅ PASSED' : '❌ FAILED'
      logger.info("🏁 Completed: #{operation} in #{duration}ms - #{status}")
      
      unless result.passed?
        result.errors.each { |error| logger.warn("⚠️  Error: #{error}") }
      end
    end

    # Log validation summary for specific validator
    def log_validation_summary(validator_name, result)
      status = result.passed? ? '✅' : '❌'
      error_count = result.errors&.length || 0
      logger.info("#{status} #{validator_name.to_s.humanize}: #{error_count} errors found")
    end

    # Log validation errors
    def log_validation_error(validator_name, error)
      logger.error("💥 #{validator_name.to_s.humanize} validation failed: #{error.message}")
      logger.debug(error.backtrace.join("\n")) if error.backtrace
    end

    # Create error result when validator fails
    def create_error_result(validator_name, error)
      ValidationResult.new(
        passed: false,
        errors: ["#{validator_name.to_s.humanize} validation system failed: #{error.message}"],
        warnings: [],
        details: { exception: error.class.name, message: error.message }
      )
    end

    # Create appropriate validator for component type
    def create_validator_for_type(type)
      case type
      when :interface, :api
        InterfaceValidator.new(project_root)
      when :error, :errors, :error_boundary
        ErrorBoundaryValidator.new(project_root)
      when :integration
        IntegrationValidator.new(project_root)
      when :documentation, :docs
        DocumentationValidator.new(project_root)
      when :observability, :monitoring, :logging
        ObservabilityValidator.new(project_root)
      when :security, :security_validation, :vulnerability
        SecurityValidation::VulnerabilityScanner.new(project_root)
      when :security_auth, :authentication
        SecurityValidation::AuthValidator.new(project_root)
      when :security_data_protection, :data_protection, :encryption
        SecurityValidation::DataProtectionValidator.new(project_root)
      when :security_compliance, :compliance
        SecurityValidation::ComplianceChecker.new(project_root)
      else
        logger.warn("⚠️  Unknown validator type: #{type}")
        nil
      end
    end

    # Validate single file or directory path
    def validate_single_path(file_path)
      if file_path.directory?
        validate_directory(file_path)
      else
        validate_file(file_path)
      end
    end

    # Validate directory contents
    def validate_directory(dir_path)
      ruby_files = Dir.glob(dir_path.join('**/*.rb'))
      results = ruby_files.map { |file| validate_file(Pathname.new(file)) }
      
      combine_validation_results(
        results.each_with_index.to_h { |result, index| [ruby_files[index], result] }
      )
    end

    # Validate single Ruby file
    def validate_file(file_path)
      return unless file_path.extname == '.rb'

      content = file_path.read
      errors = []
      warnings = []

      # Basic syntax and structure validation
      errors << "File is empty" if content.strip.empty?
      warnings << "Missing class or module definition" unless content.match?(/\A.*?(class|module)\s+\w+/m)
      warnings << "No method definitions found" unless content.match?(/def\s+\w+/)

      ValidationResult.new(
        passed: errors.empty?,
        errors: errors,
        warnings: warnings,
        details: { file_path: file_path.to_s, line_count: content.lines.count }
      )
    end

    # Combine multiple validation results into single result
    def combine_validation_results(results_hash)
      all_errors = []
      all_warnings = []
      all_details = {}

      results_hash.each do |key, result|
        next unless result.respond_to?(:errors) && result.respond_to?(:warnings)

        all_errors.concat(Array(result.errors).map { |error| "#{key}: #{error}" })
        all_warnings.concat(Array(result.warnings).map { |warning| "#{key}: #{warning}" })
        all_details[key] = result.respond_to?(:details) ? result.details : {}
      end

      ValidationResult.new(
        passed: all_errors.empty?,
        errors: all_errors,
        warnings: all_warnings,
        details: all_details
      )
    end

    # Generate summary statistics from validation results
    def generate_summary_stats(results)
      {
        total_errors: results.errors.length,
        total_warnings: results.warnings.length,
        validation_status: results.passed? ? 'PASSED' : 'FAILED',
        components_validated: results.details.keys.length
      }
    end

    # Generate actionable recommendations based on validation results
    def generate_recommendations(results)
      recommendations = []

      if results.errors.any?
        recommendations << {
          priority: 'HIGH',
          category: 'Error Resolution',
          message: 'Address all validation errors before proceeding with implementation',
          action: 'Review and fix the reported errors'
        }
      end

      if results.warnings.any?
        recommendations << {
          priority: 'MEDIUM',
          category: 'Code Quality',
          message: 'Consider addressing warnings to improve code quality',
          action: 'Review warnings and implement suggested improvements'
        }
      end

      if results.passed?
        recommendations << {
          priority: 'INFO',
          category: 'Success',
          message: 'All validations passed successfully',
          action: 'Continue with implementation or deployment'
        }
      end

      recommendations
    end

    # Calculate quality metrics from validation results
    def calculate_quality_metrics(results)
      total_checks = results.errors.length + results.warnings.length
      
      {
        error_rate: total_checks.zero? ? 0 : (results.errors.length.to_f / total_checks * 100).round(2),
        warning_rate: total_checks.zero? ? 0 : (results.warnings.length.to_f / total_checks * 100).round(2),
        quality_score: total_checks.zero? ? 100 : [(100 - results.errors.length * 10 - results.warnings.length * 2), 0].max,
        components_count: results.details.keys.length
      }
    end
  end

  # Data structure for validation results
  class ValidationResult
    attr_reader :passed, :errors, :warnings, :details

    def initialize(passed:, errors: [], warnings: [], details: {})
      @passed = passed
      @errors = Array(errors)
      @warnings = Array(warnings)
      @details = details || {}
    end

    def passed?
      @passed
    end

    def failed?
      !@passed
    end

    def has_errors?
      @errors.any?
    end

    def has_warnings?
      @warnings.any?
    end

    def detailed_results
      {
        passed: @passed,
        errors: @errors,
        warnings: @warnings,
        details: @details
      }
    end
  end
end