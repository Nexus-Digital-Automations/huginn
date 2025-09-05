# frozen_string_literal: true

require_relative 'base_validator'

module QualityGates
  module Validators
    # Generic validator that can be configured to run various validation commands
    # Used as fallback when specific validator class doesn't exist
    class GenericValidator < BaseValidator
      def validate
        execute_validation
      end

      protected

      def perform_validation
        validators = @gate_config[:validators] || []
        
        if validators.empty?
          return ValidationResult.new(
            success: false,
            errors: ["No validators configured for #{gate_name}"],
            details: { gate_config: @gate_config }
          )
        end

        results = []
        overall_success = true
        all_errors = []
        all_warnings = []

        validators.each do |validator_name|
          result = run_validator(validator_name)
          results << result
          
          if result.failed?
            overall_success = false
            all_errors.concat(result.errors)
          end
          
          all_warnings.concat(result.warnings)
          
          # Merge metrics
          @metrics.merge!(result.metrics)
        end

        ValidationResult.new(
          success: overall_success,
          errors: all_errors,
          warnings: all_warnings,
          details: {
            validator_results: results.map { |r| { success: r.success?, errors: r.errors, warnings: r.warnings } },
            total_validators: validators.count,
            passed_validators: results.count(&:success?),
            failed_validators: results.count(&:failed?)
          },
          metrics: @metrics
        )
      end

      private

      def run_validator(validator_name)
        case validator_name.to_s
        when 'rubocop'
          run_rubocop
        when 'eslint'
          run_eslint
        when 'pylint'
          run_pylint
        when 'bundler_audit'
          run_bundler_audit
        when 'brakeman'
          run_brakeman
        when 'rspec'
          run_rspec
        when 'unit_tests'
          run_unit_tests
        when 'coverage_check'
          run_coverage_check
        else
          run_generic_command(validator_name)
        end
      end

      # RuboCop validation
      def run_rubocop
        return missing_command_result('rubocop') unless command_available?('rubocop')

        command = build_rubocop_command
        result = execute_command(command)
        
        if result.success?
          add_metric(:rubocop_violations, 0, 'RuboCop violations count')
          ValidationResult.new(success: true, details: { output: result.output })
        else
          violations = parse_rubocop_violations(result.output)
          add_metric(:rubocop_violations, violations.count, 'RuboCop violations count')
          
          ValidationResult.new(
            success: false,
            errors: ["RuboCop found #{violations.count} violations"],
            details: { 
              violations: violations,
              output: result.output 
            }
          )
        end
      end

      # ESLint validation
      def run_eslint
        return missing_command_result('eslint') unless command_available?('eslint')

        command = build_eslint_command
        result = execute_command(command)
        
        if result.success?
          add_metric(:eslint_violations, 0, 'ESLint violations count')
          ValidationResult.new(success: true, details: { output: result.output })
        else
          violations = parse_eslint_violations(result.output)
          add_metric(:eslint_violations, violations.count, 'ESLint violations count')
          
          ValidationResult.new(
            success: false,
            errors: ["ESLint found #{violations.count} violations"],
            details: {
              violations: violations,
              output: result.output
            }
          )
        end
      end

      # Bundler Audit validation
      def run_bundler_audit
        return missing_command_result('bundle-audit') unless command_available?('bundle-audit')

        # Update advisory database first
        update_result = execute_command('bundle-audit update')
        
        # Run audit
        command = 'bundle-audit check'
        result = execute_command(command)
        
        if result.success?
          add_metric(:vulnerabilities_found, 0, 'Security vulnerabilities found')
          ValidationResult.new(success: true, details: { output: result.output })
        else
          vulnerabilities = parse_bundler_audit_output(result.output)
          add_metric(:vulnerabilities_found, vulnerabilities.count, 'Security vulnerabilities found')
          
          ValidationResult.new(
            success: false,
            errors: ["Bundler Audit found #{vulnerabilities.count} vulnerabilities"],
            details: {
              vulnerabilities: vulnerabilities,
              output: result.output
            }
          )
        end
      end

      # Brakeman validation
      def run_brakeman
        return missing_command_result('brakeman') unless command_available?('brakeman')

        command = 'brakeman --format json --quiet'
        result = execute_command(command)
        
        begin
          brakeman_data = JSON.parse(result.output)
          warnings = brakeman_data['warnings'] || []
          
          add_metric(:security_warnings, warnings.count, 'Brakeman security warnings')
          
          if warnings.empty?
            ValidationResult.new(success: true, details: { brakeman_data: brakeman_data })
          else
            ValidationResult.new(
              success: false,
              errors: ["Brakeman found #{warnings.count} security warnings"],
              details: {
                warnings: warnings,
                brakeman_data: brakeman_data
              }
            )
          end
        rescue JSON::ParserError
          ValidationResult.new(
            success: false,
            errors: ["Failed to parse Brakeman output"],
            details: { output: result.output }
          )
        end
      end

      # RSpec validation
      def run_rspec
        return missing_command_result('rspec') unless command_available?('rspec')

        command = 'rspec --format json'
        result = execute_command(command)
        
        begin
          rspec_data = JSON.parse(result.output)
          
          examples_count = rspec_data.dig('summary', 'example_count') || 0
          failures_count = rspec_data.dig('summary', 'failure_count') || 0
          pending_count = rspec_data.dig('summary', 'pending_count') || 0
          
          add_metric(:total_tests, examples_count, 'Total test count')
          add_metric(:failed_tests, failures_count, 'Failed test count')
          add_metric(:pending_tests, pending_count, 'Pending test count')
          
          if failures_count == 0
            ValidationResult.new(
              success: true, 
              details: { rspec_data: rspec_data }
            )
          else
            ValidationResult.new(
              success: false,
              errors: ["#{failures_count} test(s) failed"],
              details: {
                failures: rspec_data['examples']&.select { |e| e['status'] == 'failed' },
                rspec_data: rspec_data
              }
            )
          end
        rescue JSON::ParserError
          # Fallback to parsing text output
          parse_rspec_text_output(result)
        end
      end

      # Generic unit tests validation
      def run_unit_tests
        # Try different test runners in order of preference
        test_runners = %w[rspec minitest test]
        
        test_runners.each do |runner|
          if command_available?(runner)
            return send("run_#{runner}")
          end
        end
        
        ValidationResult.new(
          success: false,
          errors: ["No test runner available (tried: #{test_runners.join(', ')})"]
        )
      end

      # Coverage check validation
      def run_coverage_check
        # Look for SimpleCov coverage data
        coverage_file = File.join(project_root, 'coverage', '.resultset.json')
        
        unless File.exist?(coverage_file)
          return ValidationResult.new(
            success: false,
            errors: ["Coverage data not found at #{coverage_file}"]
          )
        end
        
        begin
          coverage_data = JSON.parse(File.read(coverage_file))
          
          # Extract coverage percentage (SimpleCov format)
          resultset = coverage_data.values.first || {}
          covered_lines = resultset.dig('coverage') || {}
          
          total_lines = covered_lines.values.count { |v| v.is_a?(Integer) }
          covered_count = covered_lines.values.count { |v| v.is_a?(Integer) && v > 0 }
          
          coverage_percent = total_lines > 0 ? ((covered_count.to_f / total_lines) * 100).round(2) : 0
          
          add_metric(:line_coverage, coverage_percent, 'Line coverage percentage')
          add_metric(:total_lines, total_lines, 'Total lines of code')
          add_metric(:covered_lines, covered_count, 'Covered lines of code')
          
          min_coverage = get_threshold(:min_line_coverage, 80)
          
          if coverage_percent >= min_coverage
            ValidationResult.new(
              success: true,
              details: { 
                coverage_percent: coverage_percent,
                min_required: min_coverage
              }
            )
          else
            ValidationResult.new(
              success: false,
              errors: ["Coverage #{coverage_percent}% is below minimum #{min_coverage}%"],
              details: {
                coverage_percent: coverage_percent,
                min_required: min_coverage
              }
            )
          end
        rescue JSON::ParserError, StandardError => e
          ValidationResult.new(
            success: false,
            errors: ["Failed to parse coverage data: #{e.message}"]
          )
        end
      end

      # Generic command execution
      def run_generic_command(validator_name)
        # Look for command configuration
        command_config = @gate_config.dig(:configuration, validator_name.to_sym) || {}
        command = command_config[:command] || validator_name
        
        result = execute_command(command)
        
        expected_exit_code = command_config[:expected_exit_code] || 0
        success = result.exit_status == expected_exit_code
        
        add_metric("#{validator_name}_exit_code".to_sym, result.exit_status, "#{validator_name} exit code")
        
        ValidationResult.new(
          success: success,
          errors: success ? [] : ["#{validator_name} command failed with exit code #{result.exit_status}"],
          details: {
            command: command,
            exit_code: result.exit_status,
            output: result.output
          }
        )
      end

      # Command builders
      def build_rubocop_command
        config_file = @gate_config.dig(:configuration, :rubocop, :config_file) || '.rubocop.yml'
        auto_correct = @gate_config.dig(:configuration, :rubocop, :auto_correct) || false
        
        command = 'rubocop'
        command += " --config #{config_file}" if File.exist?(resolve_path(config_file))
        command += ' --auto-correct' if auto_correct
        command += ' --format json'
        command
      end

      def build_eslint_command
        config_file = @gate_config.dig(:configuration, :eslint, :config_file)
        ignore_warnings = @gate_config.dig(:configuration, :eslint, :ignore_warnings) || false
        
        command = 'eslint'
        command += " --config #{config_file}" if config_file && File.exist?(resolve_path(config_file))
        command += ' --max-warnings 0' unless ignore_warnings
        command += ' --format json'
        command += ' .'
        command
      end

      # Output parsers
      def parse_rubocop_violations(output)
        begin
          data = JSON.parse(output)
          violations = []
          
          data['files']&.each do |file_data|
            file_data['offenses']&.each do |offense|
              violations << {
                file: file_data['path'],
                line: offense['location']['line'],
                column: offense['location']['column'],
                severity: offense['severity'],
                message: offense['message'],
                cop_name: offense['cop_name']
              }
            end
          end
          
          violations
        rescue JSON::ParserError
          # Fallback to text parsing
          []
        end
      end

      def parse_eslint_violations(output)
        begin
          data = JSON.parse(output)
          violations = []
          
          data.each do |file_data|
            file_data['messages']&.each do |message|
              violations << {
                file: file_data['filePath'],
                line: message['line'],
                column: message['column'],
                severity: message['severity'] == 2 ? 'error' : 'warning',
                message: message['message'],
                rule: message['ruleId']
              }
            end
          end
          
          violations
        rescue JSON::ParserError
          []
        end
      end

      def parse_bundler_audit_output(output)
        vulnerabilities = []
        current_gem = nil
        
        output.lines.each do |line|
          line = line.strip
          
          if line.match(/^Name: (.+)/)
            current_gem = $1
          elsif line.match(/^Advisory: (.+)/) && current_gem
            vulnerabilities << {
              gem: current_gem,
              advisory: $1,
              line: line
            }
          end
        end
        
        vulnerabilities
      end

      def parse_rspec_text_output(result)
        lines = result.lines
        summary_line = lines.find { |line| line.include?('examples') }
        
        if summary_line
          # Parse summary like "5 examples, 1 failure"
          examples_match = summary_line.match(/(\d+) examples?/)
          failures_match = summary_line.match(/(\d+) failures?/)
          
          examples_count = examples_match ? examples_match[1].to_i : 0
          failures_count = failures_match ? failures_match[1].to_i : 0
          
          add_metric(:total_tests, examples_count, 'Total test count')
          add_metric(:failed_tests, failures_count, 'Failed test count')
          
          ValidationResult.new(
            success: failures_count == 0,
            errors: failures_count > 0 ? ["#{failures_count} test(s) failed"] : [],
            details: { output: result.output }
          )
        else
          ValidationResult.new(
            success: result.success?,
            errors: result.success? ? [] : ["Test execution failed"],
            details: { output: result.output }
          )
        end
      end

      def missing_command_result(command)
        ValidationResult.new(
          success: false,
          errors: ["Required command '#{command}' is not available"],
          details: { missing_command: command }
        )
      end
    end
  end
end