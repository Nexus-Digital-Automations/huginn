#!/usr/bin/env ruby
# frozen_string_literal: true

# Standalone test script for Quality Gates validation system
# Can be run without Rails environment for testing

require 'pathname'
require 'json'
require 'yaml'

# Simulate Rails environment for testing
class MockRails
  def self.root
    Pathname.new(__dir__).parent.parent
  end

  def self.env
    'test'
  end
end

# Mock Rails constant if not present
Rails = MockRails unless defined?(Rails)

# Load the validation system
require_relative 'during_implementation'

module QualityGates
  # Test runner for the validation system
  class ValidationSystemTest
    attr_reader :project_root

    def initialize(project_root = Rails.root)
      @project_root = Pathname.new(project_root)
      puts "🧪 Quality Gates Validation System Test"
      puts "=" * 50
      puts "📁 Project root: #{@project_root}"
      puts "🏗️  Environment: #{Rails.env}"
      puts
    end

    # Run comprehensive system test
    def run_comprehensive_test
      puts "🚀 Starting comprehensive validation system test..."
      
      tests = [
        :test_validation_result_class,
        :test_during_implementation_init,
        :test_interface_validator,
        :test_error_boundary_validator,
        :test_integration_validator,
        :test_documentation_validator,
        :test_observability_validator,
        :test_full_validation_workflow
      ]

      passed = 0
      failed = 0

      tests.each do |test_method|
        print "🔍 Running #{test_method.to_s.humanize}... "
        
        begin
          send(test_method)
          puts "✅ PASSED"
          passed += 1
        rescue StandardError => e
          puts "❌ FAILED: #{e.message}"
          puts "   #{e.backtrace.first}" if ENV['DEBUG']
          failed += 1
        end
      end

      puts "\n" + "=" * 50
      puts "📊 TEST RESULTS SUMMARY"
      puts "=" * 50
      puts "✅ Passed: #{passed}"
      puts "❌ Failed: #{failed}"
      puts "🎯 Success rate: #{failed.zero? ? 100 : (passed.to_f / (passed + failed) * 100).round(2)}%"
      
      if failed.zero?
        puts "\n🎉 All tests passed! Quality Gates system is ready for use."
      else
        puts "\n⚠️  Some tests failed. Review the errors above."
      end

      failed.zero?
    end

    private

    # Test ValidationResult class
    def test_validation_result_class
      result = ValidationResult.new(
        passed: true,
        errors: [],
        warnings: ['Test warning'],
        details: { test: true }
      )

      raise "ValidationResult failed" unless result.passed?
      raise "Warnings not detected" unless result.has_warnings?
      raise "Details not accessible" unless result.details[:test]
    end

    # Test main validator initialization
    def test_during_implementation_init
      validator = DuringImplementation.new(project_root)
      raise "Validator not initialized" unless validator.respond_to?(:validate_all)
      raise "Project root not set" unless validator.project_root == project_root
    end

    # Test interface validator
    def test_interface_validator
      validator = InterfaceValidator.new(project_root)
      raise "Interface validator not initialized" unless validator.respond_to?(:validate)
      
      # Test with a sample Ruby file (if exists)
      sample_files = Dir.glob(project_root.join('app/models/*.rb')).first(1)
      if sample_files.any?
        file_result = validator.validate_file_interfaces(Pathname.new(sample_files.first))
        raise "File validation failed" unless file_result.is_a?(Hash)
        raise "Missing required keys" unless file_result.keys.include?(:errors)
      end
    end

    # Test error boundary validator
    def test_error_boundary_validator
      validator = ErrorBoundaryValidator.new(project_root)
      raise "Error boundary validator not initialized" unless validator.respond_to?(:validate)
    end

    # Test integration validator
    def test_integration_validator
      validator = IntegrationValidator.new(project_root)
      raise "Integration validator not initialized" unless validator.respond_to?(:validate)
    end

    # Test documentation validator
    def test_documentation_validator
      validator = DocumentationValidator.new(project_root)
      raise "Documentation validator not initialized" unless validator.respond_to?(:validate)
    end

    # Test observability validator
    def test_observability_validator
      validator = ObservabilityValidator.new(project_root)
      raise "Observability validator not initialized" unless validator.respond_to?(:validate)
    end

    # Test full validation workflow
    def test_full_validation_workflow
      validator = DuringImplementation.new(project_root)
      
      # Test component validation
      result = validator.validate_components([:interface])
      raise "Component validation failed" unless result.is_a?(ValidationResult)
      
      # Test path validation with existing paths
      existing_paths = ['lib', 'app/models'].select { |path| project_root.join(path).exist? }
      if existing_paths.any?
        path_result = validator.validate_paths(existing_paths)
        raise "Path validation failed" unless path_result.is_a?(ValidationResult)
      end

      # Test report generation
      sample_result = ValidationResult.new(passed: true, errors: [], warnings: [])
      report = validator.generate_report(sample_result)
      raise "Report generation failed" unless report.is_a?(Hash)
      raise "Report missing required fields" unless report.key?(:timestamp)
    end
  end
end

# Run tests if script is executed directly
if __FILE__ == $PROGRAM_NAME
  begin
    test_runner = QualityGates::ValidationSystemTest.new
    success = test_runner.run_comprehensive_test
    
    puts "\n🔧 SYSTEM VALIDATION COMPLETE"
    puts "Use 'rake quality_gates:during_implementation' to run validation on your project"
    
    exit(success ? 0 : 1)
    
  rescue StandardError => e
    puts "💥 Test system error: #{e.message}"
    puts e.backtrace.join("\n") if ENV['DEBUG']
    exit 1
  end
end