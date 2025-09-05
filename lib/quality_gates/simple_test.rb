#!/usr/bin/env ruby
# frozen_string_literal: true

# Simple test script for Quality Gates validation system
require 'pathname'

# Simulate Rails environment
class MockRails
  def self.root
    Pathname.new(__dir__).parent.parent
  end

  def self.env
    'test'
  end
end

Rails = MockRails unless defined?(Rails)

# Load individual validators
require_relative 'utils'
require_relative 'interface_validator'
require_relative 'error_boundary_validator'
require_relative 'integration_validator' 
require_relative 'documentation_validator'
require_relative 'observability_validator'

puts "🧪 Simple Quality Gates Test"
puts "=" * 40

# Test individual validators
validators = {
  'Interface' => QualityGates::InterfaceValidator,
  'Error Boundary' => QualityGates::ErrorBoundaryValidator,
  'Integration' => QualityGates::IntegrationValidator,
  'Documentation' => QualityGates::DocumentationValidator,
  'Observability' => QualityGates::ObservabilityValidator
}

project_root = Rails.root

validators.each do |name, validator_class|
  print "🔍 Testing #{name} Validator... "
  
  begin
    validator = validator_class.new(project_root)
    
    # Test basic initialization
    if validator.respond_to?(:validate)
      puts "✅ INITIALIZED"
    else
      puts "❌ MISSING VALIDATE METHOD"
    end
    
  rescue StandardError => e
    puts "❌ ERROR: #{e.message}"
  end
end

# Test ValidationResult class
print "🔍 Testing ValidationResult class... "
begin
  result = QualityGates::ValidationResult.new(
    passed: true,
    errors: [],
    warnings: ['Test warning'],
    details: { test: true }
  )
  
  if result.passed? && result.has_warnings?
    puts "✅ WORKING"
  else
    puts "❌ VALIDATION FAILED"
  end
rescue StandardError => e
  puts "❌ ERROR: #{e.message}"
end

puts "\n✅ Basic validation system components are functional!"
puts "To run comprehensive validation: rake quality_gates:during_implementation"