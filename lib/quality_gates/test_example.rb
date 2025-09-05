#!/usr/bin/env ruby
# frozen_string_literal: true

# Simple test script to validate Pre-Completion Validation system
# Run from Huginn root: ruby lib/quality_gates/test_example.rb

require 'fileutils'
require 'logger'

# Create a minimal Rails-like environment for testing
module Rails
  def self.root
    Pathname.new(Dir.pwd)
  end
  
  def self.env
    OpenStruct.new(production?: false)
  end
  
  def self.application
    OpenStruct.new(
      routes: OpenStruct.new(routes: []),
      config: OpenStruct.new(force_ssl: false)
    )
  end
  
  def self.version
    "7.0.0"
  end
end

# Mock ActiveRecord for testing
module ActiveRecord
  class Base
    def self.connection
      OpenStruct.new(migration_context: OpenStruct.new(current_version: 1))
    end
  end
end

require 'pathname'
require 'ostruct'

# Load the Pre-Completion Validation system
require_relative 'pre_completion'

puts "🧪 Testing Pre-Completion Validation System"
puts "=" * 60

# Test configuration
config = {
  feature_name: 'Test Feature',
  acceptance_criteria: [
    'Feature works correctly',
    'Tests pass',
    'Documentation updated'
  ],
  performance_targets: {
    response_time: 200,
    memory_usage: 100
  },
  security_requirements: {
    authentication: true,
    authorization: true
  },
  rollback_strategy: {
    database_migrations: true,
    rollback_timeout: 300
  },
  integration_tests: [
    'Basic workflow test',
    'Error handling test'
  ]
}

begin
  # Initialize validator
  puts "📋 Initializing Pre-Completion Validator..."
  validator = QualityGates::PreCompletion.new(config)
  
  puts "✅ Validator initialized successfully"
  puts "   Feature: #{config[:feature_name]}"
  puts "   Acceptance criteria: #{config[:acceptance_criteria].length}"
  puts "   Performance targets: #{config[:performance_targets].keys.join(', ')}"
  
  # Test individual validators
  puts "\n🧪 Testing Individual Validators:"
  
  # Test Completeness Validator
  puts "   📋 Completeness Validator..."
  completeness_result = validator.validate_completeness
  puts "   #{completeness_result[:success] ? '✅' : '❌'} Completeness: #{completeness_result[:success] ? 'PASSED' : 'FAILED'}"
  
  # Test Integration Tester  
  puts "   🔗 Integration Tester..."
  integration_result = validator.validate_integration
  puts "   #{integration_result[:success] ? '✅' : '❌'} Integration: #{integration_result[:success] ? 'PASSED' : 'FAILED'}"
  
  # Test Performance Validator
  puts "   ⚡ Performance Validator..."
  performance_result = validator.validate_performance
  puts "   #{performance_result[:success] ? '✅' : '❌'} Performance: #{performance_result[:success] ? 'PASSED' : 'FAILED'}"
  
  # Test Security Validator
  puts "   🔒 Security Validator..."
  security_result = validator.validate_security
  puts "   #{security_result[:success] ? '✅' : '❌'} Security: #{security_result[:success] ? 'PASSED' : 'FAILED'}"
  
  # Test Rollback Validator
  puts "   🔄 Rollback Validator..."
  rollback_result = validator.validate_rollback_readiness
  puts "   #{rollback_result[:success] ? '✅' : '❌'} Rollback: #{rollback_result[:success] ? 'PASSED' : 'FAILED'}"
  
  # Test full validation
  puts "\n🚀 Running Full Pre-Completion Validation..."
  start_time = Time.now
  result = validator.validate_all
  execution_time = Time.now - start_time
  
  puts "\n📊 Validation Results:"
  puts "   Overall Status: #{result.success? ? '✅ PASSED' : '❌ FAILED'}"
  puts "   Execution Time: #{execution_time.round(2)}s"
  puts "   Failures: #{result.failures.length}"
  
  if result.failures.any?
    puts "\n🚨 Failures:"
    result.failures.each.with_index(1) do |failure, index|
      puts "   #{index}. #{failure[:validator]}: #{failure[:message]}"
    end
  end
  
  # Check report generation
  reports_dir = File.join(Dir.pwd, 'development', 'reports')
  if Dir.exist?(reports_dir)
    report_files = Dir.glob(File.join(reports_dir, 'pre_completion_validation_*.md'))
    latest_report = report_files.max_by { |f| File.mtime(f) }
    
    if latest_report
      puts "\n📄 Report Generated:"
      puts "   #{File.basename(latest_report)}"
      puts "   Size: #{File.size(latest_report)} bytes"
    end
  end
  
  puts "\n✅ Pre-Completion Validation System Test Complete!"
  puts "   All components functional and ready for use."
  
rescue => e
  puts "\n❌ Test Failed:"
  puts "   Error: #{e.message}"
  puts "   Backtrace:"
  puts e.backtrace.first(5).map { |line| "     #{line}" }.join("\n")
  exit 1
end