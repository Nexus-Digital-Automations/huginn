#!/usr/bin/env ruby
# frozen_string_literal: true

# Simple test script for the Quality Gates system
# This tests the core functionality without requiring Rails

require 'pathname'
require 'yaml'
require 'logger'

# Set up the path to the project
PROJECT_ROOT = Pathname.new(File.expand_path('../..', __dir__))

# Load the system
$LOAD_PATH.unshift(PROJECT_ROOT.join('lib').to_s)

require 'quality_gates/pre_implementation'

# Simple test function
def test_quality_gates_system
  puts "🔍 Testing Quality Gates Pre-Implementation System"
  puts "=" * 60
  
  # Test configuration loading
  puts "📋 Testing configuration loading..."
  config_path = PROJECT_ROOT.join('config', 'quality_gates.yml')
  
  if config_path.exist?
    config = YAML.load_file(config_path)
    puts "✅ Configuration loaded successfully"
    puts "   Thresholds: #{config['quality_thresholds'].keys.join(', ')}"
  else
    puts "⚠️  Configuration file not found, will use defaults"
  end
  
  # Test system initialization
  puts "\n🏗️  Testing system initialization..."
  begin
    assessor = QualityGates::PreImplementation.new(
      config_path: config_path.exist? ? config_path.to_s : nil,
      logger: Logger.new($stdout, level: Logger::WARN)
    )
    puts "✅ PreImplementation system initialized successfully"
  rescue StandardError => e
    puts "❌ System initialization failed: #{e.message}"
    puts "   #{e.backtrace.first}"
    return false
  end
  
  # Test implementation spec creation
  puts "\n📊 Testing implementation specification creation..."
  begin
    spec = assessor.send(:create_implementation_spec, 'test_webhook_agent', :moderate)
    puts "✅ Implementation spec created successfully"
    puts "   Name: #{spec[:name]}"
    puts "   Type: #{spec[:type]}"
    puts "   Complexity factors: #{spec[:complexity_factors].count}"
  rescue StandardError => e
    puts "❌ Implementation spec creation failed: #{e.message}"
    return false
  end
  
  # Test analyzer integration initialization
  puts "\n🔧 Testing analyzer integration..."
  begin
    # This tests that all required files can be loaded
    require 'quality_gates/analyzer_integration'
    puts "✅ Analyzer integration loaded successfully"
  rescue StandardError => e
    puts "❌ Analyzer integration loading failed: #{e.message}"
    puts "   #{e.backtrace.first}"
    return false
  end
  
  # Test individual analyzer loading
  puts "\n🔍 Testing individual analyzers..."
  analyzers = [
    'context_analyzer',
    'impact_analyzer', 
    'resource_planner',
    'security_analyzer',
    'performance_analyzer'
  ]
  
  analyzers.each do |analyzer|
    begin
      require "quality_gates/analyzers/#{analyzer}"
      puts "✅ #{analyzer.capitalize.gsub('_', ' ')} loaded successfully"
    rescue StandardError => e
      puts "❌ #{analyzer.capitalize.gsub('_', ' ')} loading failed: #{e.message}"
      return false
    end
  end
  
  puts "\n📝 Testing report directory creation..."
  reports_dir = PROJECT_ROOT.join('development', 'reports')
  begin
    reports_dir.mkpath unless reports_dir.exist?
    puts "✅ Reports directory ready: #{reports_dir}"
  rescue StandardError => e
    puts "❌ Reports directory creation failed: #{e.message}"
    return false
  end
  
  puts "\n🎉 All tests passed! Quality Gates system is ready for use."
  puts "\nNext steps:"
  puts "1. Run: bundle exec rake quality_gates:validate_config"
  puts "2. Run: bundle exec rake quality_gates:pre_implementation[test_feature,simple]"
  puts "3. Check: development/reports/ for generated assessment reports"
  
  true
end

# Run the test if this script is executed directly
if __FILE__ == $0
  success = test_quality_gates_system
  exit(success ? 0 : 1)
end