# frozen_string_literal: true

# Quality Gates Initializer
# Configures the during-implementation validation system for development workflow

Rails.application.configure do
  # Load Quality Gates system only in development and test environments
  if Rails.env.development? || Rails.env.test?
    
    # Auto-load Quality Gates modules
    config.autoload_paths += %W[#{config.root}/lib/quality_gates]
    
    # Enable validation system logging
    config.quality_gates = ActiveSupport::OrderedOptions.new
    config.quality_gates.enabled = true
    config.quality_gates.log_level = :info
    config.quality_gates.auto_validate = false # Set to true for automatic validation on file changes
    
    # Configure validation thresholds
    config.quality_gates.thresholds = {
      interface_score: 70,
      error_coverage: 60,
      documentation_coverage: 50,
      observability_score: 70,
      integration_readiness: 60
    }
    
    # Real-time validation configuration (disabled by default for performance)
    config.quality_gates.real_time = ActiveSupport::OrderedOptions.new
    config.quality_gates.real_time.enabled = false
    config.quality_gates.real_time.file_patterns = %w[app/**/*.rb lib/**/*.rb]
    config.quality_gates.real_time.validation_delay = 2.seconds
    
    # Development helpers
    config.quality_gates.development = {
      show_validation_hints: true,
      auto_fix_suggestions: true,
      colorized_output: true
    }
  end
end

# Development middleware for real-time validation (optional)
if Rails.env.development? && Rails.application.config.quality_gates&.real_time&.enabled
  require_relative '../../lib/quality_gates/middleware/real_time_validator'
  
  Rails.application.configure do
    config.middleware.use QualityGates::Middleware::RealTimeValidator
  end
end

# Console integration for easy access to validation system
if Rails.env.development?
  Rails.application.console do
    puts "🔧 Quality Gates system available:"
    puts "   QualityGates::DuringImplementation.new.validate_all"
    puts "   Or use rake tasks: rake quality_gates:during_implementation"
  end
end