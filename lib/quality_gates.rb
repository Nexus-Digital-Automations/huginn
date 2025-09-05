# frozen_string_literal: true

# Quality Gates for Huginn - Main entry point
# Provides comprehensive quality validation and reporting system

require 'rails'
require 'active_support/all'

module QualityGates
  # Version information
  VERSION = '1.0.0'

  # Load core components
  autoload :Configuration, 'quality_gates/configuration'
  autoload :Orchestrator, 'quality_gates/orchestrator'
  autoload :Reporter, 'quality_gates/reporter'
  autoload :Dashboard, 'quality_gates/dashboard'
  autoload :Notifier, 'quality_gates/notifier'
  autoload :CLI, 'quality_gates/cli'
  
  # Load result classes
  autoload :ExecutionResult, 'quality_gates/execution_result'
  autoload :GateResult, 'quality_gates/execution_result'
  autoload :HealthCheck, 'quality_gates/execution_result'

  # Load validators
  module Validators
    autoload :BaseValidator, 'quality_gates/validators/base_validator'
    autoload :GenericValidator, 'quality_gates/validators/generic_validator'
  end

  # Load notification channels
  module NotificationChannels
    autoload :BaseChannel, 'quality_gates/notification_channels/base_channel'
    autoload :EmailChannel, 'quality_gates/notification_channels/email_channel'
    autoload :SlackChannel, 'quality_gates/notification_channels/slack_channel'
    autoload :WebhookChannel, 'quality_gates/notification_channels/webhook_channel'
    autoload :SmsChannel, 'quality_gates/notification_channels/sms_channel'
    autoload :TeamsChannel, 'quality_gates/notification_channels/teams_channel'
    autoload :DiscordChannel, 'quality_gates/notification_channels/discord_channel'
  end

  # Exception classes
  class Error < StandardError; end
  class ConfigurationError < Error; end
  class DependencyError < Error; end
  class PrerequisiteError < Error; end
  class ValidationError < Error; end

  # Convenience methods
  class << self
    # Get default orchestrator instance
    def orchestrator
      @orchestrator ||= Orchestrator.new
    end

    # Run quality gates with default settings
    def run(scope = :all, context = {})
      orchestrator.run_quality_gates(scope, context)
    end

    # Get current quality status
    def status
      orchestrator.get_current_quality_status
    end

    # Perform health check
    def health_check
      orchestrator.health_check
    end

    # Get configuration
    def configuration
      orchestrator.configuration
    end

    # Reset orchestrator (useful for testing)
    def reset!
      @orchestrator = nil
    end

    # Get version information
    def version_info
      {
        version: VERSION,
        huginn_version: huginn_version,
        rails_version: Rails.version,
        ruby_version: RUBY_VERSION,
        environment: Rails.env
      }
    end

    private

    def huginn_version
      File.read(File.join(Rails.root, 'VERSION')).strip
    rescue StandardError
      'unknown'
    end
  end
end

# Rails integration
if defined?(Rails)
  require 'quality_gates/railtie' if defined?(Rails::Railtie)
end