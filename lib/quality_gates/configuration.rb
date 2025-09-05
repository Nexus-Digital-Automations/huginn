# frozen_string_literal: true

require 'yaml'
require 'json'

module QualityGates
  # Centralized configuration management for quality gates system
  # Handles loading, validation, and access to all quality gate settings
  #
  # Usage:
  #   config = QualityGates::Configuration.new
  #   gates = config.enabled_gates
  #   gate_config = config.get_gate_config(:code_quality)
  #
  # Configuration Sources: YAML files, environment variables, database
  # Validation: Schema validation, dependency checking, constraint verification
  class Configuration
    attr_reader :config_file, :config_data, :environment

    # Default configuration file paths in order of precedence
    DEFAULT_CONFIG_PATHS = [
      'config/quality_gates/master_config.yml',
      'config/quality_gates.yml',
      '.quality_gates.yml'
    ].freeze

    # Required configuration keys
    REQUIRED_KEYS = %w[gates notifications reporting dashboard].freeze

    # Supported gate categories and their default configurations
    DEFAULT_GATE_CATEGORIES = {
      code_quality: {
        validators: %w[rubocop eslint pylint],
        weight: 3,
        critical: true,
        phase: :completion
      },
      security: {
        validators: %w[bundler_audit brakeman security_scan],
        weight: 5,
        critical: true,
        phase: :completion
      },
      performance: {
        validators: %w[performance_test memory_check response_time],
        weight: 2,
        critical: false,
        phase: :completion
      },
      testing: {
        validators: %w[unit_tests integration_tests coverage_check],
        weight: 4,
        critical: true,
        phase: :completion
      },
      documentation: {
        validators: %w[doc_coverage readme_check api_docs],
        weight: 1,
        critical: false,
        phase: :completion
      },
      dependencies: {
        validators: %w[vulnerability_scan dependency_check license_audit],
        weight: 3,
        critical: true,
        phase: :pre_implementation
      },
      deployment: {
        validators: %w[deployment_test configuration_check environment_validation],
        weight: 2,
        critical: false,
        phase: :completion
      },
      monitoring: {
        validators: %w[health_check metrics_collection alerting_setup],
        weight: 2,
        critical: false,
        phase: :monitoring
      }
    }.freeze

    def initialize(config_file = nil, environment = Rails.env)
      @environment = environment
      @config_file = config_file || find_config_file
      @config_data = load_configuration
      @environment_overrides = load_environment_overrides
      
      validate_configuration!
      apply_environment_specific_settings!
    end

    # Get all enabled quality gates
    # @return [Array<Symbol>] - array of enabled gate names
    def enabled_gates
      gates_config.select { |_, config| gate_enabled?(config) }.keys.map(&:to_sym)
    end

    # Check if a specific gate is enabled
    # @param gate_name [Symbol, String] - name of the gate
    # @return [Boolean] - whether the gate is enabled
    def gate_enabled?(gate_name)
      gate_config = get_gate_config(gate_name)
      return false unless gate_config

      enabled = gate_config[:enabled]
      enabled.nil? ? true : enabled # Default to enabled if not specified
    end

    # Get configuration for a specific gate
    # @param gate_name [Symbol, String] - name of the gate
    # @return [Hash] - gate configuration with defaults applied
    def get_gate_config(gate_name)
      gate_name = gate_name.to_sym
      
      # Start with default configuration if available
      base_config = DEFAULT_GATE_CATEGORIES[gate_name] || {}
      
      # Merge with user configuration
      user_config = gates_config[gate_name] || {}
      
      # Apply environment-specific overrides
      env_overrides = @environment_overrides.dig(:gates, gate_name) || {}
      
      base_config.merge(user_config).merge(env_overrides).with_indifferent_access
    end

    # Get gates for a specific phase
    # @param phase [Symbol] - execution phase
    # @return [Array<Symbol>] - gates configured for this phase
    def gates_for_phase(phase)
      enabled_gates.select do |gate_name|
        get_gate_config(gate_name)[:phase] == phase
      end
    end

    # Get gates for a specific category
    # @param category [Symbol] - gate category
    # @return [Array<Symbol>] - gates in this category
    def gates_for_category(category)
      enabled_gates.select do |gate_name|
        get_gate_config(gate_name)[:category] == category || gate_name == category
      end
    end

    # Get notification configuration
    # @return [Hash] - notification settings
    def notification_config
      config_with_defaults(:notifications, {
        enabled: true,
        channels: {
          email: { enabled: false },
          slack: { enabled: false },
          webhook: { enabled: false }
        },
        on_failure: true,
        on_success: false,
        on_completion: true
      })
    end

    # Get enabled notification channels
    # @return [Array<Symbol>] - enabled notification channel names
    def notification_channels
      notification_config[:channels].select { |_, config| config[:enabled] }.keys.map(&:to_sym)
    end

    # Get reporting configuration
    # @return [Hash] - reporting settings
    def reporting_config
      config_with_defaults(:reporting, {
        enabled: true,
        formats: %w[json html],
        directory: 'development/reports',
        retention_days: 30,
        detailed: true,
        include_metrics: true
      })
    end

    # Get dashboard configuration
    # @return [Hash] - dashboard settings
    def dashboard_config
      config_with_defaults(:dashboard, {
        enabled: true,
        real_time: false,
        refresh_interval: 60,
        metrics_retention: '7d',
        url: nil
      })
    end

    # Get execution settings
    # @return [Hash] - execution configuration
    def execution_config
      config_with_defaults(:execution, {
        fail_fast: false,
        parallel: false,
        timeout: 300,
        retry_count: 0,
        log_level: 'info'
      })
    end

    # Check if fail-fast mode is enabled
    # @return [Boolean] - whether to stop on first critical failure
    def fail_fast?
      execution_config[:fail_fast]
    end

    # Get log level for quality gates operations
    # @return [String] - log level
    def log_level
      execution_config[:log_level]
    end

    # Get reports directory path
    # @return [String] - absolute path to reports directory
    def reports_directory
      File.expand_path(reporting_config[:directory], Rails.root)
    end

    # Validate current configuration
    # @return [Boolean] - whether configuration is valid
    def valid?
      begin
        validate_configuration!
        true
      rescue ConfigurationError
        false
      end
    end

    # Get all configuration as hash (for debugging/inspection)
    # @return [Hash] - complete configuration data
    def to_hash
      {
        config_file: @config_file,
        environment: @environment,
        gates: gates_config,
        notifications: notification_config,
        reporting: reporting_config,
        dashboard: dashboard_config,
        execution: execution_config,
        metadata: {
          loaded_at: Time.now,
          enabled_gates_count: enabled_gates.count,
          notification_channels_count: notification_channels.count
        }
      }
    end

    # Reload configuration from file
    def reload!
      @config_data = load_configuration
      @environment_overrides = load_environment_overrides
      validate_configuration!
      apply_environment_specific_settings!
      true
    end

    private

    # Find the first available configuration file
    def find_config_file
      DEFAULT_CONFIG_PATHS.each do |path|
        full_path = File.expand_path(path, Rails.root)
        return full_path if File.exist?(full_path)
      end
      
      # Return the preferred path even if it doesn't exist (will create defaults)
      File.expand_path(DEFAULT_CONFIG_PATHS.first, Rails.root)
    end

    # Load configuration from YAML file
    def load_configuration
      return create_default_configuration unless File.exist?(@config_file)

      begin
        config_content = YAML.safe_load(File.read(@config_file), permitted_classes: [Symbol])
        config_content || {}
      rescue Psych::SyntaxError => e
        raise ConfigurationError, "Invalid YAML syntax in #{@config_file}: #{e.message}"
      rescue StandardError => e
        raise ConfigurationError, "Error loading configuration from #{@config_file}: #{e.message}"
      end
    end

    # Load environment-specific overrides from environment variables
    def load_environment_overrides
      overrides = {}
      
      # Load overrides from environment variables with QG_ prefix
      ENV.each do |key, value|
        next unless key.start_with?('QG_')
        
        # Convert QG_GATES_CODE_QUALITY_ENABLED to nested hash
        config_path = key.sub('QG_', '').downcase.split('_')
        set_nested_value(overrides, config_path, parse_env_value(value))
      end
      
      overrides
    end

    # Parse environment variable value to appropriate type
    def parse_env_value(value)
      case value.downcase
      when 'true' then true
      when 'false' then false
      when /^\d+$/ then value.to_i
      when /^\d+\.\d+$/ then value.to_f
      else value
      end
    end

    # Set nested hash value from array of keys
    def set_nested_value(hash, keys, value)
      key = keys.shift.to_sym
      
      if keys.empty?
        hash[key] = value
      else
        hash[key] ||= {}
        set_nested_value(hash[key], keys, value)
      end
    end

    # Create default configuration if no file exists
    def create_default_configuration
      {
        'gates' => DEFAULT_GATE_CATEGORIES.deep_stringify_keys,
        'notifications' => {
          'enabled' => false,
          'channels' => {}
        },
        'reporting' => {
          'enabled' => true,
          'directory' => 'development/reports'
        },
        'dashboard' => {
          'enabled' => false
        },
        'execution' => {
          'fail_fast' => false,
          'timeout' => 300
        }
      }
    end

    # Get gates configuration section
    def gates_config
      @config_data['gates'] || {}
    end

    # Get configuration value with defaults applied
    def config_with_defaults(section, defaults)
      user_config = @config_data[section.to_s] || {}
      env_overrides = @environment_overrides[section] || {}
      
      defaults.deep_merge(user_config).deep_merge(env_overrides).with_indifferent_access
    end

    # Validate the loaded configuration
    def validate_configuration!
      validate_required_sections!
      validate_gate_configurations!
      validate_notification_configuration!
      validate_reporting_configuration!
      validate_execution_configuration!
    end

    # Validate required configuration sections exist
    def validate_required_sections!
      REQUIRED_KEYS.each do |key|
        unless @config_data.key?(key) || create_missing_section?(key)
          raise ConfigurationError, "Required configuration section '#{key}' is missing"
        end
      end
    end

    # Create missing configuration sections with defaults
    def create_missing_section?(section)
      case section
      when 'gates'
        @config_data['gates'] = DEFAULT_GATE_CATEGORIES.deep_stringify_keys
      when 'notifications'
        @config_data['notifications'] = { 'enabled' => false }
      when 'reporting'
        @config_data['reporting'] = { 'enabled' => true, 'directory' => 'development/reports' }
      when 'dashboard'
        @config_data['dashboard'] = { 'enabled' => false }
      else
        return false
      end
      
      true
    end

    # Validate individual gate configurations
    def validate_gate_configurations!
      return unless @config_data['gates']

      @config_data['gates'].each do |gate_name, gate_config|
        validate_individual_gate_config(gate_name, gate_config)
      end
    end

    # Validate a single gate configuration
    def validate_individual_gate_config(gate_name, gate_config)
      unless gate_config.is_a?(Hash)
        raise ConfigurationError, "Gate '#{gate_name}' configuration must be a hash"
      end

      # Validate weight if specified
      if gate_config['weight'] && !gate_config['weight'].is_a?(Numeric)
        raise ConfigurationError, "Gate '#{gate_name}' weight must be numeric"
      end

      # Validate phase if specified
      valid_phases = %w[pre_implementation during_implementation completion monitoring]
      if gate_config['phase'] && !valid_phases.include?(gate_config['phase'].to_s)
        raise ConfigurationError, "Gate '#{gate_name}' has invalid phase: #{gate_config['phase']}"
      end

      # Validate dependencies if specified
      if gate_config['dependencies'] && !gate_config['dependencies'].is_a?(Array)
        raise ConfigurationError, "Gate '#{gate_name}' dependencies must be an array"
      end
    end

    # Validate notification configuration
    def validate_notification_configuration!
      return unless @config_data['notifications']

      notif_config = @config_data['notifications']
      
      if notif_config['channels'] && !notif_config['channels'].is_a?(Hash)
        raise ConfigurationError, "Notification channels configuration must be a hash"
      end
    end

    # Validate reporting configuration
    def validate_reporting_configuration!
      return unless @config_data['reporting']

      reporting_config = @config_data['reporting']
      
      if reporting_config['directory'] && !reporting_config['directory'].is_a?(String)
        raise ConfigurationError, "Reporting directory must be a string"
      end

      if reporting_config['retention_days'] && !reporting_config['retention_days'].is_a?(Numeric)
        raise ConfigurationError, "Reporting retention_days must be numeric"
      end
    end

    # Validate execution configuration
    def validate_execution_configuration!
      return unless @config_data['execution']

      exec_config = @config_data['execution']
      
      if exec_config['timeout'] && !exec_config['timeout'].is_a?(Numeric)
        raise ConfigurationError, "Execution timeout must be numeric"
      end
    end

    # Apply environment-specific settings and create directories
    def apply_environment_specific_settings!
      # Ensure reports directory exists
      reports_dir = reports_directory
      FileUtils.mkdir_p(reports_dir) unless Dir.exist?(reports_dir)

      # Apply environment-specific gate enabling/disabling
      case @environment
      when 'development'
        # Enable development-friendly gates, disable expensive ones
        @config_data['gates']&.each do |gate_name, config|
          config['enabled'] = false if %w[performance deployment].include?(gate_name)
        end
      when 'test'
        # Enable only essential gates for testing
        essential_gates = %w[code_quality testing security]
        @config_data['gates']&.each do |gate_name, config|
          config['enabled'] = essential_gates.include?(gate_name)
        end
      when 'production'
        # Enable all gates for production
        @config_data['gates']&.each_value do |config|
          config['enabled'] = true unless config.key?('enabled')
        end
      end
    end
  end

  # Configuration-related error class
  class ConfigurationError < StandardError; end
end