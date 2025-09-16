# frozen_string_literal: true

##
# Parlant Integration Initializer for Huginn
#
# Configures Parlant conversational AI integration system for function-level
# validation across all Huginn monitoring, alerting, and observability functions.
#
# This initializer sets up the Parlant integration service, configures
# validation policies, and establishes monitoring capabilities.
#
# @author Parlant Integration Team
# @since 1.0.0

Rails.application.configure do
  # Parlant Integration Configuration
  config.parlant = ActiveSupport::OrderedOptions.new

  ##
  # Core Parlant Settings
  config.parlant.enabled = ENV.fetch('PARLANT_ENABLED', 'true') == 'true'
  config.parlant.api_base_url = ENV.fetch('PARLANT_API_BASE_URL', 'http://localhost:8000')
  config.parlant.api_key = ENV['PARLANT_API_KEY']
  config.parlant.api_timeout = ENV.fetch('PARLANT_API_TIMEOUT_MS', '10000').to_i / 1000.0

  ##
  # Performance and Caching Configuration
  config.parlant.cache_enabled = ENV.fetch('PARLANT_CACHE_ENABLED', 'true') == 'true'
  config.parlant.cache_max_age = ENV.fetch('PARLANT_CACHE_MAX_AGE_MS', '300000').to_i / 1000.0
  config.parlant.cache_size = ENV.fetch('PARLANT_CACHE_SIZE', '1000').to_i
  config.parlant.concurrent_validations = ENV.fetch('PARLANT_CONCURRENT_VALIDATIONS', '5').to_i

  ##
  # Security and Risk Management
  config.parlant.require_high_risk_approval = ENV.fetch('PARLANT_REQUIRE_HIGH_RISK_APPROVAL', 'true') == 'true'
  config.parlant.enable_threat_detection = ENV.fetch('PARLANT_ENABLE_THREAT_DETECTION', 'true') == 'true'
  config.parlant.max_failed_validations = ENV.fetch('PARLANT_MAX_FAILED_VALIDATIONS', '5').to_i
  config.parlant.suspicious_threshold = ENV.fetch('PARLANT_SUSPICIOUS_THRESHOLD', '3').to_i

  ##
  # Logging and Audit Configuration
  config.parlant.log_level = ENV.fetch('PARLANT_LOG_LEVEL', 'info').to_sym
  config.parlant.enable_audit_logging = ENV.fetch('PARLANT_ENABLE_AUDIT_LOGGING', 'true') == 'true'
  config.parlant.enable_performance_logging = ENV.fetch('PARLANT_ENABLE_PERFORMANCE_LOGGING', 'true') == 'true'
  config.parlant.log_validation_details = ENV.fetch('PARLANT_LOG_VALIDATION_DETAILS', 'false') == 'true'

  ##
  # Conversation Management
  config.parlant.max_conversation_history = ENV.fetch('PARLANT_MAX_CONVERSATION_HISTORY', '100').to_i
  config.parlant.conversation_timeout = ENV.fetch('PARLANT_CONVERSATION_TIMEOUT_MS', '3600000').to_i / 1000.0
  config.parlant.session_timeout = ENV.fetch('PARLANT_SESSION_TIMEOUT_MS', '3600000').to_i / 1000.0

  ##
  # Data Retention and Cleanup
  config.parlant.audit_retention_days = ENV.fetch('PARLANT_AUDIT_RETENTION_DAYS', '90').to_i
  config.parlant.cache_cleanup_interval = ENV.fetch('PARLANT_CACHE_CLEANUP_INTERVAL_MS', '600000').to_i / 1000.0
  config.parlant.max_audit_entries = ENV.fetch('PARLANT_MAX_AUDIT_ENTRIES', '10000').to_i

  ##
  # Advanced Features
  config.parlant.enable_batch_validation = ENV.fetch('PARLANT_ENABLE_BATCH_VALIDATION', 'true') == 'true'
  config.parlant.batch_size = ENV.fetch('PARLANT_BATCH_SIZE', '10').to_i
  config.parlant.enable_predictive_caching = ENV.fetch('PARLANT_ENABLE_PREDICTIVE_CACHING', 'true') == 'true'
  config.parlant.ml_confidence_threshold = ENV.fetch('PARLANT_ML_CONFIDENCE_THRESHOLD', '0.9').to_f

  ##
  # Development and Testing
  config.parlant.development_mode = ENV.fetch('PARLANT_DEVELOPMENT_MODE', 'false') == 'true'
  config.parlant.test_mode = ENV.fetch('PARLANT_TEST_MODE', 'false') == 'true'
  config.parlant.mock_validation_response = ENV.fetch('PARLANT_MOCK_VALIDATION_RESPONSE', 'approved')
  config.parlant.emergency_bypass = ENV.fetch('PARLANT_EMERGENCY_BYPASS', 'false') == 'true'

  ##
  # Compliance and Regulatory
  config.parlant.enable_gdpr_compliance = ENV.fetch('PARLANT_ENABLE_GDPR_COMPLIANCE', 'true') == 'true'
  config.parlant.enable_sox_compliance = ENV.fetch('PARLANT_ENABLE_SOX_COMPLIANCE', 'true') == 'true'
  config.parlant.enable_hipaa_compliance = ENV.fetch('PARLANT_ENABLE_HIPAA_COMPLIANCE', 'false') == 'true'
  config.parlant.data_classification = ENV.fetch('PARLANT_DATA_CLASSIFICATION', 'internal')

  ##
  # Monitoring and Health Checks
  config.parlant.enable_health_check = ENV.fetch('PARLANT_ENABLE_HEALTH_CHECK', 'true') == 'true'
  config.parlant.health_check_interval = ENV.fetch('PARLANT_HEALTH_CHECK_INTERVAL_MS', '30000').to_i / 1000.0
  config.parlant.enable_prometheus_metrics = ENV.fetch('PARLANT_ENABLE_PROMETHEUS_METRICS', 'true') == 'true'
  config.parlant.prometheus_port = ENV.fetch('PARLANT_PROMETHEUS_PORT', '9090').to_i

  ##
  # Integration Features
  config.parlant.enable_websocket = ENV.fetch('PARLANT_ENABLE_WEBSOCKET', 'true') == 'true'
  config.parlant.websocket_timeout = ENV.fetch('PARLANT_WEBSOCKET_TIMEOUT_MS', '30000').to_i / 1000.0
  config.parlant.enable_database_audit = ENV.fetch('PARLANT_ENABLE_DATABASE_AUDIT', 'true') == 'true'
end

##
# Initialize Parlant Integration Service
Rails.application.config.after_initialize do
  if Rails.application.config.parlant.enabled
    Rails.logger.info "[ParlantInitializer] Initializing Parlant integration for Huginn"
    
    begin
      # Test Parlant service connectivity
      service = ParlantIntegrationService.new
      health_status = service.health_status
      
      if health_status[:api_connectivity][:connected]
        Rails.logger.info "[ParlantInitializer] Parlant integration successfully initialized", {
          api_base_url: Rails.application.config.parlant.api_base_url,
          cache_enabled: Rails.application.config.parlant.cache_enabled,
          performance_logging: Rails.application.config.parlant.enable_performance_logging
        }
      else
        Rails.logger.warn "[ParlantInitializer] Parlant API not reachable", {
          api_base_url: Rails.application.config.parlant.api_base_url,
          error: health_status[:api_connectivity][:error]
        }
      end
      
    rescue StandardError => e
      Rails.logger.error "[ParlantInitializer] Failed to initialize Parlant integration", {
        error: e.message,
        fallback_mode: 'enabled'
      }
    end
  else
    Rails.logger.info "[ParlantInitializer] Parlant integration disabled"
  end
end

##
# Parlant Validation Middleware Configuration
if Rails.application.config.parlant.enabled
  Rails.application.config.middleware.use 'ParlantValidationMiddleware'
end

##
# Parlant Logging Configuration
if Rails.application.config.parlant.enable_audit_logging
  Rails.application.config.logger = ActiveSupport::Logger.new(STDOUT)
  Rails.application.config.logger.level = Rails.application.config.parlant.log_level
  
  # Add Parlant-specific log formatter
  Rails.application.config.logger.formatter = proc do |severity, datetime, progname, msg|
    formatted_msg = msg.is_a?(Hash) ? msg.to_json : msg
    "[#{datetime}] #{severity} #{progname}: #{formatted_msg}\n"
  end
end

##
# Parlant Performance Monitoring
if Rails.application.config.parlant.enable_performance_logging
  Rails.application.config.after_initialize do
    # Set up performance monitoring for Parlant operations
    ActiveSupport::Notifications.subscribe 'parlant.validation' do |name, started, finished, unique_id, data|
      Rails.logger.info "[ParlantPerformance] Validation completed", {
        operation: data[:operation],
        duration_ms: ((finished - started) * 1000).round(2),
        approved: data[:approved],
        confidence: data[:confidence],
        operation_id: unique_id
      }
    end
  end
end

##
# Parlant Health Check Endpoint
if Rails.application.config.parlant.enable_health_check
  Rails.application.routes.draw do
    get '/parlant/health', to: proc { |env|
      begin
        service = ParlantIntegrationService.new
        health_status = service.health_status
        
        status_code = health_status[:api_connectivity][:connected] ? 200 : 503
        
        [status_code, 
         { 'Content-Type' => 'application/json' }, 
         [health_status.to_json]]
      rescue StandardError => e
        [500, 
         { 'Content-Type' => 'application/json' }, 
         [{ error: e.message, timestamp: Time.current.iso8601 }.to_json]]
      end
    }
  end
end

##
# Parlant Emergency Bypass Configuration
if Rails.application.config.parlant.emergency_bypass
  Rails.logger.warn "[ParlantInitializer] EMERGENCY BYPASS ENABLED - All validations will be bypassed", {
    bypass_reason: 'emergency_maintenance',
    security_warning: 'ALL_SAFETY_CHECKS_DISABLED'
  }
  
  # Override validation methods to always return approved
  ParlantIntegrationService.class_eval do
    def validate_operation(*)
      {
        approved: true,
        bypassed: true,
        bypass_reason: 'emergency_maintenance',
        confidence: 1.0,
        reasoning: 'Emergency bypass active - all operations approved',
        operation_id: "emergency_bypass_#{Time.current.to_i}",
        validation_metadata: {
          bypass_timestamp: Time.current.iso8601,
          emergency_mode: true
        }
      }
    end
  end
end

##
# Parlant Development and Testing Configuration
if Rails.env.development? || Rails.application.config.parlant.development_mode
  Rails.logger.info "[ParlantInitializer] Development mode active", {
    verbose_logging: true,
    test_endpoints: true,
    mock_responses: Rails.application.config.parlant.test_mode
  }
  
  # Add development-specific routes for testing
  Rails.application.routes.draw do
    namespace :parlant do
      get :test_validation, to: proc { |env|
        service = ParlantIntegrationService.new
        result = service.validate_operation(
          operation: 'test_operation',
          context: { test: true },
          user_intent: 'Testing Parlant integration'
        )
        
        [200, 
         { 'Content-Type' => 'application/json' }, 
         [result.to_json]]
      }
      
      get :service_status, to: proc { |env|
        service = ParlantIntegrationService.new
        status = service.health_status
        
        [200, 
         { 'Content-Type' => 'application/json' }, 
         [status.to_json]]
      }
    end
  end
end

##
# Parlant Configuration Validation
Rails.application.config.after_initialize do
  required_config = %w[
    PARLANT_ENABLED
    PARLANT_API_BASE_URL
  ]
  
  if Rails.application.config.parlant.enabled
    missing_config = required_config.select { |key| ENV[key].blank? }
    
    if missing_config.any?
      Rails.logger.error "[ParlantInitializer] Missing required configuration", {
        missing_variables: missing_config,
        fallback_action: 'disable_integration'
      }
      
      Rails.application.config.parlant.enabled = false
    end
    
    if ENV['PARLANT_API_KEY'].blank?
      Rails.logger.warn "[ParlantInitializer] No API key configured", {
        warning: 'API requests may fail without authentication'
      }
    end
  end
end