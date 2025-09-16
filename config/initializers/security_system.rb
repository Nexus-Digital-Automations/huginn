# frozen_string_literal: true

##
# Security System Initializer
#
# Configures the comprehensive security system for Huginn Parlant integration
# including authentication, authorization, monitoring, compliance, and audit systems.
#
# @author AIgent Security Team
# @since 1.0.0

Rails.application.configure do
  # Security System Configuration
  config.security_system = ActiveSupport::OrderedOptions.new

  # Authentication Bridge Configuration
  config.security_system.authentication = ActiveSupport::OrderedOptions.new
  config.security_system.authentication.jwt_algorithm = ENV.fetch('JWT_ALGORITHM', 'RS256')
  config.security_system.authentication.access_token_lifetime = ENV.fetch('JWT_ACCESS_TOKEN_LIFETIME', '3600').to_i
  config.security_system.authentication.refresh_token_lifetime = ENV.fetch('JWT_REFRESH_TOKEN_LIFETIME', '86400').to_i
  config.security_system.authentication.session_timeout = ENV.fetch('SESSION_TIMEOUT_MS', '3600000').to_i / 1000.0
  config.security_system.authentication.max_concurrent_sessions = ENV.fetch('MAX_CONCURRENT_SESSIONS', '10').to_i
  config.security_system.authentication.mfa_required_operations = %w[user_deletion permission_escalation data_export system_shutdown]

  # Security Monitoring Configuration
  config.security_system.monitoring = ActiveSupport::OrderedOptions.new
  config.security_system.monitoring.enabled = ENV.fetch('SECURITY_MONITORING_ENABLED', 'true') == 'true'
  config.security_system.monitoring.real_time_alerts = ENV.fetch('REAL_TIME_ALERTS_ENABLED', 'true') == 'true'
  config.security_system.monitoring.threat_intelligence = ENV.fetch('THREAT_INTELLIGENCE_ENABLED', 'true') == 'true'
  config.security_system.monitoring.behavioral_analysis = ENV.fetch('BEHAVIORAL_ANALYSIS_ENABLED', 'true') == 'true'
  config.security_system.monitoring.anomaly_detection = ENV.fetch('ANOMALY_DETECTION_ENABLED', 'true') == 'true'

  # Compliance Configuration
  config.security_system.compliance = ActiveSupport::OrderedOptions.new
  config.security_system.compliance.gdpr_enabled = ENV.fetch('GDPR_COMPLIANCE_ENABLED', 'true') == 'true'
  config.security_system.compliance.hipaa_enabled = ENV.fetch('HIPAA_COMPLIANCE_ENABLED', 'false') == 'true'
  config.security_system.compliance.pci_dss_enabled = ENV.fetch('PCI_DSS_COMPLIANCE_ENABLED', 'false') == 'true'
  config.security_system.compliance.soc2_enabled = ENV.fetch('SOC2_COMPLIANCE_ENABLED', 'true') == 'true'
  config.security_system.compliance.data_retention_days = ENV.fetch('DATA_RETENTION_DAYS', '2555').to_i # 7 years default
  config.security_system.compliance.automated_deletion = ENV.fetch('AUTOMATED_DATA_DELETION', 'true') == 'true'

  # Audit System Configuration
  config.security_system.audit = ActiveSupport::OrderedOptions.new
  config.security_system.audit.enabled = ENV.fetch('AUDIT_SYSTEM_ENABLED', 'true') == 'true'
  config.security_system.audit.storage_backend = ENV.fetch('AUDIT_STORAGE_BACKEND', 'database') # database, s3, blockchain
  config.security_system.audit.encryption_enabled = ENV.fetch('AUDIT_ENCRYPTION_ENABLED', 'true') == 'true'
  config.security_system.audit.digital_signatures = ENV.fetch('AUDIT_DIGITAL_SIGNATURES', 'true') == 'true'
  config.security_system.audit.searchable_index = ENV.fetch('AUDIT_SEARCHABLE_INDEX', 'true') == 'true'
  config.security_system.audit.compression_enabled = ENV.fetch('AUDIT_COMPRESSION_ENABLED', 'true') == 'true'

  # Emergency Override Configuration
  config.security_system.emergency = ActiveSupport::OrderedOptions.new
  config.security_system.emergency.enabled = ENV.fetch('EMERGENCY_OVERRIDE_ENABLED', 'true') == 'true'
  config.security_system.emergency.max_concurrent_overrides = ENV.fetch('MAX_CONCURRENT_EMERGENCY_OVERRIDES', '5').to_i
  config.security_system.emergency.monitoring_required = ENV.fetch('EMERGENCY_MONITORING_REQUIRED', 'true') == 'true'
  config.security_system.emergency.automatic_cleanup = ENV.fetch('EMERGENCY_AUTO_CLEANUP', 'true') == 'true'

  # Conversational Security Configuration
  config.security_system.conversational = ActiveSupport::OrderedOptions.new
  config.security_system.conversational.enabled = ENV.fetch('CONVERSATIONAL_SECURITY_ENABLED', 'true') == 'true'
  config.security_system.conversational.parlant_api_url = ENV.fetch('PARLANT_API_BASE_URL', 'http://localhost:8000')
  config.security_system.conversational.validation_timeout = ENV.fetch('CONVERSATIONAL_VALIDATION_TIMEOUT', '30000').to_i
  config.security_system.conversational.cache_enabled = ENV.fetch('CONVERSATIONAL_CACHE_ENABLED', 'true') == 'true'
  config.security_system.conversational.high_risk_threshold = ENV.fetch('HIGH_RISK_THRESHOLD', '0.7').to_f

  # Security Headers Configuration
  config.security_system.headers = ActiveSupport::OrderedOptions.new
  config.security_system.headers.enabled = ENV.fetch('SECURITY_HEADERS_ENABLED', 'true') == 'true'
  config.security_system.headers.hsts_enabled = ENV.fetch('HSTS_ENABLED', 'true') == 'true'
  config.security_system.headers.csp_enabled = ENV.fetch('CSP_ENABLED', 'true') == 'true'
  config.security_system.headers.frame_options = ENV.fetch('X_FRAME_OPTIONS', 'DENY')

  # Rate Limiting Configuration
  config.security_system.rate_limiting = ActiveSupport::OrderedOptions.new
  config.security_system.rate_limiting.enabled = ENV.fetch('RATE_LIMITING_ENABLED', 'true') == 'true'
  config.security_system.rate_limiting.redis_url = ENV.fetch('REDIS_URL', 'redis://localhost:6379/2')
  config.security_system.rate_limiting.default_limit = ENV.fetch('DEFAULT_RATE_LIMIT', '1000').to_i
  config.security_system.rate_limiting.burst_limit = ENV.fetch('BURST_RATE_LIMIT', '100').to_i
  config.security_system.rate_limiting.adaptive_enabled = ENV.fetch('ADAPTIVE_RATE_LIMITING', 'true') == 'true'

  # Encryption Configuration
  config.security_system.encryption = ActiveSupport::OrderedOptions.new
  config.security_system.encryption.algorithm = ENV.fetch('ENCRYPTION_ALGORITHM', 'AES-256-GCM')
  config.security_system.encryption.key_rotation_days = ENV.fetch('KEY_ROTATION_DAYS', '90').to_i
  config.security_system.encryption.key_management = ENV.fetch('KEY_MANAGEMENT', 'local') # local, vault, kms

  # Security Middleware Stack Configuration
  config.middleware.insert_before ActionDispatch::Session::CookieStore, SecurityMiddleware::SecurityHeadersFilter
  config.middleware.insert_before ActionDispatch::Session::CookieStore, SecurityMiddleware::RateLimitingFilter
  config.middleware.insert_after ActionDispatch::Session::CookieStore, SecurityMiddleware::AuthenticationFilter
  config.middleware.insert_after SecurityMiddleware::AuthenticationFilter, SecurityMiddleware::AuthorizationFilter

  # Security System Initialization
  config.after_initialize do |app|
    Rails.logger.info "[SecuritySystem] Initializing comprehensive security system..."

    begin
      # Initialize security services based on configuration
      if app.config.security_system.monitoring.enabled
        Rails.application.config.security_monitoring_service = SecurityMonitoringService.new
        Rails.application.config.security_monitoring_service.start_monitoring
        Rails.logger.info "[SecuritySystem] Security monitoring started"
      end

      if app.config.security_system.audit.enabled
        Rails.application.config.audit_system = ComprehensiveAuditSystem.new
        Rails.logger.info "[SecuritySystem] Audit system initialized"
      end

      if app.config.security_system.conversational.enabled
        Rails.application.config.conversational_validator = ConversationalSecurityValidator.new
        Rails.logger.info "[SecuritySystem] Conversational security validation enabled"
      end

      if app.config.security_system.compliance.gdpr_enabled || 
         app.config.security_system.compliance.hipaa_enabled ||
         app.config.security_system.compliance.pci_dss_enabled ||
         app.config.security_system.compliance.soc2_enabled
        Rails.application.config.compliance_service = DataProtectionComplianceService.new
        Rails.logger.info "[SecuritySystem] Data protection compliance services enabled"
      end

      if app.config.security_system.emergency.enabled
        Rails.application.config.emergency_override_service = EmergencyOverrideService.new
        Rails.logger.info "[SecuritySystem] Emergency override system initialized"
      end

      # Create initial audit trail for system startup
      if app.config.security_system.audit.enabled
        Rails.application.config.audit_system.create_audit_trail(
          event_type: 'system_configuration',
          user_id: 0, # System user
          operation: 'security_system_initialization',
          context: {
            security_components: %w[authentication monitoring compliance audit emergency],
            configuration: {
              gdpr_enabled: app.config.security_system.compliance.gdpr_enabled,
              monitoring_enabled: app.config.security_system.monitoring.enabled,
              conversational_validation: app.config.security_system.conversational.enabled,
              emergency_override: app.config.security_system.emergency.enabled
            },
            startup_time: Time.current.iso8601
          },
          risk_level: 'low'
        )
      end

      Rails.logger.info "[SecuritySystem] Comprehensive security system initialized successfully"

    rescue StandardError => e
      Rails.logger.error "[SecuritySystem] Failed to initialize security system: #{e.message}"
      Rails.logger.error e.backtrace.join("\n")
      
      # In development, we can continue without security features
      # In production, this should be a hard failure
      if Rails.env.production?
        raise SecuritySystemInitializationError, "Critical security system initialization failure: #{e.message}"
      else
        Rails.logger.warn "[SecuritySystem] Continuing in development mode with limited security features"
      end
    end
  end

  # Security System Health Check
  config.after_initialize do
    Rails.application.config.to_prepare do
      # Register health check endpoints
      if defined?(HealthCheck)
        HealthCheck.setup do |config|
          config.add_custom_check('security_system') do
            begin
              status = {
                authentication: Rails.application.config.respond_to?(:auth_bridge_service) ? 'operational' : 'disabled',
                monitoring: Rails.application.config.respond_to?(:security_monitoring_service) ? 'operational' : 'disabled',
                audit: Rails.application.config.respond_to?(:audit_system) ? 'operational' : 'disabled',
                compliance: Rails.application.config.respond_to?(:compliance_service) ? 'operational' : 'disabled',
                emergency: Rails.application.config.respond_to?(:emergency_override_service) ? 'operational' : 'disabled'
              }
              
              if status.values.all? { |s| s == 'operational' }
                'Security system fully operational'
              else
                disabled_components = status.select { |_, v| v == 'disabled' }.keys
                "Security system partially operational - disabled: #{disabled_components.join(', ')}"
              end
            rescue => e
              "Security system health check failed: #{e.message}"
            end
          end
        end
      end
    end
  end
end

# Custom error class for security system initialization failures
class SecuritySystemInitializationError < StandardError; end

# Security System Version and Information
module SecuritySystem
  VERSION = '1.0.0'.freeze
  COMPONENTS = %w[
    authentication_bridge
    security_monitoring
    conversational_validation
    comprehensive_audit
    compliance_management
    emergency_override
    security_middleware
  ].freeze

  def self.status
    {
      version: VERSION,
      components: COMPONENTS,
      initialized_at: Rails.application.config.security_system_initialized_at || 'not_initialized',
      configuration: Rails.application.config.security_system&.to_h || {}
    }
  end

  def self.health_check
    {
      overall_status: determine_overall_status,
      component_status: check_component_status,
      last_checked: Time.current.iso8601
    }
  end

  private

  def self.determine_overall_status
    component_statuses = check_component_status.values
    
    if component_statuses.all? { |status| status[:status] == 'operational' }
      'fully_operational'
    elsif component_statuses.any? { |status| status[:status] == 'operational' }
      'partially_operational'
    else
      'non_operational'
    end
  end

  def self.check_component_status
    {
      authentication: check_service_health('auth_bridge_service'),
      monitoring: check_service_health('security_monitoring_service'),
      audit: check_service_health('audit_system'),
      compliance: check_service_health('compliance_service'),
      emergency: check_service_health('emergency_override_service')
    }
  end

  def self.check_service_health(service_name)
    service = Rails.application.config.send(service_name) if Rails.application.config.respond_to?(service_name)
    
    if service && service.respond_to?(:health_status)
      service.health_status
    else
      { status: 'not_available', message: "Service #{service_name} not initialized" }
    end
  rescue => e
    { status: 'error', message: "Health check failed: #{e.message}" }
  end
end