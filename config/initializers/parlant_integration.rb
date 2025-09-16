# frozen_string_literal: true

#
# Parlant Integration Initializer for Huginn
#
# Configures comprehensive Parlant conversational AI validation for all Huginn
# monitoring and automation agents with enterprise-grade security and performance.
#

Rails.application.configure do
  # Only initialize if Parlant integration is enabled
  if ENV.fetch('HUGINN_PARLANT_ENABLED', 'true') == 'true'
    
    Rails.logger.info "[ParlantIntegration] Initializing Huginn Parlant Integration..."

    begin
      # Load Parlant integration library
      require Rails.root.join('lib', 'parlant_integration')

      # Configure Parlant integration settings
      ParlantIntegration.configure do |config|
        # Parlant service connection
        config.endpoint = ENV.fetch('PARLANT_SERVICE_ENDPOINT', 'http://localhost:3001')
        config.api_key = ENV['PARLANT_API_KEY']
        config.timeout_seconds = ENV.fetch('PARLANT_TIMEOUT_SECONDS', '30').to_i

        # Performance settings
        config.enable_caching = ENV.fetch('PARLANT_ENABLE_CACHING', 'true') == 'true'
        config.cache_ttl_minutes = ENV.fetch('PARLANT_CACHE_TTL_MINUTES', '15').to_i
        config.batch_validation_size = ENV.fetch('PARLANT_BATCH_SIZE', '5').to_i

        # Security classification defaults
        config.default_security_level = ENV.fetch('PARLANT_DEFAULT_SECURITY_LEVEL', 'INTERNAL')
        config.require_validation_for_external_emails = ENV.fetch('PARLANT_VALIDATE_EXTERNAL_EMAILS', 'true') == 'true'
        config.shell_command_security_level = ENV.fetch('PARLANT_SHELL_SECURITY_LEVEL', 'CRITICAL')

        # Audit and logging
        config.comprehensive_audit_logging = ENV.fetch('PARLANT_COMPREHENSIVE_AUDIT', 'true') == 'true'
        config.log_level = ENV.fetch('PARLANT_LOG_LEVEL', 'info').to_sym
        config.audit_retention_days = ENV.fetch('PARLANT_AUDIT_RETENTION_DAYS', '90').to_i

        # Content safety
        config.content_safety_enabled = ENV.fetch('PARLANT_CONTENT_SAFETY', 'true') == 'true'
        config.suspicious_content_patterns = ENV.fetch('PARLANT_SUSPICIOUS_PATTERNS', 
          'spam,phishing,malware,suspicious,exploit,attack').split(',')

        # Performance monitoring
        config.performance_monitoring_enabled = ENV.fetch('PARLANT_PERFORMANCE_MONITORING', 'true') == 'true'
        config.response_time_alert_threshold_ms = ENV.fetch('PARLANT_RESPONSE_TIME_THRESHOLD', '5000').to_i
        config.error_rate_alert_threshold_percent = ENV.fetch('PARLANT_ERROR_RATE_THRESHOLD', '5').to_f
      end if defined?(ParlantIntegration)

      # Initialize singleton service instance
      parlant_service = ParlantIntegration::Service.instance

      # Perform health check
      health_status = parlant_service.health_check
      
      if health_status[:status] == 'healthy'
        Rails.logger.info "[ParlantIntegration] ✅ Service initialized successfully (#{health_status[:response_time_ms]}ms)"
        Rails.logger.info "[ParlantIntegration] 📊 Metrics: #{health_status[:metrics]}"
      else
        Rails.logger.warn "[ParlantIntegration] ⚠️  Service health check failed: #{health_status[:error]}"
        Rails.logger.warn "[ParlantIntegration] Continuing with degraded validation capabilities"
      end

      # Register cleanup callbacks
      at_exit do
        Rails.logger.info "[ParlantIntegration] Shutting down Parlant integration service..."
        # Cleanup resources if needed
      end

      # Setup periodic health monitoring
      if ENV.fetch('PARLANT_HEALTH_MONITORING', 'true') == 'true'
        Thread.new do
          loop do
            sleep(ENV.fetch('PARLANT_HEALTH_CHECK_INTERVAL_SECONDS', '300').to_i)
            
            begin
              health = parlant_service.health_check
              
              if health[:status] != 'healthy'
                Rails.logger.error "[ParlantIntegration] 🚨 Health check failed: #{health[:error]}"
                
                # Could trigger alerts or notifications here
                if ENV.fetch('PARLANT_HEALTH_ALERTS_ENABLED', 'false') == 'true'
                  # Send health alert through system mailer if available
                  begin
                    SystemMailerParlant.send_critical_alert(
                      to: ENV.fetch('PARLANT_HEALTH_ALERT_RECIPIENTS', 'admin@example.com').split(','),
                      alert_type: 'parlant_service_unhealthy',
                      severity: 'high',
                      subject: 'Parlant Integration Service Health Alert',
                      body: "Parlant service health check failed: #{health[:error]}",
                      system_impact: 'Conversational validation may be degraded',
                      urgent: false
                    ).deliver_now if defined?(SystemMailerParlant)
                  rescue StandardError => alert_error
                    Rails.logger.error "[ParlantIntegration] Failed to send health alert: #{alert_error.message}"
                  end
                end
              end
              
            rescue StandardError => e
              Rails.logger.error "[ParlantIntegration] Health monitoring error: #{e.message}"
            end
          end
        end
      end

    rescue StandardError => e
      Rails.logger.error "[ParlantIntegration] ❌ Initialization failed: #{e.message}"
      Rails.logger.error e.backtrace.join("\n")
      
      # Don't fail application startup, but log the error
      Rails.logger.warn "[ParlantIntegration] Continuing without Parlant integration"
      
      # Set environment variable to disable integration
      ENV['HUGINN_PARLANT_ENABLED'] = 'false'
    end

  else
    Rails.logger.info "[ParlantIntegration] Parlant integration disabled (HUGINN_PARLANT_ENABLED=false)"
  end

  # Register middleware for request-level Parlant context
  if ENV.fetch('HUGINN_PARLANT_ENABLED', 'true') == 'true'
    config.middleware.use(Class.new do
      def initialize(app)
        @app = app
      end

      def call(env)
        # Set request-level context for Parlant operations
        Thread.current[:parlant_request_id] = SecureRandom.hex(8)
        Thread.current[:parlant_request_start] = Time.now
        
        begin
          @app.call(env)
        ensure
          # Cleanup thread-local variables
          Thread.current[:parlant_request_id] = nil
          Thread.current[:parlant_request_start] = nil
        end
      end
    end)
  end

  # Configure ActionMailer to use ParlantIntegration if available
  if defined?(SystemMailerParlant) && ENV.fetch('HUGINN_PARLANT_MAILER_ENABLED', 'true') == 'true'
    # Replace default system mailer with Parlant-enhanced version
    Rails.logger.info "[ParlantIntegration] 📧 Enhanced system mailer configured"
  end
end

# Environment validation
required_env_vars = %w[
  PARLANT_SERVICE_ENDPOINT
]

optional_env_vars = %w[
  PARLANT_API_KEY
  PARLANT_TIMEOUT_SECONDS
  PARLANT_ENABLE_CACHING
  PARLANT_DEFAULT_SECURITY_LEVEL
  INTERNAL_EMAIL_DOMAINS
  PARLANT_HEALTH_MONITORING
  PARLANT_PERFORMANCE_MONITORING
]

if Rails.env.production? && ENV.fetch('HUGINN_PARLANT_ENABLED', 'true') == 'true'
  missing_vars = required_env_vars.select { |var| ENV[var].blank? }
  
  if missing_vars.any?
    Rails.logger.error "[ParlantIntegration] ❌ Missing required environment variables: #{missing_vars.join(', ')}"
    Rails.logger.error "[ParlantIntegration] Please configure these variables for production use"
  end

  Rails.logger.info "[ParlantIntegration] 🔧 Optional environment variables available: #{optional_env_vars.map { |var| "#{var}=#{ENV[var].present? ? '[SET]' : '[NOT SET]'}" }.join(', ')}"
end

Rails.logger.info "[ParlantIntegration] 🚀 Huginn Parlant Integration initialization complete"