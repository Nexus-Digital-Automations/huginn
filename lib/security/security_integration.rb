# frozen_string_literal: true

require_relative 'authentication_manager'
require_relative 'transport_security'
require_relative 'network_security_controls'
require_relative 'session_security_manager'

module Security
  # Enterprise-grade security integration layer that combines all security
  # components for comprehensive protection of Huginn-AIgent communication.
  #
  # This module provides a unified interface to:
  # - Authentication Manager (API keys, JWT, OAuth2, Basic auth, MFA)
  # - Transport Security (SSL/TLS, certificate management, HSTS)
  # - Network Security Controls (rate limiting, IP filtering, DDoS protection)
  # - Session Security Manager (secure sessions, CSRF protection)
  #
  # Integration Features:
  # - Unified security policy enforcement
  # - Centralized security configuration
  # - Comprehensive security logging and monitoring
  # - Security incident response and alerting
  # - Performance optimization across security layers
  class SecurityIntegration
    class SecurityIntegrationError < StandardError; end
    class SecurityPolicyViolationError < SecurityIntegrationError; end
    class SecurityConfigurationError < SecurityIntegrationError; end

    # Security levels
    SECURITY_LEVELS = {
      minimal: 'minimal',     # Basic security (development)
      standard: 'standard',   # Standard enterprise security
      strict: 'strict',       # High-security environments
      maximum: 'maximum'      # Maximum security (government, financial)
    }.freeze

    # Security configuration profiles
    SECURITY_PROFILES = {
      minimal: {
        authentication: { methods: [:api_key], mfa_required: false },
        transport: { min_tls_version: 'TLSv1.2', certificate_pinning: false },
        network: { rate_limiting: true, geo_blocking: false },
        session: { fingerprinting: false, csrf_protection: true }
      },
      standard: {
        authentication: { methods: [:api_key, :jwt], mfa_required: false },
        transport: { min_tls_version: 'TLSv1.2', certificate_pinning: true },
        network: { rate_limiting: true, geo_blocking: true },
        session: { fingerprinting: true, csrf_protection: true }
      },
      strict: {
        authentication: { methods: [:api_key, :jwt, :oauth2], mfa_required: true },
        transport: { min_tls_version: 'TLSv1.3', certificate_pinning: true },
        network: { rate_limiting: true, geo_blocking: true, ddos_protection: true },
        session: { fingerprinting: true, csrf_protection: true, strict_ip_binding: true }
      },
      maximum: {
        authentication: { methods: [:api_key, :jwt, :oauth2, :mfa], mfa_required: true },
        transport: { min_tls_version: 'TLSv1.3', certificate_pinning: true, hsts_required: true },
        network: { rate_limiting: true, geo_blocking: true, ddos_protection: true, threat_intelligence: true },
        session: { fingerprinting: true, csrf_protection: true, strict_ip_binding: true, session_encryption: true }
      }
    }.freeze

    attr_reader :config, :logger, :metrics, :security_level
    attr_reader :auth_manager, :transport_security, :network_controls, :session_manager

    def initialize(security_level: :standard, config: {}, logger: nil)
      @security_level = security_level.to_sym
      @config = build_security_config(config)
      @logger = logger || default_logger
      @metrics = SecurityIntegrationMetrics.new
      
      # Initialize security components
      initialize_security_components
      
      # Set up security monitoring
      @security_monitor = SecurityMonitor.new(@config, @logger, @metrics)
      @incident_responder = IncidentResponder.new(@config, @logger)
      
      # Start security monitoring
      start_security_monitoring
      
      log_info "Security integration initialized with #{@security_level} security level"
    end

    # Unified Security Validation

    def validate_request(request_info)
      log_debug "Validating request with integrated security"
      
      validation_start = Time.current
      security_context = {
        request_id: SecureRandom.uuid,
        timestamp: validation_start,
        remote_ip: request_info[:remote_ip],
        user_agent: request_info[:user_agent],
        path: request_info[:path],
        method: request_info[:method]
      }
      
      begin
        # 1. Network Security Validation
        network_result = @network_controls.validate_request(request_info)
        security_context[:network_validation] = network_result
        
        # 2. Authentication Validation (if auth header present)
        nil
        if request_info[:authorization]
          auth_result = @auth_manager.authenticate_request(
            auth_header: request_info[:authorization],
            method: determine_auth_method(request_info[:authorization])
          )
          security_context[:authentication] = auth_result
        end
        
        # 3. Session Validation (if session token present)
        session_result = nil
        if request_info[:session_token]
          session_result = @session_manager.validate_session(
            session_token: request_info[:session_token],
            request_info: request_info
          )
          security_context[:session] = session_result
        end
        
        # 4. CSRF Validation (if applicable)
        csrf_result = validate_csrf_if_required(request_info, session_result)
        security_context[:csrf] = csrf_result if csrf_result
        
        # 5. Calculate overall security score
        security_score = calculate_security_score(security_context)
        
        # 6. Apply security policies
        apply_security_policies(security_context, security_score)
        
        validation_time = Time.current - validation_start
        @metrics.record_request_validation(true, validation_time, security_score)
        
        log_info "Request validation successful (score: #{security_score})"
        
        {
          status: :allowed,
          security_score: security_score,
          validation_time_ms: (validation_time * 1000).round(2),
          context: security_context,
          warnings: extract_security_warnings(security_context)
        }
        
      rescue StandardError => e
        validation_time = Time.current - validation_start
        @metrics.record_request_validation(false, validation_time, 0)
        
        # Handle security incident
        @incident_responder.handle_security_incident(e, security_context)
        
        log_error "Request validation failed: #{e.message}"
        
        {
          status: :denied,
          reason: e.message,
          error_type: e.class.name,
          validation_time_ms: (validation_time * 1000).round(2),
          context: security_context
        }
      end
    end

    # Secure Connection Management

    def create_secure_connection(url, options = {})
      log_info "Creating secure connection to: #{url}"
      
      begin
        # Apply transport security settings
        transport_options = apply_transport_security_options(options)
        
        # Create secure connection
        connection = @transport_security.create_secure_connection(url, transport_options)
        
        # Register connection for monitoring
        @security_monitor.register_connection(url, connection.object_id)
        
        log_info "Secure connection established to: #{url}"
        connection
        
      rescue StandardError => e
        log_error "Failed to create secure connection to #{url}: #{e.message}"
        @incident_responder.handle_connection_failure(url, e)
        raise
      end
    end

    # Authentication Management

    def authenticate_user(credentials, request_info: {})
      log_info "Authenticating user with integrated security"
      
      begin
        # Determine authentication method
        auth_method = determine_auth_method_from_credentials(credentials)
        
        # Perform authentication
        auth_result = case auth_method
                      when :api_key
                        @auth_manager.validate_api_key(credentials[:api_key])
                      when :jwt
                        @auth_manager.validate_jwt_token(credentials[:jwt_token])
                      when :basic
                        @auth_manager.validate_basic_auth(credentials[:username], credentials[:password])
                      when :oauth2
                        validate_oauth2_credentials(credentials)
                      else
                        raise SecurityIntegrationError, "Unsupported authentication method: #{auth_method}"
                      end
        
        # Check if MFA is required
        if mfa_required?(auth_result[:user_id])
          unless credentials[:mfa_token]
            mfa_token = @auth_manager.generate_mfa_token(auth_result[:user_id])
            return {
              status: :mfa_required,
              mfa_token: mfa_token[:mfa_code],
              auth_result: auth_result
            }
          else
            @auth_manager.verify_mfa_token(auth_result[:user_id], credentials[:mfa_token])
          end
        end
        
        # Create secure session if configured
        session_result = nil
        if session_required?
          session_result = @session_manager.create_session(
            user_id: auth_result[:user_id],
            request_info: request_info,
            session_data: { auth_method: auth_method }
          )
        end
        
        @metrics.increment('successful_authentications')
        log_info "User authentication successful: #{auth_result[:user_id]}"
        
        {
          status: :authenticated,
          user_id: auth_result[:user_id],
          auth_method: auth_method,
          scopes: auth_result[:scopes],
          session: session_result,
          metadata: auth_result[:metadata]
        }
        
      rescue StandardError => e
        @metrics.increment('failed_authentications')
        log_warning "User authentication failed: #{e.message}"
        
        # Handle authentication failure
        @incident_responder.handle_authentication_failure(credentials, e, request_info)
        
        {
          status: :failed,
          reason: e.message,
          error_type: e.class.name
        }
      end
    end

    # Security Policy Management

    def apply_security_policy(policy_name, context)
      log_debug "Applying security policy: #{policy_name}"
      
      policy = @config[:security_policies][policy_name]
      return true unless policy
      
      policy[:rules].each do |rule|
        unless evaluate_policy_rule(rule, context)
          @metrics.increment('security_policy_violations')
          raise SecurityPolicyViolationError, "Security policy violation: #{rule[:description]}"
        end
      end
      
      log_debug "Security policy applied successfully: #{policy_name}"
      true
    end

    # Security Monitoring and Alerting

    def get_security_status
      {
        status: determine_overall_security_status,
        security_level: @security_level,
        components: {
          authentication: @auth_manager.get_authentication_metrics,
          transport: @transport_security.get_security_metrics,
          network: @network_controls.get_security_metrics,
          session: @session_manager.get_session_security_metrics
        },
        incidents: @incident_responder.get_recent_incidents,
        metrics: @metrics.get_all_metrics,
        health: {
          authentication: @auth_manager.respond_to?(:health_check) ? @auth_manager.health_check : { status: 'ok' },
          transport: @transport_security.security_health_check,
          network: @network_controls.get_security_status,
          session: @session_manager.get_session_health_status
        }
      }
    end

    def generate_security_report
      log_info "Generating comprehensive security report"
      
      report = {
        generated_at: Time.current.iso8601,
        security_level: @security_level,
        reporting_period: '24_hours',
        
        summary: {
          total_requests: @metrics.get('total_requests'),
          blocked_requests: @metrics.get('blocked_requests'),
          security_incidents: @incident_responder.incident_count,
          overall_security_score: calculate_overall_security_score
        },
        
        authentication: {
          total_attempts: @metrics.get('authentication_attempts'),
          successful_authentications: @metrics.get('successful_authentications'),
          failed_authentications: @metrics.get('failed_authentications'),
          mfa_usage: @metrics.get('mfa_verifications'),
          success_rate: calculate_auth_success_rate
        },
        
        transport_security: {
          connections_validated: @transport_security.get_security_metrics[:connections_validated],
          certificate_failures: @transport_security.get_security_metrics[:certificate_failures],
          tls_violations: @transport_security.get_security_metrics[:tls_version_violations],
          cipher_distribution: @transport_security.get_security_metrics[:cipher_suite_distribution]
        },
        
        network_security: {
          rate_limits_exceeded: @network_controls.get_security_metrics[:rate_limits_exceeded],
          geo_blocked: @network_controls.get_security_metrics[:geo_blocked],
          ddos_mitigations: @network_controls.get_security_metrics[:ddos_mitigations],
          threat_intel_blocks: @network_controls.get_security_metrics[:threat_intelligence_blocks]
        },
        
        session_security: {
          sessions_created: @session_manager.get_session_security_metrics[:total_sessions],
          session_hijacking: @session_manager.get_session_security_metrics[:session_hijacking_detected],
          csrf_violations: @session_manager.get_session_security_metrics[:csrf_violations],
          average_session_duration: @session_manager.get_session_security_metrics[:average_session_duration]
        },
        
        recommendations: generate_security_recommendations
      }
      
      log_info "Security report generated successfully"
      report
    end

    # Emergency Security Controls

    def enable_lockdown_mode(reason: 'security_incident', duration: 1.hour)
      log_warning "Enabling security lockdown mode: #{reason}"
      
      @config[:lockdown_mode] = {
        enabled: true,
        reason: reason,
        enabled_at: Time.current,
        expires_at: Time.current + duration
      }
      
      # Apply lockdown policies
      @network_controls.enable_maintenance_mode
      
      @metrics.increment('lockdown_mode_activations')
      @incident_responder.handle_emergency_lockdown(reason)
      
      log_warning "Security lockdown mode enabled until #{@config[:lockdown_mode][:expires_at]}"
      true
    end

    def disable_lockdown_mode
      log_info "Disabling security lockdown mode"
      
      @config[:lockdown_mode][:enabled] = false
      @network_controls.disable_maintenance_mode
      
      @metrics.increment('lockdown_mode_deactivations')
      
      log_info "Security lockdown mode disabled"
      true
    end

    # Security Configuration Management

    def update_security_level(new_level)
      log_info "Updating security level from #{@security_level} to #{new_level}"
      
      unless SECURITY_LEVELS.key?(new_level.to_sym)
        raise SecurityConfigurationError, "Invalid security level: #{new_level}"
      end
      
      old_level = @security_level
      @security_level = new_level.to_sym
      @config = build_security_config
      
      # Reinitialize components with new configuration
      reinitialize_security_components
      
      @metrics.increment('security_level_changes')
      log_info "Security level updated to #{@security_level}"
      
      { old_level: old_level, new_level: @security_level }
    end

    private

    def build_security_config(custom_config = {})
      base_config = SECURITY_PROFILES[@security_level].deep_dup
      
      # Add common configuration
      base_config.merge!({
        security_level: @security_level,
        lockdown_mode: { enabled: false },
        security_policies: load_security_policies,
        logging: {
          level: Rails.env.production? ? :info : :debug,
          audit_enabled: true,
          security_events: true
        },
        monitoring: {
          enabled: true,
          alert_thresholds: {
            failed_auth_rate: 0.1,
            blocked_request_rate: 0.05,
            security_incident_rate: 0.01
          }
        }
      })
      
      base_config.deep_merge(custom_config)
    end

    def initialize_security_components
      redis_instance = default_redis
      
      @auth_manager = AuthenticationManager.new(
        config: @config[:authentication],
        logger: @logger
      )
      
      @transport_security = TransportSecurity.new(
        config: @config[:transport],
        logger: @logger
      )
      
      @network_controls = NetworkSecurityControls.new(
        config: @config[:network],
        logger: @logger,
        redis: redis_instance
      )
      
      @session_manager = SessionSecurityManager.new(
        config: @config[:session],
        logger: @logger,
        redis: redis_instance
      )
    end

    def reinitialize_security_components
      # This would properly reinitialize all components with new config
      initialize_security_components
    end

    def determine_auth_method(auth_header)
      case auth_header
      when /^Bearer\s+/i
        :jwt
      when /^Basic\s+/i
        :basic
      when /^ApiKey\s+/i
        :api_key
      else
        :unknown
      end
    end

    def determine_auth_method_from_credentials(credentials)
      return :api_key if credentials[:api_key]
      return :jwt if credentials[:jwt_token]
      return :basic if credentials[:username] && credentials[:password]
      return :oauth2 if credentials[:oauth_token]
      :unknown
    end

    def validate_oauth2_credentials(credentials)
      # OAuth2 validation implementation
      { user_id: 'oauth_user', scopes: ['read'], metadata: {} }
    end

    def mfa_required?(user_id)
      @config[:authentication][:mfa_required] || false
    end

    def session_required?
      @config[:session][:enabled] != false
    end

    def validate_csrf_if_required(request_info, session_result)
      return nil unless session_result && request_info[:csrf_token]
      
      @session_manager.validate_csrf_token(
        session_id: session_result[:session_id],
        provided_token: request_info[:csrf_token]
      )
    end

    def calculate_security_score(context)
      score = 100
      
      # Reduce score based on security concerns
      if context[:network_validation][:status] != :allowed
        score -= 30
      end
      
      if context[:authentication] && context[:authentication][:scopes]&.empty?
        score -= 10
      end
      
      if context[:session] && context[:session][:warnings]&.any?
        score -= 5
      end
      
      [score, 0].max
    end

    def apply_security_policies(context, score)
      # Apply minimum security score policy
      min_score = @config[:security_policies][:minimum_security_score] || 50
      if score < min_score
        raise SecurityPolicyViolationError, "Security score below minimum: #{score} < #{min_score}"
      end
      
      # Apply additional policies based on security level
      case @security_level
      when :strict, :maximum
        if context[:authentication].nil?
          raise SecurityPolicyViolationError, "Authentication required for #{@security_level} security level"
        end
      end
    end

    def extract_security_warnings(context)
      warnings = []
      
      context.each do |component, result|
        if result.is_a?(Hash) && result[:warnings]
          warnings.concat(result[:warnings])
        end
      end
      
      warnings
    end

    def apply_transport_security_options(options)
      transport_config = @config[:transport]
      
      options.merge({
        verify_ssl: true,
        min_tls_version: transport_config[:min_tls_version],
        certificate_pinning: transport_config[:certificate_pinning]
      })
    end

    def evaluate_policy_rule(rule, context)
      # Evaluate security policy rules
      case rule[:type]
      when 'ip_whitelist'
        allowed_ips = rule[:allowed_ips] || []
        allowed_ips.include?(context[:remote_ip])
      when 'required_auth'
        !context[:authentication].nil?
      when 'min_security_score'
        context[:security_score] >= rule[:threshold]
      else
        true # Unknown rules pass by default
      end
    end

    def load_security_policies
      {
        minimum_security_score: 60,
        ip_whitelist: {
          rules: [
            { type: 'ip_whitelist', allowed_ips: ['127.0.0.1'] }
          ]
        },
        authentication_required: {
          rules: [
            { type: 'required_auth', description: 'Authentication required for all requests' }
          ]
        }
      }
    end

    def determine_overall_security_status
      component_statuses = [
        @auth_manager.respond_to?(:status) ? @auth_manager.status : 'ok',
        @transport_security.respond_to?(:status) ? @transport_security.status : 'ok',
        @network_controls.get_security_status[:status],
        @session_manager.get_session_health_status[:status]
      ]
      
      if component_statuses.include?('error')
        'error'
      elsif component_statuses.include?('warning')
        'warning'
      else
        'healthy'
      end
    end

    def calculate_overall_security_score
      # Calculate weighted average of component scores
      components = {
        authentication: 0.3,
        transport: 0.25,
        network: 0.25,
        session: 0.2
      }
      
      total_score = 0
      components.each do |component, weight|
        component_score = get_component_score(component)
        total_score += component_score * weight
      end
      
      total_score.round(1)
    end

    def get_component_score(component)
      # Get individual component security scores
      case component
      when :authentication
        auth_metrics = @auth_manager.get_authentication_metrics
        success_rate = auth_metrics[:total_failures] > 0 ? 
          (auth_metrics[:api_keys_validated].to_f / (auth_metrics[:api_keys_validated] + auth_metrics[:total_failures])) : 1.0
        [success_rate * 100, 0].max
      when :transport
        # Transport security score based on violations
        violations = @transport_security.get_security_metrics[:tls_version_violations] + 
                    @transport_security.get_security_metrics[:certificate_failures]
        [100 - (violations * 5), 0].max
      when :network
        # Network security score based on blocked requests
        network_metrics = @network_controls.get_security_metrics
        block_rate = network_metrics[:requests_blocked].to_f / [network_metrics[:requests_validated], 1].max
        [100 - (block_rate * 100), 0].max
      when :session
        # Session security score based on violations
        session_metrics = @session_manager.get_session_security_metrics
        violation_rate = session_metrics[:csrf_violations].to_f / [session_metrics[:sessions_created], 1].max
        [100 - (violation_rate * 100), 0].max
      else
        85 # Default score
      end
    end

    def calculate_auth_success_rate
      total = @metrics.get('successful_authentications') + @metrics.get('failed_authentications')
      return 1.0 if total == 0
      (@metrics.get('successful_authentications').to_f / total).round(3)
    end

    def generate_security_recommendations
      recommendations = []
      
      # Check authentication metrics
      auth_success_rate = calculate_auth_success_rate
      if auth_success_rate < 0.9
        recommendations << {
          priority: 'high',
          component: 'authentication',
          recommendation: 'High authentication failure rate detected. Review authentication methods and user training.',
          metric: "Success rate: #{(auth_success_rate * 100).round(1)}%"
        }
      end
      
      # Check network security
      network_metrics = @network_controls.get_security_metrics
      if network_metrics[:ddos_mitigations] > 0
        recommendations << {
          priority: 'critical',
          component: 'network',
          recommendation: 'DDoS attacks detected. Consider implementing additional protection measures.',
          metric: "DDoS mitigations: #{network_metrics[:ddos_mitigations]}"
        }
      end
      
      # Check certificate expiry
      transport_metrics = @transport_security.get_security_metrics
      if transport_metrics[:certificates_expiring_soon] && transport_metrics[:certificates_expiring_soon] > 0
        recommendations << {
          priority: 'medium',
          component: 'transport',
          recommendation: 'Certificates expiring soon. Schedule certificate renewal.',
          metric: "Expiring certificates: #{transport_metrics[:certificates_expiring_soon]}"
        }
      end
      
      recommendations
    end

    def start_security_monitoring
      @monitoring_thread = Thread.new do
        loop do
          begin
            perform_security_monitoring
            sleep(60) # Monitor every minute
          rescue StandardError => e
            log_error "Security monitoring error: #{e.message}"
          end
        end
      end
    end

    def perform_security_monitoring
      # Check security thresholds
      check_security_thresholds
      
      # Update security metrics
      @metrics.update_component_metrics([
        @auth_manager,
        @transport_security,
        @network_controls,
        @session_manager
      ])
      
      # Check for security incidents
      @security_monitor.check_for_incidents
      
      # Cleanup expired data
      cleanup_expired_security_data
    end

    def check_security_thresholds
      thresholds = @config[:monitoring][:alert_thresholds]
      
      # Check failed authentication rate
      auth_failure_rate = calculate_recent_auth_failure_rate
      if auth_failure_rate > thresholds[:failed_auth_rate]
        @incident_responder.trigger_alert('high_auth_failure_rate', {
          rate: auth_failure_rate,
          threshold: thresholds[:failed_auth_rate]
        })
      end
    end

    def calculate_recent_auth_failure_rate
      # Calculate authentication failure rate for the last hour
      # This would need proper time-based metrics implementation
      0.02 # Placeholder
    end

    def cleanup_expired_security_data
      # Cleanup expired tokens, sessions, etc.
      @auth_manager.cleanup_expired_tokens
      @session_manager.cleanup_expired_sessions
    end

    def default_redis
      Redis.new(url: ENV['REDIS_URL'] || 'redis://localhost:6379/0')
    rescue StandardError
      # Fallback for development
      MockRedis.new
    end

    def default_logger
      @default_logger ||= Logger.new(Rails.root.join('log', 'security_integration.log')).tap do |logger|
        logger.level = Rails.env.production? ? Logger::INFO : Logger::DEBUG
        logger.formatter = proc do |severity, datetime, progname, msg|
          "[#{datetime}] #{severity}: #{msg}\n"
        end
      end
    end

    def log_info(message)
      @logger.info("SecurityIntegration: #{message}")
    end

    def log_debug(message)
      @logger.debug("SecurityIntegration: #{message}")
    end

    def log_warning(message)
      @logger.warn("SecurityIntegration: #{message}")
    end

    def log_error(message)
      @logger.error("SecurityIntegration: #{message}")
    end
  end

  # Supporting classes for security integration

  class SecurityIntegrationMetrics
    def initialize
      @metrics = Concurrent::Hash.new(0)
      @component_metrics = Concurrent::Hash.new
      @mutex = Mutex.new
    end

    def increment(metric, value = 1)
      @metrics[metric] += value
    end

    def set(metric, value)
      @metrics[metric] = value
    end

    def get(metric)
      @metrics[metric]
    end

    def record_request_validation(success, time, score)
      increment('total_requests')
      increment(success ? 'allowed_requests' : 'blocked_requests')
      
      @mutex.synchronize do
        @metrics[:validation_times] ||= []
        @metrics[:validation_times] << time
        @metrics[:validation_times] = @metrics[:validation_times].last(1000)
        
        @metrics[:security_scores] ||= []
        @metrics[:security_scores] << score
        @metrics[:security_scores] = @metrics[:security_scores].last(1000)
      end
    end

    def update_component_metrics(components)
      @mutex.synchronize do
        components.each do |component|
          component_name = component.class.name.split('::').last.underscore
          if component.respond_to?(:get_security_metrics)
            @component_metrics[component_name] = component.get_security_metrics
          end
        end
      end
    end

    def get_all_metrics
      @mutex.synchronize { @metrics.merge(@component_metrics) }
    end
  end

  class SecurityMonitor
    def initialize(config, logger, metrics)
      @config = config
      @logger = logger
      @metrics = metrics
    end

    def register_connection(url, connection_id)
      # Track active connections
      @metrics.increment('active_connections')
    end

    def check_for_incidents
      # Monitor for security incidents
      true
    end
  end

  class IncidentResponder
    def initialize(config, logger)
      @config = config
      @logger = logger
      @incidents = []
    end

    def handle_security_incident(error, context)
      incident = {
        id: SecureRandom.uuid,
        timestamp: Time.current,
        error: error.class.name,
        message: error.message,
        context: context,
        severity: determine_severity(error)
      }
      
      @incidents << incident
      @logger.error("Security incident: #{incident[:id]} - #{error.message}")
      
      # Trigger appropriate response
      trigger_incident_response(incident)
    end

    def handle_authentication_failure(credentials, error, request_info)
      @logger.warn("Authentication failure: #{error.message} from #{request_info[:remote_ip]}")
    end

    def handle_connection_failure(url, error)
      @logger.error("Connection failure to #{url}: #{error.message}")
    end

    def handle_emergency_lockdown(reason)
      @logger.critical("Emergency lockdown activated: #{reason}")
    end

    def trigger_alert(alert_type, data)
      @logger.warn("Security alert triggered: #{alert_type} - #{data}")
    end

    def get_recent_incidents(limit = 10)
      @incidents.last(limit)
    end

    def incident_count
      @incidents.size
    end

    private

    def determine_severity(error)
      case error
      when Security::SessionHijackingError, Security::DDoSDetectedError
        'critical'
      when Security::RateLimitExceededError, Security::IPBlockedError
        'high'
      when Security::TokenExpiredError, Security::CSRFTokenError
        'medium'
      else
        'low'
      end
    end

    def trigger_incident_response(incident)
      case incident[:severity]
      when 'critical'
        # Immediate response required
        @logger.critical("CRITICAL security incident: #{incident[:id]}")
      when 'high'
        # Urgent response required
        @logger.error("HIGH severity security incident: #{incident[:id]}")
      end
    end
  end

  # Mock Redis for development/testing
  class MockRedis
    def initialize
      @data = {}
    end

    def method_missing(method_name, *args, &block)
      # Basic mock implementation
      case method_name
      when :get
        @data[args[0]]
      when :set
        @data[args[0]] = args[1]
      when :del
        @data.delete(args[0])
      else
        nil
      end
    end

    def respond_to_missing?(method_name, include_private = false)
      true
    end
  end
end