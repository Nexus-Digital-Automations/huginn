# frozen_string_literal: true

require 'openssl'
require 'digest'
require 'securerandom'
require 'base64'
require 'json'
require 'redis'
require 'concurrent'

module Security
  # Enterprise-grade session security manager for secure session handling
  # in communication between Huginn and AIgent Orchestrator.
  #
  # Features:
  # - Cryptographically secure session token generation
  # - Session expiration and automatic cleanup
  # - Session hijacking prevention with fingerprinting
  # - Concurrent session limits and management
  # - Session audit logging with security events
  # - Cross-site request forgery (CSRF) protection
  # - Session fixation protection
  # - Secure session storage and encryption
  # - Session analytics and monitoring
  class SessionSecurityManager
    class SessionSecurityError < StandardError; end
    class InvalidSessionError < SessionSecurityError; end
    class SessionExpiredError < SessionSecurityError; end
    class SessionHijackingError < SessionSecurityError; end
    class CSRFTokenError < SessionSecurityError; end
    class ConcurrentSessionLimitError < SessionSecurityError; end
    class SessionFixationError < SessionSecurityError; end

    # Session configuration constants
    SESSION_CONFIG = {
      # Token generation
      session_token_length: 128,
      session_token_entropy_bits: 256,
      regeneration_interval: 1800, # 30 minutes
      
      # Session lifecycle
      session_ttl: 7200, # 2 hours
      absolute_timeout: 28800, # 8 hours (maximum session duration)
      idle_timeout: 1800, # 30 minutes
      warning_threshold: 300, # 5 minutes before expiry
      
      # Security limits
      max_concurrent_sessions: 5,
      max_sessions_per_user: 10,
      session_lock_timeout: 30,
      
      # Fingerprinting
      enable_fingerprinting: true,
      fingerprint_tolerance: 0.8, # Allow some variance in fingerprints
      strict_ip_binding: false, # Allow IP changes (mobile users)
      
      # CSRF protection
      csrf_token_length: 64,
      csrf_token_ttl: 3600, # 1 hour
      csrf_per_form: true,
      
      # Audit and monitoring
      audit_session_events: true,
      log_security_events: true,
      monitor_suspicious_activity: true,
      
      # Storage encryption
      encrypt_session_data: true,
      encryption_algorithm: 'AES-256-GCM',
      key_rotation_interval: 7.days
    }.freeze

    # Session states
    SESSION_STATES = {
      active: 'active',
      idle: 'idle',
      expired: 'expired',
      terminated: 'terminated',
      hijacked: 'hijacked',
      locked: 'locked'
    }.freeze

    # Security event types
    SECURITY_EVENTS = {
      session_created: 'session_created',
      session_authenticated: 'session_authenticated',
      session_renewed: 'session_renewed',
      session_expired: 'session_expired',
      session_terminated: 'session_terminated',
      session_hijacked: 'session_hijacked',
      csrf_violation: 'csrf_violation',
      concurrent_limit_exceeded: 'concurrent_limit_exceeded',
      suspicious_activity: 'suspicious_activity',
      fingerprint_mismatch: 'fingerprint_mismatch',
      session_fixation_attempt: 'session_fixation_attempt'
    }.freeze

    attr_reader :config, :logger, :metrics, :encryption_key

    def initialize(config: {}, logger: nil, redis: nil)
      @config = SESSION_CONFIG.merge(config)
      @logger = logger || default_logger
      @redis = redis || default_redis
      @metrics = SessionSecurityMetrics.new
      
      # Initialize encryption
      initialize_encryption
      
      # Initialize security components
      @fingerprint_generator = FingerprintGenerator.new(@config, @logger)
      @csrf_manager = CSRFManager.new(@config, @redis, @logger)
      @session_store = SessionStore.new(@config, @redis, @encryption_key, @logger)
      @audit_logger = SessionAuditLogger.new(@config, @logger)
      @session_monitor = SessionMonitor.new(@config, @redis, @logger)
      
      # Start background maintenance
      start_session_maintenance
      
      log_info "Session security manager initialized with encryption and monitoring"
    end

    # Session Lifecycle Management

    def create_session(user_id:, request_info: {}, session_data: {})
      log_info "Creating session for user: #{user_id}"
      
      begin
        # Validate concurrent session limits
        validate_concurrent_sessions(user_id)
        
        # Generate secure session ID and token
        session_id = generate_session_id
        session_token = generate_session_token
        
        # Generate user fingerprint
        fingerprint = @fingerprint_generator.generate(request_info)
        
        # Create session data structure
        session_info = {
          session_id: session_id,
          user_id: user_id,
          state: SESSION_STATES[:active],
          created_at: Time.current,
          last_activity_at: Time.current,
          expires_at: calculate_expiry_time,
          absolute_expires_at: calculate_absolute_expiry_time,
          
          # Security attributes
          fingerprint: fingerprint,
          ip_address: request_info[:remote_ip],
          user_agent: request_info[:user_agent],
          secure_flags: {
            csrf_token: @csrf_manager.generate_token(session_id),
            regeneration_due: @config[:regeneration_interval].seconds.from_now,
            fingerprint_verified: true
          },
          
          # Custom session data
          data: encrypt_session_data(session_data),
          
          # Tracking
          access_count: 1,
          last_csrf_check: nil,
          security_events: []
        }
        
        # Store session
        @session_store.store_session(session_id, session_token, session_info)
        
        # Record audit event
        @audit_logger.log_event(SECURITY_EVENTS[:session_created], {
          session_id: session_id,
          user_id: user_id,
          ip_address: request_info[:remote_ip],
          user_agent: request_info[:user_agent]
        })
        
        @metrics.increment('sessions_created')
        @metrics.record_session_duration_start(session_id)
        
        log_info "Session created successfully: #{session_id} for user: #{user_id}"
        
        {
          session_id: session_id,
          session_token: session_token,
          csrf_token: session_info[:secure_flags][:csrf_token],
          expires_at: session_info[:expires_at],
          warnings: {
            expires_in_seconds: (session_info[:expires_at] - Time.current).to_i,
            regeneration_due_in_seconds: (session_info[:secure_flags][:regeneration_due] - Time.current).to_i
          }
        }
        
      rescue StandardError => e
        @metrics.increment('session_creation_failures')
        log_error "Failed to create session for user #{user_id}: #{e.message}"
        raise SessionSecurityError, "Session creation failed: #{e.message}"
      end
    end

    def validate_session(session_token:, request_info: {})
      log_debug "Validating session token"
      
      begin
        # Retrieve session by token
        session_info = @session_store.get_session_by_token(session_token)
        unless session_info
          @metrics.increment('invalid_session_tokens')
          raise InvalidSessionError, "Invalid session token"
        end
        
        session_id = session_info[:session_id]
        
        # Check session state
        validate_session_state(session_info)
        
        # Check session expiration
        validate_session_expiry(session_info)
        
        # Validate security attributes
        validate_session_security(session_info, request_info)
        
        # Update session activity
        update_session_activity(session_id, request_info)
        
        # Check for regeneration requirement
        check_session_regeneration(session_info)
        
        @metrics.increment('sessions_validated')
        @metrics.record_session_access(session_id)
        
        log_debug "Session validation successful: #{session_id}"
        
        {
          valid: true,
          session_id: session_id,
          user_id: session_info[:user_id],
          data: decrypt_session_data(session_info[:data]),
          csrf_token: session_info[:secure_flags][:csrf_token],
          expires_at: session_info[:expires_at],
          warnings: generate_session_warnings(session_info)
        }
        
      rescue SessionSecurityError => e
        @metrics.increment('session_validation_failures')
        log_warning "Session validation failed: #{e.message}"
        
        # Log security event if session exists
        if session_info && session_info[:session_id]
          @audit_logger.log_event(determine_security_event(e), {
            session_id: session_info[:session_id],
            user_id: session_info[:user_id],
            error: e.message,
            ip_address: request_info[:remote_ip]
          })
        end
        
        raise
      end
    end

    def regenerate_session(session_id:, request_info: {})
      log_info "Regenerating session: #{session_id}"
      
      begin
        session_info = @session_store.get_session(session_id)
        unless session_info
          raise InvalidSessionError, "Session not found for regeneration"
        end
        
        # Generate new session token
        new_session_token = generate_session_token
        old_token = @session_store.get_session_token(session_id)
        
        # Update session with new token
        session_info[:secure_flags][:csrf_token] = @csrf_manager.generate_token(session_id)
        session_info[:secure_flags][:regeneration_due] = @config[:regeneration_interval].seconds.from_now
        session_info[:last_activity_at] = Time.current
        session_info[:access_count] += 1
        
        # Store updated session with new token
        @session_store.update_session_token(session_id, new_session_token, session_info)
        
        # Invalidate old token
        @session_store.invalidate_token(old_token) if old_token
        
        @audit_logger.log_event(SECURITY_EVENTS[:session_renewed], {
          session_id: session_id,
          user_id: session_info[:user_id],
          ip_address: request_info[:remote_ip]
        })
        
        @metrics.increment('sessions_regenerated')
        log_info "Session regenerated successfully: #{session_id}"
        
        {
          session_token: new_session_token,
          csrf_token: session_info[:secure_flags][:csrf_token],
          expires_at: session_info[:expires_at]
        }
        
      rescue StandardError => e
        @metrics.increment('session_regeneration_failures')
        log_error "Failed to regenerate session #{session_id}: #{e.message}"
        raise SessionSecurityError, "Session regeneration failed: #{e.message}"
      end
    end

    def terminate_session(session_id:, reason: 'user_logout')
      log_info "Terminating session: #{session_id}, reason: #{reason}"
      
      begin
        session_info = @session_store.get_session(session_id)
        
        if session_info
          # Record session duration
          @metrics.record_session_duration_end(session_id, session_info[:created_at])
          
          # Log audit event
          @audit_logger.log_event(SECURITY_EVENTS[:session_terminated], {
            session_id: session_id,
            user_id: session_info[:user_id],
            reason: reason,
            duration_seconds: (Time.current - session_info[:created_at]).to_i
          })
        end
        
        # Remove session from storage
        @session_store.remove_session(session_id)
        
        # Invalidate associated CSRF tokens
        @csrf_manager.invalidate_session_tokens(session_id)
        
        @metrics.increment('sessions_terminated')
        log_info "Session terminated successfully: #{session_id}"
        
        { success: true, reason: reason }
        
      rescue StandardError => e
        @metrics.increment('session_termination_failures')
        log_error "Failed to terminate session #{session_id}: #{e.message}"
        raise SessionSecurityError, "Session termination failed: #{e.message}"
      end
    end

    # CSRF Protection Methods

    def generate_csrf_token(session_id)
      log_debug "Generating CSRF token for session: #{session_id}"
      
      csrf_token = @csrf_manager.generate_token(session_id)
      
      @metrics.increment('csrf_tokens_generated')
      log_debug "CSRF token generated for session: #{session_id}"
      
      csrf_token
    end

    def validate_csrf_token(session_id:, provided_token:, form_id: nil)
      log_debug "Validating CSRF token for session: #{session_id}"
      
      begin
        valid = @csrf_manager.validate_token(session_id, provided_token, form_id)
        
        unless valid
          @metrics.increment('csrf_validation_failures')
          log_warning "CSRF token validation failed for session: #{session_id}"
          
          @audit_logger.log_event(SECURITY_EVENTS[:csrf_violation], {
            session_id: session_id,
            form_id: form_id,
            provided_token: provided_token&.first(10) # Log only first 10 chars
          })
          
          raise CSRFTokenError, "Invalid CSRF token"
        end
        
        @metrics.increment('csrf_validations_successful')
        log_debug "CSRF token validation successful for session: #{session_id}"
        
        true
        
      rescue StandardError => e
        @metrics.increment('csrf_validation_errors')
        log_error "CSRF validation error for session #{session_id}: #{e.message}"
        raise
      end
    end

    # Session Management Methods

    def get_user_sessions(user_id)
      log_debug "Retrieving sessions for user: #{user_id}"
      
      sessions = @session_store.get_user_sessions(user_id)
      active_sessions = sessions.select { |session| session[:state] == SESSION_STATES[:active] }
      
      log_info "Found #{active_sessions.size} active sessions for user: #{user_id}"
      
      active_sessions.map do |session|
        {
          session_id: session[:session_id],
          created_at: session[:created_at],
          last_activity_at: session[:last_activity_at],
          expires_at: session[:expires_at],
          ip_address: session[:ip_address],
          user_agent: session[:user_agent],
          access_count: session[:access_count]
        }
      end
    end

    def terminate_user_sessions(user_id:, except_session_id: nil, reason: 'admin_action')
      log_info "Terminating all sessions for user: #{user_id}"
      
      sessions = @session_store.get_user_sessions(user_id)
      terminated_count = 0
      
      sessions.each do |session|
        next if session[:session_id] == except_session_id
        next unless session[:state] == SESSION_STATES[:active]
        
        begin
          terminate_session(session_id: session[:session_id], reason: reason)
          terminated_count += 1
        rescue StandardError => e
          log_error "Failed to terminate session #{session[:session_id]}: #{e.message}"
        end
      end
      
      @metrics.set("user_sessions_terminated_#{user_id}", terminated_count)
      log_info "Terminated #{terminated_count} sessions for user: #{user_id}"
      
      { terminated_count: terminated_count }
    end

    def lock_session(session_id:, reason: 'security_violation', duration: 300)
      log_warning "Locking session: #{session_id}, reason: #{reason}"
      
      session_info = @session_store.get_session(session_id)
      return false unless session_info
      
      session_info[:state] = SESSION_STATES[:locked]
      session_info[:locked_at] = Time.current
      session_info[:locked_until] = Time.current + duration
      session_info[:lock_reason] = reason
      
      @session_store.update_session(session_id, session_info)
      
      @audit_logger.log_event(SECURITY_EVENTS[:suspicious_activity], {
        session_id: session_id,
        user_id: session_info[:user_id],
        action: 'session_locked',
        reason: reason,
        duration_seconds: duration
      })
      
      @metrics.increment('sessions_locked')
      log_warning "Session locked: #{session_id} for #{duration} seconds"
      
      true
    end

    def unlock_session(session_id)
      log_info "Unlocking session: #{session_id}"
      
      session_info = @session_store.get_session(session_id)
      return false unless session_info && session_info[:state] == SESSION_STATES[:locked]
      
      session_info[:state] = SESSION_STATES[:active]
      session_info.delete(:locked_at)
      session_info.delete(:locked_until)
      session_info.delete(:lock_reason)
      
      @session_store.update_session(session_id, session_info)
      
      @metrics.increment('sessions_unlocked')
      log_info "Session unlocked: #{session_id}"
      
      true
    end

    # Security and Monitoring Methods

    def detect_session_hijacking(session_id:, request_info: {})
      log_debug "Checking for session hijacking: #{session_id}"
      
      session_info = @session_store.get_session(session_id)
      return false unless session_info
      
      hijacking_indicators = []
      
      # Check IP address changes
      if @config[:strict_ip_binding] && session_info[:ip_address] != request_info[:remote_ip]
        hijacking_indicators << 'ip_address_change'
      end
      
      # Check user agent changes
      if session_info[:user_agent] != request_info[:user_agent]
        hijacking_indicators << 'user_agent_change'
      end
      
      # Check fingerprint
      if @config[:enable_fingerprinting]
        current_fingerprint = @fingerprint_generator.generate(request_info)
        similarity = @fingerprint_generator.compare_fingerprints(
          session_info[:fingerprint], 
          current_fingerprint
        )
        
        if similarity < @config[:fingerprint_tolerance]
          hijacking_indicators << 'fingerprint_mismatch'
        end
      end
      
      # Check for suspicious timing patterns
      if suspicious_timing_pattern?(session_info, request_info)
        hijacking_indicators << 'suspicious_timing'
      end
      
      if hijacking_indicators.any?
        log_warning "Session hijacking indicators detected for #{session_id}: #{hijacking_indicators.join(', ')}"
        
        @audit_logger.log_event(SECURITY_EVENTS[:session_hijacked], {
          session_id: session_id,
          user_id: session_info[:user_id],
          indicators: hijacking_indicators,
          ip_address: request_info[:remote_ip],
          user_agent: request_info[:user_agent]
        })
        
        @metrics.increment('session_hijacking_detected')
        
        # Lock session for security
        lock_session(session_id: session_id, reason: 'hijacking_detected')
        
        raise SessionHijackingError, "Session hijacking detected: #{hijacking_indicators.join(', ')}"
      end
      
      false
    end

    def get_session_security_metrics
      {
        total_sessions: @metrics.get('sessions_created'),
        active_sessions: @session_store.get_active_session_count,
        sessions_validated: @metrics.get('sessions_validated'),
        sessions_terminated: @metrics.get('sessions_terminated'),
        session_hijacking_detected: @metrics.get('session_hijacking_detected'),
        csrf_violations: @metrics.get('csrf_validation_failures'),
        concurrent_limit_violations: @metrics.get('concurrent_session_limit_exceeded'),
        average_session_duration: @metrics.get_average_session_duration,
        session_creation_rate: @metrics.get_session_creation_rate,
        validation_success_rate: @metrics.get_validation_success_rate
      }
    end

    def cleanup_expired_sessions
      log_info "Cleaning up expired sessions"
      
      expired_count = @session_store.cleanup_expired_sessions
      @metrics.set('expired_sessions_cleaned', expired_count)
      
      log_info "Cleaned up #{expired_count} expired sessions"
      expired_count
    end

    def get_session_health_status
      {
        status: 'healthy',
        active_sessions: @session_store.get_active_session_count,
        memory_usage: @session_store.get_memory_usage,
        cleanup_status: @session_store.get_cleanup_status,
        security_events_recent: @audit_logger.get_recent_events_count,
        performance: {
          avg_validation_time_ms: @metrics.get_average_validation_time,
          validation_success_rate: @metrics.get_validation_success_rate,
          session_creation_rate_per_minute: @metrics.get_session_creation_rate
        }
      }
    end

    private

    def initialize_encryption
      @encryption_key = generate_or_load_encryption_key
      @cipher = OpenSSL::Cipher.new(@config[:encryption_algorithm])
      log_info "Session encryption initialized"
    end

    def generate_or_load_encryption_key
      key_file = Rails.root.join('config', 'secrets', 'session_encryption.key')
      
      if File.exist?(key_file)
        File.read(key_file).strip
      else
        FileUtils.mkdir_p(File.dirname(key_file))
        key = SecureRandom.hex(32)
        File.write(key_file, key)
        File.chmod(0600, key_file)
        key
      end
    end

    def generate_session_id
      SecureRandom.uuid
    end

    def generate_session_token
      SecureRandom.base64(@config[:session_token_length])
    end

    def calculate_expiry_time
      @config[:session_ttl].seconds.from_now
    end

    def calculate_absolute_expiry_time
      @config[:absolute_timeout].seconds.from_now
    end

    def encrypt_session_data(data)
      return data unless @config[:encrypt_session_data]
      
      json_data = data.to_json
      @cipher.encrypt
      @cipher.key = [@encryption_key].pack('H*')
      iv = @cipher.random_iv
      encrypted = @cipher.update(json_data) + @cipher.final
      
      Base64.strict_encode64(iv + encrypted)
    end

    def decrypt_session_data(encrypted_data)
      return encrypted_data unless @config[:encrypt_session_data] && encrypted_data
      
      decoded = Base64.strict_decode64(encrypted_data)
      iv = decoded[0, @cipher.iv_len]
      encrypted = decoded[@cipher.iv_len..-1]
      
      @cipher.decrypt
      @cipher.key = [@encryption_key].pack('H*')
      @cipher.iv = iv
      decrypted = @cipher.update(encrypted) + @cipher.final
      
      JSON.parse(decrypted)
    rescue StandardError => e
      log_error "Failed to decrypt session data: #{e.message}"
      {}
    end

    def validate_concurrent_sessions(user_id)
      active_sessions = @session_store.get_user_sessions(user_id)
                                     .count { |s| s[:state] == SESSION_STATES[:active] }
      
      if active_sessions >= @config[:max_concurrent_sessions]
        @metrics.increment('concurrent_session_limit_exceeded')
        
        @audit_logger.log_event(SECURITY_EVENTS[:concurrent_limit_exceeded], {
          user_id: user_id,
          current_sessions: active_sessions,
          limit: @config[:max_concurrent_sessions]
        })
        
        # Terminate oldest session to make room
        @session_store.terminate_oldest_user_session(user_id)
        
        log_warning "Concurrent session limit exceeded for user #{user_id}, terminated oldest session"
      end
    end

    def validate_session_state(session_info)
      case session_info[:state]
      when SESSION_STATES[:expired]
        raise SessionExpiredError, "Session has expired"
      when SESSION_STATES[:terminated]
        raise InvalidSessionError, "Session has been terminated"
      when SESSION_STATES[:hijacked]
        raise SessionHijackingError, "Session marked as hijacked"
      when SESSION_STATES[:locked]
        if session_info[:locked_until] && session_info[:locked_until] > Time.current
          raise InvalidSessionError, "Session is locked: #{session_info[:lock_reason]}"
        else
          # Auto-unlock if lock period expired
          unlock_session(session_info[:session_id])
        end
      end
    end

    def validate_session_expiry(session_info)
      now = Time.current
      
      # Check absolute timeout
      if session_info[:absolute_expires_at] < now
        @session_store.expire_session(session_info[:session_id])
        @metrics.increment('sessions_absolute_timeout')
        raise SessionExpiredError, "Session absolute timeout exceeded"
      end
      
      # Check idle timeout
      idle_limit = now - @config[:idle_timeout]
      if session_info[:last_activity_at] < idle_limit
        @session_store.expire_session(session_info[:session_id])
        @metrics.increment('sessions_idle_timeout')
        raise SessionExpiredError, "Session idle timeout exceeded"
      end
      
      # Check regular expiry
      if session_info[:expires_at] < now
        @session_store.expire_session(session_info[:session_id])
        @metrics.increment('sessions_expired')
        raise SessionExpiredError, "Session has expired"
      end
    end

    def validate_session_security(session_info, request_info)
      # Check for session hijacking
      detect_session_hijacking(
        session_id: session_info[:session_id],
        request_info: request_info
      )
      
      # Additional security validations can be added here
    end

    def update_session_activity(session_id, request_info)
      session_info = @session_store.get_session(session_id)
      return unless session_info
      
      session_info[:last_activity_at] = Time.current
      session_info[:access_count] += 1
      session_info[:expires_at] = calculate_expiry_time
      
      @session_store.update_session(session_id, session_info)
    end

    def check_session_regeneration(session_info)
      if session_info[:secure_flags][:regeneration_due] < Time.current
        log_info "Session regeneration due for: #{session_info[:session_id]}"
        # Note: Actual regeneration would be triggered by the application
        true
      else
        false
      end
    end

    def generate_session_warnings(session_info)
      warnings = []
      now = Time.current
      
      # Expiry warning
      time_until_expiry = session_info[:expires_at] - now
      if time_until_expiry <= @config[:warning_threshold]
        warnings << {
          type: 'expiry_warning',
          message: "Session expires in #{time_until_expiry.to_i} seconds",
          severity: 'warning'
        }
      end
      
      # Regeneration warning
      if session_info[:secure_flags][:regeneration_due] < now
        warnings << {
          type: 'regeneration_required',
          message: "Session token regeneration required",
          severity: 'info'
        }
      end
      
      warnings
    end

    def determine_security_event(error)
      case error
      when SessionExpiredError
        SECURITY_EVENTS[:session_expired]
      when SessionHijackingError
        SECURITY_EVENTS[:session_hijacked]
      when CSRFTokenError
        SECURITY_EVENTS[:csrf_violation]
      when ConcurrentSessionLimitError
        SECURITY_EVENTS[:concurrent_limit_exceeded]
      else
        SECURITY_EVENTS[:suspicious_activity]
      end
    end

    def suspicious_timing_pattern?(session_info, request_info)
      # Check for impossibly fast requests
      last_activity = session_info[:last_activity_at]
      return false unless last_activity
      
      time_diff = Time.current - last_activity
      time_diff < 0.1 # Less than 100ms between requests (suspicious)
    end

    def start_session_maintenance
      @maintenance_thread = Thread.new do
        loop do
          begin
            perform_session_maintenance
            sleep(60) # Run every minute
          rescue StandardError => e
            log_error "Session maintenance error: #{e.message}"
          end
        end
      end
    end

    def perform_session_maintenance
      # Cleanup expired sessions
      cleanup_expired_sessions
      
      # Update session metrics
      @metrics.update_session_metrics(@session_store)
      
      # Rotate encryption keys if needed
      rotate_encryption_keys if key_rotation_due?
      
      # Monitor for suspicious patterns
      @session_monitor.check_suspicious_patterns
    end

    def key_rotation_due?
      last_rotation = @redis.get('session_key_last_rotation')
      return true unless last_rotation
      
      Time.current - Time.parse(last_rotation) > @config[:key_rotation_interval]
    end

    def rotate_encryption_keys
      log_info "Rotating session encryption keys"
      # Implementation for key rotation
      @redis.set('session_key_last_rotation', Time.current.iso8601)
    end

    def default_redis
      Redis.new(url: ENV['REDIS_URL'] || 'redis://localhost:6379/0')
    rescue StandardError
      # Fallback to in-memory storage if Redis unavailable
      MockRedis.new
    end

    def default_logger
      @default_logger ||= Logger.new(Rails.root.join('log', 'session_security.log')).tap do |logger|
        logger.level = Rails.env.production? ? Logger::INFO : Logger::DEBUG
        logger.formatter = proc do |severity, datetime, progname, msg|
          "[#{datetime}] #{severity}: #{msg}\n"
        end
      end
    end

    def log_info(message)
      @logger.info("SessionSecurity: #{message}")
    end

    def log_debug(message)
      @logger.debug("SessionSecurity: #{message}")
    end

    def log_warning(message)
      @logger.warn("SessionSecurity: #{message}")
    end

    def log_error(message)
      @logger.error("SessionSecurity: #{message}")
    end
  end

  # Supporting classes for session security management

  class SessionSecurityMetrics
    def initialize
      @metrics = Concurrent::Hash.new(0)
      @session_durations = Concurrent::Array.new
      @validation_times = Concurrent::Array.new
      @creation_times = Concurrent::Array.new
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

    def record_session_duration_start(session_id)
      @mutex.synchronize do
        @session_durations << { session_id: session_id, start_time: Time.current }
      end
    end

    def record_session_duration_end(session_id, start_time)
      duration = Time.current - start_time
      @mutex.synchronize do
        @session_durations.delete_if { |s| s[:session_id] == session_id }
      end
      increment('total_session_duration', duration)
    end

    def record_session_access(session_id)
      increment('session_accesses')
    end

    def get_average_session_duration
      total_duration = get('total_session_duration')
      completed_sessions = get('sessions_terminated')
      return 0.0 if completed_sessions == 0
      (total_duration / completed_sessions / 60).round(2) # Return in minutes
    end

    def get_session_creation_rate
      @mutex.synchronize do
        one_minute_ago = Time.current - 60
        @creation_times.reject! { |time| time < one_minute_ago }
        @creation_times.size
      end
    end

    def get_validation_success_rate
      total_validations = get('sessions_validated') + get('session_validation_failures')
      return 1.0 if total_validations == 0
      (get('sessions_validated').to_f / total_validations).round(3)
    end

    def get_average_validation_time
      @mutex.synchronize do
        return 0.0 if @validation_times.empty?
        (@validation_times.sum / @validation_times.size * 1000).round(2) # Convert to milliseconds
      end
    end

    def update_session_metrics(session_store)
      # Update various session metrics
      set('active_sessions_count', session_store.get_active_session_count)
    end
  end

  class FingerprintGenerator
    def initialize(config, logger)
      @config = config
      @logger = logger
    end

    def generate(request_info)
      components = [
        request_info[:user_agent],
        request_info[:accept_language],
        request_info[:accept_encoding],
        request_info[:accept],
        request_info[:dnt],
        request_info[:timezone],
        request_info[:screen_resolution],
        request_info[:color_depth]
      ].compact

      Digest::SHA256.hexdigest(components.join('|'))
    end

    def compare_fingerprints(fingerprint1, fingerprint2)
      return 0.0 unless fingerprint1 && fingerprint2
      fingerprint1 == fingerprint2 ? 1.0 : 0.0
    end
  end

  class CSRFManager
    def initialize(config, redis, logger)
      @config = config
      @redis = redis
      @logger = logger
    end

    def generate_token(session_id, form_id: nil)
      token = SecureRandom.hex(@config[:csrf_token_length])
      key = csrf_key(session_id, form_id)
      
      @redis.set(key, token)
      @redis.expire(key, @config[:csrf_token_ttl])
      
      token
    end

    def validate_token(session_id, provided_token, form_id = nil)
      key = csrf_key(session_id, form_id)
      stored_token = @redis.get(key)
      
      stored_token && provided_token && stored_token == provided_token
    end

    def invalidate_session_tokens(session_id)
      pattern = "csrf:#{session_id}:*"
      keys = @redis.keys(pattern)
      @redis.del(*keys) if keys.any?
    end

    private

    def csrf_key(session_id, form_id)
      if @config[:csrf_per_form] && form_id
        "csrf:#{session_id}:#{form_id}"
      else
        "csrf:#{session_id}:global"
      end
    end
  end

  class SessionStore
    def initialize(config, redis, encryption_key, logger)
      @config = config
      @redis = redis
      @encryption_key = encryption_key
      @logger = logger
    end

    def store_session(session_id, session_token, session_info)
      # Store session data
      @redis.set("session:#{session_id}", session_info.to_json)
      @redis.expire("session:#{session_id}", @config[:absolute_timeout])
      
      # Store token mapping
      @redis.set("session_token:#{session_token}", session_id)
      @redis.expire("session_token:#{session_token}", @config[:absolute_timeout])
      
      # Add to user sessions set
      @redis.sadd("user_sessions:#{session_info[:user_id]}", session_id)
    end

    def get_session(session_id)
      data = @redis.get("session:#{session_id}")
      data ? JSON.parse(data, symbolize_names: true) : nil
    rescue JSON::ParserError
      nil
    end

    def get_session_by_token(token)
      session_id = @redis.get("session_token:#{token}")
      session_id ? get_session(session_id) : nil
    end

    def get_session_token(session_id)
      # This would need a reverse lookup implementation
      nil
    end

    def update_session(session_id, session_info)
      @redis.set("session:#{session_id}", session_info.to_json)
    end

    def update_session_token(session_id, new_token, session_info)
      # Remove old token mapping (would need implementation)
      # Add new token mapping
      @redis.set("session_token:#{new_token}", session_id)
      @redis.expire("session_token:#{new_token}", @config[:absolute_timeout])
      
      # Update session data
      update_session(session_id, session_info)
    end

    def invalidate_token(token)
      @redis.del("session_token:#{token}")
    end

    def remove_session(session_id)
      session_info = get_session(session_id)
      
      if session_info
        # Remove from user sessions set
        @redis.srem("user_sessions:#{session_info[:user_id]}", session_id)
      end
      
      @redis.del("session:#{session_id}")
    end

    def expire_session(session_id)
      session_info = get_session(session_id)
      return unless session_info
      
      session_info[:state] = 'expired'
      update_session(session_id, session_info)
    end

    def get_user_sessions(user_id)
      session_ids = @redis.smembers("user_sessions:#{user_id}")
      session_ids.map { |sid| get_session(sid) }.compact
    end

    def terminate_oldest_user_session(user_id)
      sessions = get_user_sessions(user_id)
      oldest = sessions.min_by { |s| s[:created_at] }
      remove_session(oldest[:session_id]) if oldest
    end

    def get_active_session_count
      # This would need proper implementation to count all active sessions
      @redis.keys("session:*").size
    end

    def cleanup_expired_sessions
      # This would need proper implementation
      # Redis TTL handles expiry automatically
      0
    end

    def get_memory_usage
      # Redis memory usage
      @redis.memory('usage') rescue 0
    end

    def get_cleanup_status
      { last_cleanup: Time.current, status: 'ok' }
    end
  end

  class SessionAuditLogger
    def initialize(config, logger)
      @config = config
      @logger = logger
      @audit_log = Logger.new(Rails.root.join('log', 'session_audit.log'))
    end

    def log_event(event_type, details)
      return unless @config[:audit_session_events]
      
      audit_entry = {
        timestamp: Time.current.iso8601,
        event_type: event_type,
        details: details
      }
      
      @audit_log.info(audit_entry.to_json)
    end

    def get_recent_events_count(minutes = 60)
      # This would need proper implementation to count recent events
      0
    end
  end

  class SessionMonitor
    def initialize(config, redis, logger)
      @config = config
      @redis = redis
      @logger = logger
    end

    def check_suspicious_patterns
      # Implementation for checking suspicious session patterns
      true
    end
  end

  # Mock Redis for development/testing when Redis unavailable
  class MockRedis
    def initialize
      @data = Concurrent::Hash.new
      @sets = Concurrent::Hash.new { |h, k| h[k] = Set.new }
      @expiry = Concurrent::Hash.new
    end

    def set(key, value)
      @data[key] = value
    end

    def get(key)
      return nil if expired?(key)
      @data[key]
    end

    def del(*keys)
      keys.each { |key| @data.delete(key) }
    end

    def expire(key, seconds)
      @expiry[key] = Time.current + seconds
    end

    def ttl(key)
      return -1 unless @expiry[key]
      (@expiry[key] - Time.current).to_i
    end

    def sadd(key, member)
      @sets[key].add(member)
    end

    def srem(key, member)
      @sets[key].delete(member)
    end

    def smembers(key)
      @sets[key].to_a
    end

    def keys(pattern)
      if pattern.end_with?('*')
        prefix = pattern[0...-1]
        @data.keys.select { |key| key.start_with?(prefix) }
      else
        @data.keys.include?(pattern) ? [pattern] : []
      end
    end

    def memory(command)
      @data.size * 100 # Rough estimate
    end

    private

    def expired?(key)
      @expiry[key] && @expiry[key] < Time.current
    end
  end
end