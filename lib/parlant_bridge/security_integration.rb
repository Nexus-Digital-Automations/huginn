# frozen_string_literal: true

require 'jwt'
require 'openssl'
require 'securerandom'
require 'digest'

module ParlantBridge
  ##
  # Security Integration Module for Parlant Bridge
  # Provides secure authentication with AIgent's existing auth system,
  # session management, user context propagation, audit logging,
  # and rate limiting for comprehensive security.
  #
  module SecurityIntegration
    # Security constants
    JWT_ALGORITHM = 'RS256'
    SESSION_TIMEOUT = 3600 # 1 hour
    MAX_FAILED_ATTEMPTS = 5
    LOCKOUT_DURATION = 900 # 15 minutes
    AUDIT_RETENTION_DAYS = 90

    # Rate limiting constants
    DEFAULT_RATE_LIMIT = 100 # requests per window
    DEFAULT_RATE_WINDOW = 60 # seconds
    BURST_RATE_LIMIT = 20 # requests per burst window
    BURST_RATE_WINDOW = 10 # seconds

    ##
    # Authentication Manager for secure token validation and session management
    #
    class AuthenticationManager
      include MonitorMixin

      attr_reader :jwt_public_key, :logger, :rate_limiter

      ##
      # Initialize authentication manager
      #
      # @param jwt_public_key_path [String] Path to JWT public key
      # @param jwt_algorithm [String] JWT algorithm to use
      # @param session_timeout [Integer] Session timeout in seconds
      # @param logger [Logger] Logger instance
      #
      def initialize(jwt_public_key_path: nil, jwt_algorithm: JWT_ALGORITHM,
                     session_timeout: SESSION_TIMEOUT, logger: nil)
        super() # Initialize MonitorMixin
        
        @jwt_algorithm = jwt_algorithm
        @session_timeout = session_timeout
        @logger = logger || Logger.new($stdout)
        
        # Load JWT public key
        @jwt_public_key = load_jwt_public_key(jwt_public_key_path)
        
        # Session storage (in production, use Redis or similar)
        @active_sessions = Concurrent::Hash.new
        @failed_attempts = Concurrent::Hash.new { |h, k| h[k] = 0 }
        @lockout_times = Concurrent::Hash.new
        
        # Rate limiting
        @rate_limiter = RateLimiter.new(logger: @logger)
        
        # Session cleanup task
        @cleanup_task = schedule_session_cleanup
        
        @logger.info("ParlantBridge::AuthenticationManager initialized")
      end

      ##
      # Validate AIgent JWT token and create Parlant session
      #
      # @param token [String] JWT token from AIgent
      # @param client_info [Hash] Client information
      # @return [SecurityContext] Security context for the session
      #
      def authenticate(token, client_info = {})
        raise AuthenticationError, 'Token required' if token.nil? || token.empty?
        
        # Check rate limiting
        client_id = extract_client_id(client_info)
        @rate_limiter.check_rate_limit!(client_id, 'authentication')
        
        # Check if client is locked out
        check_lockout_status!(client_id)
        
        begin
          # Decode and validate JWT
          payload, header = JWT.decode(token, @jwt_public_key, true, algorithm: @jwt_algorithm)
          
          # Create security context
          security_context = create_security_context(payload, header, client_info)
          
          # Create active session
          session_id = create_session(security_context)
          security_context.session_id = session_id
          
          # Reset failed attempts on successful authentication
          @failed_attempts.delete(client_id)
          @lockout_times.delete(client_id)
          
          @logger.info("Authentication successful - User: #{security_context.user_id}, Session: #{session_id}")
          security_context
          
        rescue JWT::DecodeError, JWT::ExpiredSignature, JWT::InvalidIssuerError => e
          handle_authentication_failure(client_id, e.message)
          raise AuthenticationError, "Invalid token: #{e.message}"
        rescue StandardError => e
          handle_authentication_failure(client_id, e.message)
          raise AuthenticationError, "Authentication failed: #{e.message}"
        end
      end

      ##
      # Validate existing session
      #
      # @param session_id [String] Session identifier
      # @return [SecurityContext, nil] Security context if valid, nil if invalid
      #
      def validate_session(session_id)
        return nil if session_id.nil? || session_id.empty?
        
        synchronize do
          session_data = @active_sessions[session_id]
          return nil unless session_data
          
          # Check session expiration
          if session_expired?(session_data)
            @active_sessions.delete(session_id)
            @logger.info("Session expired and removed - Session: #{session_id}")
            return nil
          end
          
          # Update last activity
          session_data[:last_activity] = Time.now
          
          SecurityContext.from_session_data(session_data)
        end
      end

      ##
      # Invalidate session (logout)
      #
      # @param session_id [String] Session identifier
      # @return [Boolean] True if session was invalidated
      #
      def invalidate_session(session_id)
        return false if session_id.nil? || session_id.empty?
        
        synchronize do
          session_data = @active_sessions.delete(session_id)
          if session_data
            @logger.info("Session invalidated - Session: #{session_id}, User: #{session_data[:user_id]}")
            true
          else
            false
          end
        end
      end

      ##
      # Get authentication metrics
      #
      # @return [Hash] Authentication statistics
      #
      def metrics
        synchronize do
          {
            active_sessions: @active_sessions.size,
            locked_out_clients: @lockout_times.size,
            failed_attempts: @failed_attempts.size,
            rate_limiter_stats: @rate_limiter.stats,
            session_cleanup_active: @cleanup_task&.running? || false
          }
        end
      end

      ##
      # Cleanup expired sessions and reset failed attempts
      #
      def cleanup_expired_sessions
        synchronize do
          expired_sessions = []
          
          @active_sessions.each do |session_id, session_data|
            if session_expired?(session_data)
              expired_sessions << session_id
            end
          end
          
          expired_sessions.each { |session_id| @active_sessions.delete(session_id) }
          
          # Cleanup old lockouts
          current_time = Time.now
          @lockout_times.delete_if { |_, lockout_time| current_time - lockout_time > LOCKOUT_DURATION }
          
          @logger.info("Session cleanup completed - #{expired_sessions.size} expired sessions removed") if expired_sessions.any?
        end
      end

      ##
      # Shutdown authentication manager
      #
      def shutdown
        @cleanup_task&.shutdown
        @active_sessions.clear
        @failed_attempts.clear
        @lockout_times.clear
      end

      private

      ##
      # Load JWT public key from file or environment
      #
      def load_jwt_public_key(key_path)
        if key_path && File.exist?(key_path)
          OpenSSL::PKey::RSA.new(File.read(key_path))
        elsif ENV['JWT_PUBLIC_KEY']
          OpenSSL::PKey::RSA.new(ENV['JWT_PUBLIC_KEY'])
        else
          raise ConfigurationError, 'JWT public key not configured'
        end
      end

      ##
      # Create security context from JWT payload
      #
      def create_security_context(payload, header, client_info)
        SecurityContext.new(
          user_id: payload['sub'],
          username: payload['username'],
          email: payload['email'],
          roles: payload['roles'] || [],
          permissions: payload['permissions'] || [],
          security_level: determine_security_level(payload),
          client_info: client_info,
          issued_at: Time.at(payload['iat']),
          expires_at: Time.at(payload['exp']),
          issuer: payload['iss']
        )
      end

      ##
      # Create new session
      #
      def create_session(security_context)
        session_id = SecureRandom.hex(16)
        
        session_data = {
          session_id: session_id,
          user_id: security_context.user_id,
          username: security_context.username,
          roles: security_context.roles,
          permissions: security_context.permissions,
          security_level: security_context.security_level,
          created_at: Time.now,
          last_activity: Time.now,
          expires_at: Time.now + @session_timeout,
          client_info: security_context.client_info
        }
        
        @active_sessions[session_id] = session_data
        session_id
      end

      ##
      # Check if session has expired
      #
      def session_expired?(session_data)
        Time.now > session_data[:expires_at]
      end

      ##
      # Determine security level based on user roles and permissions
      #
      def determine_security_level(payload)
        roles = payload['roles'] || []
        permissions = payload['permissions'] || []
        
        return 'CLASSIFIED' if roles.include?('super_admin')
        return 'RESTRICTED' if roles.include?('admin')
        return 'CONFIDENTIAL' if roles.include?('privileged_user')
        return 'INTERNAL' if roles.include?('user')
        'PUBLIC'
      end

      ##
      # Extract client ID from client info
      #
      def extract_client_id(client_info)
        client_info[:ip_address] || client_info[:user_agent] || 'unknown'
      end

      ##
      # Check if client is locked out
      #
      def check_lockout_status!(client_id)
        lockout_time = @lockout_times[client_id]
        return unless lockout_time
        
        if Time.now - lockout_time < LOCKOUT_DURATION
          remaining_time = LOCKOUT_DURATION - (Time.now - lockout_time)
          raise AuthenticationError, "Account locked. Try again in #{remaining_time.round} seconds"
        else
          @lockout_times.delete(client_id)
          @failed_attempts.delete(client_id)
        end
      end

      ##
      # Handle authentication failure
      #
      def handle_authentication_failure(client_id, error_message)
        @failed_attempts[client_id] += 1
        
        if @failed_attempts[client_id] >= MAX_FAILED_ATTEMPTS
          @lockout_times[client_id] = Time.now
          @logger.warn("Client locked out - ClientID: #{client_id}, Attempts: #{@failed_attempts[client_id]}")
        end
        
        @logger.warn("Authentication failed - ClientID: #{client_id}, Error: #{error_message}")
      end

      ##
      # Schedule periodic session cleanup
      #
      def schedule_session_cleanup
        Concurrent::TimerTask.new(execution_interval: 300) do # 5 minutes
          begin
            cleanup_expired_sessions
          rescue StandardError => e
            @logger.error("Session cleanup failed: #{e.message}")
          end
        end.tap(&:execute)
      end
    end

    ##
    # Security Context class representing authenticated user session
    #
    class SecurityContext
      attr_accessor :session_id
      attr_reader :user_id, :username, :email, :roles, :permissions, :security_level,
                  :client_info, :issued_at, :expires_at, :issuer, :created_at

      def initialize(user_id:, username: nil, email: nil, roles: [], permissions: [],
                     security_level: 'PUBLIC', client_info: {}, issued_at: nil,
                     expires_at: nil, issuer: nil)
        @user_id = user_id
        @username = username
        @email = email
        @roles = roles || []
        @permissions = permissions || []
        @security_level = security_level
        @client_info = client_info || {}
        @issued_at = issued_at
        @expires_at = expires_at
        @issuer = issuer
        @created_at = Time.now
      end

      ##
      # Create security context from session data
      #
      def self.from_session_data(session_data)
        context = new(
          user_id: session_data[:user_id],
          username: session_data[:username],
          roles: session_data[:roles],
          permissions: session_data[:permissions],
          security_level: session_data[:security_level],
          client_info: session_data[:client_info]
        )
        context.session_id = session_data[:session_id]
        context
      end

      ##
      # Check if user has specific role
      #
      def has_role?(role)
        @roles.include?(role.to_s)
      end

      ##
      # Check if user has specific permission
      #
      def has_permission?(permission)
        @permissions.include?(permission.to_s)
      end

      ##
      # Check if user can access security classification level
      #
      def can_access_classification?(classification)
        security_levels = ['PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED', 'CLASSIFIED']
        user_level_index = security_levels.index(@security_level) || 0
        required_level_index = security_levels.index(classification.upcase) || 0
        
        user_level_index >= required_level_index
      end

      ##
      # Convert to hash for serialization
      #
      def to_h
        {
          session_id: @session_id,
          user_id: @user_id,
          username: @username,
          email: @email,
          roles: @roles,
          permissions: @permissions,
          security_level: @security_level,
          client_info: @client_info,
          issued_at: @issued_at&.iso8601,
          expires_at: @expires_at&.iso8601,
          issuer: @issuer,
          created_at: @created_at.iso8601
        }
      end
    end

    ##
    # Rate Limiter for API protection
    #
    class RateLimiter
      include MonitorMixin

      attr_reader :logger

      def initialize(default_limit: DEFAULT_RATE_LIMIT, default_window: DEFAULT_RATE_WINDOW,
                     burst_limit: BURST_RATE_LIMIT, burst_window: BURST_RATE_WINDOW,
                     logger: nil)
        super()
        
        @default_limit = default_limit
        @default_window = default_window
        @burst_limit = burst_limit
        @burst_window = burst_window
        @logger = logger || Logger.new($stdout)
        
        # Request tracking (in production, use Redis)
        @request_counts = Concurrent::Hash.new { |h, k| h[k] = [] }
        @burst_counts = Concurrent::Hash.new { |h, k| h[k] = [] }
        
        # Cleanup task
        @cleanup_task = schedule_cleanup
        
        @logger.info("RateLimiter initialized - Limit: #{@default_limit}/#{@default_window}s, Burst: #{@burst_limit}/#{@burst_window}s")
      end

      ##
      # Check rate limit for client and operation
      #
      # @param client_id [String] Client identifier
      # @param operation [String] Operation name
      # @param limit [Integer] Custom limit override
      # @param window [Integer] Custom window override
      # @raise [RateLimitError] If rate limit exceeded
      #
      def check_rate_limit!(client_id, operation = 'default', limit: nil, window: nil)
        effective_limit = limit || @default_limit
        effective_window = window || @default_window
        
        synchronize do
          key = "#{client_id}:#{operation}"
          current_time = Time.now
          
          # Check burst rate limit first
          check_burst_limit!(key, current_time)
          
          # Clean old requests outside the window
          @request_counts[key].delete_if { |timestamp| current_time - timestamp > effective_window }
          
          # Check if limit would be exceeded
          if @request_counts[key].length >= effective_limit
            @logger.warn("Rate limit exceeded - Client: #{client_id}, Operation: #{operation}, Limit: #{effective_limit}")
            raise RateLimitError, "Rate limit exceeded: #{effective_limit} requests per #{effective_window} seconds"
          end
          
          # Record this request
          @request_counts[key] << current_time
        end
      end

      ##
      # Get current rate limit status for client
      #
      # @param client_id [String] Client identifier
      # @param operation [String] Operation name
      # @return [Hash] Rate limit status
      #
      def rate_limit_status(client_id, operation = 'default')
        synchronize do
          key = "#{client_id}:#{operation}"
          current_time = Time.now
          
          # Clean old requests
          @request_counts[key].delete_if { |timestamp| current_time - timestamp > @default_window }
          @burst_counts[key].delete_if { |timestamp| current_time - timestamp > @burst_window }
          
          {
            requests_in_window: @request_counts[key].length,
            limit: @default_limit,
            window: @default_window,
            remaining: [@default_limit - @request_counts[key].length, 0].max,
            burst_requests: @burst_counts[key].length,
            burst_limit: @burst_limit,
            burst_remaining: [@burst_limit - @burst_counts[key].length, 0].max,
            reset_time: current_time + @default_window
          }
        end
      end

      ##
      # Get rate limiter statistics
      #
      # @return [Hash] Statistics
      #
      def stats
        synchronize do
          {
            active_clients: @request_counts.size,
            total_tracked_requests: @request_counts.values.sum(&:size),
            burst_tracked_requests: @burst_counts.values.sum(&:size),
            cleanup_task_active: @cleanup_task&.running? || false
          }
        end
      end

      ##
      # Cleanup old tracking data
      #
      def cleanup
        synchronize do
          current_time = Time.now
          
          # Clean request counts
          @request_counts.delete_if do |key, timestamps|
            timestamps.delete_if { |timestamp| current_time - timestamp > @default_window }
            timestamps.empty?
          end
          
          # Clean burst counts
          @burst_counts.delete_if do |key, timestamps|
            timestamps.delete_if { |timestamp| current_time - timestamp > @burst_window }
            timestamps.empty?
          end
          
          @logger.debug("Rate limiter cleanup completed")
        end
      end

      ##
      # Shutdown rate limiter
      #
      def shutdown
        @cleanup_task&.shutdown
        @request_counts.clear
        @burst_counts.clear
      end

      private

      ##
      # Check burst rate limit
      #
      def check_burst_limit!(key, current_time)
        @burst_counts[key].delete_if { |timestamp| current_time - timestamp > @burst_window }
        
        if @burst_counts[key].length >= @burst_limit
          raise RateLimitError, "Burst rate limit exceeded: #{@burst_limit} requests per #{@burst_window} seconds"
        end
        
        @burst_counts[key] << current_time
      end

      ##
      # Schedule periodic cleanup
      #
      def schedule_cleanup
        Concurrent::TimerTask.new(execution_interval: 60) do # 1 minute
          begin
            cleanup
          rescue StandardError => e
            @logger.error("Rate limiter cleanup failed: #{e.message}")
          end
        end.tap(&:execute)
      end
    end

    ##
    # Audit Logger for security events and compliance
    #
    class AuditLogger
      attr_reader :logger, :retention_days

      def initialize(retention_days: AUDIT_RETENTION_DAYS, logger: nil)
        @retention_days = retention_days
        @logger = logger || Logger.new($stdout)
        
        # Audit event storage (in production, use dedicated audit database)
        @audit_events = Concurrent::Array.new
        
        # Cleanup task
        @cleanup_task = schedule_audit_cleanup
        
        @logger.info("AuditLogger initialized - Retention: #{@retention_days} days")
      end

      ##
      # Log security event
      #
      # @param event_type [String] Type of security event
      # @param user_context [SecurityContext] User security context
      # @param details [Hash] Event details
      # @param severity [String] Event severity (low, medium, high, critical)
      #
      def log_security_event(event_type, user_context = nil, details = {}, severity = 'medium')
        audit_event = {
          event_id: SecureRandom.hex(8),
          event_type: event_type,
          severity: severity,
          timestamp: Time.now.utc.iso8601,
          user_id: user_context&.user_id,
          session_id: user_context&.session_id,
          client_info: user_context&.client_info || {},
          details: details,
          ip_address: details[:ip_address] || user_context&.client_info&.dig(:ip_address),
          user_agent: details[:user_agent] || user_context&.client_info&.dig(:user_agent)
        }
        
        @audit_events << audit_event
        
        # Log to regular logger as well
        log_message = build_audit_log_message(audit_event)
        case severity
        when 'critical'
          @logger.error(log_message)
        when 'high'
          @logger.warn(log_message)
        else
          @logger.info(log_message)
        end
        
        audit_event[:event_id]
      end

      ##
      # Log authentication event
      #
      def log_authentication(user_id, success, details = {})
        event_type = success ? 'authentication_success' : 'authentication_failure'
        severity = success ? 'low' : 'medium'
        
        log_security_event(event_type, nil, details.merge(user_id: user_id), severity)
      end

      ##
      # Log authorization event
      #
      def log_authorization(user_context, resource, action, success, details = {})
        event_type = success ? 'authorization_success' : 'authorization_failure'
        severity = success ? 'low' : 'high'
        
        log_security_event(
          event_type,
          user_context,
          details.merge(resource: resource, action: action),
          severity
        )
      end

      ##
      # Log validation event
      #
      def log_validation(user_context, operation, result, details = {})
        event_type = "validation_#{result}"
        severity = result == 'rejected' ? 'medium' : 'low'
        
        log_security_event(
          event_type,
          user_context,
          details.merge(operation: operation, result: result),
          severity
        )
      end

      ##
      # Get audit events for analysis
      #
      # @param filters [Hash] Filters for events
      # @return [Array] Filtered audit events
      #
      def get_audit_events(filters = {})
        events = @audit_events.to_a
        
        events = events.select { |event| event[:user_id] == filters[:user_id] } if filters[:user_id]
        events = events.select { |event| event[:event_type] == filters[:event_type] } if filters[:event_type]
        events = events.select { |event| event[:severity] == filters[:severity] } if filters[:severity]
        
        if filters[:start_time]
          start_time = filters[:start_time].is_a?(String) ? Time.parse(filters[:start_time]) : filters[:start_time]
          events = events.select { |event| Time.parse(event[:timestamp]) >= start_time }
        end
        
        if filters[:end_time]
          end_time = filters[:end_time].is_a?(String) ? Time.parse(filters[:end_time]) : filters[:end_time]
          events = events.select { |event| Time.parse(event[:timestamp]) <= end_time }
        end
        
        events.sort_by { |event| event[:timestamp] }.reverse
      end

      ##
      # Get audit statistics
      #
      # @return [Hash] Audit statistics
      #
      def audit_stats
        events = @audit_events.to_a
        
        {
          total_events: events.size,
          events_by_type: events.group_by { |e| e[:event_type] }.transform_values(&:size),
          events_by_severity: events.group_by { |e| e[:severity] }.transform_values(&:size),
          unique_users: events.map { |e| e[:user_id] }.compact.uniq.size,
          oldest_event: events.min_by { |e| e[:timestamp] }&.dig(:timestamp),
          newest_event: events.max_by { |e| e[:timestamp] }&.dig(:timestamp)
        }
      end

      ##
      # Cleanup old audit events
      #
      def cleanup_old_events
        cutoff_time = Time.now.utc - (@retention_days * 24 * 60 * 60)
        
        initial_count = @audit_events.size
        @audit_events.delete_if { |event| Time.parse(event[:timestamp]) < cutoff_time }
        cleaned_count = initial_count - @audit_events.size
        
        @logger.info("Audit cleanup completed - #{cleaned_count} old events removed") if cleaned_count > 0
      end

      ##
      # Shutdown audit logger
      #
      def shutdown
        @cleanup_task&.shutdown
        @audit_events.clear
      end

      private

      ##
      # Build audit log message
      #
      def build_audit_log_message(audit_event)
        "AUDIT[#{audit_event[:event_type]}] User: #{audit_event[:user_id]}, " \
        "Session: #{audit_event[:session_id]}, IP: #{audit_event[:ip_address]}, " \
        "Details: #{audit_event[:details]}"
      end

      ##
      # Schedule audit cleanup
      #
      def schedule_audit_cleanup
        Concurrent::TimerTask.new(execution_interval: 24 * 60 * 60) do # Daily
          begin
            cleanup_old_events
          rescue StandardError => e
            @logger.error("Audit cleanup failed: #{e.message}")
          end
        end.tap(&:execute)
      end
    end
  end
end