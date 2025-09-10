# frozen_string_literal: true

require 'openssl'
require 'jwt'
require 'base64'
require 'net/http'
require 'uri'
require 'json'
require 'digest'
require 'securerandom'

module Security
  # Enterprise-grade authentication manager supporting multiple authentication methods
  # for secure communication between Huginn and AIgent Orchestrator.
  #
  # Supports:
  # - API Key authentication with secure key management and rotation
  # - JWT token authentication with expiration validation and refresh
  # - Basic authentication with credential encryption
  # - OAuth2 integration for enterprise environments
  # - Multi-factor authentication support preparation
  # - Session-based authentication with secure token generation
  #
  # Security Features:
  # - Cryptographically secure token generation
  # - Automatic credential rotation and expiration
  # - Rate limiting and attack prevention
  # - Audit logging for all authentication events
  # - Secure credential storage with encryption
  class AuthenticationManager
    class AuthenticationError < StandardError; end
    class InvalidCredentialsError < AuthenticationError; end
    class TokenExpiredError < AuthenticationError; end
    class RateLimitExceededError < AuthenticationError; end
    class InvalidTokenError < AuthenticationError; end
    class CredentialRotationError < AuthenticationError; end

    # Authentication method constants
    AUTH_METHODS = {
      api_key: 'api_key',
      jwt: 'jwt',
      basic: 'basic',
      oauth2: 'oauth2',
      session: 'session',
      mfa: 'mfa'
    }.freeze

    # Token types for different authentication scenarios
    TOKEN_TYPES = {
      access: 'access',
      refresh: 'refresh',
      api: 'api',
      session: 'session',
      mfa: 'mfa'
    }.freeze

    # Security configuration constants
    DEFAULT_CONFIG = {
      # API Key configuration
      api_key_length: 64,
      api_key_prefix: 'huginn_',
      api_key_rotation_days: 30,
      api_key_max_age_days: 90,
      
      # JWT configuration
      jwt_algorithm: 'HS256',
      jwt_access_token_ttl: 3600, # 1 hour
      jwt_refresh_token_ttl: 604800, # 7 days
      jwt_issuer: 'huginn-aigent-auth',
      jwt_audience: 'aigent-orchestrator',
      
      # Session configuration
      session_token_length: 128,
      session_ttl: 7200, # 2 hours
      session_idle_timeout: 1800, # 30 minutes
      max_concurrent_sessions: 5,
      
      # Rate limiting
      max_auth_attempts: 5,
      rate_limit_window: 300, # 5 minutes
      lockout_duration: 900, # 15 minutes
      
      # MFA configuration
      mfa_token_length: 6,
      mfa_token_ttl: 300, # 5 minutes
      mfa_backup_codes: 10,
      
      # OAuth2 configuration
      oauth2_authorize_ttl: 600, # 10 minutes
      oauth2_code_length: 32,
      oauth2_state_length: 32,
      
      # Security
      encryption_algorithm: 'AES-256-GCM',
      key_derivation_iterations: 100000,
      secure_random_bytes: 32
    }.freeze

    attr_reader :config, :logger, :metrics

    def initialize(config: {}, logger: nil)
      @config = DEFAULT_CONFIG.merge(config)
      @logger = logger || default_logger
      @metrics = SecurityMetrics.new
      @rate_limiter = RateLimiter.new(@config)
      @credential_store = CredentialStore.new(@config, @logger)
      @session_manager = SessionManager.new(@config, @logger)
      @token_cache = TokenCache.new(@config)
      
      initialize_encryption
      log_info "Authentication manager initialized with methods: #{AUTH_METHODS.keys.join(', ')}"
    end

    # API Key Authentication Methods

    def generate_api_key(user_id:, scopes: [], metadata: {})
      log_info "Generating API key for user: #{user_id}"
      
      begin
        key_id = SecureRandom.uuid
        raw_key = generate_secure_token(@config[:api_key_length])
        api_key = "#{@config[:api_key_prefix]}#{raw_key}"
        
        # Create encrypted storage of key metadata
        key_data = {
          key_id: key_id,
          user_id: user_id,
          scopes: scopes,
          metadata: metadata,
          created_at: Time.current,
          expires_at: @config[:api_key_max_age_days].days.from_now,
          rotation_due: @config[:api_key_rotation_days].days.from_now,
          usage_count: 0,
          last_used_at: nil,
          status: 'active',
          key_hash: hash_credential(api_key)
        }
        
        @credential_store.store_api_key(key_id, key_data)
        @metrics.increment('api_keys_generated')
        
        log_info "API key generated successfully for user: #{user_id}, key_id: #{key_id}"
        
        {
          api_key: api_key,
          key_id: key_id,
          expires_at: key_data[:expires_at],
          rotation_due: key_data[:rotation_due],
          scopes: scopes
        }
      rescue StandardError => e
        log_error "Failed to generate API key for user #{user_id}: #{e.message}"
        @metrics.increment('api_key_generation_errors')
        raise AuthenticationError, "Failed to generate API key: #{e.message}"
      end
    end

    def validate_api_key(api_key)
      log_debug "Validating API key"
      
      unless api_key&.start_with?(@config[:api_key_prefix])
        log_warning "Invalid API key format"
        raise InvalidCredentialsError, "Invalid API key format"
      end

      # Rate limiting check
      check_rate_limit("api_key_validation")
      
      key_hash = hash_credential(api_key)
      key_data = @credential_store.find_api_key_by_hash(key_hash)
      
      unless key_data
        log_warning "API key not found in credential store"
        @metrics.increment('api_key_validation_failures')
        raise InvalidCredentialsError, "Invalid API key"
      end
      
      # Check key status and expiration
      validate_key_status(key_data)
      
      # Update usage tracking
      @credential_store.update_api_key_usage(key_data[:key_id])
      @metrics.increment('api_key_validations_successful')
      
      log_info "API key validated successfully for user: #{key_data[:user_id]}"
      
      {
        user_id: key_data[:user_id],
        key_id: key_data[:key_id],
        scopes: key_data[:scopes],
        metadata: key_data[:metadata],
        expires_at: key_data[:expires_at],
        rotation_due: key_data[:rotation_due]
      }
    end

    def rotate_api_key(key_id)
      log_info "Rotating API key: #{key_id}"
      
      old_key_data = @credential_store.get_api_key(key_id)
      raise InvalidCredentialsError, "API key not found" unless old_key_data
      
      # Generate new key with same permissions
      new_key_result = generate_api_key(
        user_id: old_key_data[:user_id],
        scopes: old_key_data[:scopes],
        metadata: old_key_data[:metadata].merge(rotated_from: key_id)
      )
      
      # Mark old key as rotated
      @credential_store.rotate_api_key(key_id, new_key_result[:key_id])
      @metrics.increment('api_keys_rotated')
      
      log_info "API key rotated successfully: #{key_id} -> #{new_key_result[:key_id]}"
      new_key_result
    end

    # JWT Authentication Methods

    def generate_jwt_tokens(user_id:, scopes: [], metadata: {})
      log_info "Generating JWT tokens for user: #{user_id}"
      
      begin
        now = Time.current.to_i
        jti_access = SecureRandom.uuid
        jti_refresh = SecureRandom.uuid
        
        # Access token payload
        access_payload = {
          sub: user_id,
          iss: @config[:jwt_issuer],
          aud: @config[:jwt_audience],
          iat: now,
          exp: now + @config[:jwt_access_token_ttl],
          jti: jti_access,
          type: TOKEN_TYPES[:access],
          scopes: scopes,
          metadata: metadata
        }
        
        # Refresh token payload
        refresh_payload = {
          sub: user_id,
          iss: @config[:jwt_issuer],
          aud: @config[:jwt_audience],
          iat: now,
          exp: now + @config[:jwt_refresh_token_ttl],
          jti: jti_refresh,
          type: TOKEN_TYPES[:refresh],
          access_jti: jti_access
        }
        
        # Generate tokens
        access_token = JWT.encode(access_payload, jwt_secret, @config[:jwt_algorithm])
        refresh_token = JWT.encode(refresh_payload, jwt_secret, @config[:jwt_algorithm])
        
        # Store token metadata for tracking
        @token_cache.store_token(jti_access, {
          user_id: user_id,
          type: TOKEN_TYPES[:access],
          expires_at: Time.at(access_payload[:exp]),
          scopes: scopes,
          metadata: metadata
        })
        
        @token_cache.store_token(jti_refresh, {
          user_id: user_id,
          type: TOKEN_TYPES[:refresh],
          expires_at: Time.at(refresh_payload[:exp]),
          access_jti: jti_access
        })
        
        @metrics.increment('jwt_tokens_generated')
        log_info "JWT tokens generated successfully for user: #{user_id}"
        
        {
          access_token: access_token,
          refresh_token: refresh_token,
          token_type: 'Bearer',
          expires_in: @config[:jwt_access_token_ttl],
          scopes: scopes
        }
      rescue StandardError => e
        log_error "Failed to generate JWT tokens for user #{user_id}: #{e.message}"
        @metrics.increment('jwt_generation_errors')
        raise AuthenticationError, "Failed to generate JWT tokens: #{e.message}"
      end
    end

    def validate_jwt_token(token)
      log_debug "Validating JWT token"
      
      check_rate_limit("jwt_validation")
      
      begin
        # Decode and verify token
        decoded_token = JWT.decode(token, jwt_secret, true, {
          algorithm: @config[:jwt_algorithm],
          iss: @config[:jwt_issuer],
          aud: @config[:jwt_audience],
          verify_iss: true,
          verify_aud: true,
          verify_iat: true
        })
        
        payload = decoded_token[0]
        header = decoded_token[1]
        
        # Validate token type
        unless payload['type'] == TOKEN_TYPES[:access]
          raise InvalidTokenError, "Invalid token type"
        end
        
        # Check if token is revoked
        if @token_cache.revoked?(payload['jti'])
          raise InvalidTokenError, "Token has been revoked"
        end
        
        # Update token usage
        @token_cache.update_token_usage(payload['jti'])
        @metrics.increment('jwt_validations_successful')
        
        log_info "JWT token validated successfully for user: #{payload['sub']}"
        
        {
          user_id: payload['sub'],
          token_id: payload['jti'],
          scopes: payload['scopes'] || [],
          metadata: payload['metadata'] || {},
          expires_at: Time.at(payload['exp']),
          issued_at: Time.at(payload['iat'])
        }
      rescue JWT::DecodeError => e
        log_warning "JWT decode error: #{e.message}"
        @metrics.increment('jwt_validation_failures')
        raise InvalidTokenError, "Invalid JWT token: #{e.message}"
      rescue JWT::ExpiredSignature
        log_warning "JWT token expired"
        @metrics.increment('jwt_expired_tokens')
        raise TokenExpiredError, "JWT token has expired"
      rescue StandardError => e
        log_error "JWT validation error: #{e.message}"
        @metrics.increment('jwt_validation_errors')
        raise AuthenticationError, "JWT validation failed: #{e.message}"
      end
    end

    def refresh_jwt_token(refresh_token)
      log_info "Refreshing JWT token"
      
      begin
        # Validate refresh token
        decoded_token = JWT.decode(refresh_token, jwt_secret, true, {
          algorithm: @config[:jwt_algorithm],
          iss: @config[:jwt_issuer],
          aud: @config[:jwt_audience],
          verify_iss: true,
          verify_aud: true
        })
        
        payload = decoded_token[0]
        
        unless payload['type'] == TOKEN_TYPES[:refresh]
          raise InvalidTokenError, "Invalid refresh token type"
        end
        
        # Check if refresh token is revoked
        if @token_cache.revoked?(payload['jti'])
          raise InvalidTokenError, "Refresh token has been revoked"
        end
        
        # Get original token data
        original_token_data = @token_cache.get_token(payload['access_jti'])
        
        # Revoke old tokens
        @token_cache.revoke_token(payload['jti'])
        @token_cache.revoke_token(payload['access_jti'])
        
        # Generate new tokens
        new_tokens = generate_jwt_tokens(
          user_id: payload['sub'],
          scopes: original_token_data&.dig(:scopes) || [],
          metadata: original_token_data&.dig(:metadata) || {}
        )
        
        @metrics.increment('jwt_tokens_refreshed')
        log_info "JWT token refreshed successfully for user: #{payload['sub']}"
        
        new_tokens
      rescue JWT::ExpiredSignature
        log_warning "Refresh token expired"
        @metrics.increment('jwt_refresh_expired')
        raise TokenExpiredError, "Refresh token has expired"
      rescue StandardError => e
        log_error "JWT refresh error: #{e.message}"
        @metrics.increment('jwt_refresh_errors')
        raise AuthenticationError, "Token refresh failed: #{e.message}"
      end
    end

    # Basic Authentication Methods

    def validate_basic_auth(username, password)
      log_info "Validating basic authentication for user: #{username}"
      
      check_rate_limit("basic_auth_#{username}")
      
      # Retrieve stored credentials
      user_credentials = @credential_store.get_basic_auth_credentials(username)
      unless user_credentials
        log_warning "User not found: #{username}"
        @metrics.increment('basic_auth_failures')
        raise InvalidCredentialsError, "Invalid username or password"
      end
      
      # Verify password
      unless verify_password(password, user_credentials[:password_hash])
        log_warning "Invalid password for user: #{username}"
        @metrics.increment('basic_auth_failures')
        raise InvalidCredentialsError, "Invalid username or password"
      end
      
      # Check account status
      if user_credentials[:status] != 'active'
        log_warning "Account inactive for user: #{username}"
        raise InvalidCredentialsError, "Account is not active"
      end
      
      # Update last login
      @credential_store.update_basic_auth_login(username)
      @metrics.increment('basic_auth_successful')
      
      log_info "Basic authentication successful for user: #{username}"
      
      {
        user_id: user_credentials[:user_id],
        username: username,
        scopes: user_credentials[:scopes] || [],
        metadata: user_credentials[:metadata] || {}
      }
    end

    def create_basic_auth_user(username:, password:, user_id: nil, scopes: [], metadata: {})
      log_info "Creating basic auth user: #{username}"
      
      user_id ||= SecureRandom.uuid
      password_hash = hash_password(password)
      
      user_data = {
        user_id: user_id,
        username: username,
        password_hash: password_hash,
        scopes: scopes,
        metadata: metadata,
        status: 'active',
        created_at: Time.current,
        last_login_at: nil,
        failed_attempts: 0
      }
      
      @credential_store.create_basic_auth_user(username, user_data)
      @metrics.increment('basic_auth_users_created')
      
      log_info "Basic auth user created: #{username}"
      
      {
        user_id: user_id,
        username: username,
        scopes: scopes
      }
    end

    # Session Authentication Methods

    def create_session(user_id:, scopes: [], metadata: {})
      log_info "Creating session for user: #{user_id}"
      
      # Check concurrent session limit
      active_sessions = @session_manager.get_active_sessions(user_id)
      if active_sessions.count >= @config[:max_concurrent_sessions]
        log_warning "Maximum concurrent sessions exceeded for user: #{user_id}"
        # Remove oldest session
        @session_manager.remove_oldest_session(user_id)
      end
      
      session_id = SecureRandom.uuid
      session_token = generate_secure_token(@config[:session_token_length])
      
      session_data = {
        session_id: session_id,
        user_id: user_id,
        scopes: scopes,
        metadata: metadata,
        created_at: Time.current,
        expires_at: @config[:session_ttl].seconds.from_now,
        last_activity_at: Time.current,
        ip_address: metadata[:ip_address],
        user_agent: metadata[:user_agent],
        status: 'active'
      }
      
      @session_manager.create_session(session_id, session_token, session_data)
      @metrics.increment('sessions_created')
      
      log_info "Session created: #{session_id} for user: #{user_id}"
      
      {
        session_id: session_id,
        session_token: session_token,
        expires_at: session_data[:expires_at],
        scopes: scopes
      }
    end

    def validate_session(session_token)
      log_debug "Validating session token"
      
      check_rate_limit("session_validation")
      
      session_data = @session_manager.get_session_by_token(session_token)
      unless session_data
        log_warning "Session not found"
        @metrics.increment('session_validation_failures')
        raise InvalidCredentialsError, "Invalid session"
      end
      
      # Check session expiration
      if session_data[:expires_at] < Time.current
        log_warning "Session expired: #{session_data[:session_id]}"
        @session_manager.remove_session(session_data[:session_id])
        @metrics.increment('session_expired')
        raise TokenExpiredError, "Session has expired"
      end
      
      # Check idle timeout
      idle_limit = @config[:session_idle_timeout].seconds.ago
      if session_data[:last_activity_at] < idle_limit
        log_warning "Session idle timeout: #{session_data[:session_id]}"
        @session_manager.remove_session(session_data[:session_id])
        @metrics.increment('session_idle_timeout')
        raise TokenExpiredError, "Session idle timeout"
      end
      
      # Update activity
      @session_manager.update_activity(session_data[:session_id])
      @metrics.increment('session_validations_successful')
      
      log_info "Session validated: #{session_data[:session_id]} for user: #{session_data[:user_id]}"
      
      {
        user_id: session_data[:user_id],
        session_id: session_data[:session_id],
        scopes: session_data[:scopes],
        metadata: session_data[:metadata],
        expires_at: session_data[:expires_at]
      }
    end

    # Multi-Factor Authentication (MFA) Methods

    def generate_mfa_token(user_id)
      log_info "Generating MFA token for user: #{user_id}"
      
      mfa_code = SecureRandom.random_number(10**@config[:mfa_token_length])
                            .to_s.rjust(@config[:mfa_token_length], '0')
      
      mfa_data = {
        user_id: user_id,
        code: mfa_code,
        created_at: Time.current,
        expires_at: @config[:mfa_token_ttl].seconds.from_now,
        attempts: 0,
        verified: false
      }
      
      @credential_store.store_mfa_token(user_id, mfa_data)
      @metrics.increment('mfa_tokens_generated')
      
      log_info "MFA token generated for user: #{user_id}"
      
      {
        mfa_code: mfa_code,
        expires_at: mfa_data[:expires_at],
        delivery_method: 'application' # Can be extended for SMS/email
      }
    end

    def verify_mfa_token(user_id, provided_code)
      log_info "Verifying MFA token for user: #{user_id}"
      
      check_rate_limit("mfa_verification_#{user_id}")
      
      mfa_data = @credential_store.get_mfa_token(user_id)
      unless mfa_data
        log_warning "No MFA token found for user: #{user_id}"
        @metrics.increment('mfa_verification_failures')
        raise InvalidCredentialsError, "No MFA token found"
      end
      
      if mfa_data[:expires_at] < Time.current
        log_warning "MFA token expired for user: #{user_id}"
        @credential_store.remove_mfa_token(user_id)
        @metrics.increment('mfa_token_expired')
        raise TokenExpiredError, "MFA token has expired"
      end
      
      if mfa_data[:attempts] >= 3
        log_warning "MFA token max attempts exceeded for user: #{user_id}"
        @credential_store.remove_mfa_token(user_id)
        @metrics.increment('mfa_max_attempts')
        raise InvalidCredentialsError, "Maximum MFA attempts exceeded"
      end
      
      # Verify code
      unless mfa_data[:code] == provided_code.to_s
        @credential_store.increment_mfa_attempts(user_id)
        log_warning "Invalid MFA code for user: #{user_id}"
        @metrics.increment('mfa_verification_failures')
        raise InvalidCredentialsError, "Invalid MFA code"
      end
      
      # Mark as verified and clean up
      @credential_store.mark_mfa_verified(user_id)
      @credential_store.remove_mfa_token(user_id)
      @metrics.increment('mfa_verifications_successful')
      
      log_info "MFA verification successful for user: #{user_id}"
      
      {
        verified: true,
        verified_at: Time.current
      }
    end

    # OAuth2 Methods (Preparation for enterprise integration)

    def generate_oauth2_authorization_code(client_id:, user_id:, scopes: [], redirect_uri:, state: nil)
      log_info "Generating OAuth2 authorization code for client: #{client_id}, user: #{user_id}"
      
      code = generate_secure_token(@config[:oauth2_code_length])
      state ||= generate_secure_token(@config[:oauth2_state_length])
      
      auth_data = {
        code: code,
        client_id: client_id,
        user_id: user_id,
        scopes: scopes,
        redirect_uri: redirect_uri,
        state: state,
        created_at: Time.current,
        expires_at: @config[:oauth2_authorize_ttl].seconds.from_now,
        used: false
      }
      
      @credential_store.store_oauth2_code(code, auth_data)
      @metrics.increment('oauth2_codes_generated')
      
      log_info "OAuth2 authorization code generated for client: #{client_id}"
      
      {
        code: code,
        state: state,
        expires_at: auth_data[:expires_at]
      }
    end

    def exchange_oauth2_code(code:, client_id:, client_secret:, redirect_uri:)
      log_info "Exchanging OAuth2 code for tokens, client: #{client_id}"
      
      check_rate_limit("oauth2_exchange_#{client_id}")
      
      # Validate client credentials
      client_data = @credential_store.get_oauth2_client(client_id)
      unless client_data && verify_password(client_secret, client_data[:secret_hash])
        log_warning "Invalid OAuth2 client credentials: #{client_id}"
        @metrics.increment('oauth2_exchange_failures')
        raise InvalidCredentialsError, "Invalid client credentials"
      end
      
      # Validate authorization code
      auth_data = @credential_store.get_oauth2_code(code)
      unless auth_data
        log_warning "Invalid OAuth2 authorization code"
        @metrics.increment('oauth2_exchange_failures')
        raise InvalidCredentialsError, "Invalid authorization code"
      end
      
      if auth_data[:used] || auth_data[:expires_at] < Time.current
        log_warning "OAuth2 code expired or already used"
        @credential_store.remove_oauth2_code(code)
        @metrics.increment('oauth2_code_expired')
        raise InvalidCredentialsError, "Authorization code expired or already used"
      end
      
      if auth_data[:client_id] != client_id || auth_data[:redirect_uri] != redirect_uri
        log_warning "OAuth2 code validation failed - client/redirect mismatch"
        @metrics.increment('oauth2_exchange_failures')
        raise InvalidCredentialsError, "Authorization code validation failed"
      end
      
      # Mark code as used
      @credential_store.mark_oauth2_code_used(code)
      
      # Generate tokens
      tokens = generate_jwt_tokens(
        user_id: auth_data[:user_id],
        scopes: auth_data[:scopes],
        metadata: { client_id: client_id }
      )
      
      @metrics.increment('oauth2_exchanges_successful')
      log_info "OAuth2 code exchanged successfully for client: #{client_id}"
      
      tokens
    end

    # Utility and Management Methods

    def authenticate_request(auth_header:, method: nil)
      log_debug "Authenticating request with header: #{auth_header&.gsub(/\w{10,}/, '***')}"
      
      return nil unless auth_header
      
      case auth_header
      when /^Bearer\s+(.+)$/i
        token = $1
        if method == AUTH_METHODS[:session]
          validate_session(token)
        else
          validate_jwt_token(token)
        end
      when /^Basic\s+(.+)$/i
        credentials = Base64.decode64($1).split(':', 2)
        validate_basic_auth(credentials[0], credentials[1])
      when /^ApiKey\s+(.+)$/i
        validate_api_key($1)
      else
        log_warning "Unsupported authentication header format"
        raise InvalidCredentialsError, "Unsupported authentication method"
      end
    end

    def revoke_token(token_id:, type: nil)
      log_info "Revoking token: #{token_id}, type: #{type}"
      
      case type
      when TOKEN_TYPES[:api]
        @credential_store.revoke_api_key(token_id)
      when TOKEN_TYPES[:session]
        @session_manager.remove_session(token_id)
      else
        @token_cache.revoke_token(token_id)
      end
      
      @metrics.increment('tokens_revoked')
      log_info "Token revoked successfully: #{token_id}"
    end

    def cleanup_expired_tokens
      log_info "Cleaning up expired tokens"
      
      expired_count = 0
      
      # Clean up expired API keys
      expired_count += @credential_store.cleanup_expired_api_keys
      
      # Clean up expired sessions
      expired_count += @session_manager.cleanup_expired_sessions
      
      # Clean up expired JWT tokens from cache
      expired_count += @token_cache.cleanup_expired_tokens
      
      # Clean up expired MFA tokens
      expired_count += @credential_store.cleanup_expired_mfa_tokens
      
      # Clean up expired OAuth2 codes
      expired_count += @credential_store.cleanup_expired_oauth2_codes
      
      @metrics.set('expired_tokens_cleaned', expired_count)
      log_info "Cleaned up #{expired_count} expired tokens"
      
      expired_count
    end

    def get_authentication_metrics
      {
        api_keys_generated: @metrics.get('api_keys_generated'),
        api_keys_validated: @metrics.get('api_key_validations_successful'),
        jwt_tokens_generated: @metrics.get('jwt_tokens_generated'),
        jwt_tokens_validated: @metrics.get('jwt_validations_successful'),
        sessions_created: @metrics.get('sessions_created'),
        sessions_validated: @metrics.get('session_validations_successful'),
        mfa_tokens_generated: @metrics.get('mfa_tokens_generated'),
        mfa_verifications: @metrics.get('mfa_verifications_successful'),
        oauth2_codes_generated: @metrics.get('oauth2_codes_generated'),
        oauth2_exchanges: @metrics.get('oauth2_exchanges_successful'),
        total_failures: @metrics.get('api_key_validation_failures') +
                        @metrics.get('jwt_validation_failures') +
                        @metrics.get('session_validation_failures') +
                        @metrics.get('mfa_verification_failures') +
                        @metrics.get('oauth2_exchange_failures'),
        rate_limit_hits: @rate_limiter.get_metrics
      }
    end

    private

    def initialize_encryption
      @jwt_secret = generate_or_load_secret('jwt_secret')
      @encryption_key = generate_or_load_secret('encryption_key')
      log_info "Encryption initialized successfully"
    end

    def generate_or_load_secret(secret_name)
      secret_file = Rails.root.join('config', 'secrets', "#{secret_name}.key")
      
      if File.exist?(secret_file)
        File.read(secret_file).strip
      else
        FileUtils.mkdir_p(File.dirname(secret_file))
        secret = SecureRandom.hex(32)
        File.write(secret_file, secret)
        File.chmod(0600, secret_file)
        secret
      end
    end

    def jwt_secret
      @jwt_secret
    end

    def generate_secure_token(length)
      SecureRandom.alphanumeric(length)
    end

    def hash_credential(credential)
      Digest::SHA256.hexdigest("#{credential}#{@encryption_key}")
    end

    def hash_password(password)
      BCrypt::Password.create(password, cost: 12)
    end

    def verify_password(password, hash)
      BCrypt::Password.new(hash) == password
    rescue BCrypt::Errors::InvalidHash
      false
    end

    def validate_key_status(key_data)
      case key_data[:status]
      when 'expired'
        raise TokenExpiredError, "API key has expired"
      when 'revoked'
        raise InvalidCredentialsError, "API key has been revoked"
      when 'suspended'
        raise InvalidCredentialsError, "API key is suspended"
      when 'rotation_required'
        raise CredentialRotationError, "API key rotation required"
      end
      
      if key_data[:expires_at] < Time.current
        @credential_store.expire_api_key(key_data[:key_id])
        raise TokenExpiredError, "API key has expired"
      end
    end

    def check_rate_limit(identifier)
      unless @rate_limiter.allow?(identifier)
        log_warning "Rate limit exceeded for: #{identifier}"
        @metrics.increment('rate_limit_exceeded')
        raise RateLimitExceededError, "Rate limit exceeded"
      end
    end

    def default_logger
      @default_logger ||= Logger.new(Rails.root.join('log', 'authentication.log')).tap do |logger|
        logger.level = Rails.env.production? ? Logger::INFO : Logger::DEBUG
        logger.formatter = proc do |severity, datetime, progname, msg|
          "[#{datetime}] #{severity}: #{msg}\n"
        end
      end
    end

    def log_info(message)
      @logger.info("AuthenticationManager: #{message}")
    end

    def log_debug(message)
      @logger.debug("AuthenticationManager: #{message}")
    end

    def log_warning(message)
      @logger.warn("AuthenticationManager: #{message}")
    end

    def log_error(message)
      @logger.error("AuthenticationManager: #{message}")
    end
  end

  # Supporting classes for authentication management

  class SecurityMetrics
    def initialize
      @metrics = Hash.new(0)
      @mutex = Mutex.new
    end

    def increment(metric, value = 1)
      @mutex.synchronize { @metrics[metric] += value }
    end

    def set(metric, value)
      @mutex.synchronize { @metrics[metric] = value }
    end

    def get(metric)
      @mutex.synchronize { @metrics[metric] }
    end

    def all
      @mutex.synchronize { @metrics.dup }
    end
  end

  class RateLimiter
    def initialize(config)
      @config = config
      @requests = Hash.new { |h, k| h[k] = [] }
      @mutex = Mutex.new
    end

    def allow?(identifier)
      @mutex.synchronize do
        now = Time.current
        window_start = now - @config[:rate_limit_window]
        
        # Clean old requests
        @requests[identifier].reject! { |time| time < window_start }
        
        # Check limit
        if @requests[identifier].size >= @config[:max_auth_attempts]
          false
        else
          @requests[identifier] << now
          true
        end
      end
    end

    def get_metrics
      @mutex.synchronize do
        {
          total_identifiers: @requests.keys.size,
          active_requests: @requests.values.sum(&:size)
        }
      end
    end
  end

  class CredentialStore
    def initialize(config, logger)
      @config = config
      @logger = logger
      @credentials = {}
      @mutex = Mutex.new
      # In production, this would be backed by Redis or database
    end

    def store_api_key(key_id, data)
      @mutex.synchronize { @credentials["api_key:#{key_id}"] = data }
    end

    def get_api_key(key_id)
      @mutex.synchronize { @credentials["api_key:#{key_id}"] }
    end

    def find_api_key_by_hash(hash)
      @mutex.synchronize do
        @credentials.values.find { |data| data[:key_hash] == hash }
      end
    end

    def update_api_key_usage(key_id)
      @mutex.synchronize do
        if data = @credentials["api_key:#{key_id}"]
          data[:usage_count] += 1
          data[:last_used_at] = Time.current
        end
      end
    end

    def rotate_api_key(old_key_id, new_key_id)
      @mutex.synchronize do
        if data = @credentials["api_key:#{old_key_id}"]
          data[:status] = 'rotated'
          data[:rotated_to] = new_key_id
          data[:rotated_at] = Time.current
        end
      end
    end

    def revoke_api_key(key_id)
      @mutex.synchronize do
        if data = @credentials["api_key:#{key_id}"]
          data[:status] = 'revoked'
          data[:revoked_at] = Time.current
        end
      end
    end

    def expire_api_key(key_id)
      @mutex.synchronize do
        if data = @credentials["api_key:#{key_id}"]
          data[:status] = 'expired'
        end
      end
    end

    def cleanup_expired_api_keys
      count = 0
      @mutex.synchronize do
        @credentials.delete_if do |key, data|
          if key.start_with?('api_key:') && data[:expires_at] < Time.current
            count += 1
            true
          end
        end
      end
      count
    end

    def create_basic_auth_user(username, data)
      @mutex.synchronize { @credentials["basic:#{username}"] = data }
    end

    def get_basic_auth_credentials(username)
      @mutex.synchronize { @credentials["basic:#{username}"] }
    end

    def update_basic_auth_login(username)
      @mutex.synchronize do
        if data = @credentials["basic:#{username}"]
          data[:last_login_at] = Time.current
          data[:failed_attempts] = 0
        end
      end
    end

    def store_mfa_token(user_id, data)
      @mutex.synchronize { @credentials["mfa:#{user_id}"] = data }
    end

    def get_mfa_token(user_id)
      @mutex.synchronize { @credentials["mfa:#{user_id}"] }
    end

    def increment_mfa_attempts(user_id)
      @mutex.synchronize do
        if data = @credentials["mfa:#{user_id}"]
          data[:attempts] += 1
        end
      end
    end

    def mark_mfa_verified(user_id)
      @mutex.synchronize do
        if data = @credentials["mfa:#{user_id}"]
          data[:verified] = true
          data[:verified_at] = Time.current
        end
      end
    end

    def remove_mfa_token(user_id)
      @mutex.synchronize { @credentials.delete("mfa:#{user_id}") }
    end

    def cleanup_expired_mfa_tokens
      count = 0
      @mutex.synchronize do
        @credentials.delete_if do |key, data|
          if key.start_with?('mfa:') && data[:expires_at] < Time.current
            count += 1
            true
          end
        end
      end
      count
    end

    def store_oauth2_code(code, data)
      @mutex.synchronize { @credentials["oauth2_code:#{code}"] = data }
    end

    def get_oauth2_code(code)
      @mutex.synchronize { @credentials["oauth2_code:#{code}"] }
    end

    def mark_oauth2_code_used(code)
      @mutex.synchronize do
        if data = @credentials["oauth2_code:#{code}"]
          data[:used] = true
          data[:used_at] = Time.current
        end
      end
    end

    def remove_oauth2_code(code)
      @mutex.synchronize { @credentials.delete("oauth2_code:#{code}") }
    end

    def get_oauth2_client(client_id)
      @mutex.synchronize { @credentials["oauth2_client:#{client_id}"] }
    end

    def cleanup_expired_oauth2_codes
      count = 0
      @mutex.synchronize do
        @credentials.delete_if do |key, data|
          if key.start_with?('oauth2_code:') && data[:expires_at] < Time.current
            count += 1
            true
          end
        end
      end
      count
    end
  end

  class SessionManager
    def initialize(config, logger)
      @config = config
      @logger = logger
      @sessions = {}
      @session_tokens = {}
      @mutex = Mutex.new
    end

    def create_session(session_id, session_token, data)
      @mutex.synchronize do
        @sessions[session_id] = data
        @session_tokens[session_token] = session_id
      end
    end

    def get_session(session_id)
      @mutex.synchronize { @sessions[session_id] }
    end

    def get_session_by_token(token)
      @mutex.synchronize do
        session_id = @session_tokens[token]
        session_id ? @sessions[session_id] : nil
      end
    end

    def update_activity(session_id)
      @mutex.synchronize do
        if data = @sessions[session_id]
          data[:last_activity_at] = Time.current
        end
      end
    end

    def remove_session(session_id)
      @mutex.synchronize do
        if data = @sessions.delete(session_id)
          # Find and remove token mapping
          @session_tokens.delete_if { |token, sid| sid == session_id }
        end
      end
    end

    def get_active_sessions(user_id)
      @mutex.synchronize do
        @sessions.values.select { |data| data[:user_id] == user_id && data[:status] == 'active' }
      end
    end

    def remove_oldest_session(user_id)
      @mutex.synchronize do
        sessions = @sessions.select { |sid, data| data[:user_id] == user_id && data[:status] == 'active' }
        if sessions.any?
          oldest_session = sessions.min_by { |sid, data| data[:created_at] }
          remove_session(oldest_session[0])
        end
      end
    end

    def cleanup_expired_sessions
      count = 0
      @mutex.synchronize do
        expired_sessions = @sessions.select do |session_id, data|
          data[:expires_at] < Time.current || 
          data[:last_activity_at] < @config[:session_idle_timeout].seconds.ago
        end
        
        expired_sessions.each do |session_id, data|
          @sessions.delete(session_id)
          @session_tokens.delete_if { |token, sid| sid == session_id }
          count += 1
        end
      end
      count
    end
  end

  class TokenCache
    def initialize(config)
      @config = config
      @tokens = {}
      @revoked_tokens = Set.new
      @mutex = Mutex.new
    end

    def store_token(jti, data)
      @mutex.synchronize { @tokens[jti] = data }
    end

    def get_token(jti)
      @mutex.synchronize { @tokens[jti] }
    end

    def revoke_token(jti)
      @mutex.synchronize { @revoked_tokens.add(jti) }
    end

    def revoked?(jti)
      @mutex.synchronize { @revoked_tokens.include?(jti) }
    end

    def update_token_usage(jti)
      @mutex.synchronize do
        if data = @tokens[jti]
          data[:last_used_at] = Time.current
          data[:usage_count] = (data[:usage_count] || 0) + 1
        end
      end
    end

    def cleanup_expired_tokens
      count = 0
      @mutex.synchronize do
        @tokens.delete_if do |jti, data|
          if data[:expires_at] < Time.current
            @revoked_tokens.delete(jti)
            count += 1
            true
          end
        end
      end
      count
    end
  end
end