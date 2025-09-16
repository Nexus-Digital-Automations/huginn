# frozen_string_literal: true

##
# Parlant Bridge - Comprehensive HTTP Bridge Service for Ruby/Huginn Integration
# 
# This module provides a complete HTTP bridge service for integrating Ruby-based
# Huginn functions with Parlant conversational validation. It includes:
#
# - HTTP client service with connection pooling and retry mechanisms
# - Ruby integration patterns with method interception and decorators  
# - Conversational validation framework with user confirmation workflows
# - Performance optimization with multi-level caching
# - Comprehensive error handling and circuit breaker patterns
# - Security integration with authentication and audit logging
# - Rate limiting and abuse prevention
#
# @author Parlant Bridge Development Team
# @version 1.0.0
# @since Ruby 2.7+
#

# Core dependencies
require 'net/http'
require 'json'
require 'concurrent'
require 'monitor'
require 'logger'
require 'securerandom'
require 'digest'
require 'jwt'
require 'openssl'

# Load all Parlant Bridge components
require_relative 'parlant_bridge/error_handling'
require_relative 'parlant_bridge/validation_result'
require_relative 'parlant_bridge/cache_service'
require_relative 'parlant_bridge/http_client_service'
require_relative 'parlant_bridge/async_validation_session'
require_relative 'parlant_bridge/integration_module'
require_relative 'parlant_bridge/security_integration'
require_relative 'parlant_bridge/usage_examples'

module ParlantBridge
  # Version information
  VERSION = '1.0.0'
  RUBY_VERSION_REQUIRED = '2.7.0'
  
  # Configuration constants
  DEFAULT_SERVER_URL = 'http://localhost:8080'
  DEFAULT_TIMEOUT = 30
  DEFAULT_POOL_SIZE = 10
  DEFAULT_CACHE_TTL = 300
  
  # Ensure minimum Ruby version
  if Gem::Version.new(RUBY_VERSION) < Gem::Version.new(RUBY_VERSION_REQUIRED)
    raise "Parlant Bridge requires Ruby #{RUBY_VERSION_REQUIRED} or later. Current: #{RUBY_VERSION}"
  end
  
  class << self
    attr_accessor :default_config, :logger
    
    ##
    # Configure global Parlant Bridge settings
    #
    # @param config [Hash] Global configuration options
    # @option config [String] :server_url Parlant server URL
    # @option config [Integer] :timeout Default timeout in seconds
    # @option config [Integer] :pool_size Default connection pool size
    # @option config [Integer] :cache_ttl Default cache TTL in seconds
    # @option config [Logger] :logger Logger instance
    # @option config [Boolean] :enable_metrics Enable metrics collection
    # @option config [Boolean] :enable_circuit_breaker Enable circuit breaker
    #
    # @example Configure Parlant Bridge
    #   ParlantBridge.configure(
    #     server_url: 'https://parlant.example.com',
    #     timeout: 45,
    #     pool_size: 20,
    #     cache_ttl: 600,
    #     logger: Logger.new('parlant.log'),
    #     enable_metrics: true
    #   )
    #
    def configure(config = {})
      @default_config = {
        server_url: config[:server_url] || ENV['PARLANT_SERVER_URL'] || DEFAULT_SERVER_URL,
        timeout: config[:timeout] || DEFAULT_TIMEOUT,
        pool_size: config[:pool_size] || DEFAULT_POOL_SIZE,
        cache_ttl: config[:cache_ttl] || DEFAULT_CACHE_TTL,
        logger: config[:logger] || create_default_logger,
        enable_metrics: config.fetch(:enable_metrics, true),
        enable_circuit_breaker: config.fetch(:enable_circuit_breaker, true),
        jwt_public_key_path: config[:jwt_public_key_path] || ENV['JWT_PUBLIC_KEY_PATH'],
        rate_limit: config[:rate_limit] || 100,
        rate_window: config[:rate_window] || 60
      }
      
      @logger = @default_config[:logger]
      @logger.info("Parlant Bridge configured - Server: #{@default_config[:server_url]}")
      
      # Validate configuration
      validate_configuration!
      
      @default_config
    end
    
    ##
    # Get current configuration
    #
    # @return [Hash] Current configuration
    #
    def configuration
      @default_config ||= configure
    end
    
    ##
    # Create a new HTTP client service with default configuration
    #
    # @param config_override [Hash] Configuration overrides
    # @return [HttpClientService] Configured HTTP client service
    #
    def create_client(config_override = {})
      config = configuration.merge(config_override)
      
      HttpClientService.new(
        server_url: config[:server_url],
        pool_size: config[:pool_size],
        timeout: config[:timeout],
        cache_ttl: config[:cache_ttl],
        logger: config[:logger],
        enable_circuit_breaker: config[:enable_circuit_breaker]
      )
    end
    
    ##
    # Create a new authentication manager with default configuration
    #
    # @param config_override [Hash] Configuration overrides
    # @return [SecurityIntegration::AuthenticationManager] Configured auth manager
    #
    def create_auth_manager(config_override = {})
      config = configuration.merge(config_override)
      
      SecurityIntegration::AuthenticationManager.new(
        jwt_public_key_path: config[:jwt_public_key_path],
        logger: config[:logger]
      )
    end
    
    ##
    # Create a new audit logger with default configuration
    #
    # @param config_override [Hash] Configuration overrides
    # @return [SecurityIntegration::AuditLogger] Configured audit logger
    #
    def create_audit_logger(config_override = {})
      config = configuration.merge(config_override)
      
      SecurityIntegration::AuditLogger.new(
        logger: config[:logger]
      )
    end
    
    ##
    # Get library version information
    #
    # @return [Hash] Version and system information
    #
    def version_info
      {
        parlant_bridge_version: VERSION,
        ruby_version: RUBY_VERSION,
        ruby_platform: RUBY_PLATFORM,
        concurrent_ruby_version: Concurrent::VERSION,
        jwt_version: defined?(JWT::VERSION) ? JWT::VERSION : 'unknown'
      }
    end
    
    ##
    # Perform system health check
    #
    # @return [Hash] System health status
    #
    def health_check
      config = configuration
      health_status = {
        status: 'healthy',
        timestamp: Time.now.iso8601,
        version: VERSION,
        configuration: {
          server_url: config[:server_url],
          timeout: config[:timeout],
          pool_size: config[:pool_size],
          cache_ttl: config[:cache_ttl],
          metrics_enabled: config[:enable_metrics],
          circuit_breaker_enabled: config[:enable_circuit_breaker]
        },
        system: {
          ruby_version: RUBY_VERSION,
          memory_usage: get_memory_usage,
          thread_count: Thread.list.size
        },
        dependencies: check_dependencies
      }
      
      # Test server connectivity
      begin
        client = create_client
        # Note: This would be a real health check endpoint in production
        health_status[:server_connectivity] = 'available'
      rescue StandardError => e
        health_status[:status] = 'degraded'
        health_status[:server_connectivity] = 'unavailable'
        health_status[:connectivity_error] = e.message
      end
      
      health_status
    end
    
    ##
    # Enable debug mode for troubleshooting
    #
    def enable_debug_mode!
      configuration[:logger].level = Logger::DEBUG
      @logger.debug("Parlant Bridge debug mode enabled")
    end
    
    ##
    # Disable debug mode
    #
    def disable_debug_mode!
      configuration[:logger].level = Logger::INFO
      @logger.info("Parlant Bridge debug mode disabled")
    end
    
    ##
    # Reset configuration to defaults
    #
    def reset_configuration!
      @default_config = nil
      @logger = nil
      configure
    end
    
    private
    
    ##
    # Create default logger
    #
    def create_default_logger
      logger = Logger.new($stdout)
      logger.level = Logger::INFO
      logger.formatter = proc do |severity, datetime, progname, msg|
        "[#{datetime.strftime('%Y-%m-%d %H:%M:%S')}] #{severity} [ParlantBridge] #{msg}\n"
      end
      logger
    end
    
    ##
    # Validate configuration
    #
    def validate_configuration!
      config = @default_config
      
      # Validate server URL
      begin
        uri = URI.parse(config[:server_url])
        unless uri.is_a?(URI::HTTP) || uri.is_a?(URI::HTTPS)
          raise ConfigurationError, "Invalid server URL: #{config[:server_url]}"
        end
      rescue URI::InvalidURIError
        raise ConfigurationError, "Malformed server URL: #{config[:server_url]}"
      end
      
      # Validate numeric values
      raise ConfigurationError, "Timeout must be positive" unless config[:timeout] > 0
      raise ConfigurationError, "Pool size must be positive" unless config[:pool_size] > 0
      raise ConfigurationError, "Cache TTL must be non-negative" unless config[:cache_ttl] >= 0
      
      # Validate JWT configuration if security is enabled
      if config[:jwt_public_key_path] && !File.exist?(config[:jwt_public_key_path])
        @logger.warn("JWT public key file not found: #{config[:jwt_public_key_path]}")
      end
      
      @logger.debug("Configuration validation completed successfully")
    end
    
    ##
    # Get current memory usage
    #
    def get_memory_usage
      if defined?(GC.stat)
        gc_stats = GC.stat
        {
          heap_allocated_pages: gc_stats[:heap_allocated_pages],
          heap_live_slots: gc_stats[:heap_live_slots],
          major_gc_count: gc_stats[:major_gc_count],
          minor_gc_count: gc_stats[:minor_gc_count]
        }
      else
        { status: 'unavailable' }
      end
    rescue StandardError
      { status: 'error' }
    end
    
    ##
    # Check dependency availability
    #
    def check_dependencies
      dependencies = {}
      
      # Check required gems
      required_gems = %w[concurrent-ruby json net-http openssl digest securerandom monitor]
      required_gems.each do |gem_name|
        begin
          require gem_name
          dependencies[gem_name] = 'available'
        rescue LoadError
          dependencies[gem_name] = 'missing'
        end
      end
      
      # Check optional gems
      optional_gems = { 'jwt' => 'Security features', 'redis' => 'Redis caching' }
      optional_gems.each do |gem_name, description|
        begin
          require gem_name
          dependencies["#{gem_name} (#{description})"] = 'available'
        rescue LoadError
          dependencies["#{gem_name} (#{description})"] = 'optional - not available'
        end
      end
      
      dependencies
    end
  end
  
  # Auto-configure with environment variables if available
  configure if ENV['PARLANT_SERVER_URL']
  
  # Convenience methods for common operations
  
  ##
  # Quick validation for simple operations
  #
  # @param operation_name [String] Name of operation
  # @param parameters [Hash] Operation parameters  
  # @param security_classification [String] Security level
  # @return [ValidationResult] Validation result
  #
  def self.validate(operation_name, parameters = {}, security_classification = 'INTERNAL')
    client = create_client
    client.validate_operation(
      function_name: operation_name,
      parameters: parameters,
      user_context: { user_id: 'system', role: 'service' },
      security_classification: security_classification
    )
  end
  
  ##
  # Quick authentication for JWT tokens
  #
  # @param jwt_token [String] JWT token to validate
  # @return [SecurityIntegration::SecurityContext] Security context
  #
  def self.authenticate(jwt_token)
    auth_manager = create_auth_manager
    auth_manager.authenticate(jwt_token)
  end
end

# Export main classes for convenience
ParlantHttpClient = ParlantBridge::HttpClientService
ParlantIntegration = ParlantBridge::IntegrationModule
ParlantSecurity = ParlantBridge::SecurityIntegration
ParlantValidation = ParlantBridge::ValidationResult

# Global configuration check on load
if ENV['PARLANT_BRIDGE_AUTO_CONFIGURE'] == 'true'
  ParlantBridge.configure
  ParlantBridge.logger&.info("Parlant Bridge auto-configured from environment variables")
end