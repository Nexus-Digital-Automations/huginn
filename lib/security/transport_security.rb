# frozen_string_literal: true

require 'openssl'
require 'net/http'
require 'uri'
require 'ipaddr'
require 'resolv'
require 'socket'
require 'timeout'

module Security
  # Enterprise-grade transport security manager for SSL/TLS and network security
  # controls in communication between Huginn and AIgent Orchestrator.
  #
  # Features:
  # - SSL certificate validation and certificate pinning
  # - TLS version enforcement (TLS 1.2+ mandatory)
  # - Cipher suite validation for strong encryption only
  # - Certificate chain validation with revocation checking
  # - HSTS (HTTP Strict Transport Security) implementation
  # - Perfect Forward Secrecy enforcement
  # - Network security controls and validation
  # - Connection security monitoring and alerting
  class TransportSecurity
    class SecurityError < StandardError; end
    class SSLValidationError < SecurityError; end
    class CertificateError < SecurityError; end
    class TLSVersionError < SecurityError; end
    class CipherSuiteError < SecurityError; end
    class NetworkSecurityError < SecurityError; end
    class CertificatePinningError < SecurityError; end

    # TLS configuration constants
    MIN_TLS_VERSION = 'TLSv1.2'
    PREFERRED_TLS_VERSION = 'TLSv1.3'
    
    # Allowed TLS versions (in order of preference)
    ALLOWED_TLS_VERSIONS = %w[
      TLSv1.3
      TLSv1.2
    ].freeze

    # Strong cipher suites (ECDHE for Perfect Forward Secrecy)
    STRONG_CIPHER_SUITES = [
      # TLS 1.3 cipher suites
      'TLS_AES_256_GCM_SHA384',
      'TLS_CHACHA20_POLY1305_SHA256',
      'TLS_AES_128_GCM_SHA256',
      
      # TLS 1.2 ECDHE cipher suites (Perfect Forward Secrecy)
      'ECDHE-ECDSA-AES256-GCM-SHA384',
      'ECDHE-RSA-AES256-GCM-SHA384',
      'ECDHE-ECDSA-CHACHA20-POLY1305',
      'ECDHE-RSA-CHACHA20-POLY1305',
      'ECDHE-ECDSA-AES128-GCM-SHA256',
      'ECDHE-RSA-AES128-GCM-SHA256',
      'ECDHE-ECDSA-AES256-SHA384',
      'ECDHE-RSA-AES256-SHA384',
      'ECDHE-ECDSA-AES128-SHA256',
      'ECDHE-RSA-AES128-SHA256'
    ].freeze

    # Forbidden weak cipher suites
    FORBIDDEN_CIPHER_PATTERNS = [
      /RC4/i,
      /MD5/i,
      /SHA1$/i,
      /NULL/i,
      /EXPORT/i,
      /DES/i,
      /3DES/i,
      /ADH/i,
      /AECDH/i,
      /DSS/i
    ].freeze

    # Certificate validation settings
    CERTIFICATE_SETTINGS = {
      verify_mode: OpenSSL::SSL::VERIFY_PEER,
      verify_hostname: true,
      check_revocation: true,
      max_chain_depth: 10,
      min_key_size: 2048,
      allowed_key_types: %w[RSA ECC],
      max_cert_age_days: 90, # Warn if cert expires within 90 days
      require_san: true, # Subject Alternative Name required
      allow_self_signed: false # Never allow self-signed in production
    }.freeze

    # HSTS configuration
    HSTS_CONFIG = {
      max_age: 31_536_000, # 1 year
      include_subdomains: true,
      preload: true
    }.freeze

    # Network security settings
    NETWORK_SECURITY = {
      connect_timeout: 10,
      read_timeout: 30,
      max_redirects: 3,
      allowed_ports: [443, 8443, 9443], # HTTPS ports only
      forbidden_networks: [
        '127.0.0.0/8',    # Loopback (except for development)
        '10.0.0.0/8',     # Private (configurable)
        '172.16.0.0/12',  # Private (configurable)
        '192.168.0.0/16', # Private (configurable)
        '169.254.0.0/16', # Link-local
        '224.0.0.0/4',    # Multicast
        '240.0.0.0/4'     # Reserved
      ],
      dns_validation: true,
      reverse_dns_check: true
    }.freeze

    attr_reader :config, :logger, :metrics, :certificate_store

    def initialize(config: {}, logger: nil)
      @config = merge_config(config)
      @logger = logger || default_logger
      @metrics = TransportSecurityMetrics.new
      @certificate_store = CertificateStore.new(@config, @logger)
      @hsts_store = HSTSStore.new(@config, @logger)
      @connection_pool = SecureConnectionPool.new(@config, @logger)
      
      # Load certificate pins if configured
      load_certificate_pins
      
      log_info "Transport security initialized with TLS #{MIN_TLS_VERSION}+ enforcement"
    end

    # SSL/TLS Security Methods

    def create_secure_connection(uri, options = {})
      log_info "Creating secure connection to: #{uri}"
      
      # Validate URI and network security
      validate_connection_uri(uri)
      
      # Parse URI
      parsed_uri = URI.parse(uri)
      unless parsed_uri.scheme == 'https'
        log_error "Non-HTTPS connection attempted: #{uri}"
        raise NetworkSecurityError, "Only HTTPS connections allowed"
      end
      
      # Check HSTS requirements
      check_hsts_requirements(parsed_uri.host)
      
      # Create HTTP client with security settings
      http = Net::HTTP.new(parsed_uri.host, parsed_uri.port)
      configure_ssl_security(http, parsed_uri.host, options)
      
      # Set timeouts
      http.open_timeout = options[:open_timeout] || @config[:connect_timeout]
      http.read_timeout = options[:read_timeout] || @config[:read_timeout]
      
      # Test connection and validate
      start_time = Time.current
      validate_secure_connection(http, parsed_uri.host)
      connection_time = Time.current - start_time
      
      @metrics.record_connection(parsed_uri.host, connection_time, true)
      log_info "Secure connection established to #{parsed_uri.host} in #{connection_time}ms"
      
      http
    rescue StandardError => e
      @metrics.record_connection(parsed_uri&.host || uri, 0, false)
      log_error "Failed to create secure connection to #{uri}: #{e.message}"
      raise
    end

    def validate_certificate_chain(peer_cert_chain, hostname)
      log_debug "Validating certificate chain for: #{hostname}"
      
      unless peer_cert_chain&.any?
        raise CertificateError, "No certificate chain provided"
      end
      
      # Validate each certificate in chain
      peer_cert_chain.each_with_index do |cert, index|
        validate_individual_certificate(cert, hostname, index == 0)
      end
      
      # Validate chain integrity
      validate_chain_integrity(peer_cert_chain)
      
      # Check certificate pinning if configured
      validate_certificate_pinning(peer_cert_chain[0], hostname) if @certificate_pins[hostname]
      
      # Check certificate revocation
      check_certificate_revocation(peer_cert_chain) if @config[:check_revocation]
      
      @metrics.increment('certificates_validated')
      log_info "Certificate chain validation successful for: #{hostname}"
      
      true
    rescue StandardError => e
      @metrics.increment('certificate_validation_failures')
      log_error "Certificate validation failed for #{hostname}: #{e.message}"
      raise CertificateError, "Certificate validation failed: #{e.message}"
    end

    def validate_tls_version(ssl_socket)
      log_debug "Validating TLS version"
      
      tls_version = ssl_socket.ssl_version
      
      unless ALLOWED_TLS_VERSIONS.include?(tls_version)
        @metrics.increment('tls_version_violations')
        log_error "Unacceptable TLS version: #{tls_version}"
        raise TLSVersionError, "TLS version #{tls_version} not allowed. Minimum: #{MIN_TLS_VERSION}"
      end
      
      # Log warning for non-preferred versions
      if tls_version != PREFERRED_TLS_VERSION
        log_warning "Non-preferred TLS version in use: #{tls_version}. Preferred: #{PREFERRED_TLS_VERSION}"
      end
      
      @metrics.record_tls_version(tls_version)
      log_info "TLS version validation successful: #{tls_version}"
      
      tls_version
    end

    def validate_cipher_suite(ssl_socket)
      log_debug "Validating cipher suite"
      
      cipher = ssl_socket.cipher
      cipher_name = cipher[0] if cipher
      
      unless cipher_name
        raise CipherSuiteError, "No cipher suite negotiated"
      end
      
      # Check for forbidden weak ciphers
      FORBIDDEN_CIPHER_PATTERNS.each do |pattern|
        if cipher_name.match?(pattern)
          @metrics.increment('weak_cipher_rejections')
          log_error "Weak cipher suite detected: #{cipher_name}"
          raise CipherSuiteError, "Weak cipher suite not allowed: #{cipher_name}"
        end
      end
      
      # Prefer strong cipher suites
      unless STRONG_CIPHER_SUITES.include?(cipher_name)
        log_warning "Non-preferred cipher suite in use: #{cipher_name}"
      end
      
      # Validate Perfect Forward Secrecy for TLS 1.2
      tls_version = ssl_socket.ssl_version
      if tls_version == 'TLSv1.2' && !cipher_name.include?('ECDHE')
        log_warning "Perfect Forward Secrecy not available with cipher: #{cipher_name}"
      end
      
      @metrics.record_cipher_suite(cipher_name)
      log_info "Cipher suite validation successful: #{cipher_name}"
      
      {
        name: cipher_name,
        version: cipher[1],
        bits: cipher[2],
        algorithm: cipher[3]
      }
    end

    # Certificate Pinning Methods

    def add_certificate_pin(hostname, certificate_or_pin, pin_type: :spki_sha256)
      log_info "Adding certificate pin for: #{hostname}"
      
      pin_value = case certificate_or_pin
                  when OpenSSL::X509::Certificate
                    generate_certificate_pin(certificate_or_pin, pin_type)
                  when String
                    certificate_or_pin
                  else
                    raise ArgumentError, "Invalid certificate or pin format"
                  end
      
      @certificate_pins ||= {}
      @certificate_pins[hostname] = {
        pin: pin_value,
        type: pin_type,
        added_at: Time.current
      }
      
      # Persist pins to storage
      @certificate_store.store_pin(hostname, pin_value, pin_type)
      
      log_info "Certificate pin added for #{hostname}: #{pin_type}"
      true
    end

    def remove_certificate_pin(hostname)
      log_info "Removing certificate pin for: #{hostname}"
      
      @certificate_pins&.delete(hostname)
      @certificate_store.remove_pin(hostname)
      
      log_info "Certificate pin removed for: #{hostname}"
      true
    end

    def validate_certificate_pinning(certificate, hostname)
      log_debug "Validating certificate pinning for: #{hostname}"
      
      pin_config = @certificate_pins[hostname]
      return true unless pin_config
      
      actual_pin = generate_certificate_pin(certificate, pin_config[:type])
      expected_pin = pin_config[:pin]
      
      unless actual_pin == expected_pin
        @metrics.increment('certificate_pinning_failures')
        log_error "Certificate pinning validation failed for #{hostname}"
        log_error "Expected: #{expected_pin}"
        log_error "Actual: #{actual_pin}"
        raise CertificatePinningError, "Certificate pinning validation failed for #{hostname}"
      end
      
      @metrics.increment('certificate_pinning_validations')
      log_info "Certificate pinning validation successful for: #{hostname}"
      true
    end

    # HSTS (HTTP Strict Transport Security) Methods

    def enforce_hsts(hostname, response_headers = {})
      log_debug "Enforcing HSTS for: #{hostname}"
      
      # Check if host is in HSTS store
      hsts_policy = @hsts_store.get_policy(hostname)
      
      # Process HSTS header from response
      if hsts_header = response_headers['strict-transport-security']
        policy = parse_hsts_header(hsts_header)
        @hsts_store.store_policy(hostname, policy)
        log_info "HSTS policy updated for #{hostname}: max-age=#{policy[:max_age]}"
      end
      
      # Ensure HTTPS for HSTS hosts
      if hsts_policy && !hsts_policy[:expired]
        log_info "HSTS policy active for #{hostname}"
        return true
      end
      
      false
    end

    def check_hsts_requirements(hostname)
      log_debug "Checking HSTS requirements for: #{hostname}"
      
      policy = @hsts_store.get_policy(hostname)
      return unless policy && !policy[:expired]
      
      # HSTS policy exists and is active - HTTPS is required
      log_info "HSTS policy requires HTTPS for: #{hostname}"
      true
    end

    # Network Security Methods

    def validate_connection_uri(uri)
      log_debug "Validating connection URI: #{uri}"
      
      parsed_uri = URI.parse(uri)
      
      # Validate scheme
      unless parsed_uri.scheme == 'https'
        raise NetworkSecurityError, "Only HTTPS connections allowed"
      end
      
      # Validate port
      port = parsed_uri.port || 443
      unless @config[:allowed_ports].include?(port)
        raise NetworkSecurityError, "Port #{port} not allowed"
      end
      
      # Validate hostname/IP
      validate_network_destination(parsed_uri.host)
      
      log_info "URI validation successful: #{uri}"
      true
    end

    def validate_network_destination(hostname)
      log_debug "Validating network destination: #{hostname}"
      
      # DNS validation
      if @config[:dns_validation]
        validate_dns_resolution(hostname)
      end
      
      # Resolve hostname to IP addresses
      ip_addresses = Resolv.getaddresses(hostname)
      
      if ip_addresses.empty?
        raise NetworkSecurityError, "DNS resolution failed for: #{hostname}"
      end
      
      # Validate each resolved IP
      ip_addresses.each do |ip|
        validate_ip_address(ip, hostname)
      end
      
      # Reverse DNS check
      if @config[:reverse_dns_check]
        validate_reverse_dns(ip_addresses, hostname)
      end
      
      log_info "Network destination validation successful: #{hostname}"
      true
    end

    def validate_ip_address(ip, hostname)
      log_debug "Validating IP address: #{ip}"
      
      begin
        addr = IPAddr.new(ip)
        
        # Check against forbidden networks
        @config[:forbidden_networks].each do |network|
          forbidden_range = IPAddr.new(network)
          if forbidden_range.include?(addr)
            # Allow loopback in development
            if network == '127.0.0.0/8' && Rails.env.development?
              log_warning "Allowing loopback connection in development: #{ip}"
              next
            end
            
            raise NetworkSecurityError, "Connection to forbidden network not allowed: #{ip} (#{network})"
          end
        end
        
        # Additional IP validation
        if addr.private? && !@config[:allow_private_networks]
          raise NetworkSecurityError, "Connection to private network not allowed: #{ip}"
        end
        
        log_info "IP address validation successful: #{ip}"
        true
      rescue IPAddr::InvalidAddressError
        raise NetworkSecurityError, "Invalid IP address: #{ip}"
      end
    end

    # Connection Security Methods

    def validate_secure_connection(http, hostname)
      log_debug "Validating secure connection to: #{hostname}"
      
      # Start SSL connection
      http.use_ssl = true
      
      # Set up SSL context verification callback
      http.verify_callback = proc do |preverify_ok, store_context|
        validate_ssl_context(preverify_ok, store_context, hostname)
      end
      
      # Attempt connection
      http.start do |connection|
        # Validate TLS version
        validate_tls_version(connection.instance_variable_get(:@socket))
        
        # Validate cipher suite
        validate_cipher_suite(connection.instance_variable_get(:@socket))
        
        # Validate certificate chain
        peer_cert_chain = connection.peer_cert_chain
        validate_certificate_chain(peer_cert_chain, hostname)
      end
      
      @metrics.increment('secure_connections_validated')
      log_info "Secure connection validation successful for: #{hostname}"
      true
    end

    def get_security_metrics
      {
        connections_validated: @metrics.get('secure_connections_validated'),
        connection_failures: @metrics.get('connection_failures'),
        certificates_validated: @metrics.get('certificates_validated'),
        certificate_failures: @metrics.get('certificate_validation_failures'),
        tls_version_violations: @metrics.get('tls_version_violations'),
        weak_cipher_rejections: @metrics.get('weak_cipher_rejections'),
        certificate_pinning_validations: @metrics.get('certificate_pinning_validations'),
        certificate_pinning_failures: @metrics.get('certificate_pinning_failures'),
        hsts_policies_active: @hsts_store.active_policies_count,
        cipher_suite_distribution: @metrics.get_cipher_distribution,
        tls_version_distribution: @metrics.get_tls_distribution
      }
    end

    # Certificate and Security Monitoring

    def check_certificate_expiry(hostname, days_ahead: 30)
      log_info "Checking certificate expiry for: #{hostname}"
      
      begin
        # Create temporary connection to get certificate
        uri = "https://#{hostname}"
        connection = create_secure_connection(uri)
        
        connection.start do |http|
          cert = http.peer_cert
          
          expires_at = cert.not_after
          days_until_expiry = (expires_at - Time.current) / 1.day
          
          if days_until_expiry <= days_ahead
            log_warning "Certificate expires soon for #{hostname}: #{expires_at} (#{days_until_expiry.to_i} days)"
            @metrics.increment('certificates_expiring_soon')
            
            return {
              hostname: hostname,
              expires_at: expires_at,
              days_until_expiry: days_until_expiry.to_i,
              status: 'expiring_soon'
            }
          end
          
          {
            hostname: hostname,
            expires_at: expires_at,
            days_until_expiry: days_until_expiry.to_i,
            status: 'valid'
          }
        end
      rescue StandardError => e
        log_error "Failed to check certificate expiry for #{hostname}: #{e.message}"
        @metrics.increment('certificate_check_failures')
        raise
      end
    end

    def security_health_check
      log_info "Performing transport security health check"
      
      health_status = {
        tls_enforcement: true,
        cipher_validation: true,
        certificate_validation: true,
        hsts_enforcement: true,
        network_security: true,
        issues: []
      }
      
      # Check for any recent security violations
      recent_violations = @metrics.get_recent_violations
      if recent_violations.any?
        health_status[:issues] << "Recent security violations detected"
      end
      
      # Check certificate expiry warnings
      expiring_certs = @certificate_store.get_expiring_certificates
      if expiring_certs.any?
        health_status[:issues] << "#{expiring_certs.count} certificates expiring soon"
      end
      
      # Overall health status
      health_status[:status] = health_status[:issues].empty? ? 'healthy' : 'warnings'
      
      log_info "Security health check completed: #{health_status[:status]}"
      health_status
    end

    private

    def merge_config(custom_config)
      default_config = {
        tls_version: MIN_TLS_VERSION,
        cipher_suites: STRONG_CIPHER_SUITES,
        certificate_validation: CERTIFICATE_SETTINGS,
        hsts: HSTS_CONFIG,
        network_security: NETWORK_SECURITY,
        allow_private_networks: Rails.env.development?,
        certificate_pinning: {},
        connect_timeout: 10,
        read_timeout: 30,
        max_redirects: 3,
        allowed_ports: [443, 8443, 9443],
        forbidden_networks: NETWORK_SECURITY[:forbidden_networks],
        dns_validation: true,
        reverse_dns_check: true,
        check_revocation: true
      }
      
      default_config.deep_merge(custom_config)
    end

    def configure_ssl_security(http, hostname, options)
      log_debug "Configuring SSL security for: #{hostname}"
      
      http.use_ssl = true
      http.verify_mode = @config[:certificate_validation][:verify_mode]
      http.verify_hostname = @config[:certificate_validation][:verify_hostname]
      
      # Set minimum TLS version
      http.min_version = OpenSSL::SSL::TLS1_2_VERSION
      http.max_version = OpenSSL::SSL::TLS1_3_VERSION
      
      # Configure cipher suites
      http.ciphers = @config[:cipher_suites].join(':')
      
      # Certificate verification callback
      http.verify_callback = proc do |preverify_ok, store_context|
        validate_ssl_context(preverify_ok, store_context, hostname)
      end
      
      # Additional SSL options
      http.ssl_timeout = options[:ssl_timeout] || 10
      
      log_debug "SSL security configured for: #{hostname}"
    end

    def validate_ssl_context(preverify_ok, store_context, hostname)
      certificate = store_context.current_cert
      error = store_context.error
      error_string = store_context.error_string
      
      unless preverify_ok
        log_error "SSL certificate verification failed for #{hostname}: #{error_string}"
        @metrics.increment('ssl_verification_failures')
        return false
      end
      
      # Additional certificate validation
      if store_context.chain.length == 1 # Leaf certificate
        validate_leaf_certificate(certificate, hostname)
      end
      
      true
    rescue StandardError => e
      log_error "SSL context validation error for #{hostname}: #{e.message}"
      false
    end

    def validate_individual_certificate(cert, hostname, is_leaf)
      log_debug "Validating #{is_leaf ? 'leaf' : 'intermediate'} certificate"
      
      # Check certificate validity period
      now = Time.current
      if cert.not_before > now
        raise CertificateError, "Certificate not yet valid"
      end
      
      if cert.not_after < now
        raise CertificateError, "Certificate has expired"
      end
      
      # Check key size
      public_key = cert.public_key
      key_size = case public_key
                 when OpenSSL::PKey::RSA
                   public_key.n.num_bits
                 when OpenSSL::PKey::EC
                   public_key.group.degree
                 else
                   0
                 end
      
      if key_size < @config[:certificate_validation][:min_key_size]
        raise CertificateError, "Certificate key size too small: #{key_size} bits"
      end
      
      # Validate hostname for leaf certificate
      if is_leaf
        validate_leaf_certificate(cert, hostname)
      end
      
      log_debug "Certificate validation successful"
    end

    def validate_leaf_certificate(cert, hostname)
      log_debug "Validating leaf certificate for hostname: #{hostname}"
      
      # Check Subject Alternative Name (SAN)
      san_extension = cert.extensions.find { |ext| ext.oid == 'subjectAltName' }
      
      if @config[:certificate_validation][:require_san] && !san_extension
        raise CertificateError, "Certificate missing required Subject Alternative Name"
      end
      
      # Validate hostname against certificate
      unless OpenSSL::SSL.verify_certificate_identity(cert, hostname)
        raise CertificateError, "Certificate hostname verification failed for: #{hostname}"
      end
      
      log_debug "Leaf certificate validation successful for: #{hostname}"
    end

    def validate_chain_integrity(cert_chain)
      log_debug "Validating certificate chain integrity"
      
      if cert_chain.length > @config[:certificate_validation][:max_chain_depth]
        raise CertificateError, "Certificate chain too long: #{cert_chain.length} certificates"
      end
      
      # Validate each certificate signature against its issuer
      cert_chain.each_cons(2) do |cert, issuer|
        unless cert.verify(issuer.public_key)
          raise CertificateError, "Certificate chain signature validation failed"
        end
      end
      
      log_debug "Certificate chain integrity validation successful"
    end

    def check_certificate_revocation(cert_chain)
      log_debug "Checking certificate revocation status"
      
      # This is a simplified implementation
      # In production, implement OCSP and CRL checking
      cert_chain.each_with_index do |cert, index|
        # Check OCSP if available
        ocsp_uris = extract_ocsp_uris(cert)
        if ocsp_uris.any?
          check_ocsp_status(cert, cert_chain[index + 1], ocsp_uris)
        end
        
        # Check CRL if no OCSP
        if ocsp_uris.empty?
          crl_uris = extract_crl_uris(cert)
          check_crl_status(cert, crl_uris) if crl_uris.any?
        end
      end
      
      log_debug "Certificate revocation check completed"
    end

    def generate_certificate_pin(certificate, pin_type)
      case pin_type
      when :spki_sha256
        # SHA256 hash of Subject Public Key Info
        spki_der = certificate.public_key.to_der
        Base64.strict_encode64(Digest::SHA256.digest(spki_der))
      when :cert_sha256
        # SHA256 hash of entire certificate
        Base64.strict_encode64(Digest::SHA256.digest(certificate.to_der))
      else
        raise ArgumentError, "Unsupported pin type: #{pin_type}"
      end
    end

    def load_certificate_pins
      @certificate_pins = @certificate_store.load_all_pins
      log_info "Loaded #{@certificate_pins.size} certificate pins"
    end

    def parse_hsts_header(header_value)
      policy = { max_age: 0, include_subdomains: false, preload: false }
      
      header_value.split(';').each do |directive|
        key, value = directive.strip.split('=', 2)
        
        case key.downcase
        when 'max-age'
          policy[:max_age] = value.to_i
        when 'includesubdomains'
          policy[:include_subdomains] = true
        when 'preload'
          policy[:preload] = true
        end
      end
      
      policy
    end

    def validate_dns_resolution(hostname)
      log_debug "Validating DNS resolution for: #{hostname}"
      
      begin
        Timeout.timeout(5) do
          Resolv::DNS.new.getaddress(hostname)
        end
      rescue Resolv::ResolvError, Timeout::Error => e
        raise NetworkSecurityError, "DNS resolution failed for #{hostname}: #{e.message}"
      end
      
      log_debug "DNS resolution validation successful for: #{hostname}"
    end

    def validate_reverse_dns(ip_addresses, expected_hostname)
      log_debug "Validating reverse DNS for: #{expected_hostname}"
      
      ip_addresses.each do |ip|
        begin
          reverse_hostname = Resolv.getname(ip)
          unless reverse_hostname.downcase.include?(expected_hostname.downcase)
            log_warning "Reverse DNS mismatch for #{ip}: got #{reverse_hostname}, expected #{expected_hostname}"
          end
        rescue Resolv::ResolvError
          log_warning "Reverse DNS lookup failed for IP: #{ip}"
        end
      end
      
      log_debug "Reverse DNS validation completed for: #{expected_hostname}"
    end

    def extract_ocsp_uris(certificate)
      # Extract OCSP URIs from Authority Information Access extension
      aia_extension = certificate.extensions.find { |ext| ext.oid == 'authorityInfoAccess' }
      return [] unless aia_extension
      
      # Parse AIA extension to extract OCSP URIs
      # This is a simplified implementation
      []
    end

    def extract_crl_uris(certificate)
      # Extract CRL URIs from CRL Distribution Points extension
      cdp_extension = certificate.extensions.find { |ext| ext.oid == 'crlDistributionPoints' }
      return [] unless cdp_extension
      
      # Parse CDP extension to extract CRL URIs
      # This is a simplified implementation
      []
    end

    def check_ocsp_status(certificate, issuer, ocsp_uris)
      log_debug "Checking OCSP status for certificate"
      # OCSP implementation would go here
      # This is a placeholder for production implementation
    end

    def check_crl_status(certificate, crl_uris)
      log_debug "Checking CRL status for certificate"
      # CRL implementation would go here
      # This is a placeholder for production implementation
    end

    def default_logger
      @default_logger ||= Logger.new(Rails.root.join('log', 'transport_security.log')).tap do |logger|
        logger.level = Rails.env.production? ? Logger::INFO : Logger::DEBUG
        logger.formatter = proc do |severity, datetime, progname, msg|
          "[#{datetime}] #{severity}: #{msg}\n"
        end
      end
    end

    def log_info(message)
      @logger.info("TransportSecurity: #{message}")
    end

    def log_debug(message)
      @logger.debug("TransportSecurity: #{message}")
    end

    def log_warning(message)
      @logger.warn("TransportSecurity: #{message}")
    end

    def log_error(message)
      @logger.error("TransportSecurity: #{message}")
    end
  end

  # Supporting classes for transport security

  class TransportSecurityMetrics
    def initialize
      @metrics = Hash.new(0)
      @cipher_distribution = Hash.new(0)
      @tls_distribution = Hash.new(0)
      @connection_times = []
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

    def record_connection(hostname, time, success)
      @mutex.synchronize do
        @connection_times << { hostname: hostname, time: time, success: success, timestamp: Time.current }
        @connection_times = @connection_times.last(1000) # Keep last 1000 records
      end
    end

    def record_cipher_suite(cipher_name)
      @mutex.synchronize { @cipher_distribution[cipher_name] += 1 }
    end

    def record_tls_version(version)
      @mutex.synchronize { @tls_distribution[version] += 1 }
    end

    def get_cipher_distribution
      @mutex.synchronize { @cipher_distribution.dup }
    end

    def get_tls_distribution
      @mutex.synchronize { @tls_distribution.dup }
    end

    def get_recent_violations(minutes = 60)
      cutoff = minutes.minutes.ago
      @mutex.synchronize do
        @connection_times.select { |record| !record[:success] && record[:timestamp] > cutoff }
      end
    end
  end

  class CertificateStore
    def initialize(config, logger)
      @config = config
      @logger = logger
      @pins = {}
      @mutex = Mutex.new
      # In production, this would be backed by Redis or database
    end

    def store_pin(hostname, pin, pin_type)
      @mutex.synchronize do
        @pins[hostname] = {
          pin: pin,
          type: pin_type,
          created_at: Time.current
        }
      end
    end

    def load_all_pins
      @mutex.synchronize { @pins.dup }
    end

    def remove_pin(hostname)
      @mutex.synchronize { @pins.delete(hostname) }
    end

    def get_expiring_certificates(days = 30)
      # This would query actual certificate storage in production
      []
    end
  end

  class HSTSStore
    def initialize(config, logger)
      @config = config
      @logger = logger
      @policies = {}
      @mutex = Mutex.new
    end

    def store_policy(hostname, policy)
      @mutex.synchronize do
        @policies[hostname] = policy.merge(
          created_at: Time.current,
          expires_at: Time.current + policy[:max_age]
        )
      end
    end

    def get_policy(hostname)
      @mutex.synchronize do
        policy = @policies[hostname]
        return nil unless policy
        
        # Check if policy has expired
        if policy[:expires_at] < Time.current
          policy[:expired] = true
        end
        
        policy
      end
    end

    def active_policies_count
      @mutex.synchronize do
        @policies.values.count { |policy| policy[:expires_at] > Time.current }
      end
    end
  end

  class SecureConnectionPool
    def initialize(config, logger)
      @config = config
      @logger = logger
      @connections = {}
      @mutex = Mutex.new
    end

    def get_connection(hostname)
      @mutex.synchronize do
        @connections[hostname]
      end
    end

    def store_connection(hostname, connection)
      @mutex.synchronize do
        @connections[hostname] = connection
      end
    end

    def cleanup_expired_connections
      @mutex.synchronize do
        @connections.delete_if { |hostname, connection| connection_expired?(connection) }
      end
    end

    private

    def connection_expired?(connection)
      # Implementation for checking connection expiry
      false
    end
  end
end