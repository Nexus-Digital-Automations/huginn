# frozen_string_literal: true

require 'uri'
require 'ipaddr'
require 'resolv'

module Security
  # AIgent Input Validator - Comprehensive input validation and sanitization
  # for the AIgent Trigger Agent to prevent injection attacks and ensure data integrity.
  #
  # This validator provides enterprise-grade input validation with:
  # - URL validation with injection prevention and scheme validation
  # - Target agent validation with command injection prevention
  # - Goal template validation with Liquid template security
  # - Configuration field validation with type, range, and format checks
  # - Security logging and monitoring integration
  #
  # @example Basic Usage
  #   validator = Security::AigentInputValidator.new
  #   result = validator.validate_orchestrator_url('http://localhost:8080')
  #   if result[:valid]
  #     # URL is safe to use
  #   else
  #     # Handle validation errors: result[:errors]
  #   end
  #
  # @example Configuration Validation
  #   config = {
  #     orchestrator_url: 'https://aigent.example.com',
  #     target_agent: 'browser_automation_agent',
  #     goal: 'Process file: {{ file_path }}',
  #     timeout_seconds: 300
  #   }
  #   result = validator.validate_full_configuration(config)
  #
  # @author AI Security Framework
  # @since 1.0.0
  class AigentInputValidator
    # Maximum allowed length for various input fields
    MAX_URL_LENGTH = 2048
    MAX_AGENT_NAME_LENGTH = 100
    MAX_GOAL_LENGTH = 10_000
    MAX_CONTEXT_DATA_SIZE = 1_000_000 # 1MB JSON limit
    MAX_TAG_LENGTH = 50
    MAX_TAGS_COUNT = 20
    MAX_HEADER_KEY_LENGTH = 128
    MAX_HEADER_VALUE_LENGTH = 8192
    
    # Timeout and retry limits
    MIN_TIMEOUT_SECONDS = 30
    MAX_TIMEOUT_SECONDS = 3600
    MIN_RETRY_ATTEMPTS = 0
    MAX_RETRY_ATTEMPTS = 10
    
    # Allowed URL schemes for orchestrator connections
    ALLOWED_URL_SCHEMES = %w[http https].freeze
    
    # Blocked IP ranges for security (prevent SSRF attacks)
    BLOCKED_IP_RANGES = [
      IPAddr.new('127.0.0.0/8'),     # Loopback (except localhost whitelist)
      IPAddr.new('10.0.0.0/8'),      # Private networks
      IPAddr.new('172.16.0.0/12'),   # Private networks
      IPAddr.new('192.168.0.0/16'),  # Private networks  
      IPAddr.new('169.254.0.0/16'),  # Link-local
      IPAddr.new('224.0.0.0/4'),     # Multicast
      IPAddr.new('::1/128'),         # IPv6 loopback
      IPAddr.new('fc00::/7'),        # IPv6 unique local
      IPAddr.new('fe80::/10')        # IPv6 link-local
    ].freeze
    
    # Whitelisted localhost addresses for development
    LOCALHOST_WHITELIST = %w[
      127.0.0.1
      localhost
      ::1
    ].freeze
    
    # Dangerous patterns in goal templates that could indicate injection attempts
    DANGEROUS_GOAL_PATTERNS = [
      /system\s*\(/i,
      /exec\s*\(/i,
      /eval\s*\(/i,
      /`[^`]*`/,                    # Backtick command execution
      /\$\([^)]*\)/,                # Command substitution
      /\|\s*(rm|del|format)/i,      # Pipe to dangerous commands
      /;\s*(rm|del|format)/i,       # Command chaining
      /&&\s*(rm|del|format)/i,      # Command chaining
      /__FILE__|__LINE__|__DIR__/i, # Ruby file system access
      /File\.|Dir\.|IO\./i,         # Ruby file operations
      /require\s*\(|load\s*\(/i,    # Ruby dynamic loading
      /<script[^>]*>/i,             # XSS prevention
      /javascript:/i,               # JavaScript URLs
      /vbscript:/i,                 # VBScript URLs
      /data:.*base64/i              # Base64 data URLs
    ].freeze
    
    # Pattern for valid agent naming conventions
    VALID_AGENT_NAME_PATTERN = /\A[a-z0-9_]+\z/.freeze
    
    # Valid priority levels
    VALID_PRIORITIES = %w[low normal high urgent critical].freeze
    
    # Valid execution modes  
    VALID_EXECUTION_MODES = %w[synchronous asynchronous background].freeze
    
    # Valid trigger conditions
    VALID_TRIGGER_CONDITIONS = %w[
      on_event
      on_schedule  
      on_condition_met
      on_threshold_exceeded
      on_pattern_match
      on_anomaly_detected
    ].freeze
    
    attr_reader :logger, :security_config
    
    # Initialize the AIgent Input Validator
    #
    # @param logger [Logger] Logger instance for security events (optional)
    # @param security_config [Hash] Security configuration options (optional)
    # @option security_config [Boolean] :strict_mode Enable strict validation mode
    # @option security_config [Array<String>] :allowed_hosts Whitelist of allowed orchestrator hosts
    # @option security_config [Boolean] :allow_private_networks Allow private network connections
    # @option security_config [Integer] :max_validation_time Maximum time for validation operations
    def initialize(logger: nil, security_config: {})
      @logger = logger || create_default_logger
      @security_config = {
        strict_mode: true,
        allowed_hosts: [],
        allow_private_networks: false,
        max_validation_time: 10,
        log_validation_attempts: true,
        fail_on_dns_errors: true
      }.merge(security_config)
      
      log_security_event(:info, 'AIgent Input Validator initialized', {
        strict_mode: @security_config[:strict_mode],
        allowed_hosts_count: @security_config[:allowed_hosts].length
      })
    end
    
    # Validate orchestrator URL for security and accessibility
    #
    # Performs comprehensive validation including:
    # - URL format and scheme validation
    # - Host resolution and IP address validation
    # - SSRF attack prevention
    # - Network accessibility testing (optional)
    #
    # @param url [String] The orchestrator URL to validate
    # @param options [Hash] Validation options
    # @option options [Boolean] :check_accessibility Test network connectivity
    # @option options [Integer] :timeout Connection timeout in seconds
    # @return [Hash] Validation result with :valid, :errors, :warnings keys
    def validate_orchestrator_url(url, options = {})
      start_time = Time.current
      result = { valid: false, errors: [], warnings: [] }
      
      begin
        # Basic input validation
        return add_error(result, 'URL cannot be nil or empty') if url.nil? || url.strip.empty?
        return add_error(result, "URL too long (max #{MAX_URL_LENGTH} characters)") if url.length > MAX_URL_LENGTH
        
        # Parse and validate URL structure
        uri = validate_url_structure(url, result)
        return result unless uri
        
        # Validate URL scheme
        unless ALLOWED_URL_SCHEMES.include?(uri.scheme&.downcase)
          return add_error(result, "Invalid URL scheme: #{uri.scheme}. Allowed: #{ALLOWED_URL_SCHEMES.join(', ')}")
        end
        
        # Validate host component
        return result unless validate_host_component(uri, result)
        
        # Perform DNS resolution and IP validation
        return result unless validate_dns_and_ip(uri, result)
        
        # Optional accessibility check
        if options[:check_accessibility]
          validate_url_accessibility(uri, result, options)
        end
        
        # Success
        result[:valid] = true
        result[:normalized_url] = uri.to_s
        
        log_security_event(:info, 'URL validation successful', {
          url: url,
          normalized_url: uri.to_s,
          validation_time_ms: ((Time.current - start_time) * 1000).round(2)
        })
        
      rescue => e
        add_error(result, "URL validation failed: #{e.message}")
        log_security_event(:error, 'URL validation exception', {
          url: url,
          error: e.message,
          backtrace: e.backtrace&.first(3)
        })
      end
      
      result
    end
    
    # Validate target agent identifier
    #
    # Prevents command injection by ensuring agent names follow safe patterns
    # and don't contain dangerous characters or sequences.
    #
    # @param agent_name [String] The target agent identifier
    # @return [Hash] Validation result with :valid, :errors, :warnings keys
    def validate_target_agent(agent_name)
      result = { valid: false, errors: [], warnings: [] }
      
      # Basic validation
      return add_error(result, 'Target agent cannot be nil or empty') if agent_name.nil? || agent_name.strip.empty?
      
      agent_name = agent_name.to_s.strip
      
      # Length validation
      if agent_name.length > MAX_AGENT_NAME_LENGTH
        return add_error(result, "Agent name too long (max #{MAX_AGENT_NAME_LENGTH} characters)")
      end
      
      # Pattern validation - only allow safe characters
      unless agent_name.match?(VALID_AGENT_NAME_PATTERN)
        return add_error(result, 'Agent name must contain only lowercase letters, numbers, and underscores')
      end
      
      # Check for reserved names that might cause conflicts
      reserved_names = %w[system admin root config agent huginn orchestrator api]
      if reserved_names.include?(agent_name.downcase)
        add_warning(result, "Agent name '#{agent_name}' is reserved and may cause conflicts")
      end
      
      # Success
      result[:valid] = true
      result[:sanitized_agent_name] = agent_name
      
      log_security_event(:debug, 'Target agent validation successful', {
        agent_name: agent_name
      })
      
      result
    end
    
    # Validate and sanitize goal template
    #
    # Provides comprehensive security validation for Liquid templates including:
    # - Dangerous function detection
    # - Template complexity limits
    # - Input sanitization for template variables
    # - Safe template parsing validation
    #
    # @param goal_template [String] The Liquid goal template
    # @return [Hash] Validation result with :valid, :errors, :warnings, :sanitized_template keys
    def validate_goal_template(goal_template)
      result = { valid: false, errors: [], warnings: [] }
      
      # Basic validation
      return add_error(result, 'Goal template cannot be nil or empty') if goal_template.nil? || goal_template.strip.empty?
      
      goal_template = goal_template.to_s.strip
      
      # Length validation
      if goal_template.length > MAX_GOAL_LENGTH
        return add_error(result, "Goal template too long (max #{MAX_GOAL_LENGTH} characters)")
      end
      
      # Dangerous pattern detection
      DANGEROUS_GOAL_PATTERNS.each do |pattern|
        if goal_template.match?(pattern)
          return add_error(result, "Goal template contains potentially dangerous pattern: #{pattern.inspect}")
        end
      end
      
      # Liquid template syntax validation
      begin
        require 'liquid'
        template = Liquid::Template.parse(goal_template)
        
        # Check for excessive complexity (prevent DoS)
        node_count = count_template_nodes(template.root)
        if node_count > 1000
          return add_error(result, "Template too complex (#{node_count} nodes, max 1000)")
        end
        
      rescue Liquid::SyntaxError => e
        return add_error(result, "Invalid Liquid template syntax: #{e.message}")
      rescue => e
        return add_error(result, "Template parsing error: #{e.message}")
      end
      
      # Template variable validation
      validate_template_variables(goal_template, result)
      
      # Sanitize and prepare result
      result[:valid] = true
      result[:sanitized_template] = sanitize_template_content(goal_template)
      
      log_security_event(:debug, 'Goal template validation successful', {
        template_length: goal_template.length,
        node_count: node_count
      })
      
      result
    end
    
    # Validate configuration field with type, range, and format validation
    #
    # @param field_name [String] Name of the configuration field
    # @param value [Object] Value to validate
    # @param field_type [Symbol] Expected field type (:string, :integer, :boolean, :array, :hash)
    # @param constraints [Hash] Additional validation constraints
    # @return [Hash] Validation result
    def validate_configuration_field(field_name, value, field_type, constraints = {})
      result = { valid: false, errors: [], warnings: [] }
      
      # Handle nil/empty values
      if value.nil? || (value.respond_to?(:empty?) && value.empty?)
        if constraints[:required]
          return add_error(result, "#{field_name} is required")
        else
          result[:valid] = true
          return result
        end
      end
      
      # Type validation
      case field_type
      when :string
        validate_string_field(field_name, value, constraints, result)
      when :integer
        validate_integer_field(field_name, value, constraints, result)
      when :boolean
        validate_boolean_field(field_name, value, constraints, result)
      when :array
        validate_array_field(field_name, value, constraints, result)
      when :hash
        validate_hash_field(field_name, value, constraints, result)
      else
        return add_error(result, "Unsupported field type: #{field_type}")
      end
      
      result
    end
    
    # Validate complete AIgent configuration
    #
    # Performs comprehensive validation of all configuration fields with
    # security checks, type validation, and business logic validation.
    #
    # @param config [Hash] Complete configuration hash
    # @return [Hash] Validation result with detailed field-by-field results
    def validate_full_configuration(config)
      start_time = Time.current
      result = { 
        valid: false, 
        errors: [], 
        warnings: [], 
        field_results: {},
        sanitized_config: {}
      }
      
      return add_error(result, 'Configuration must be a hash') unless config.is_a?(Hash)
      
      # Validate required fields
      required_fields = %w[orchestrator_url target_agent goal]
      required_fields.each do |field|
        unless config.key?(field) || config.key?(field.to_sym)
          add_error(result, "Required field missing: #{field}")
        end
      end
      
      return result unless result[:errors].empty?
      
      # Validate orchestrator URL
      if config['orchestrator_url'] || config[:orchestrator_url]
        url = config['orchestrator_url'] || config[:orchestrator_url]
        url_result = validate_orchestrator_url(url)
        result[:field_results][:orchestrator_url] = url_result
        
        unless url_result[:valid]
          result[:errors].concat(url_result[:errors].map { |e| "orchestrator_url: #{e}" })
        else
          result[:sanitized_config][:orchestrator_url] = url_result[:normalized_url]
        end
      end
      
      # Validate target agent
      if config['target_agent'] || config[:target_agent]
        agent = config['target_agent'] || config[:target_agent]
        agent_result = validate_target_agent(agent)
        result[:field_results][:target_agent] = agent_result
        
        unless agent_result[:valid]
          result[:errors].concat(agent_result[:errors].map { |e| "target_agent: #{e}" })
        else
          result[:sanitized_config][:target_agent] = agent_result[:sanitized_agent_name]
        end
      end
      
      # Validate goal template
      if config['goal'] || config[:goal]
        goal = config['goal'] || config[:goal]
        goal_result = validate_goal_template(goal)
        result[:field_results][:goal] = goal_result
        
        unless goal_result[:valid]
          result[:errors].concat(goal_result[:errors].map { |e| "goal: #{e}" })
        else
          result[:sanitized_config][:goal] = goal_result[:sanitized_template]
        end
      end
      
      # Validate optional fields
      validate_optional_configuration_fields(config, result)
      
      # Overall validation result
      result[:valid] = result[:errors].empty?
      
      log_security_event(:info, 'Full configuration validation completed', {
        valid: result[:valid],
        error_count: result[:errors].length,
        warning_count: result[:warnings].length,
        validation_time_ms: ((Time.current - start_time) * 1000).round(2)
      })
      
      result
    end
    
    # Generate security validation report
    #
    # @param config [Hash] Configuration to analyze
    # @return [Hash] Detailed security report
    def generate_security_report(config)
      report = {
        timestamp: Time.current.iso8601,
        overall_security_score: 0,
        risk_level: 'unknown',
        vulnerabilities: [],
        recommendations: [],
        compliance_checks: {}
      }
      
      # Validate configuration
      validation_result = validate_full_configuration(config)
      
      # Calculate security score
      score = calculate_security_score(config, validation_result)
      report[:overall_security_score] = score
      report[:risk_level] = determine_risk_level(score)
      
      # Identify vulnerabilities
      identify_vulnerabilities(config, validation_result, report)
      
      # Generate recommendations
      generate_security_recommendations(config, validation_result, report)
      
      # Compliance checks
      perform_compliance_checks(config, report)
      
      log_security_event(:info, 'Security report generated', {
        security_score: score,
        risk_level: report[:risk_level],
        vulnerability_count: report[:vulnerabilities].length
      })
      
      report
    end
    
    private
    
    # Validate URL structure and parse
    def validate_url_structure(url, result)
      begin
        uri = URI.parse(url.strip)
        
        # Validate required components
        if uri.scheme.nil? || uri.scheme.empty?
          add_error(result, 'URL must include a scheme (http or https)')
          return nil
        end
        
        if uri.host.nil? || uri.host.empty?
          add_error(result, 'URL must include a valid host')
          return nil
        end
        
        # Validate port range
        if uri.port && (uri.port < 1 || uri.port > 65535)
          add_error(result, "Invalid port number: #{uri.port}")
          return nil
        end
        
        uri
      rescue URI::InvalidURIError => e
        add_error(result, "Invalid URL format: #{e.message}")
        nil
      end
    end
    
    # Validate host component for security
    def validate_host_component(uri, result)
      host = uri.host.downcase
      
      # Check for malicious host patterns
      if host.include?('..') || host.include?('//') || host.match?(/[<>"'&]/)
        add_error(result, 'Host contains invalid or potentially malicious characters')
        return false
      end
      
      # Validate against allowed hosts if configured
      if @security_config[:allowed_hosts].any?
        unless @security_config[:allowed_hosts].include?(host)
          add_error(result, "Host not in allowed list: #{host}")
          return false
        end
      end
      
      true
    end
    
    # Validate DNS resolution and IP addresses
    def validate_dns_and_ip(uri, result)
      host = uri.host
      
      begin
        # Skip IP validation for localhost in development
        if LOCALHOST_WHITELIST.include?(host.downcase)
          return true if @security_config[:allow_private_networks]
        end
        
        # Resolve DNS
        addresses = Resolv.getaddresses(host)
        
        if addresses.empty? && @security_config[:fail_on_dns_errors]
          add_error(result, "Cannot resolve DNS for host: #{host}")
          return false
        end
        
        # Validate IP addresses for SSRF prevention
        addresses.each do |addr|
          begin
            ip = IPAddr.new(addr)
            
            # Check against blocked ranges
            BLOCKED_IP_RANGES.each do |blocked_range|
              if blocked_range.include?(ip)
                unless @security_config[:allow_private_networks]
                  add_error(result, "Host resolves to blocked IP range: #{addr}")
                  return false
                end
              end
            end
            
          rescue IPAddr::InvalidAddressError
            add_warning(result, "Invalid IP address returned by DNS: #{addr}")
          end
        end
        
        true
        
      rescue Resolv::ResolvError => e
        if @security_config[:fail_on_dns_errors]
          add_error(result, "DNS resolution failed: #{e.message}")
          false
        else
          add_warning(result, "DNS resolution failed: #{e.message}")
          true
        end
      rescue => e
        add_error(result, "DNS validation error: #{e.message}")
        false
      end
    end
    
    # Validate URL accessibility
    def validate_url_accessibility(uri, result, options)
      timeout = options[:timeout] || 10
      
      begin
        require 'net/http'
        
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = (uri.scheme == 'https')
        http.open_timeout = timeout
        http.read_timeout = timeout
        
        if uri.scheme == 'https'
          http.verify_mode = OpenSSL::SSL::VERIFY_PEER
        end
        
        start_time = Time.current
        response = http.request_head(uri.path.empty? ? '/' : uri.path)
        response_time = ((Time.current - start_time) * 1000).round(2)
        
        # Log response for monitoring
        log_security_event(:debug, 'URL accessibility check completed', {
          url: uri.to_s,
          response_code: response.code,
          response_time_ms: response_time
        })
        
        unless response.is_a?(Net::HTTPSuccess) || response.is_a?(Net::HTTPRedirection)
          add_warning(result, "URL returned HTTP #{response.code}: #{response.message}")
        end
        
      rescue Net::TimeoutError => e
        add_warning(result, "Connection timeout: #{e.message}")
      rescue OpenSSL::SSL::SSLError => e
        add_error(result, "SSL error: #{e.message}")
      rescue => e
        add_warning(result, "Accessibility check failed: #{e.message}")
      end
    end
    
    # Count Liquid template nodes for complexity validation
    def count_template_nodes(node, count = 0)
      return count + 1 unless node.respond_to?(:nodelist)
      
      count += 1
      node.nodelist.each do |child_node|
        count = count_template_nodes(child_node, count)
      end
      
      count
    end
    
    # Validate template variables for security
    def validate_template_variables(template, result)
      # Extract variable references
      variable_matches = template.scan(/\{\{\s*([^}]+)\s*\}\}/)
      
      variable_matches.each do |match|
        variable_expr = match[0].strip
        
        # Check for dangerous variable expressions
        if variable_expr.match?(/\b(system|exec|eval|require|load|File|Dir|IO)\b/i)
          add_error(result, "Template variable contains dangerous expression: #{variable_expr}")
        end
        
        # Check for complex expressions that might cause issues
        if variable_expr.length > 200
          add_warning(result, "Complex template variable expression: #{variable_expr[0..50]}...")
        end
      end
    end
    
    # Sanitize template content
    def sanitize_template_content(template)
      # Basic sanitization - remove any null bytes or control characters
      sanitized = template.gsub(/\x00/, '').gsub(/[\x01-\x08\x0B\x0C\x0E-\x1F\x7F]/, '')
      
      # Normalize line endings
      sanitized.gsub(/\r\n?/, "\n")
    end
    
    # Validate string fields
    def validate_string_field(field_name, value, constraints, result)
      unless value.is_a?(String)
        add_error(result, "#{field_name} must be a string")
        return
      end
      
      # Length constraints
      if constraints[:min_length] && value.length < constraints[:min_length]
        add_error(result, "#{field_name} too short (min #{constraints[:min_length]} characters)")
        return
      end
      
      if constraints[:max_length] && value.length > constraints[:max_length]
        add_error(result, "#{field_name} too long (max #{constraints[:max_length]} characters)")
        return
      end
      
      # Pattern matching
      if constraints[:pattern] && !value.match?(constraints[:pattern])
        add_error(result, "#{field_name} format invalid")
        return
      end
      
      # Allowed values
      if constraints[:allowed_values] && !constraints[:allowed_values].include?(value)
        add_error(result, "#{field_name} must be one of: #{constraints[:allowed_values].join(', ')}")
        return
      end
      
      result[:valid] = true
    end
    
    # Validate integer fields
    def validate_integer_field(field_name, value, constraints, result)
      int_value = value.is_a?(String) ? value.to_i : value
      
      unless int_value.is_a?(Integer) || (value.is_a?(String) && value.match?(/\A\d+\z/))
        add_error(result, "#{field_name} must be an integer")
        return
      end
      
      int_value = int_value.to_i
      
      # Range constraints
      if constraints[:min] && int_value < constraints[:min]
        add_error(result, "#{field_name} too small (min #{constraints[:min]})")
        return
      end
      
      if constraints[:max] && int_value > constraints[:max]
        add_error(result, "#{field_name} too large (max #{constraints[:max]})")
        return
      end
      
      result[:valid] = true
      result[:normalized_value] = int_value
    end
    
    # Validate boolean fields
    def validate_boolean_field(field_name, value, constraints, result)
      unless [true, false, 'true', 'false', '1', '0'].include?(value)
        add_error(result, "#{field_name} must be a boolean (true/false)")
        return
      end
      
      result[:valid] = true
      result[:normalized_value] = ['true', '1', true].include?(value)
    end
    
    # Validate array fields
    def validate_array_field(field_name, value, constraints, result)
      unless value.is_a?(Array)
        add_error(result, "#{field_name} must be an array")
        return
      end
      
      # Size constraints
      if constraints[:min_size] && value.size < constraints[:min_size]
        add_error(result, "#{field_name} too small (min #{constraints[:min_size]} items)")
        return
      end
      
      if constraints[:max_size] && value.size > constraints[:max_size]
        add_error(result, "#{field_name} too large (max #{constraints[:max_size]} items)")
        return
      end
      
      # Element validation
      if constraints[:element_type]
        value.each_with_index do |item, index|
          element_result = validate_configuration_field(
            "#{field_name}[#{index}]", 
            item, 
            constraints[:element_type],
            constraints[:element_constraints] || {}
          )
          
          unless element_result[:valid]
            result[:errors].concat(element_result[:errors])
            return
          end
        end
      end
      
      result[:valid] = true
    end
    
    # Validate hash fields
    def validate_hash_field(field_name, value, constraints, result)
      unless value.is_a?(Hash)
        add_error(result, "#{field_name} must be a hash/object")
        return
      end
      
      # Size constraints
      if constraints[:max_size] && value.to_json.length > constraints[:max_size]
        add_error(result, "#{field_name} too large (max #{constraints[:max_size]} bytes)")
        return
      end
      
      # Required keys
      if constraints[:required_keys]
        missing_keys = constraints[:required_keys] - value.keys.map(&:to_s)
        unless missing_keys.empty?
          add_error(result, "#{field_name} missing required keys: #{missing_keys.join(', ')}")
          return
        end
      end
      
      result[:valid] = true
    end
    
    # Validate optional configuration fields
    def validate_optional_configuration_fields(config, result)
      field_configs = {
        priority: { type: :string, constraints: { allowed_values: VALID_PRIORITIES } },
        execution_mode: { type: :string, constraints: { allowed_values: VALID_EXECUTION_MODES } },
        timeout_seconds: { type: :integer, constraints: { min: MIN_TIMEOUT_SECONDS, max: MAX_TIMEOUT_SECONDS } },
        retry_attempts: { type: :integer, constraints: { min: MIN_RETRY_ATTEMPTS, max: MAX_RETRY_ATTEMPTS } },
        verify_ssl: { type: :boolean },
        emit_events: { type: :boolean },
        include_execution_metadata: { type: :boolean },
        include_original_event: { type: :boolean },
        tags: { type: :array, constraints: { max_size: MAX_TAGS_COUNT, element_type: :string, 
                element_constraints: { max_length: MAX_TAG_LENGTH } } },
        context_data: { type: :hash, constraints: { max_size: MAX_CONTEXT_DATA_SIZE } }
      }
      
      field_configs.each do |field_name, config_def|
        value = config[field_name.to_s] || config[field_name]
        next if value.nil?
        
        field_result = validate_configuration_field(
          field_name.to_s,
          value,
          config_def[:type],
          config_def[:constraints] || {}
        )
        
        result[:field_results][field_name] = field_result
        
        unless field_result[:valid]
          result[:errors].concat(field_result[:errors])
        else
          sanitized_value = field_result[:normalized_value] || value
          result[:sanitized_config][field_name] = sanitized_value
        end
      end
    end
    
    # Calculate overall security score
    def calculate_security_score(config, validation_result)
      score = 100
      
      # Deduct points for errors
      score -= validation_result[:errors].length * 10
      
      # Deduct points for warnings  
      score -= validation_result[:warnings].length * 5
      
      # Security feature bonuses
      score += 5 if config['verify_ssl'] != false
      score += 3 if config['api_key']&.length&.> 20
      
      # Security penalties
      score -= 10 if config['verify_ssl'] == false
      score -= 5 if config['orchestrator_url']&.start_with?('http://') # Non-HTTPS
      
      [score, 0].max
    end
    
    # Determine risk level based on score
    def determine_risk_level(score)
      case score
      when 90..100 then 'low'
      when 70..89 then 'medium'
      when 50..69 then 'high'
      else 'critical'
      end
    end
    
    # Identify security vulnerabilities
    def identify_vulnerabilities(config, validation_result, report)
      # Check for common vulnerabilities
      if config['verify_ssl'] == false
        report[:vulnerabilities] << {
          type: 'insecure_transport',
          severity: 'high',
          description: 'SSL verification disabled - man-in-the-middle attacks possible'
        }
      end
      
      if config['orchestrator_url']&.start_with?('http://')
        report[:vulnerabilities] << {
          type: 'unencrypted_transport',
          severity: 'medium', 
          description: 'Using HTTP instead of HTTPS - data transmitted in clear text'
        }
      end
      
      if config['api_key']&.length&.< 20
        report[:vulnerabilities] << {
          type: 'weak_authentication',
          severity: 'medium',
          description: 'API key appears to be too short for secure authentication'
        }
      end
    end
    
    # Generate security recommendations
    def generate_security_recommendations(config, validation_result, report)
      if config['verify_ssl'] == false
        report[:recommendations] << 'Enable SSL verification for production deployments'
      end
      
      if config['orchestrator_url']&.start_with?('http://')
        report[:recommendations] << 'Use HTTPS instead of HTTP for encrypted communication'
      end
      
      unless config['api_key']
        report[:recommendations] << 'Consider adding API key authentication for enhanced security'
      end
      
      if validation_result[:warnings].any?
        report[:recommendations] << 'Address validation warnings to improve security posture'
      end
    end
    
    # Perform compliance checks
    def perform_compliance_checks(config, report)
      compliance = report[:compliance_checks]
      
      # SOC2 compliance checks
      compliance[:soc2] = {
        encryption_in_transit: config['orchestrator_url']&.start_with?('https://') && config['verify_ssl'] != false,
        authentication_enabled: !config['api_key'].nil?,
        input_validation: true # This validator ensures input validation
      }
      
      # GDPR compliance checks
      compliance[:gdpr] = {
        data_minimization: config['include_execution_metadata'] != true, # Don't include excessive metadata
        secure_processing: config['verify_ssl'] != false
      }
    end
    
    # Helper methods for result management
    def add_error(result, message)
      result[:errors] << message
      result
    end
    
    def add_warning(result, message)
      result[:warnings] << message
      result
    end
    
    # Security event logging
    def log_security_event(level, message, details = {})
      return unless @security_config[:log_validation_attempts]
      
      log_entry = {
        timestamp: Time.current.iso8601,
        level: level,
        message: message,
        component: 'AigentInputValidator',
        details: details
      }
      
      @logger&.send(level, log_entry.to_json)
    end
    
    # Create default logger if none provided
    def create_default_logger
      logger = Logger.new(STDOUT)
      logger.level = Logger::INFO
      logger.formatter = proc do |severity, datetime, progname, msg|
        "[#{datetime}] #{severity} #{msg}\n"
      end
      logger
    rescue
      # Fallback to null logger if creation fails
      Class.new do
        def method_missing(*); end
        def respond_to_missing?(*); true; end
      end.new
    end
  end
end