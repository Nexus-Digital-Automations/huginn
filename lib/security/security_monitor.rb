# frozen_string_literal: true

require 'json'
require 'digest'
require 'openssl'

module Security
  ##
  # Comprehensive Security Monitoring Framework for Huginn AIgent Trigger Agent
  #
  # This class provides enterprise-grade security monitoring capabilities including:
  # - Real-time threat detection and analysis
  # - Attack pattern recognition and correlation  
  # - Security event logging and correlation
  # - Automated incident response triggering
  # - Compliance monitoring and reporting
  # - Security metrics collection and analysis
  #
  class SecurityMonitor
    include Singleton

    # Security event severity levels
    SEVERITY_LEVELS = %w[info low medium high critical].freeze

    # Attack vector categories for classification
    ATTACK_VECTORS = {
      'injection' => %w[sql_injection xss_injection ldap_injection command_injection],
      'authentication' => %w[brute_force credential_stuffing session_hijacking],
      'authorization' => %w[privilege_escalation access_control_bypass],
      'data_exposure' => %w[sensitive_data_leak information_disclosure],
      'denial_of_service' => %w[resource_exhaustion flood_attack],
      'malware' => %w[backdoor trojan virus worm],
      'network' => %w[man_in_the_middle dns_poisoning arp_spoofing],
      'application' => %w[csrf ssrf xxe deserialization]
    }.freeze

    # Compliance framework mappings
    COMPLIANCE_MAPPINGS = {
      'owasp_top_10' => {
        'A01' => 'broken_access_control',
        'A02' => 'cryptographic_failures',
        'A03' => 'injection',
        'A04' => 'insecure_design',
        'A05' => 'security_misconfiguration',
        'A06' => 'vulnerable_components',
        'A07' => 'authentication_failures',
        'A08' => 'integrity_failures',
        'A09' => 'logging_monitoring_failures',
        'A10' => 'ssrf'
      },
      'pci_dss' => {
        'req_1' => 'firewall_configuration',
        'req_2' => 'default_passwords',
        'req_3' => 'cardholder_data_protection',
        'req_4' => 'encryption_transmission',
        'req_6' => 'secure_systems',
        'req_7' => 'access_restriction',
        'req_8' => 'user_identification',
        'req_9' => 'physical_access',
        'req_10' => 'monitoring_logging',
        'req_11' => 'security_testing',
        'req_12' => 'security_policy'
      },
      'soc2' => {
        'cc1' => 'control_environment',
        'cc2' => 'communication_information',
        'cc3' => 'risk_assessment',
        'cc4' => 'monitoring_activities',
        'cc5' => 'control_activities',
        'cc6' => 'logical_physical_access',
        'cc7' => 'system_operations',
        'cc8' => 'change_management',
        'cc9' => 'risk_mitigation'
      }
    }.freeze

    # Risk scoring matrix
    RISK_MATRIX = {
      'critical' => { base_score: 10.0, multiplier: 1.0 },
      'high' => { base_score: 7.5, multiplier: 0.8 },
      'medium' => { base_score: 5.0, multiplier: 0.6 },
      'low' => { base_score: 2.5, multiplier: 0.4 },
      'info' => { base_score: 0.0, multiplier: 0.1 }
    }.freeze

    def initialize
      @monitoring_enabled = false
      @security_events = []
      @threat_patterns = {}
      @baseline_metrics = {}
      @anomaly_threshold = 2.0 # Standard deviations from baseline
      @correlation_window = 300 # 5 minutes correlation window
      @incident_counter = 0
      @compliance_status = {}
      @risk_score_cache = {}
      @alert_rules = load_alert_rules
      @security_policies = load_security_policies
      
      initialize_logging
      load_threat_intelligence
    end

    ##
    # Enable comprehensive security monitoring
    #
    # @param [Hash] config Configuration options
    # @option config [Boolean] :real_time_monitoring Enable real-time monitoring
    # @option config [Array<String>] :monitored_events Event types to monitor
    # @option config [Hash] :alerting_config Alerting configuration
    # @option config [Hash] :compliance_frameworks Compliance frameworks to monitor
    def enable_monitoring(config = {})
      @monitoring_enabled = true
      @config = default_config.merge(config)
      
      log_security_event('monitoring_enabled', {
        configuration: @config,
        timestamp: Time.current.iso8601,
        monitor_version: '2.0.0'
      }, 'info')

      setup_baseline_metrics
      initialize_threat_detection_engine
      start_correlation_engine if @config[:real_time_monitoring]
      
      Rails.logger.info "[SecurityMonitor] Comprehensive security monitoring enabled"
    end

    ##
    # Disable security monitoring
    def disable_monitoring
      @monitoring_enabled = false
      stop_correlation_engine
      
      log_security_event('monitoring_disabled', {
        total_events_processed: @security_events.length,
        monitoring_duration: calculate_monitoring_duration,
        timestamp: Time.current.iso8601
      }, 'info')
      
      Rails.logger.info "[SecurityMonitor] Security monitoring disabled"
    end

    ##
    # Monitor AIgent Trigger Agent security event
    #
    # @param [String] event_type Type of security event
    # @param [Hash] event_data Event data to analyze
    # @param [Hash] context Additional context information
    # @return [Hash] Security analysis result
    def monitor_aigent_event(event_type, event_data, context = {})
      return { monitored: false } unless @monitoring_enabled

      # Generate unique event ID
      event_id = generate_event_id(event_type, event_data)
      
      # Comprehensive security analysis
      security_analysis = perform_security_analysis(event_type, event_data, context)
      
      # Create security event record
      security_event = {
        id: event_id,
        type: event_type,
        data: sanitize_sensitive_data(event_data),
        context: context,
        analysis: security_analysis,
        timestamp: Time.current.iso8601,
        source: 'huginn_aigent_trigger_agent',
        session_id: context[:session_id] || 'unknown'
      }

      # Store event for correlation and analysis
      @security_events << security_event
      
      # Perform real-time threat correlation
      correlation_results = correlate_security_events(security_event)
      
      # Update risk scoring
      update_risk_scoring(security_event, correlation_results)
      
      # Check for compliance violations
      compliance_violations = check_compliance_violations(security_event)
      
      # Generate alerts if necessary
      alerts_generated = evaluate_alert_conditions(security_event, correlation_results)
      
      # Update security metrics
      update_security_metrics(security_event)
      
      # Log comprehensive security event
      log_security_event(event_type, {
        event_id: event_id,
        security_analysis: security_analysis,
        correlation_results: correlation_results,
        compliance_status: compliance_violations,
        alerts_generated: alerts_generated,
        risk_score: @risk_score_cache[event_id]
      }, security_analysis[:severity])

      # Return monitoring result
      {
        monitored: true,
        event_id: event_id,
        security_analysis: security_analysis,
        risk_score: @risk_score_cache[event_id],
        correlation_results: correlation_results,
        compliance_violations: compliance_violations,
        alerts_generated: alerts_generated,
        recommendations: generate_security_recommendations(security_analysis)
      }
    end

    ##
    # Get comprehensive security dashboard
    #
    # @return [Hash] Security monitoring dashboard data
    def get_security_dashboard
      calculate_dashboard_metrics
    end

    ##
    # Generate security incident report
    #
    # @param [String] incident_id Incident ID to generate report for
    # @return [Hash] Comprehensive incident report
    def generate_incident_report(incident_id = nil)
      if incident_id
        generate_specific_incident_report(incident_id)
      else
        generate_comprehensive_security_report
      end
    end

    ##
    # Validate compliance against security frameworks
    #
    # @param [Array<String>] frameworks List of frameworks to validate against
    # @return [Hash] Compliance validation results
    def validate_compliance(frameworks = ['owasp_top_10', 'pci_dss', 'soc2'])
      compliance_results = {}
      
      frameworks.each do |framework|
        compliance_results[framework] = validate_framework_compliance(framework)
      end
      
      overall_compliance_score = calculate_overall_compliance_score(compliance_results)
      
      {
        overall_compliance_score: overall_compliance_score,
        framework_results: compliance_results,
        compliance_timestamp: Time.current.iso8601,
        recommendations: generate_compliance_recommendations(compliance_results)
      }
    end

    ##
    # Export security events for external analysis
    #
    # @param [Hash] options Export options
    # @return [String] Path to exported file
    def export_security_events(options = {})
      export_format = options[:format] || 'json'
      date_range = options[:date_range] || 7.days
      
      filtered_events = filter_events_by_date(@security_events, date_range)
      
      export_path = generate_export_path(export_format)
      
      case export_format.downcase
      when 'json'
        export_events_json(filtered_events, export_path)
      when 'csv'
        export_events_csv(filtered_events, export_path)
      when 'siem'
        export_events_siem_format(filtered_events, export_path)
      else
        raise ArgumentError, "Unsupported export format: #{export_format}"
      end
      
      log_security_event('security_export', {
        export_path: export_path,
        events_exported: filtered_events.length,
        export_format: export_format
      }, 'info')
      
      export_path
    end

    private

    def default_config
      {
        real_time_monitoring: true,
        monitored_events: %w[
          aigent_execution authentication_attempt authorization_check
          data_access sensitive_data_processing compliance_validation
          error_handling security_validation
        ],
        alerting_config: {
          email_alerts: true,
          slack_notifications: true,
          siem_integration: true,
          alert_thresholds: {
            critical: 1,
            high: 3,
            medium: 10
          }
        },
        compliance_frameworks: %w[owasp_top_10 pci_dss soc2],
        correlation_window: 300,
        anomaly_detection_enabled: true,
        threat_intelligence_enabled: true
      }
    end

    def perform_security_analysis(event_type, event_data, context)
      analysis = {
        event_classification: classify_security_event(event_type, event_data),
        threat_indicators: detect_threat_indicators(event_data),
        attack_patterns: identify_attack_patterns(event_data),
        anomaly_score: calculate_anomaly_score(event_type, event_data),
        severity: 'info',
        confidence_score: 0.0,
        potential_impact: assess_potential_impact(event_data, context),
        mitigation_recommendations: []
      }

      # Calculate severity based on multiple factors
      analysis[:severity] = calculate_event_severity(analysis)
      analysis[:confidence_score] = calculate_confidence_score(analysis)
      analysis[:mitigation_recommendations] = generate_mitigation_recommendations(analysis)

      # Advanced threat analysis
      if analysis[:threat_indicators].any? || analysis[:anomaly_score] > @anomaly_threshold
        analysis[:advanced_threat_analysis] = perform_advanced_threat_analysis(event_data)
        analysis[:ioc_analysis] = perform_ioc_analysis(event_data)
      end

      analysis
    end

    def classify_security_event(event_type, event_data)
      classifications = []
      
      # Check for injection patterns
      if contains_injection_patterns?(event_data)
        classifications << 'injection_attempt'
      end
      
      # Check for authentication/authorization issues
      if contains_auth_patterns?(event_data)
        classifications << 'authentication_security'
      end
      
      # Check for data exposure risks
      if contains_sensitive_data?(event_data)
        classifications << 'data_exposure_risk'
      end
      
      # Check for DoS patterns
      if contains_dos_patterns?(event_data)
        classifications << 'denial_of_service'
      end

      # Check for compliance violations
      compliance_violations = detect_compliance_violations(event_data)
      classifications.concat(compliance_violations)

      classifications.empty? ? ['normal_operation'] : classifications.uniq
    end

    def detect_threat_indicators(event_data)
      indicators = []
      
      # Pattern-based detection
      THREAT_PATTERNS.each do |category, patterns|
        patterns.each do |pattern|
          if data_matches_pattern?(event_data, pattern)
            indicators << {
              category: category,
              pattern: pattern[:name],
              confidence: pattern[:confidence],
              severity: pattern[:severity]
            }
          end
        end
      end
      
      # Behavioral analysis
      behavioral_indicators = analyze_behavioral_patterns(event_data)
      indicators.concat(behavioral_indicators)
      
      # IP reputation analysis
      ip_indicators = analyze_ip_reputation(event_data)
      indicators.concat(ip_indicators)
      
      indicators
    end

    def identify_attack_patterns(event_data)
      attack_patterns = []
      
      ATTACK_VECTORS.each do |category, attack_types|
        attack_types.each do |attack_type|
          if matches_attack_signature?(event_data, attack_type)
            attack_patterns << {
              category: category,
              attack_type: attack_type,
              indicators: extract_attack_indicators(event_data, attack_type),
              severity: assess_attack_severity(attack_type),
              mitigation: get_attack_mitigation(attack_type)
            }
          end
        end
      end
      
      attack_patterns
    end

    def calculate_anomaly_score(event_type, event_data)
      return 0.0 unless @baseline_metrics[event_type]
      
      baseline = @baseline_metrics[event_type]
      current_metrics = extract_event_metrics(event_data)
      
      anomaly_scores = []
      
      current_metrics.each do |metric_name, value|
        baseline_value = baseline[metric_name]
        next unless baseline_value && baseline_value[:std_dev] > 0
        
        deviation = (value - baseline_value[:mean]).abs
        normalized_deviation = deviation / baseline_value[:std_dev]
        anomaly_scores << normalized_deviation
      end
      
      anomaly_scores.empty? ? 0.0 : anomaly_scores.max
    end

    def assess_potential_impact(event_data, context)
      impact_factors = {
        data_sensitivity: assess_data_sensitivity(event_data),
        system_criticality: assess_system_criticality(context),
        user_privileges: assess_user_privileges(context),
        network_exposure: assess_network_exposure(context),
        compliance_impact: assess_compliance_impact(event_data)
      }
      
      # Calculate weighted impact score
      weights = {
        data_sensitivity: 0.3,
        system_criticality: 0.25,
        user_privileges: 0.2,
        network_exposure: 0.15,
        compliance_impact: 0.1
      }
      
      total_impact = impact_factors.sum { |factor, score| weights[factor] * score }
      
      {
        overall_impact: total_impact,
        impact_factors: impact_factors,
        impact_level: categorize_impact_level(total_impact)
      }
    end

    def calculate_event_severity(analysis)
      severity_scores = []
      
      # Base severity from threat indicators
      analysis[:threat_indicators].each do |indicator|
        severity_scores << severity_to_score(indicator[:severity])
      end
      
      # Severity from attack patterns
      analysis[:attack_patterns].each do |pattern|
        severity_scores << severity_to_score(pattern[:severity])
      end
      
      # Anomaly-based severity
      if analysis[:anomaly_score] > @anomaly_threshold
        anomaly_severity = analysis[:anomaly_score] > 3.0 ? 'high' : 'medium'
        severity_scores << severity_to_score(anomaly_severity)
      end
      
      # Impact-based severity
      impact_level = analysis.dig(:potential_impact, :impact_level)
      if impact_level
        severity_scores << severity_to_score(impact_level)
      end
      
      # Calculate overall severity
      max_severity_score = severity_scores.max || 0
      score_to_severity(max_severity_score)
    end

    def correlate_security_events(current_event)
      correlation_window_start = Time.current - @correlation_window.seconds
      recent_events = @security_events.select do |event|
        Time.parse(event[:timestamp]) > correlation_window_start
      end
      
      correlations = {
        temporal_correlations: find_temporal_correlations(current_event, recent_events),
        pattern_correlations: find_pattern_correlations(current_event, recent_events),
        source_correlations: find_source_correlations(current_event, recent_events),
        attack_chain_detection: detect_attack_chains(current_event, recent_events)
      }
      
      # Calculate correlation confidence
      correlations[:confidence_score] = calculate_correlation_confidence(correlations)
      correlations[:correlated_events_count] = recent_events.length
      
      correlations
    end

    def check_compliance_violations(security_event)
      violations = []
      
      @config[:compliance_frameworks].each do |framework|
        framework_violations = check_framework_violations(security_event, framework)
        violations.concat(framework_violations) if framework_violations.any?
      end
      
      violations
    end

    def evaluate_alert_conditions(security_event, correlation_results)
      alerts = []
      
      # Severity-based alerts
      severity = security_event.dig(:analysis, :severity)
      threshold = @config.dig(:alerting_config, :alert_thresholds, severity.to_sym)
      
      if threshold && should_generate_alert?(severity, threshold)
        alerts << generate_severity_alert(security_event, severity)
      end
      
      # Correlation-based alerts
      if correlation_results[:confidence_score] > 0.8
        alerts << generate_correlation_alert(security_event, correlation_results)
      end
      
      # Compliance violation alerts
      compliance_violations = security_event.dig(:analysis, :compliance_violations)
      if compliance_violations&.any?
        alerts << generate_compliance_alert(security_event, compliance_violations)
      end
      
      # Custom rule-based alerts
      custom_alerts = evaluate_custom_alert_rules(security_event)
      alerts.concat(custom_alerts)
      
      # Send alerts to configured channels
      send_alerts(alerts) if alerts.any?
      
      alerts
    end

    def update_security_metrics(security_event)
      event_type = security_event[:type]
      severity = security_event.dig(:analysis, :severity)
      Time.parse(security_event[:timestamp])
      
      # Update event counts
      increment_metric("events_total")
      increment_metric("events_by_type.#{event_type}")
      increment_metric("events_by_severity.#{severity}")
      
      # Update threat detection metrics
      if security_event.dig(:analysis, :threat_indicators)&.any?
        increment_metric("threats_detected")
        increment_metric("threats_by_severity.#{severity}")
      end
      
      # Update compliance metrics
      compliance_violations = security_event.dig(:analysis, :compliance_violations)
      if compliance_violations&.any?
        increment_metric("compliance_violations")
        compliance_violations.each do |violation|
          increment_metric("violations_by_framework.#{violation[:framework]}")
        end
      end
      
      # Update performance metrics
      response_time = calculate_response_time(security_event)
      update_performance_metric("response_time", response_time)
      
      # Update baseline metrics for anomaly detection
      update_baseline_metrics(event_type, security_event)
    end

    def log_security_event(event_type, event_data, severity)
      log_entry = {
        timestamp: Time.current.iso8601,
        event_type: event_type,
        severity: severity,
        data: event_data,
        source: 'huginn_security_monitor',
        version: '2.0.0'
      }
      
      # Write to security log file
      security_log_path = Rails.root.join('logs', 'security', 'security_audit.jsonl')
      File.open(security_log_path, 'a') do |file|
        file.puts JSON.generate(log_entry)
      end
      
      # Log to Rails logger with appropriate level
      case severity.to_s
      when 'critical'
        Rails.logger.error "[SECURITY-CRITICAL] #{event_type}: #{event_data}"
      when 'high'
        Rails.logger.warn "[SECURITY-HIGH] #{event_type}: #{event_data}"
      when 'medium'
        Rails.logger.warn "[SECURITY-MEDIUM] #{event_type}: #{event_data}"
      when 'low'
        Rails.logger.info "[SECURITY-LOW] #{event_type}: #{event_data}"
      else
        Rails.logger.info "[SECURITY-INFO] #{event_type}: #{event_data}"
      end
      
      # Send to external SIEM if configured
      if @config.dig(:alerting_config, :siem_integration)
        send_to_siem(log_entry)
      end
    end

    def initialize_logging
      # Ensure security logs directory exists
      security_logs_dir = Rails.root.join('logs', 'security')
      FileUtils.mkdir_p(security_logs_dir)
      
      # Initialize log files
      security_log_path = security_logs_dir.join('security_audit.jsonl')
      unless File.exist?(security_log_path)
        File.open(security_log_path, 'w') do |file|
          file.puts JSON.generate({
            initialized_at: Time.current.iso8601,
            monitor_version: '2.0.0',
            log_format: 'jsonl'
          })
        end
      end
    end

    def load_threat_intelligence
      # Load threat patterns and indicators
      @threat_patterns = THREAT_PATTERNS
      
      # Load IP reputation data (in production, this would come from threat feeds)
      @ip_reputation = {}
      
      # Load known attack signatures
      @attack_signatures = load_attack_signatures
      
      Rails.logger.info "[SecurityMonitor] Threat intelligence loaded successfully"
    end

    def sanitize_sensitive_data(data)
      sanitized = data.deep_dup
      
      # Patterns for sensitive data detection
      sensitive_patterns = {
        /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/ => '[CARD_NUMBER_REDACTED]',
        /\b\d{3}[\s-]?\d{2}[\s-]?\d{4}\b/ => '[SSN_REDACTED]',
        /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/ => '[EMAIL_REDACTED]',
        /(?i)password[:=]\s*[^\s&]+/ => 'password=[REDACTED]',
        /(?i)api[_-]?key[:=]\s*[^\s&]+/ => 'api_key=[REDACTED]',
        /(?i)token[:=]\s*[^\s&]+/ => 'token=[REDACTED]'
      }
      
      # Recursively sanitize data
      sanitize_hash_values(sanitized, sensitive_patterns)
    end

    def sanitize_hash_values(hash, patterns)
      hash.each do |key, value|
        case value
        when Hash
          sanitize_hash_values(value, patterns)
        when Array
          value.map! { |item| item.is_a?(Hash) ? sanitize_hash_values(item, patterns) : sanitize_string_value(item, patterns) }
        when String
          hash[key] = sanitize_string_value(value, patterns)
        end
      end
      
      hash
    end

    def sanitize_string_value(value, patterns)
      return value unless value.is_a?(String)
      
      patterns.each do |pattern, replacement|
        value = value.gsub(pattern, replacement)
      end
      
      value
    end

    # Additional helper methods would be implemented here for:
    # - setup_baseline_metrics
    # - calculate_dashboard_metrics
    # - validate_framework_compliance
    # - generate_security_recommendations
    # - And other supporting functionality

    # Constants for threat patterns (simplified for example)
    THREAT_PATTERNS = {
      'injection' => [
        {
          name: 'sql_injection',
          pattern: /(union\s+select|drop\s+table|exec\s*\(|script\s*>)/i,
          confidence: 0.9,
          severity: 'high'
        },
        {
          name: 'xss_injection',
          pattern: /(<script|javascript:|on\w+\s*=)/i,
          confidence: 0.8,
          severity: 'high'
        }
      ]
    }.freeze

    def generate_event_id(event_type, event_data)
      data_hash = Digest::SHA256.hexdigest(event_data.to_json)
      "SEC-#{Time.current.strftime('%Y%m%d')}-#{event_type.upcase}-#{data_hash[0..7]}"
    end

    def severity_to_score(severity)
      { 'critical' => 5, 'high' => 4, 'medium' => 3, 'low' => 2, 'info' => 1 }[severity.to_s] || 1
    end

    def score_to_severity(score)
      case score
      when 5 then 'critical'
      when 4 then 'high'
      when 3 then 'medium'
      when 2 then 'low'
      else 'info'
      end
    end

    # Placeholder methods for complex functionality
    def contains_injection_patterns?(data)
      data.to_s.match?(/(union\s+select|drop\s+table|<script|javascript:)/i)
    end

    def contains_auth_patterns?(data)
      data.to_s.match?(/(login|password|session|token|auth)/i)
    end

    def contains_sensitive_data?(data)
      data.to_s.match?(/(\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}|\d{3}[\s-]?\d{2}[\s-]?\d{4})/i)
    end

    def contains_dos_patterns?(data)
      data.to_s.length > 10000 # Simple size-based DoS detection
    end

    def increment_metric(metric_name)
      @security_metrics ||= {}
      @security_metrics[metric_name] = (@security_metrics[metric_name] || 0) + 1
    end

    def load_alert_rules
      {} # Placeholder for alert rules configuration
    end

    def load_security_policies  
      {} # Placeholder for security policies
    end

    def setup_baseline_metrics
      @baseline_metrics = {} # Placeholder for baseline metrics setup
    end

    def initialize_threat_detection_engine
      # Placeholder for threat detection engine initialization
    end

    def start_correlation_engine
      # Placeholder for correlation engine startup
    end

    def stop_correlation_engine
      # Placeholder for correlation engine shutdown
    end

    def calculate_monitoring_duration
      # Placeholder for monitoring duration calculation
      0
    end
  end
end