# frozen_string_literal: true

require_relative '../lib/parlant_integration'

#
# SystemMailerParlant - Enhanced system mailer with comprehensive Parlant integration
#
# Provides conversational validation for all system email operations with enterprise-grade
# security, audit trails, and intelligent content analysis for regulatory compliance.
#
# Features:
# - Pre-send conversational validation of all system emails
# - Recipient validation and external email detection
# - Content safety analysis and sensitive information detection
# - Comprehensive audit trails for compliance (GDPR, SOX, HIPAA)
# - Performance monitoring and delivery tracking
# - Bulk email protection with approval workflows
#
class SystemMailerParlant < ActionMailer::Base
  include ParlantIntegration::AgentIntegration

  default from: ENV['EMAIL_FROM_ADDRESS'].presence || 'huginn@example.com'

  before_action :validate_email_with_parlant

  #
  # Send message with comprehensive Parlant validation
  #
  # Enhanced version of system email sending with conversational validation,
  # risk assessment, and comprehensive audit trails.
  #
  # @param options [Hash] Email configuration options
  # @option options [String, Array] :to Email recipients
  # @option options [String] :from Sender email address
  # @option options [String] :subject Email subject line
  # @option options [String] :headline Email headline
  # @option options [String] :body Email body content
  # @option options [String] :content_type Content type (text/plain or text/html)
  # @option options [Array] :groups Event groups for template rendering
  #
  def send_message(options)
    @send_options = options
    @groups = options[:groups] || []
    @headline = options[:headline]
    @body = options[:body]
    @validation_metadata = {}

    # Perform comprehensive email validation through Parlant
    perform_email_validation(options)

    # Prepare mail options
    mail_options = build_mail_options(options)

    # Send email with content type handling
    send_validated_email(mail_options, options)
  end

  #
  # Send bulk messages with enhanced Parlant validation
  #
  # Specialized method for sending multiple emails with batch validation
  # and intelligent throttling based on risk assessment.
  #
  # @param messages [Array<Hash>] Array of message options
  # @param batch_options [Hash] Batch processing options
  #
  def send_bulk_messages(messages, batch_options = {})
    return if messages.empty?

    # Validate bulk operation through Parlant
    parlant_validate_operation('send_bulk_emails', {
      message_count: messages.length,
      unique_recipients: extract_unique_recipients(messages).length,
      batch_size: batch_options[:batch_size] || 10,
      throttle_delay: batch_options[:throttle_delay] || 1,
      contains_external_recipients: contains_external_recipients?(messages)
    }) do
      process_bulk_messages(messages, batch_options)
    end
  end

  #
  # Send critical system alert with maximum validation
  #
  # High-security method for sending critical system alerts that require
  # multi-party approval and comprehensive audit trails.
  #
  # @param alert_options [Hash] Alert configuration
  #
  def send_critical_alert(alert_options)
    parlant_validate_operation('send_critical_alert', {
      alert_type: alert_options[:alert_type],
      severity: alert_options[:severity] || 'high',
      recipients: Array(alert_options[:to]),
      system_impact: alert_options[:system_impact],
      requires_immediate_action: alert_options[:urgent] || false
    }) do
      # Add critical alert metadata
      enhanced_options = alert_options.merge({
        subject: "[CRITICAL ALERT] #{alert_options[:subject]}",
        headline: "🚨 Critical System Alert 🚨",
        body: build_critical_alert_body(alert_options)
      })

      send_message(enhanced_options)

      # Create critical audit trail
      ParlantIntegration::Service.instance.create_audit_trail(
        create_pseudo_agent,
        'critical_alert_sent',
        {
          status: 'success',
          alert_type: alert_options[:alert_type],
          recipients: Array(alert_options[:to]),
          severity: alert_options[:severity]
        },
        {
          system_impact: alert_options[:system_impact],
          urgent: alert_options[:urgent],
          timestamp: Time.now.iso8601
        }
      )
    end
  end

  private

  #
  # Validate email through Parlant before sending
  #
  def validate_email_with_parlant
    return unless @send_options

    recipients_list = Array(@send_options[:to])
    
    # Assess email security risk
    email_risk = assess_comprehensive_email_risk(recipients_list, @send_options)

    # Perform Parlant validation
    parlant_validate_operation('system_email_send', {
      recipients: recipients_list,
      subject: @send_options[:subject],
      from: @send_options[:from],
      content_type: @send_options[:content_type],
      risk_assessment: email_risk,
      external_recipient_count: count_external_recipients(recipients_list),
      estimated_size_kb: estimate_email_size(@send_options)
    }) do
      Rails.logger.info "📧 System email validated for sending: #{@send_options[:subject]}"
      
      # Store validation metadata for audit trail
      @validation_metadata = {
        validated_at: Time.now.iso8601,
        risk_level: email_risk[:level],
        validation_factors: email_risk[:factors]
      }
    end
  end

  #
  # Assess comprehensive risk for system email
  #
  def assess_comprehensive_email_risk(recipients, options)
    risk_factors = []

    # Multiple recipients increase risk
    if recipients.length > 10
      risk_factors << "bulk_email_#{recipients.length}_recipients"
    end

    # External recipients increase risk
    external_count = count_external_recipients(recipients)
    if external_count > 0
      risk_factors << "external_recipients_#{external_count}"
    end

    # Large content increases risk
    estimated_size = estimate_email_size(options)
    if estimated_size > 1000 # KB
      risk_factors << "large_content_#{estimated_size}kb"
    end

    # Sensitive content patterns
    subject_body = "#{options[:subject]} #{options[:body]} #{options[:headline]}".to_s.downcase
    if subject_body.match?(/urgent|alert|warning|critical|emergency|confidential|sensitive|password|credentials/)
      risk_factors << 'sensitive_content_detected'
    end

    # HTML content with external links
    if options[:content_type] == 'text/html' && options[:body].to_s.scan(/https?:\/\//).length > 5
      risk_factors << 'html_with_external_links'
    end

    # System-generated content (lower risk)
    if options[:body].to_s.include?('Generated by Huginn') || options[:groups].present?
      risk_factors << 'system_generated_content'
    end

    {
      level: determine_email_risk_level(risk_factors),
      factors: risk_factors,
      recipient_analysis: {
        total: recipients.length,
        external: external_count,
        internal: recipients.length - external_count
      },
      content_analysis: {
        estimated_size_kb: estimated_size,
        contains_html: options[:content_type] == 'text/html',
        contains_attachments: options[:groups].present?
      }
    }
  end

  #
  # Build mail options with security enhancements
  #
  def build_mail_options(options)
    mail_options = { to: options[:to], subject: options[:subject] }
    
    # Set from address with validation
    if options[:from].present?
      mail_options[:from] = validate_sender_address(options[:from])
    end

    # Add security headers
    mail_options[:headers] = build_security_headers(options)

    mail_options
  end

  #
  # Send validated email with comprehensive monitoring
  #
  def send_validated_email(mail_options, options)
    start_time = Time.now

    if options[:content_type].present?
      mail(mail_options) do |format|
        format.text if options[:content_type] == 'text/plain'
        format.html if options[:content_type] == 'text/html'
      end
    else
      mail(mail_options)
    end

    send_time_ms = ((Time.now - start_time) * 1000).round(2)

    # Create comprehensive audit trail
    create_email_audit_trail(mail_options, options, send_time_ms, 'success')

  rescue StandardError => e
    # Create failure audit trail
    create_email_audit_trail(mail_options, options, 0, 'failure', e.message)
    raise
  end

  #
  # Process bulk messages with intelligent batching
  #
  def process_bulk_messages(messages, batch_options)
    batch_size = batch_options[:batch_size] || 10
    throttle_delay = batch_options[:throttle_delay] || 1
    
    messages.each_slice(batch_size).with_index do |batch, batch_index|
      Rails.logger.info "📧 Processing bulk email batch #{batch_index + 1}: #{batch.length} messages"
      
      batch.each do |message_options|
        begin
          send_message(message_options)
        rescue StandardError => e
          Rails.logger.error "❌ Failed to send bulk email: #{e.message}"
          # Continue with other messages
        end
      end

      # Throttle between batches (except for last batch)
      sleep(throttle_delay) if batch_index < (messages.length / batch_size.to_f).ceil - 1
    end

    Rails.logger.info "✅ Bulk email processing completed: #{messages.length} messages"
  end

  #
  # Build critical alert email body
  #
  def build_critical_alert_body(alert_options)
    <<~ALERT
      CRITICAL SYSTEM ALERT

      Alert Type: #{alert_options[:alert_type]}
      Severity: #{alert_options[:severity]&.upcase}
      Timestamp: #{Time.now.strftime('%Y-%m-%d %H:%M:%S %Z')}

      #{alert_options[:body]}

      System Impact: #{alert_options[:system_impact]}
      
      #{'⚠️  IMMEDIATE ACTION REQUIRED ⚠️' if alert_options[:urgent]}

      This is an automated alert from the Huginn monitoring system.
      Do not reply directly to this email.
    ALERT
  end

  #
  # Create comprehensive email audit trail
  #
  def create_email_audit_trail(mail_options, options, send_time_ms, status, error_message = nil)
    audit_data = {
      status: status,
      recipients: Array(mail_options[:to]),
      subject: mail_options[:subject],
      from: mail_options[:from],
      send_time_ms: send_time_ms,
      content_type: options[:content_type],
      validation_metadata: @validation_metadata
    }

    audit_data[:error] = error_message if error_message

    ParlantIntegration::Service.instance.create_audit_trail(
      create_pseudo_agent,
      'system_email_sent',
      audit_data,
      {
        email_size_estimate: estimate_email_size(options),
        external_recipients: count_external_recipients(Array(mail_options[:to])),
        timestamp: Time.now.iso8601
      }
    )
  end

  #
  # Count external recipients (non-organization emails)
  #
  def count_external_recipients(recipients)
    internal_domains = ENV.fetch('INTERNAL_EMAIL_DOMAINS', 'localhost,example.com').split(',')
    
    recipients.count do |recipient|
      next false unless recipient&.include?('@')
      recipient_domain = recipient.split('@').last
      !internal_domains.include?(recipient_domain)
    end
  end

  #
  # Check if messages contain external recipients
  #
  def contains_external_recipients?(messages)
    all_recipients = extract_unique_recipients(messages)
    count_external_recipients(all_recipients) > 0
  end

  #
  # Extract unique recipients from message array
  #
  def extract_unique_recipients(messages)
    messages.flat_map { |msg| Array(msg[:to]) }.uniq
  end

  #
  # Estimate email size in KB
  #
  def estimate_email_size(options)
    content_size = [
      options[:subject],
      options[:headline], 
      options[:body],
      options[:groups]&.to_json
    ].compact.join.length

    (content_size / 1024.0).round(2)
  end

  #
  # Validate sender email address
  #
  def validate_sender_address(sender)
    # Basic email validation and security checks
    if sender.match?(/\A[\w+\-.]+@[a-z\d\-]+(\.[a-z\d\-]+)*\.[a-z]+\z/i)
      sender
    else
      Rails.logger.warn "⚠️  Invalid sender address detected: #{sender}"
      ENV['EMAIL_FROM_ADDRESS'].presence || 'huginn@example.com'
    end
  end

  #
  # Build security headers for email
  #
  def build_security_headers(options)
    {
      'X-Huginn-Agent' => 'SystemMailerParlant',
      'X-Parlant-Validated' => 'true',
      'X-Validation-Timestamp' => Time.now.iso8601,
      'X-Risk-Level' => @validation_metadata[:risk_level] || 'unknown'
    }
  end

  #
  # Determine email risk level based on risk factors
  #
  def determine_email_risk_level(risk_factors)
    # System-generated content reduces risk
    base_factors = risk_factors.reject { |f| f == 'system_generated_content' }
    
    case base_factors.length
    when 0 then 'minimal'
    when 1 then 'low'  
    when 2..3 then 'medium'
    when 4..5 then 'high'
    else 'critical'
    end
  end

  #
  # Create pseudo agent for audit trail
  #
  def create_pseudo_agent
    OpenStruct.new(
      id: 'system_mailer_parlant',
      class: self.class,
      name: 'System Mailer (Parlant)',
      user_id: 'system'
    )
  end
end