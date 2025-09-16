require 'net/smtp'
require_relative '../../../lib/parlant_integration'

module Agents
  # EmailAgent with comprehensive Parlant integration
  # 
  # Enhanced email agent that includes conversational validation for all email sending operations
  # through Parlant's conversational AI validation engine, ensuring secure and audited communication.
  #
  class EmailAgentParlant < Agent
    include EmailConcern
    include ParlantIntegration::AgentIntegration

    can_dry_run!
    default_schedule "never"
    cannot_create_events!
    no_bulk_receive!

    description <<~MD
      The Enhanced Email Agent with Parlant Integration sends any events it receives via email immediately,
      with comprehensive conversational validation and audit trails for enterprise security.

      ## Parlant Integration Features:
      - **Conversational Validation**: Each email is validated through natural language conversation
      - **Risk Assessment**: Automatic risk classification based on recipients and content
      - **Audit Trails**: Complete audit trail for all email operations with approval reasoning
      - **Security Controls**: Multi-level approval for sensitive or bulk email operations
      - **Performance Optimization**: Intelligent caching for similar email validations

      You can specify the email's subject line by providing a `subject` option, which can contain [Liquid](https://github.com/huginn/huginn/wiki/Formatting-Events-using-Liquid) formatting.  E.g.,
      you could provide `"Huginn email"` to set a simple subject, or `{{subject}}` to use the `subject` key from the incoming Event.

      By default, the email body will contain an optional `headline`, followed by a listing of the Events' keys.

      You can customize the email body by including the optional `body` param.  Like the `subject`, the `body` can be a simple message
      or a Liquid template.  You could send only the Event's `some_text` field with a `body` set to `{{ some_text }}`.
      The body can contain simple HTML and will be sanitized. Note that when using `body`, it will be wrapped with `<html>` and `<body>` tags,
      so you do not need to add these yourself.

      You can specify one or more `recipients` for the email, or skip the option in order to send the email to your
      account's default email address.

      You can provide a `from` address for the email, or leave it blank to default to the value of `EMAIL_FROM_ADDRESS` (`#{ENV['EMAIL_FROM_ADDRESS']}`).

      You can provide a `content_type` for the email and specify `text/plain` or `text/html` to be sent.
      If you do not specify `content_type`, then the recipient email server will determine the correct rendering.

      Set `expected_receive_period_in_days` to the maximum amount of time that you'd expect to pass between Events being received by this Agent.
    MD

    def default_options
      {
        'subject' => "You have a notification!",
        'headline' => "Your notification:",
        'expected_receive_period_in_days' => "2",
        # Parlant-specific options
        'parlant_validation_enabled' => true,
        'require_approval_for_external_emails' => true,
        'max_recipients_without_approval' => 5
      }
    end

    def working?
      received_event_without_error?
    end

    def receive(incoming_events)
      incoming_events.each do |event|
        process_event_with_parlant_validation(event)
      end
    end

    private

    #
    # Process event with comprehensive Parlant validation
    #
    def process_event_with_parlant_validation(event)
      recipients_list = recipients(event.payload)
      interpolated_options = interpolated(event)

      # Assess email sending risk
      email_risk = assess_email_risk(recipients_list, interpolated_options, event)

      recipients_list.each do |recipient|
        # Parlant conversational validation for email sending
        parlant_validate_operation('send_email', {
          recipient: recipient,
          subject: interpolated_options['subject'],
          from: interpolated_options['from'],
          event_id: event.id,
          payload_summary: event.payload.keys.join(', '),
          risk_assessment: email_risk,
          recipient_count: recipients_list.length,
          external_recipient: is_external_recipient?(recipient)
        }) do
          send_validated_email(recipient, interpolated_options, event)
        end
      rescue StandardError => e
        handle_email_error(recipient, event, e)
      end
    end

    #
    # Send email after Parlant validation approval
    #
    def send_validated_email(recipient, interpolated_options, event)
      start_time = Time.now

      SystemMailer.send_message(
        to: recipient,
        from: interpolated_options['from'],
        subject: interpolated_options['subject'],
        headline: interpolated_options['headline'],
        body: interpolated_options['body'],
        content_type: interpolated_options['content_type'],
        groups: [present(event.payload)]
      ).deliver_now

      send_time_ms = ((Time.now - start_time) * 1000).round(2)

      # Create comprehensive audit trail for successful email
      parlant_audit('email_sent', {
        status: 'success',
        recipient: recipient,
        subject: interpolated_options['subject'],
        event_id: event.id,
        delivery_time_ms: send_time_ms,
        external_recipient: is_external_recipient?(recipient)
      }, {
        event_payload_keys: event.payload.keys,
        agent_id: self.id,
        agent_name: self.name
      })

      log "✅ Sent mail to #{recipient} with event #{event.id} (validated by Parlant, #{send_time_ms}ms)"
    end

    #
    # Handle email sending errors with audit trail
    #
    def handle_email_error(recipient, event, error)
      # Create comprehensive audit trail for failed email
      parlant_audit('email_failed', {
        status: 'failure',
        recipient: recipient,
        error: error.message,
        error_class: error.class.name,
        event_id: event.id
      }, {
        event_payload_keys: event.payload.keys,
        agent_id: self.id,
        agent_name: self.name,
        backtrace: error.backtrace&.first(5)
      })

      error("❌ Error sending mail to #{recipient} with event #{event.id}: #{error.message}")
      raise
    end

    #
    # Assess risk level for email operations
    #
    def assess_email_risk(recipients_list, interpolated_options, event)
      risk_factors = []
      
      # Multiple recipients increase risk
      if recipients_list.length > (interpolated_options['max_recipients_without_approval'] || 5).to_i
        risk_factors << "bulk_email_#{recipients_list.length}_recipients"
      end

      # External recipients increase risk
      external_recipients = recipients_list.select { |r| is_external_recipient?(r) }
      if external_recipients.any?
        risk_factors << "external_recipients_#{external_recipients.length}"
      end

      # Sensitive content keywords increase risk
      subject_body = "#{interpolated_options['subject']} #{interpolated_options['body']}".downcase
      if subject_body.match?(/urgent|alert|warning|critical|emergency|confidential|sensitive/)
        risk_factors << 'sensitive_content'
      end

      # File attachments or large payloads increase risk
      if event.payload.to_s.length > 10_000
        risk_factors << 'large_payload'
      end

      {
        level: determine_risk_level(risk_factors.length),
        factors: risk_factors,
        recipient_analysis: {
          total: recipients_list.length,
          external: external_recipients.length,
          internal: recipients_list.length - external_recipients.length
        }
      }
    end

    #
    # Determine if recipient is external (not organization email)
    #
    def is_external_recipient?(recipient)
      return false unless recipient&.include?('@')
      
      # Define internal domains (customize for your organization)
      internal_domains = ENV.fetch('INTERNAL_EMAIL_DOMAINS', 'localhost,example.com').split(',')
      recipient_domain = recipient.split('@').last
      
      !internal_domains.include?(recipient_domain)
    end

    #
    # Determine overall risk level based on risk factors
    #
    def determine_risk_level(factor_count)
      case factor_count
      when 0 then 'low'
      when 1..2 then 'medium'  
      when 3..4 then 'high'
      else 'critical'
      end
    end

    # Add Parlant validation to critical methods
    parlant_validate_methods :receive, risk_level: ParlantIntegration::RiskLevel::HIGH
    parlant_validate_methods :process_event_with_parlant_validation, risk_level: ParlantIntegration::RiskLevel::MEDIUM
  end
end