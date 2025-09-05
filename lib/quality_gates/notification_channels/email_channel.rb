# frozen_string_literal: true

require_relative 'base_channel'

module QualityGates
  module NotificationChannels
    # Email notification channel using ActionMailer
    class EmailChannel < BaseChannel
      def send_notification(message)
        return false unless available?

        begin
          QualityGatesMailer.notification_email(
            to: @config[:to_addresses],
            from: @config[:from_address],
            subject: message[:title],
            body: message[:body],
            severity: message[:severity]
          ).deliver_now

          log_info("Email notification sent successfully", {
            recipients: @config[:to_addresses],
            subject: message[:title]
          })
          true
          
        rescue StandardError => e
          log_error("Failed to send email notification", {
            error: e.message,
            recipients: @config[:to_addresses]
          })
          false
        end
      end

      def format_message(message_data, notification_type, severity)
        formatted = super(message_data, notification_type, severity)
        
        # Add email-specific formatting
        formatted[:subject] = build_email_subject(message_data, severity)
        formatted[:html_body] = build_html_body(message_data)
        
        formatted
      end

      def self.validate_configuration!(config)
        super(config)
        
        raise ArgumentError, "Email channel requires to_addresses" unless config[:to_addresses]&.any?
        raise ArgumentError, "Email channel requires from_address" unless config[:from_address]
        
        # Validate SMTP settings if provided
        if config[:smtp_settings]
          smtp = config[:smtp_settings]
          required_smtp_keys = %w[address port domain]
          required_smtp_keys.each do |key|
            unless smtp[key.to_sym] || smtp[key]
              raise ArgumentError, "SMTP settings missing required key: #{key}"
            end
          end
        end
      end

      protected

      def configuration_valid?
        super && 
        @config[:to_addresses]&.any? && 
        @config[:from_address] &&
        smtp_configured?
      end

      private

      def smtp_configured?
        # Check if SMTP is configured either in channel config or ActionMailer
        @config[:smtp_settings] || ActionMailer::Base.smtp_settings&.any?
      end

      def build_email_subject(message_data, severity)
        severity_prefix = case severity
                         when :critical then "[CRITICAL] "
                         when :error then "[ERROR] "
                         when :warning then "[WARNING] "
                         else ""
                         end
        
        "#{severity_prefix}#{message_data[:title]}"
      end

      def build_html_body(message_data)
        <<~HTML
          <!DOCTYPE html>
          <html>
          <head>
            <meta charset="utf-8">
            <style>
              body { font-family: Arial, sans-serif; line-height: 1.6; }
              .header { background: #f5f5f5; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
              .summary { background: white; border: 1px solid #ddd; padding: 15px; border-radius: 5px; margin: 10px 0; }
              .details { background: #fafafa; padding: 10px; border-radius: 3px; margin: 10px 0; }
              .actions { background: #e8f4f8; padding: 10px; border-radius: 3px; margin: 10px 0; }
              .critical { border-left: 4px solid #e74c3c; }
              .error { border-left: 4px solid #f39c12; }
              .warning { border-left: 4px solid #f1c40f; }
              .info { border-left: 4px solid #3498db; }
            </style>
          </head>
          <body>
            <div class="header">
              <h2>#{message_data[:title]}</h2>
              <p>Generated: #{Time.current.strftime('%Y-%m-%d %H:%M:%S %Z')}</p>
            </div>
            
            <div class="summary">
              #{message_data[:summary]}
            </div>
            
            #{build_details_section(message_data)}
            #{build_actions_section(message_data)}
            
            <p style="color: #666; font-size: 12px; margin-top: 30px;">
              This notification was sent by Quality Gates for Huginn.<br>
              Environment: #{@configuration.environment}
            </p>
          </body>
          </html>
        HTML
      end

      def build_details_section(message_data)
        return '' unless message_data[:details]&.any?

        details_html = message_data[:details].map do |key, value|
          next if key.to_s.start_with?('raw_')
          "<tr><td style='font-weight: bold;'>#{key.to_s.humanize}:</td><td>#{value}</td></tr>"
        end.compact.join("\n")

        <<~HTML
          <div class="details">
            <h3>Details</h3>
            <table style="width: 100%;">
              #{details_html}
            </table>
          </div>
        HTML
      end

      def build_actions_section(message_data)
        return '' unless message_data[:actions]&.any?

        actions_html = message_data[:actions].map.with_index do |action, index|
          "<li>#{action}</li>"
        end.join("\n")

        <<~HTML
          <div class="actions">
            <h3>Recommended Actions</h3>
            <ol>
              #{actions_html}
            </ol>
          </div>
        HTML
      end
    end
  end
end