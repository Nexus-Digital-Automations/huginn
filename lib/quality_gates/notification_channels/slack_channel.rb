# frozen_string_literal: true

require_relative 'base_channel'
require 'net/http'
require 'json'

module QualityGates
  module NotificationChannels
    # Slack notification channel using incoming webhooks
    class SlackChannel < BaseChannel
      def send_notification(message)
        return false unless available?

        begin
          payload = build_slack_payload(message)
          response = send_webhook_request(payload)
          
          if response.code == '200'
            log_info("Slack notification sent successfully", {
              channel: @config[:channel],
              webhook_response: response.code
            })
            true
          else
            log_error("Slack webhook returned error", {
              status_code: response.code,
              response_body: response.body
            })
            false
          end
          
        rescue StandardError => e
          log_error("Failed to send Slack notification", {
            error: e.message,
            webhook_url: @config[:webhook_url]&.gsub(/hooks\.slack\.com.*/, 'hooks.slack.com/[redacted]')
          })
          false
        end
      end

      def format_message(message_data, notification_type, severity)
        formatted = super(message_data, notification_type, severity)
        
        # Add Slack-specific formatting
        formatted[:color] = severity_color(severity)
        formatted[:fields] = build_slack_fields(message_data)
        formatted[:attachments] = build_slack_attachments(message_data, severity)
        
        formatted
      end

      def self.validate_configuration!(config)
        super(config)
        
        raise ArgumentError, "Slack channel requires webhook_url" unless config[:webhook_url]
        raise ArgumentError, "Invalid Slack webhook URL" unless valid_slack_webhook?(config[:webhook_url])
      end

      def self.valid_slack_webhook?(url)
        url&.match?(/https:\/\/hooks\.slack\.com\/services\//)
      end

      protected

      def configuration_valid?
        super && 
        @config[:webhook_url] && 
        self.class.valid_slack_webhook?(@config[:webhook_url])
      end

      private

      def build_slack_payload(message)
        payload = {
          username: @config[:username] || "Quality Gates Bot",
          icon_emoji: @config[:icon_emoji] || ":warning:",
          channel: @config[:channel]
        }

        # Use modern Slack blocks format if available, fallback to attachments
        if message[:attachments]
          payload[:attachments] = message[:attachments]
        else
          payload[:text] = message[:title]
          payload[:attachments] = [{
            color: message[:color],
            text: message[:body],
            fields: message[:fields] || [],
            ts: Time.current.to_i
          }]
        end

        payload
      end

      def build_slack_fields(message_data)
        fields = []
        
        # Add execution context fields
        if message_data[:details]
          if message_data[:details][:execution_id]
            fields << {
              title: "Execution ID",
              value: message_data[:details][:execution_id],
              short: true
            }
          end
          
          if message_data[:details][:environment]
            fields << {
              title: "Environment", 
              value: message_data[:details][:environment],
              short: true
            }
          end
          
          if message_data[:details][:timestamp]
            fields << {
              title: "Timestamp",
              value: message_data[:details][:timestamp],
              short: true
            }
          end
        end

        # Add metrics if available
        if message_data[:metrics]
          message_data[:metrics].each do |key, value|
            fields << {
              title: key.to_s.humanize,
              value: value.to_s,
              short: true
            }
          end
        end

        fields
      end

      def build_slack_attachments(message_data, severity)
        attachments = []
        
        # Main attachment with message content
        main_attachment = {
          color: severity_color(severity),
          title: message_data[:title],
          text: message_data[:summary],
          fields: build_slack_fields(message_data),
          footer: "Quality Gates for Huginn",
          footer_icon: "https://github.com/huginn/huginn/raw/master/media/huginn-logo.png",
          ts: Time.current.to_i
        }

        attachments << main_attachment

        # Add actions attachment if actions are present
        if message_data[:actions]&.any?
          actions_text = message_data[:actions].map.with_index do |action, index|
            "#{index + 1}. #{action}"
          end.join("\n")

          actions_attachment = {
            color: "#36a64f",
            title: "Recommended Actions",
            text: actions_text,
            footer: "Quality Gates Actions"
          }
          
          attachments << actions_attachment
        end

        # Add details attachment for failed gates
        if message_data[:details] && message_data[:details][:failed_gates]&.any?
          failed_gates = message_data[:details][:failed_gates]
          details_text = "Failed Gates:\n" + failed_gates.map { |gate| "• #{gate}" }.join("\n")
          
          details_attachment = {
            color: severity_color(:error),
            title: "Failure Details",
            text: details_text
          }
          
          attachments << details_attachment
        end

        attachments
      end

      def severity_color(severity)
        case severity
        when :critical then "#e74c3c"    # Red
        when :error then "#f39c12"       # Orange  
        when :warning then "#f1c40f"     # Yellow
        when :info then "#3498db"        # Blue
        else "#95a5a6"                   # Gray
        end
      end

      def send_webhook_request(payload)
        uri = URI(@config[:webhook_url])
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = true
        http.open_timeout = 10
        http.read_timeout = 30

        request = Net::HTTP::Post.new(uri)
        request['Content-Type'] = 'application/json'
        request.body = JSON.generate(payload)

        http.request(request)
      end
    end
  end
end