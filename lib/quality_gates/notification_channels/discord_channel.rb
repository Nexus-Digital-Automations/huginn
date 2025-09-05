# frozen_string_literal: true

require_relative 'base_channel'
require 'net/http'
require 'json'

module QualityGates
  module NotificationChannels
    # Discord notification channel using webhooks
    class DiscordChannel < BaseChannel
      def send_notification(message)
        return false unless available?

        begin
          payload = build_discord_payload(message)
          response = send_webhook_request(payload)
          
          success = response.code == '200' || response.code == '204'
          
          if success
            log_info("Discord notification sent successfully")
          else
            log_error("Discord webhook returned error", {
              status_code: response.code,
              response_body: response.body
            })
          end
          
          success
          
        rescue StandardError => e
          log_error("Failed to send Discord notification", {
            error: e.message
          })
          false
        end
      end

      def self.validate_configuration!(config)
        super(config)
        
        raise ArgumentError, "Discord channel requires webhook_url" unless config[:webhook_url]
        raise ArgumentError, "Invalid Discord webhook URL" unless valid_discord_webhook?(config[:webhook_url])
      end

      def self.valid_discord_webhook?(url)
        url&.match?(/discord(?:app)?\.com\/api\/webhooks/)
      end

      protected

      def configuration_valid?
        super && 
        @config[:webhook_url] && 
        self.class.valid_discord_webhook?(@config[:webhook_url])
      end

      private

      def build_discord_payload(message)
        payload = {
          username: @config[:username] || "Quality Gates",
          avatar_url: @config[:avatar_url]
        }

        # Use Discord embeds for rich formatting
        embed = {
          title: message[:title],
          description: message[:body],
          color: severity_color_int(message[:severity]),
          timestamp: Time.current.iso8601,
          footer: {
            text: "Quality Gates for Huginn"
          }
        }

        # Add fields for structured data
        if message[:fields]&.any?
          embed[:fields] = message[:fields].map do |field|
            {
              name: field[:title] || field[:name],
              value: field[:value].to_s,
              inline: field[:short] || false
            }
          end
        end

        payload[:embeds] = [embed]
        payload
      end

      def severity_color_int(severity)
        case severity
        when :critical then 0xe74c3c    # Red
        when :error then 0xf39c12       # Orange
        when :warning then 0xf1c40f     # Yellow
        when :info then 0x3498db        # Blue
        else 0x95a5a6                   # Gray
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