# frozen_string_literal: true

require_relative 'base_channel'
require 'net/http'
require 'json'

module QualityGates
  module NotificationChannels
    # Microsoft Teams notification channel using incoming webhooks
    class TeamsChannel < BaseChannel
      def send_notification(message)
        return false unless available?

        begin
          payload = build_teams_payload(message)
          response = send_webhook_request(payload)
          
          if response.code == '200'
            log_info("Teams notification sent successfully")
            true
          else
            log_error("Teams webhook returned error", {
              status_code: response.code,
              response_body: response.body
            })
            false
          end
          
        rescue StandardError => e
          log_error("Failed to send Teams notification", {
            error: e.message
          })
          false
        end
      end

      def self.validate_configuration!(config)
        super(config)
        
        raise ArgumentError, "Teams channel requires webhook_url" unless config[:webhook_url]
        raise ArgumentError, "Invalid Teams webhook URL" unless valid_teams_webhook?(config[:webhook_url])
      end

      def self.valid_teams_webhook?(url)
        url&.match?(/outlook\.office\.com\/webhook/)
      end

      protected

      def configuration_valid?
        super && 
        @config[:webhook_url] && 
        self.class.valid_teams_webhook?(@config[:webhook_url])
      end

      private

      def build_teams_payload(message)
        {
          "@type" => "MessageCard",
          "@context" => "http://schema.org/extensions",
          "themeColor" => severity_color(message[:severity]),
          "summary" => message[:title],
          "sections" => [{
            "activityTitle" => message[:title],
            "activitySubtitle" => "Quality Gates for Huginn",
            "text" => message[:body],
            "facts" => build_teams_facts(message)
          }]
        }
      end

      def build_teams_facts(message)
        facts = []
        
        facts << {
          "name" => "Severity",
          "value" => message[:severity].to_s.capitalize
        }
        
        facts << {
          "name" => "Timestamp", 
          "value" => Time.current.strftime('%Y-%m-%d %H:%M:%S %Z')
        }
        
        facts << {
          "name" => "Environment",
          "value" => @configuration.environment
        }

        facts
      end

      def severity_color(severity)
        case severity
        when :critical then "FF0000"    # Red
        when :error then "FF8C00"       # Orange
        when :warning then "FFD700"     # Yellow
        when :info then "0078D4"        # Microsoft Blue
        else "808080"                   # Gray
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