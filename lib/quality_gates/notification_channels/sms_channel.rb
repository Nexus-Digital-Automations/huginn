# frozen_string_literal: true

require_relative 'base_channel'

module QualityGates
  module NotificationChannels
    # SMS notification channel (requires Twilio or similar service)
    class SmsChannel < BaseChannel
      def send_notification(message)
        return false unless available?

        # Placeholder implementation - would integrate with SMS service like Twilio
        log_info("SMS notification would be sent", {
          message: message[:title],
          recipients: @config[:to_numbers]
        })
        
        # For now, return true to indicate the channel is working
        # In production, this would integrate with actual SMS service
        true
      end

      def format_message(message_data, notification_type, severity)
        # SMS has character limits, so format concisely
        severity_prefix = case severity
                         when :critical then "🔴 CRITICAL: "
                         when :error then "⚠️ ERROR: "
                         when :warning then "⚠️ WARNING: "
                         else ""
                         end

        {
          text: "#{severity_prefix}#{message_data[:title]} - #{message_data[:summary]}"[0..160], # SMS limit
          severity: severity,
          timestamp: Time.current.iso8601
        }
      end

      def self.validate_configuration!(config)
        super(config)
        
        raise ArgumentError, "SMS channel requires to_numbers" unless config[:to_numbers]&.any?
        raise ArgumentError, "SMS channel requires provider" unless config[:provider]
        
        # Validate provider-specific settings
        case config[:provider]
        when 'twilio'
          validate_twilio_config!(config)
        else
          raise ArgumentError, "Unsupported SMS provider: #{config[:provider]}"
        end
      end

      def self.validate_twilio_config!(config)
        required_keys = %w[account_sid auth_token from_number]
        required_keys.each do |key|
          unless config[key.to_sym] || config[key]
            raise ArgumentError, "Twilio SMS requires #{key}"
          end
        end
      end

      protected

      def configuration_valid?
        super && 
        @config[:to_numbers]&.any? && 
        @config[:provider] &&
        provider_configured?
      end

      private

      def provider_configured?
        case @config[:provider]
        when 'twilio'
          @config[:account_sid] && @config[:auth_token] && @config[:from_number]
        else
          false
        end
      end
    end
  end
end