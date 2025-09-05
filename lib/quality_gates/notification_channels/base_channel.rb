# frozen_string_literal: true

module QualityGates
  module NotificationChannels
    # Base class for all notification channels
    # Provides common interface and functionality for sending notifications
    class BaseChannel
      attr_reader :config, :configuration

      def initialize(channel_config, configuration)
        @config = channel_config || {}
        @configuration = configuration
        @enabled = @config[:enabled] == true
        
        validate_configuration!
      end

      # Send notification - must be implemented by subclasses
      def send_notification(message)
        raise NotImplementedError, "#{self.class} must implement #send_notification"
      end

      # Format message for this channel - can be overridden by subclasses
      def format_message(message_data, notification_type, severity)
        {
          title: message_data[:title],
          body: format_message_body(message_data),
          severity: severity,
          timestamp: Time.current.iso8601,
          notification_type: notification_type
        }
      end

      # Check if channel is available - can be overridden by subclasses
      def available?
        @enabled && configuration_valid?
      end

      # Validate channel configuration - should be overridden by subclasses
      def self.validate_configuration!(config)
        # Base validation - subclasses should call super and add their own
        raise ArgumentError, "Channel configuration cannot be nil" if config.nil?
        raise ArgumentError, "Channel must have enabled flag" unless config.key?(:enabled)
      end

      protected

      def format_message_body(message_data)
        body_parts = []
        
        body_parts << message_data[:summary] if message_data[:summary]
        
        if message_data[:details]&.any?
          body_parts << "\nDetails:"
          message_data[:details].each do |key, value|
            next if key.to_s.start_with?('raw_') # Skip raw data
            body_parts << "  #{key.to_s.humanize}: #{value}"
          end
        end

        if message_data[:actions]&.any?
          body_parts << "\nRecommended Actions:"
          message_data[:actions].each_with_index do |action, index|
            body_parts << "  #{index + 1}. #{action}"
          end
        end

        body_parts.join("\n")
      end

      def configuration_valid?
        # Basic configuration validation
        @config.is_a?(Hash) && @config[:enabled] == true
      end

      def validate_configuration!
        self.class.validate_configuration!(@config)
      end

      def log_info(message, data = {})
        Rails.logger&.info("#{self.class.name} - #{message}: #{data}")
      end

      def log_error(message, data = {})
        Rails.logger&.error("#{self.class.name} - #{message}: #{data}")
      end
    end
  end
end