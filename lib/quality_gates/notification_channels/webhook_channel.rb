# frozen_string_literal: true

require_relative 'base_channel'
require 'net/http'
require 'json'

module QualityGates
  module NotificationChannels
    # Generic webhook notification channel
    class WebhookChannel < BaseChannel
      def send_notification(message)
        return false unless available?

        begin
          payload = build_webhook_payload(message)
          response = send_webhook_request(payload)
          
          success = response.code.start_with?('2')
          
          if success
            log_info("Webhook notification sent successfully", {
              url: sanitize_url(@config[:url]),
              status_code: response.code
            })
          else
            log_error("Webhook returned error", {
              url: sanitize_url(@config[:url]),
              status_code: response.code,
              response_body: response.body
            })
          end
          
          success
          
        rescue StandardError => e
          log_error("Failed to send webhook notification", {
            error: e.message,
            url: sanitize_url(@config[:url])
          })
          false
        end
      end

      def self.validate_configuration!(config)
        super(config)
        
        raise ArgumentError, "Webhook channel requires url" unless config[:url]
        raise ArgumentError, "Invalid webhook URL" unless valid_url?(config[:url])
        
        # Validate method if specified
        if config[:method] && !%w[GET POST PUT PATCH].include?(config[:method].upcase)
          raise ArgumentError, "Invalid HTTP method: #{config[:method]}"
        end
      end

      def self.valid_url?(url)
        uri = URI.parse(url)
        uri.is_a?(URI::HTTP) || uri.is_a?(URI::HTTPS)
      rescue URI::InvalidURIError
        false
      end

      protected

      def configuration_valid?
        super && 
        @config[:url] && 
        self.class.valid_url?(@config[:url])
      end

      private

      def build_webhook_payload(message)
        # Build comprehensive payload for webhook
        payload = {
          event: "quality_gates_notification",
          timestamp: Time.current.iso8601,
          notification: {
            title: message[:title],
            body: message[:body],
            severity: message[:severity],
            notification_type: message[:notification_type]
          }
        }

        # Add webhook-specific data
        payload[:metadata] = {
          huginn_version: get_huginn_version,
          quality_gates_version: "1.0.0",
          environment: @configuration.environment
        }

        # Include original message data for maximum flexibility
        payload[:raw_message_data] = message

        payload
      end

      def send_webhook_request(payload)
        uri = URI(@config[:url])
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = uri.scheme == 'https'
        http.open_timeout = @config[:timeout] || 30
        http.read_timeout = @config[:timeout] || 30

        # Determine HTTP method
        http_method = (@config[:method] || 'POST').upcase
        request_class = case http_method
                       when 'GET' then Net::HTTP::Get
                       when 'POST' then Net::HTTP::Post  
                       when 'PUT' then Net::HTTP::Put
                       when 'PATCH' then Net::HTTP::Patch
                       else Net::HTTP::Post
                       end

        request = request_class.new(uri)
        
        # Set headers
        default_headers = { 'Content-Type' => 'application/json' }
        headers = default_headers.merge(@config[:headers] || {})
        headers.each { |key, value| request[key] = value }
        
        # Apply authentication
        apply_authentication(request)
        
        # Set body for non-GET requests
        unless http_method == 'GET'
          request.body = JSON.generate(payload)
        end

        # Make request with retry logic
        attempt = 0
        max_retries = @config[:retry_count] || 2
        
        begin
          response = http.request(request)
          
          # Retry on server errors if configured
          if response.code.start_with?('5') && attempt < max_retries
            attempt += 1
            sleep(2 ** attempt) # Exponential backoff
            retry
          end
          
          response
        rescue Net::TimeoutError, Net::OpenTimeout => e
          if attempt < max_retries
            attempt += 1
            sleep(2 ** attempt)
            retry
          else
            raise e
          end
        end
      end

      def apply_authentication(request)
        auth_config = @config[:auth]
        return unless auth_config && auth_config[:type] != 'none'

        case auth_config[:type].to_s
        when 'basic'
          request.basic_auth(auth_config[:username], auth_config[:password])
        when 'bearer'
          request['Authorization'] = "Bearer #{auth_config[:token]}"
        when 'api_key'
          header_name = auth_config[:header] || 'X-API-Key'
          request[header_name] = auth_config[:key]
        when 'custom'
          # Allow custom header-based authentication
          auth_config[:headers]&.each do |header, value|
            request[header] = value
          end
        end
      end

      def sanitize_url(url)
        return "[invalid]" unless url
        
        # Remove sensitive information from URL for logging
        uri = URI.parse(url)
        "#{uri.scheme}://#{uri.host}#{uri.port != uri.default_port ? ":#{uri.port}" : ''}#{uri.path}"
      rescue URI::InvalidURIError
        "[invalid]"
      end

      def get_huginn_version
        File.read(File.join(Rails.root, 'VERSION')).strip
      rescue StandardError
        'unknown'
      end
    end
  end
end