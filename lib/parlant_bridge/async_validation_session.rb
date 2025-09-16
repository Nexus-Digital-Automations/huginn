# frozen_string_literal: true

require 'concurrent'
require 'securerandom'
require 'json'

module ParlantBridge
  ##
  # Async Validation Session for Real-time Conversational Validation
  # Provides streaming validation capabilities with progress callbacks,
  # confirmation workflows, and session state management for complex operations.
  #
  # @example Basic usage
  #   session = client.create_async_session(
  #     session_config: {
  #       operation_id: 'op_123',
  #       confirmation_required: true,
  #       timeout: 300
  #     },
  #     progress_callback: ->(progress) { puts "Progress: #{progress[:status]}" }
  #   )
  #   
  #   confirmation = session.wait_for_confirmation
  #
  class AsyncValidationSession
    include Concurrent::Async

    # Session states
    STATE_INITIALIZING = 'initializing'
    STATE_ACTIVE = 'active'
    STATE_WAITING_CONFIRMATION = 'waiting_confirmation'
    STATE_CONFIRMED = 'confirmed'
    STATE_REJECTED = 'rejected'
    STATE_TIMEOUT = 'timeout'
    STATE_ERROR = 'error'
    STATE_COMPLETED = 'completed'

    VALID_STATES = [
      STATE_INITIALIZING,
      STATE_ACTIVE,
      STATE_WAITING_CONFIRMATION,
      STATE_CONFIRMED,
      STATE_REJECTED,
      STATE_TIMEOUT,
      STATE_ERROR,
      STATE_COMPLETED
    ].freeze

    # Confirmation result structure
    ConfirmationResult = Struct.new(:approved, :reason, :confidence, :metadata, :timestamp) do
      def approved?
        approved == true
      end

      def rejected?
        !approved?
      end
    end

    attr_reader :session_id, :client, :config, :logger, :state, :created_at, 
                :progress_callback, :confirmation_result, :error

    ##
    # Initialize async validation session
    #
    # @param client [HttpClientService] HTTP client service instance
    # @param session_id [String] Unique session identifier
    # @param config [Hash] Session configuration
    # @param progress_callback [Proc] Optional callback for progress updates
    # @param logger [Logger] Logger instance for monitoring
    #
    def initialize(client:, session_id:, config:, progress_callback: nil, logger: nil)
      super() # Initialize Concurrent::Async
      
      @client = client
      @session_id = session_id
      @config = config.dup
      @progress_callback = progress_callback
      @logger = logger || Logger.new($stdout, level: Logger::INFO)
      
      # Session state management
      @state = STATE_INITIALIZING
      @state_mutex = Mutex.new
      @created_at = Time.now
      @updated_at = Time.now
      
      # Confirmation management
      @confirmation_result = nil
      @confirmation_future = nil
      @confirmation_timeout = config[:timeout] || 300
      
      # Progress tracking
      @progress_history = []
      @progress_mutex = Mutex.new
      
      # Error handling
      @error = nil
      
      # WebSocket connection for real-time updates (if supported)
      @websocket_connection = nil
      
      @logger.info("AsyncValidationSession initialized - Session: #{@session_id}, Timeout: #{@confirmation_timeout}s")
      
      # Initialize session
      initialize_session
    end

    ##
    # Wait for user confirmation with timeout
    #
    # @param timeout [Integer] Optional timeout override in seconds
    # @return [ConfirmationResult] Confirmation result
    #
    def wait_for_confirmation(timeout: nil)
      effective_timeout = timeout || @confirmation_timeout
      
      @logger.info("Waiting for confirmation - Session: #{@session_id}, Timeout: #{effective_timeout}s")
      
      update_state(STATE_WAITING_CONFIRMATION)
      emit_progress('waiting_for_confirmation', 'User confirmation required')
      
      # Create confirmation future
      @confirmation_future = Concurrent::Future.execute do
        wait_for_user_response(effective_timeout)
      end
      
      begin
        result = @confirmation_future.value!(effective_timeout + 5) # Extra buffer
        
        if result.approved?
          update_state(STATE_CONFIRMED)
          emit_progress('confirmed', 'User approved operation')
        else
          update_state(STATE_REJECTED)
          emit_progress('rejected', "User rejected operation: #{result.reason}")
        end
        
        @confirmation_result = result
        result
        
      rescue Concurrent::TimeoutError
        update_state(STATE_TIMEOUT)
        emit_progress('timeout', 'Confirmation request timed out')
        @confirmation_result = ConfirmationResult.new(
          false, 'Confirmation timeout', 0.0, { timeout: true }, Time.now
        )
        @confirmation_result
      rescue StandardError => e
        handle_session_error(e)
        raise e
      end
    end

    ##
    # Send progress update through the session
    #
    # @param status [String] Progress status
    # @param message [String] Progress message
    # @param metadata [Hash] Additional progress data
    #
    def update_progress(status, message, metadata = {})
      progress_data = {
        session_id: @session_id,
        status: status,
        message: message,
        metadata: metadata,
        timestamp: Time.now.iso8601
      }
      
      add_progress_entry(progress_data)
      emit_progress(status, message, metadata)
    end

    ##
    # Get current session status
    #
    # @return [Hash] Comprehensive session status
    #
    def status
      @state_mutex.synchronize do
        {
          session_id: @session_id,
          state: @state,
          created_at: @created_at.iso8601,
          updated_at: @updated_at.iso8601,
          elapsed_time: (Time.now - @created_at).round(2),
          config: @config,
          progress_count: @progress_history.length,
          confirmation_result: @confirmation_result&.to_h,
          error: @error&.message,
          websocket_connected: websocket_connected?
        }
      end
    end

    ##
    # Get session progress history
    #
    # @return [Array] Array of progress entries
    #
    def progress_history
      @progress_mutex.synchronize { @progress_history.dup }
    end

    ##
    # Check if session is active
    #
    # @return [Boolean] True if session is active
    #
    def active?
      [STATE_ACTIVE, STATE_WAITING_CONFIRMATION].include?(@state)
    end

    ##
    # Check if session is completed
    #
    # @return [Boolean] True if session is completed
    #
    def completed?
      [STATE_CONFIRMED, STATE_REJECTED, STATE_TIMEOUT, STATE_ERROR, STATE_COMPLETED].include?(@state)
    end

    ##
    # Check if session has error
    #
    # @return [Boolean] True if session has error
    #
    def error?
      @state == STATE_ERROR
    end

    ##
    # Cancel session
    #
    # @param reason [String] Cancellation reason
    #
    def cancel(reason = 'Session cancelled by user')
      @logger.info("Cancelling session - Session: #{@session_id}, Reason: #{reason}")
      
      @confirmation_future&.cancel
      update_state(STATE_REJECTED)
      
      @confirmation_result = ConfirmationResult.new(
        false, reason, 0.0, { cancelled: true }, Time.now
      )
      
      emit_progress('cancelled', reason)
      close_websocket_connection
    end

    ##
    # Close session and cleanup resources
    #
    def close
      @logger.info("Closing session - Session: #{@session_id}")
      
      @confirmation_future&.cancel
      close_websocket_connection
      update_state(STATE_COMPLETED)
      emit_progress('closed', 'Session closed')
    end

    private

    ##
    # Initialize session with remote service
    #
    def initialize_session
      begin
        # Send initialization request to Parlant service
        init_response = send_session_request('/session/initialize', {
          session_id: @session_id,
          config: @config,
          client_info: {
            type: 'huginn_async_session',
            version: '1.0.0'
          }
        })
        
        if init_response.success?
          update_state(STATE_ACTIVE)
          emit_progress('initialized', 'Session initialized successfully')
          
          # Attempt to establish WebSocket connection for real-time updates
          establish_websocket_connection if @config[:enable_websocket]
        else
          raise "Session initialization failed: #{init_response.body}"
        end
        
      rescue StandardError => e
        handle_session_error(e)
        raise e
      end
    end

    ##
    # Wait for user response through polling or WebSocket
    #
    def wait_for_user_response(timeout)
      start_time = Time.now
      poll_interval = 2 # seconds
      
      while (Time.now - start_time) < timeout
        # Check for response via WebSocket first
        if websocket_connected?
          ws_response = check_websocket_response
          return ws_response if ws_response
        end
        
        # Fallback to HTTP polling
        response = poll_for_confirmation
        return response if response
        
        sleep(poll_interval)
      end
      
      # Timeout reached
      ConfirmationResult.new(
        false, 'Confirmation timeout', 0.0, { timeout: true }, Time.now
      )
    end

    ##
    # Poll for confirmation via HTTP
    #
    def poll_for_confirmation
      response = send_session_request('/session/poll', {
        session_id: @session_id,
        poll_type: 'confirmation'
      })
      
      return nil unless response.success?
      
      data = JSON.parse(response.body)
      return nil unless data['confirmation_available']
      
      ConfirmationResult.new(
        data['approved'],
        data['reason'],
        data['confidence']&.to_f || 0.0,
        data['metadata'] || {},
        Time.parse(data['timestamp'])
      )
      
    rescue JSON::ParserError, StandardError => e
      @logger.error("Error polling for confirmation: #{e.message}")
      nil
    end

    ##
    # Establish WebSocket connection for real-time updates
    #
    def establish_websocket_connection
      return if @websocket_connection # Already connected
      
      begin
        ws_url = @client.server_url.gsub(/^http/, 'ws') + '/session/websocket'
        
        # Note: This is a simplified WebSocket implementation
        # In production, you'd use a proper WebSocket client library
        @websocket_connection = WebSocketConnection.new(
          url: ws_url,
          session_id: @session_id,
          on_message: method(:handle_websocket_message),
          logger: @logger
        )
        
        @websocket_connection.connect
        @logger.info("WebSocket connection established - Session: #{@session_id}")
        
      rescue StandardError => e
        @logger.warn("Failed to establish WebSocket connection: #{e.message}")
        @websocket_connection = nil
      end
    end

    ##
    # Handle incoming WebSocket message
    #
    def handle_websocket_message(message)
      data = JSON.parse(message)
      
      case data['type']
      when 'confirmation_response'
        @websocket_confirmation_result = ConfirmationResult.new(
          data['approved'],
          data['reason'],
          data['confidence']&.to_f || 0.0,
          data['metadata'] || {},
          Time.now
        )
      when 'progress_update'
        emit_progress(data['status'], data['message'], data['metadata'] || {})
      when 'session_update'
        handle_session_update(data)
      end
      
    rescue JSON::ParserError, StandardError => e
      @logger.error("Error handling WebSocket message: #{e.message}")
    end

    ##
    # Check for WebSocket confirmation response
    #
    def check_websocket_response
      @websocket_confirmation_result.tap { @websocket_confirmation_result = nil }
    end

    ##
    # Handle session update from WebSocket
    #
    def handle_session_update(data)
      case data['update_type']
      when 'state_change'
        update_state(data['new_state']) if VALID_STATES.include?(data['new_state'])
      when 'timeout_warning'
        emit_progress('timeout_warning', "Session will timeout in #{data['remaining_seconds']} seconds")
      end
    end

    ##
    # Close WebSocket connection
    #
    def close_websocket_connection
      return unless @websocket_connection
      
      begin
        @websocket_connection.close
        @websocket_connection = nil
        @logger.info("WebSocket connection closed - Session: #{@session_id}")
      rescue StandardError => e
        @logger.warn("Error closing WebSocket connection: #{e.message}")
      end
    end

    ##
    # Check if WebSocket is connected
    #
    def websocket_connected?
      @websocket_connection&.connected? || false
    end

    ##
    # Send HTTP request to session endpoint
    #
    def send_session_request(endpoint, payload)
      uri = URI("#{@client.server_url}#{endpoint}")
      
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = uri.scheme == 'https'
      http.open_timeout = 10
      http.read_timeout = 30
      
      request = Net::HTTP::Post.new(uri)
      request['Content-Type'] = 'application/json'
      request['X-Session-ID'] = @session_id
      request.body = JSON.generate(payload)
      
      response = http.request(request)
      
      HttpResponse.new(
        status: response.code.to_i,
        body: response.body,
        headers: response.to_hash,
        success: response.is_a?(Net::HTTPSuccess)
      )
    end

    ##
    # Update session state thread-safely
    #
    def update_state(new_state)
      @state_mutex.synchronize do
        old_state = @state
        @state = new_state
        @updated_at = Time.now
        
        @logger.debug("State transition - Session: #{@session_id}, #{old_state} -> #{new_state}")
      end
    end

    ##
    # Add progress entry to history
    #
    def add_progress_entry(progress_data)
      @progress_mutex.synchronize do
        @progress_history << progress_data
        # Keep only last 100 entries to prevent memory bloat
        @progress_history.shift if @progress_history.size > 100
      end
    end

    ##
    # Emit progress update via callback
    #
    def emit_progress(status, message, metadata = {})
      return unless @progress_callback
      
      begin
        @progress_callback.call({
          session_id: @session_id,
          status: status,
          message: message,
          metadata: metadata,
          state: @state,
          timestamp: Time.now.iso8601
        })
      rescue StandardError => e
        @logger.error("Error in progress callback: #{e.message}")
      end
    end

    ##
    # Handle session error
    #
    def handle_session_error(error)
      @error = error
      update_state(STATE_ERROR)
      emit_progress('error', error.message)
      @logger.error("Session error - Session: #{@session_id}, Error: #{error.message}")
    end
  end

  ##
  # Simple WebSocket Connection wrapper
  # In production, replace with a proper WebSocket client library
  #
  class WebSocketConnection
    attr_reader :url, :session_id, :logger

    def initialize(url:, session_id:, on_message:, logger:)
      @url = url
      @session_id = session_id
      @on_message = on_message
      @logger = logger
      @connected = false
    end

    def connect
      # Placeholder for WebSocket connection
      # In production, implement with proper WebSocket library
      @connected = true
      @logger.info("WebSocket connected to #{@url}")
    end

    def connected?
      @connected
    end

    def close
      @connected = false
      @logger.info("WebSocket connection closed")
    end

    def send_message(message)
      # Placeholder for sending WebSocket message
      @logger.debug("WebSocket send: #{message}")
    end
  end
end