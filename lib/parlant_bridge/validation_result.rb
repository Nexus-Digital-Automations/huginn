# frozen_string_literal: true

require 'json'

module ParlantBridge
  ##
  # Validation Result Class for Parlant Bridge Integration
  # Represents the result of a conversational validation request with comprehensive
  # status information, confidence scoring, and audit trail data.
  #
  # @example Basic usage
  #   result = ValidationResult.new(
  #     status: 'approved',
  #     operation_id: 'op_123',
  #     confidence: 0.95,
  #     reason: 'User confirmed operation'
  #   )
  #   
  #   if result.approved?
  #     # Execute operation
  #   end
  #
  class ValidationResult
    # Validation status constants
    STATUS_APPROVED = 'approved'
    STATUS_REJECTED = 'rejected'
    STATUS_REQUIRES_CONFIRMATION = 'requires_confirmation'
    STATUS_PENDING = 'pending'
    STATUS_TIMEOUT = 'timeout'
    STATUS_ERROR = 'error'
    STATUS_BYPASS = 'bypass'

    VALID_STATUSES = [
      STATUS_APPROVED,
      STATUS_REJECTED,
      STATUS_REQUIRES_CONFIRMATION,
      STATUS_PENDING,
      STATUS_TIMEOUT,
      STATUS_ERROR,
      STATUS_BYPASS
    ].freeze

    attr_reader :status, :operation_id, :confidence, :reason, :metadata, 
                :timestamp, :conversation_id, :audit_trail, :performance_metrics

    ##
    # Initialize validation result
    #
    # @param status [String] Validation status (approved, rejected, requires_confirmation, etc.)
    # @param operation_id [String] Unique operation identifier
    # @param confidence [Float] Confidence score (0.0-1.0)
    # @param reason [String] Human-readable reason for the validation result
    # @param metadata [Hash] Additional metadata about the validation
    # @param conversation_id [String] Associated conversation identifier
    # @param audit_trail [Array] Audit trail entries
    # @param performance_metrics [Hash] Performance timing and metrics
    #
    def initialize(status:, operation_id:, confidence: nil, reason: nil, 
                   metadata: {}, conversation_id: nil, audit_trail: [], 
                   performance_metrics: {})
      validate_status!(status)
      
      @status = status
      @operation_id = operation_id
      @confidence = confidence
      @reason = reason
      @metadata = metadata || {}
      @conversation_id = conversation_id
      @audit_trail = audit_trail || []
      @performance_metrics = performance_metrics || {}
      @timestamp = Time.now
      
      # Validate confidence score if provided
      validate_confidence_score! if @confidence
    end

    ##
    # Create ValidationResult from HTTP response
    #
    # @param response [HttpResponse] HTTP response object
    # @param operation_id [String] Operation identifier
    # @return [ValidationResult] Parsed validation result
    #
    def self.from_response(response, operation_id)
      if response.success?
        begin
          data = JSON.parse(response.body)
          new(
            status: data['status'],
            operation_id: operation_id,
            confidence: data['confidence']&.to_f,
            reason: data['reason'],
            metadata: data['metadata'] || {},
            conversation_id: data['conversation_id'],
            audit_trail: data['audit_trail'] || [],
            performance_metrics: {
              response_time: data['response_time'],
              server_processing_time: data['server_processing_time'],
              cache_hit: data['cache_hit'] || false
            }
          )
        rescue JSON::ParserError => e
          create_error_result("Invalid JSON response: #{e.message}", operation_id)
        end
      else
        create_error_result("HTTP #{response.status}: #{response.body}", operation_id)
      end
    end

    ##
    # Create ValidationResult from cached data
    #
    # @param cached_data [Hash] Cached validation data
    # @param operation_id [String] Operation identifier
    # @return [ValidationResult] Cached validation result
    #
    def self.from_cache(cached_data, operation_id)
      new(
        status: cached_data['status'],
        operation_id: operation_id,
        confidence: cached_data['confidence']&.to_f,
        reason: cached_data['reason'],
        metadata: cached_data['metadata'] || {},
        conversation_id: cached_data['conversation_id'],
        audit_trail: cached_data['audit_trail'] || [],
        performance_metrics: {
          cached: true,
          cache_timestamp: cached_data['cache_timestamp']
        }
      )
    end

    ##
    # Create fallback result for error conditions
    #
    # @param error_type [String] Type of error
    # @param operation_id [String] Operation identifier
    # @return [ValidationResult] Fallback validation result
    #
    def self.create_fallback(error_type, operation_id)
      case error_type
      when 'circuit_breaker_open'
        new(
          status: STATUS_BYPASS,
          operation_id: operation_id,
          reason: 'Circuit breaker is open, allowing operation with reduced validation',
          metadata: { fallback_reason: 'circuit_breaker_open', risk_level: 'medium' }
        )
      when 'timeout'
        new(
          status: STATUS_TIMEOUT,
          operation_id: operation_id,
          reason: 'Validation request timed out',
          metadata: { fallback_reason: 'timeout', risk_level: 'high' }
        )
      when 'connection_error'
        new(
          status: STATUS_ERROR,
          operation_id: operation_id,
          reason: 'Unable to connect to validation service',
          metadata: { fallback_reason: 'connection_error', risk_level: 'high' }
        )
      else
        new(
          status: STATUS_ERROR,
          operation_id: operation_id,
          reason: "Unknown error: #{error_type}",
          metadata: { fallback_reason: error_type, risk_level: 'critical' }
        )
      end
    end

    ##
    # Create error result
    #
    # @param error_message [String] Error description
    # @param operation_id [String] Operation identifier
    # @return [ValidationResult] Error validation result
    #
    def self.create_error_result(error_message, operation_id)
      new(
        status: STATUS_ERROR,
        operation_id: operation_id,
        reason: error_message,
        metadata: { error: true }
      )
    end

    ##
    # Check if validation was approved
    #
    # @return [Boolean] True if approved
    #
    def approved?
      @status == STATUS_APPROVED
    end

    ##
    # Check if validation was rejected
    #
    # @return [Boolean] True if rejected
    #
    def rejected?
      @status == STATUS_REJECTED
    end

    ##
    # Check if validation requires user confirmation
    #
    # @return [Boolean] True if confirmation required
    #
    def requires_confirmation?
      @status == STATUS_REQUIRES_CONFIRMATION
    end

    ##
    # Check if validation is pending
    #
    # @return [Boolean] True if pending
    #
    def pending?
      @status == STATUS_PENDING
    end

    ##
    # Check if validation timed out
    #
    # @return [Boolean] True if timed out
    #
    def timeout?
      @status == STATUS_TIMEOUT
    end

    ##
    # Check if validation encountered an error
    #
    # @return [Boolean] True if error occurred
    #
    def error?
      @status == STATUS_ERROR
    end

    ##
    # Check if validation was bypassed
    #
    # @return [Boolean] True if bypassed
    #
    def bypass?
      @status == STATUS_BYPASS
    end

    ##
    # Check if validation was successful (not error/timeout)
    #
    # @return [Boolean] True if successful
    #
    def success?
      !error? && !timeout?
    end

    ##
    # Check if operation can proceed
    #
    # @return [Boolean] True if operation can proceed
    #
    def can_proceed?
      approved? || bypass?
    end

    ##
    # Get risk level based on status and metadata
    #
    # @return [String] Risk level (low, medium, high, critical)
    #
    def risk_level
      return @metadata['risk_level'] if @metadata.key?('risk_level')
      
      case @status
      when STATUS_APPROVED
        'low'
      when STATUS_BYPASS
        'medium'
      when STATUS_REQUIRES_CONFIRMATION
        'medium'
      when STATUS_REJECTED, STATUS_TIMEOUT
        'high'
      when STATUS_ERROR
        'critical'
      else
        'medium'
      end
    end

    ##
    # Get confidence score with default handling
    #
    # @return [Float] Confidence score (0.0-1.0)
    #
    def confidence_score
      @confidence || default_confidence_for_status
    end

    ##
    # Check if result is from cache
    #
    # @return [Boolean] True if from cache
    #
    def cached?
      @performance_metrics[:cached] || false
    end

    ##
    # Get response time in milliseconds
    #
    # @return [Float] Response time in ms, nil if not available
    #
    def response_time_ms
      return nil unless @performance_metrics[:response_time]
      (@performance_metrics[:response_time] * 1000).round(2)
    end

    ##
    # Add audit trail entry
    #
    # @param action [String] Action description
    # @param actor [String] Actor performing the action
    # @param details [Hash] Additional details
    #
    def add_audit_entry(action, actor, details = {})
      @audit_trail << {
        timestamp: Time.now.iso8601,
        action: action,
        actor: actor,
        details: details
      }
    end

    ##
    # Update performance metrics
    #
    # @param metrics [Hash] Performance metrics to merge
    #
    def update_performance_metrics(metrics)
      @performance_metrics.merge!(metrics)
    end

    ##
    # Convert to hash for caching
    #
    # @return [Hash] Cacheable representation
    #
    def to_cache_format
      {
        'status' => @status,
        'confidence' => @confidence,
        'reason' => @reason,
        'metadata' => @metadata,
        'conversation_id' => @conversation_id,
        'audit_trail' => @audit_trail,
        'cache_timestamp' => Time.now.iso8601
      }
    end

    ##
    # Convert to JSON
    #
    # @return [String] JSON representation
    #
    def to_json(*args)
      to_h.to_json(*args)
    end

    ##
    # Convert to hash
    #
    # @return [Hash] Hash representation
    #
    def to_h
      {
        status: @status,
        operation_id: @operation_id,
        confidence: @confidence,
        reason: @reason,
        metadata: @metadata,
        conversation_id: @conversation_id,
        audit_trail: @audit_trail,
        performance_metrics: @performance_metrics,
        timestamp: @timestamp.iso8601,
        risk_level: risk_level,
        can_proceed: can_proceed?
      }
    end

    ##
    # String representation
    #
    # @return [String] String representation
    #
    def to_s
      "ValidationResult[#{@status}](op_id: #{@operation_id}, confidence: #{@confidence}, reason: #{@reason})"
    end

    ##
    # Detailed string representation
    #
    # @return [String] Detailed string representation
    #
    def inspect
      "<ValidationResult:#{object_id} status=#{@status} op_id=#{@operation_id} " \
      "confidence=#{@confidence} risk=#{risk_level} cached=#{cached?}>"
    end

    ##
    # Compare two validation results
    #
    # @param other [ValidationResult] Other result to compare
    # @return [Boolean] True if equal
    #
    def ==(other)
      return false unless other.is_a?(ValidationResult)
      
      @status == other.status &&
        @operation_id == other.operation_id &&
        @confidence == other.confidence &&
        @reason == other.reason
    end

    ##
    # Hash code for validation result
    #
    # @return [Integer] Hash code
    #
    def hash
      [@status, @operation_id, @confidence, @reason].hash
    end

    private

    ##
    # Validate status value
    #
    def validate_status!(status)
      unless VALID_STATUSES.include?(status)
        raise ArgumentError, "Invalid status: #{status}. Valid statuses: #{VALID_STATUSES.join(', ')}"
      end
    end

    ##
    # Validate confidence score
    #
    def validate_confidence_score!
      unless @confidence.is_a?(Numeric) && @confidence >= 0.0 && @confidence <= 1.0
        raise ArgumentError, "Confidence score must be a number between 0.0 and 1.0, got: #{@confidence}"
      end
    end

    ##
    # Get default confidence score for status
    #
    def default_confidence_for_status
      case @status
      when STATUS_APPROVED
        0.9
      when STATUS_REJECTED
        0.1
      when STATUS_REQUIRES_CONFIRMATION
        0.5
      when STATUS_BYPASS
        0.3
      when STATUS_PENDING
        0.0
      when STATUS_TIMEOUT, STATUS_ERROR
        0.0
      else
        0.0
      end
    end
  end
end