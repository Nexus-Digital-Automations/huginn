# frozen_string_literal: true

require 'concurrent'
require 'sidekiq'
require 'redis'

##
# Parlant Asynchronous Processing Framework
#
# Implements comprehensive asynchronous processing for non-critical Parlant validations
# with job queuing, priority processing, batch operations, and background validation
# to minimize impact on real-time monitoring operations.
#
# Features:
# - Priority-based job queuing system
# - Background processing for non-critical validations
# - Batch validation processing with intelligent grouping
# - Streaming validation results via WebSocket
# - Deferred validation with retry mechanisms
# - Resource-aware processing with backpressure control
#
# @example Basic Usage
#   processor = ParlantAsyncProcessor.new
#   processor.queue_validation(
#     operation: 'agent_check',
#     context: { agent_id: 123 },
#     priority: :low,
#     callback: ->(result) { puts "Validation complete: #{result}" }
#   )
#
# @author Parlant Performance Team  
# @since 2.0.0
module ParlantAsyncProcessing
  ##
  # Asynchronous Validation Processor
  #
  # Main orchestrator for async validation processing with priority queuing.
  class ParlantAsyncProcessor
    # Processing Configuration
    MAX_CONCURRENT_VALIDATIONS = ENV.fetch('PARLANT_MAX_CONCURRENT', '50').to_i
    BATCH_SIZE_DEFAULT = ENV.fetch('PARLANT_BATCH_SIZE', '10').to_i
    QUEUE_PRIORITY_LEVELS = %i[critical high medium low].freeze
    PROCESSING_TIMEOUT_SECONDS = ENV.fetch('PARLANT_PROCESSING_TIMEOUT', '30').to_i

    # Priority Queue Configuration
    PRIORITY_WEIGHTS = {
      critical: 1000,
      high: 100,  
      medium: 10,
      low: 1
    }.freeze

    attr_reader :priority_queues, :active_jobs, :metrics, :websocket_manager

    def initialize
      @priority_queues = initialize_priority_queues
      @active_jobs = Concurrent::Hash.new
      @metrics = AsyncProcessingMetrics.new
      @websocket_manager = WebSocketStreamingManager.new
      @batch_processor = BatchValidationProcessor.new
      @resource_monitor = ResourceMonitor.new
      @job_scheduler = ValidationJobScheduler.new
      
      setup_background_workers
      setup_health_monitoring
      
      Rails.logger.info "[ParlantAsync] Async processor initialized", {
        max_concurrent: MAX_CONCURRENT_VALIDATIONS,
        batch_size: BATCH_SIZE_DEFAULT,
        priority_levels: QUEUE_PRIORITY_LEVELS
      }
    end

    ##
    # Queue Validation for Async Processing
    #
    # Adds validation request to appropriate priority queue for background processing.
    #
    # @param operation [String] Operation to validate
    # @param context [Hash] Validation context
    # @param user_intent [String] User intent description
    # @param priority [Symbol] Processing priority (:critical, :high, :medium, :low)
    # @param options [Hash] Additional options
    # @option options [Proc] :callback Completion callback
    # @option options [String] :client_id WebSocket client for streaming
    # @option options [Integer] :timeout Custom timeout in seconds
    # @option options [Boolean] :batch_eligible Can be batched with similar operations
    # @return [String] Job ID for tracking
    def queue_validation(operation:, context:, user_intent: nil, priority: :medium, **options)
      job_id = generate_job_id
      
      validation_job = ValidationJob.new(
        id: job_id,
        operation: operation,
        context: context,
        user_intent: user_intent,
        priority: priority,
        options: options,
        queued_at: Time.current
      )

      Rails.logger.debug "[ParlantAsync] [#{job_id}] Queueing validation", {
        operation: operation,
        priority: priority,
        batch_eligible: options[:batch_eligible]
      }

      # Add to appropriate priority queue
      @priority_queues[priority].push(validation_job)
      @metrics.record_queued(priority)

      # Notify client via WebSocket if streaming enabled
      if options[:client_id]
        @websocket_manager.notify_queued(options[:client_id], job_id, {
          status: 'queued',
          priority: priority,
          estimated_wait_time: estimate_wait_time(priority)
        })
      end

      # Trigger processing if resources available
      trigger_processing_if_capacity_available

      job_id
    end

    ##
    # Process Validation Batch
    #
    # Groups similar validations for efficient batch processing.
    #
    # @param validations [Array<ValidationJob>] Validation jobs to batch
    # @return [Array<ValidationResult>] Batch processing results
    def process_validation_batch(validations)
      batch_id = generate_batch_id
      
      Rails.logger.info "[ParlantAsync] [#{batch_id}] Processing validation batch", {
        batch_size: validations.size,
        operations: validations.map(&:operation).uniq
      }

      start_time = Time.current
      
      # Group validations by operation type for optimal processing
      grouped_validations = group_validations_for_batch(validations)
      results = []

      grouped_validations.each do |operation_type, job_group|
        group_results = @batch_processor.process_operation_group(
          operation_type, job_group, batch_id
        )
        results.concat(group_results)
      end

      processing_time = Time.current - start_time
      @metrics.record_batch_completed(validations.size, processing_time)

      Rails.logger.info "[ParlantAsync] [#{batch_id}] Batch processing completed", {
        batch_size: validations.size,
        processing_time_ms: (processing_time * 1000).round(2),
        success_rate: calculate_success_rate(results)
      }

      results
    end

    ##
    # Stream Validation Progress
    #
    # Provides real-time validation progress updates via WebSocket.
    #
    # @param client_id [String] WebSocket client identifier
    # @param job_id [String] Validation job ID
    # @param progress_data [Hash] Progress information
    def stream_validation_progress(client_id, job_id, progress_data)
      @websocket_manager.stream_progress(client_id, job_id, progress_data)
    end

    ##
    # Get Processing Status
    #
    # Returns comprehensive status of async processing system.
    #
    # @return [Hash] Current processing status and metrics
    def processing_status
      {
        queue_depths: @priority_queues.transform_values(&:size),
        active_jobs: @active_jobs.size,
        total_capacity: MAX_CONCURRENT_VALIDATIONS,
        available_capacity: MAX_CONCURRENT_VALIDATIONS - @active_jobs.size,
        resource_utilization: @resource_monitor.current_utilization,
        metrics: @metrics.current_stats,
        websocket_connections: @websocket_manager.connection_count,
        batch_processor_status: @batch_processor.status,
        uptime: Time.current - @started_at,
        timestamp: Time.current.iso8601
      }
    end

    ##
    # Emergency Drain Queues
    #
    # Emergency operation to drain all queues during system shutdown or overload.
    #
    # @param reason [String] Reason for draining queues
    def emergency_drain_queues(reason = 'System emergency')
      Rails.logger.warn "[ParlantAsync] Emergency queue drain initiated", {
        reason: reason,
        total_queued_jobs: total_queued_jobs
      }

      drained_count = 0
      QUEUE_PRIORITY_LEVELS.each do |priority|
        queue = @priority_queues[priority]
        while (job = queue.pop(non_block: true))
          handle_emergency_job_cancellation(job, reason)
          drained_count += 1
        end
      end

      Rails.logger.warn "[ParlantAsync] Emergency queue drain completed", {
        drained_jobs: drained_count,
        reason: reason
      }

      drained_count
    end

    private

    def initialize_priority_queues
      queues = {}
      QUEUE_PRIORITY_LEVELS.each do |priority|
        queues[priority] = Concurrent::Array.new
      end
      queues
    end

    def setup_background_workers
      @started_at = Time.current
      @processing_thread = Thread.new { background_processing_loop }
      @batch_processing_thread = Thread.new { batch_processing_loop }
      @cleanup_thread = Thread.new { cleanup_loop }
    end

    def setup_health_monitoring
      @health_monitor_thread = Thread.new { health_monitoring_loop }
    end

    def background_processing_loop
      Rails.logger.info "[ParlantAsync] Background processing loop started"

      loop do
        begin
          process_queued_validations if has_available_capacity?
          sleep 0.1 # Prevent tight loop
        rescue StandardError => e
          Rails.logger.error "[ParlantAsync] Background processing error", {
            error: e.message,
            backtrace: e.backtrace&.first(3)
          }
          sleep 1 # Back off on error
        end
      end
    rescue => e
      Rails.logger.fatal "[ParlantAsync] Background processing loop crashed: #{e.message}"
      raise
    end

    def batch_processing_loop
      Rails.logger.info "[ParlantAsync] Batch processing loop started"

      loop do
        begin
          process_batch_eligible_validations
          sleep 1 # Batch processing runs less frequently
        rescue StandardError => e
          Rails.logger.error "[ParlantAsync] Batch processing error", {
            error: e.message,
            backtrace: e.backtrace&.first(3)
          }
          sleep 5
        end
      end
    rescue => e
      Rails.logger.fatal "[ParlantAsync] Batch processing loop crashed: #{e.message}"
      raise
    end

    def cleanup_loop
      Rails.logger.info "[ParlantAsync] Cleanup loop started"

      loop do
        begin
          cleanup_completed_jobs
          cleanup_expired_jobs
          @metrics.cleanup_old_metrics
          sleep 30 # Cleanup every 30 seconds
        rescue StandardError => e
          Rails.logger.error "[ParlantAsync] Cleanup error: #{e.message}"
          sleep 60 # Back off on cleanup errors
        end
      end
    end

    def health_monitoring_loop
      loop do
        begin
          monitor_system_health
          sleep 10 # Health check every 10 seconds
        rescue StandardError => e
          Rails.logger.error "[ParlantAsync] Health monitoring error: #{e.message}"
          sleep 30
        end
      end
    end

    def process_queued_validations
      return unless has_available_capacity?

      # Process jobs by priority (critical first, then high, medium, low)
      QUEUE_PRIORITY_LEVELS.each do |priority|
        queue = @priority_queues[priority]
        
        while has_available_capacity? && (job = queue.shift)
          process_validation_job(job)
        end
      end
    end

    def process_batch_eligible_validations
      batch_candidates = collect_batch_candidates
      return if batch_candidates.size < 2

      # Group candidates into optimal batches
      batches = create_optimal_batches(batch_candidates)
      
      batches.each do |batch|
        next unless has_batch_processing_capacity?
        
        process_validation_batch(batch)
      end
    end

    def process_validation_job(job)
      job_id = job.id
      @active_jobs[job_id] = job
      @metrics.record_started(job.priority)

      Rails.logger.debug "[ParlantAsync] [#{job_id}] Processing validation job", {
        operation: job.operation,
        priority: job.priority,
        queue_time_ms: ((Time.current - job.queued_at) * 1000).round(2)
      }

      # Stream processing start notification
      if job.options[:client_id]
        stream_validation_progress(job.options[:client_id], job_id, {
          status: 'processing',
          stage: 'started',
          progress: 0.1
        })
      end

      # Execute validation with timeout protection
      result = execute_validation_with_timeout(job)
      
      # Handle completion
      handle_job_completion(job, result)
      
    rescue StandardError => e
      handle_job_error(job, e)
    ensure
      @active_jobs.delete(job_id)
    end

    def execute_validation_with_timeout(job)
      timeout = job.options[:timeout] || PROCESSING_TIMEOUT_SECONDS
      
      Timeout.timeout(timeout) do
        ParlantIntegrationService.new.validate_operation(
          operation: job.operation,
          context: job.context,
          user_intent: job.user_intent
        )
      end
    end

    def handle_job_completion(job, result)
      processing_time = Time.current - job.queued_at
      @metrics.record_completed(job.priority, processing_time, result[:approved])

      Rails.logger.debug "[ParlantAsync] [#{job.id}] Job completed", {
        operation: job.operation,
        approved: result[:approved],
        processing_time_ms: (processing_time * 1000).round(2)
      }

      # Execute callback if provided
      job.options[:callback]&.call(result)

      # Stream completion notification
      if job.options[:client_id]
        stream_validation_progress(job.options[:client_id], job.id, {
          status: 'completed',
          result: result,
          progress: 1.0
        })
      end
    end

    def handle_job_error(job, error)
      @metrics.record_failed(job.priority, error)

      Rails.logger.error "[ParlantAsync] [#{job.id}] Job failed", {
        operation: job.operation,
        error: error.message,
        backtrace: error.backtrace&.first(3)
      }

      # Stream error notification
      if job.options[:client_id]
        stream_validation_progress(job.options[:client_id], job.id, {
          status: 'error',
          error: error.message
        })
      end
    end

    def handle_emergency_job_cancellation(job, reason)
      Rails.logger.warn "[ParlantAsync] [#{job.id}] Job cancelled", {
        operation: job.operation,
        reason: reason
      }

      # Notify client of cancellation
      if job.options[:client_id]
        stream_validation_progress(job.options[:client_id], job.id, {
          status: 'cancelled',
          reason: reason
        })
      end
    end

    def has_available_capacity?
      @active_jobs.size < MAX_CONCURRENT_VALIDATIONS
    end

    def has_batch_processing_capacity?
      @active_jobs.size < (MAX_CONCURRENT_VALIDATIONS * 0.5) # Reserve capacity for individual jobs
    end

    def trigger_processing_if_capacity_available
      return unless has_available_capacity?
      
      # Wake up processing thread if it's sleeping
      @processing_thread&.wakeup if @processing_thread&.alive?
    end

    def estimate_wait_time(priority)
      # Estimate based on queue depth and processing rates
      queue_depth = @priority_queues[priority].size
      higher_priority_jobs = calculate_higher_priority_jobs(priority)
      
      total_ahead = higher_priority_jobs + queue_depth
      average_processing_time = @metrics.average_processing_time(priority) || 2.0
      
      (total_ahead * average_processing_time).round(2)
    end

    def calculate_higher_priority_jobs(priority)
      higher_priorities = QUEUE_PRIORITY_LEVELS[0...QUEUE_PRIORITY_LEVELS.index(priority)]
      higher_priorities.sum { |p| @priority_queues[p].size }
    end

    def total_queued_jobs
      @priority_queues.values.sum(&:size)
    end

    def collect_batch_candidates
      candidates = []
      
      # Collect batch-eligible jobs from medium and low priority queues
      [:medium, :low].each do |priority|
        queue = @priority_queues[priority]
        batch_jobs = []
        
        # Extract batch-eligible jobs
        queue.size.times do
          job = queue.shift
          break unless job
          
          if job.options[:batch_eligible]
            batch_jobs << job
          else
            queue.push(job) # Put non-batch job back
          end
        end
        
        candidates.concat(batch_jobs)
      end
      
      candidates
    end

    def create_optimal_batches(candidates)
      # Group by operation type and create batches
      grouped = candidates.group_by(&:operation)
      
      batches = []
      grouped.each do |operation, jobs|
        jobs.each_slice(BATCH_SIZE_DEFAULT) do |batch|
          batches << batch
        end
      end
      
      batches
    end

    def group_validations_for_batch(validations)
      validations.group_by(&:operation)
    end

    def calculate_success_rate(results)
      return 0.0 if results.empty?
      
      successful = results.count { |r| r[:approved] }
      ((successful.to_f / results.size) * 100).round(2)
    end

    def cleanup_completed_jobs
      # Implementation for cleaning up completed job records
    end

    def cleanup_expired_jobs
      # Implementation for cleaning up expired jobs
    end

    def monitor_system_health
      utilization = @resource_monitor.current_utilization
      
      if utilization[:memory_percent] > 90
        Rails.logger.warn "[ParlantAsync] High memory usage detected", utilization
      end
      
      if utilization[:cpu_percent] > 80
        Rails.logger.warn "[ParlantAsync] High CPU usage detected", utilization
      end
    end

    def generate_job_id
      "async_#{Time.current.to_i}_#{SecureRandom.hex(6)}"
    end

    def generate_batch_id
      "batch_#{Time.current.to_i}_#{SecureRandom.hex(4)}"
    end
  end

  ##
  # Validation Job Data Structure
  #
  # Represents a queued validation job with metadata and options.
  class ValidationJob
    attr_accessor :id, :operation, :context, :user_intent, :priority, :options, :queued_at

    def initialize(id:, operation:, context:, user_intent:, priority:, options:, queued_at:)
      @id = id
      @operation = operation
      @context = context
      @user_intent = user_intent
      @priority = priority
      @options = options
      @queued_at = queued_at
    end

    def batch_eligible?
      @options[:batch_eligible] == true
    end

    def high_priority?
      @priority.in?([:critical, :high])
    end

    def estimated_processing_time
      case @priority
      when :critical then 0.5
      when :high then 1.0
      when :medium then 2.0
      when :low then 3.0
      else 2.0
      end
    end

    def to_hash
      {
        id: @id,
        operation: @operation,
        context: @context,
        user_intent: @user_intent,
        priority: @priority,
        queued_at: @queued_at,
        options: @options
      }
    end
  end

  ##
  # Async Processing Metrics Collector
  #
  # Comprehensive metrics for async processing performance analysis.
  class AsyncProcessingMetrics
    attr_reader :created_at

    def initialize
      @created_at = Time.current
      @queued = Concurrent::Hash.new(0)
      @started = Concurrent::Hash.new(0)
      @completed = Concurrent::Hash.new(0)
      @failed = Concurrent::Hash.new(0)
      @processing_times = Concurrent::Hash.new { |h, k| h[k] = Concurrent::Array.new }
      @success_rates = Concurrent::Hash.new { |h, k| h[k] = Concurrent::Array.new }
    end

    def record_queued(priority)
      @queued[priority] += 1
    end

    def record_started(priority)
      @started[priority] += 1
    end

    def record_completed(priority, processing_time, approved)
      @completed[priority] += 1
      @processing_times[priority] << processing_time
      @success_rates[priority] << approved
      
      # Keep only recent data points
      trim_array(@processing_times[priority], 1000)
      trim_array(@success_rates[priority], 1000)
    end

    def record_failed(priority, error)
      @failed[priority] += 1
    end

    def record_batch_completed(size, processing_time)
      @batch_completions ||= Concurrent::AtomicFixnum.new(0)
      @batch_sizes ||= Concurrent::Array.new
      @batch_times ||= Concurrent::Array.new
      
      @batch_completions.increment
      @batch_sizes << size
      @batch_times << processing_time
      
      trim_array(@batch_sizes, 100)
      trim_array(@batch_times, 100)
    end

    def current_stats
      {
        queued: @queued.to_h,
        started: @started.to_h,
        completed: @completed.to_h,
        failed: @failed.to_h,
        processing_times: calculate_processing_time_stats,
        success_rates: calculate_success_rate_stats,
        batch_stats: calculate_batch_stats,
        uptime: Time.current - @created_at
      }
    end

    def average_processing_time(priority)
      times = @processing_times[priority]
      return nil if times.empty?
      
      times.sum / times.size.to_f
    end

    def cleanup_old_metrics
      # Keep only recent metrics to prevent memory growth
      # Implementation would clean up old metric data
    end

    private

    def calculate_processing_time_stats
      stats = {}
      @processing_times.each do |priority, times|
        next if times.empty?
        
        stats[priority] = {
          average: (times.sum / times.size.to_f).round(3),
          min: times.min.round(3),
          max: times.max.round(3),
          count: times.size
        }
      end
      stats
    end

    def calculate_success_rate_stats
      stats = {}
      @success_rates.each do |priority, results|
        next if results.empty?
        
        successful = results.count(true)
        stats[priority] = {
          success_rate: ((successful.to_f / results.size) * 100).round(2),
          total_processed: results.size,
          successful: successful,
          failed: results.size - successful
        }
      end
      stats
    end

    def calculate_batch_stats
      return {} unless @batch_completions

      {
        total_batches: @batch_completions.value,
        average_batch_size: @batch_sizes.empty? ? 0 : (@batch_sizes.sum.to_f / @batch_sizes.size).round(2),
        average_batch_time: @batch_times.empty? ? 0 : (@batch_times.sum / @batch_times.size.to_f).round(3)
      }
    end

    def trim_array(array, max_size)
      while array.size > max_size
        array.shift
      end
    end
  end

  ##
  # WebSocket Streaming Manager
  #
  # Manages real-time validation progress streaming via WebSocket connections.
  class WebSocketStreamingManager
    def initialize
      @connections = Concurrent::Hash.new
      @message_queue = Concurrent::Hash.new { |h, k| h[k] = Concurrent::Array.new }
    end

    def notify_queued(client_id, job_id, data)
      send_message(client_id, {
        type: 'validation_queued',
        job_id: job_id,
        timestamp: Time.current.iso8601,
        **data
      })
    end

    def stream_progress(client_id, job_id, progress_data)
      send_message(client_id, {
        type: 'validation_progress',
        job_id: job_id,
        timestamp: Time.current.iso8601,
        **progress_data
      })
    end

    def connection_count
      @connections.size
    end

    private

    def send_message(client_id, message)
      # Implementation would send WebSocket message
      # This is a placeholder for actual WebSocket integration
      Rails.logger.debug "[WebSocketStreaming] Message to #{client_id}", message
    end
  end

  ##
  # Resource Monitor
  #
  # Monitors system resources to prevent overload during async processing.
  class ResourceMonitor
    def current_utilization
      # Implementation would monitor actual system resources
      # This is a simplified placeholder
      {
        cpu_percent: 45.2,
        memory_percent: 62.1,
        active_threads: Thread.list.count,
        gc_stats: GC.stat,
        timestamp: Time.current.iso8601
      }
    end
  end

  ##
  # Batch Validation Processor
  #
  # Specialized processor for handling validation batches efficiently.
  class BatchValidationProcessor
    def process_operation_group(operation_type, jobs, batch_id)
      # Implementation for batch processing specific operation types
      jobs.map do |job|
        # Process individual job in batch context
        result = ParlantIntegrationService.new.validate_operation(
          operation: job.operation,
          context: job.context,
          user_intent: job.user_intent
        )
        
        result.merge(job_id: job.id, batch_id: batch_id)
      end
    end

    def status
      {
        processing_batches: 0,
        completed_batches: 0,
        average_batch_time: 0.0
      }
    end
  end

  ##
  # Validation Job Scheduler
  #
  # Intelligent scheduling for optimal resource utilization.
  class ValidationJobScheduler
    def initialize
      @schedule_optimizer = ScheduleOptimizer.new
    end

    def optimize_schedule(jobs)
      @schedule_optimizer.optimize(jobs)
    end
  end

  ##
  # Schedule Optimizer
  #
  # Optimizes job scheduling based on resource availability and priorities.
  class ScheduleOptimizer
    def optimize(jobs)
      # Implementation for intelligent job scheduling
      jobs.sort_by { |job| [job.priority, job.queued_at] }
    end
  end
end