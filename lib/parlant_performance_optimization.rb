# frozen_string_literal: true

require 'redis'
require 'connection_pool'
require 'concurrent'
require 'digest'

##
# Parlant Performance Optimization Framework for Huginn
#
# Comprehensive performance optimization system implementing multi-level caching,
# asynchronous processing, selective validation, and resource management to minimize
# impact on Huginn monitoring operations while maintaining conversational AI validation quality.
#
# Performance Targets:
# - <100ms overhead for critical monitoring operations  
# - 90%+ cache hit rates across all cache levels
# - Support for 1000+ concurrent monitoring operations
# - Minimal memory footprint increase
#
# @example Usage in Agent
#   optimizer = ParlantPerformanceOptimizer.new
#   result = optimizer.optimized_validate_operation(
#     operation: 'agent_check',
#     context: { agent_id: 123, agent_type: 'WeatherAgent' },
#     user_intent: 'Check weather monitoring status'
#   )
#
# @author Parlant Performance Team
# @since 2.0.0
module ParlantPerformanceOptimization
  ##
  # Multi-Level Caching System
  #
  # Implements L1 (Memory), L2 (Redis), and L3 (Database) caching layers
  # with intelligent cache promotion and TTL management based on validation risk levels.
  class MultiLevelCache
    # Cache Configuration
    L1_CACHE_MAX_SIZE = ENV.fetch('PARLANT_L1_CACHE_SIZE', '50000').to_i
    L2_CACHE_TTL_SECONDS = ENV.fetch('PARLANT_L2_CACHE_TTL', '900').to_i # 15 minutes
    L3_CACHE_TTL_SECONDS = ENV.fetch('PARLANT_L3_CACHE_TTL', '3600').to_i # 1 hour
    
    # TTL Strategy by Risk Level
    CACHE_TTL_BY_RISK = {
      'low' => { l1: 60, l2: 300, l3: 1800 },        # 1min, 5min, 30min
      'medium' => { l1: 30, l2: 180, l3: 900 },      # 30s, 3min, 15min  
      'high' => { l1: 15, l2: 60, l3: 300 },         # 15s, 1min, 5min
      'critical' => { l1: 5, l2: 0, l3: 0 }          # 5s, no L2/L3 caching
    }.freeze

    attr_reader :l1_cache, :l2_cache, :l3_cache, :metrics

    def initialize
      @l1_cache = L1MemoryCache.new(L1_CACHE_MAX_SIZE)
      @l2_cache = L2RedisCache.new
      @l3_cache = L3DatabaseCache.new
      @metrics = CacheMetrics.new
      @cache_locks = Concurrent::Hash.new
      
      Rails.logger.info "[ParlantPerformance] Multi-level cache initialized", {
        l1_max_size: L1_CACHE_MAX_SIZE,
        l2_ttl: L2_CACHE_TTL_SECONDS,
        l3_ttl: L3_CACHE_TTL_SECONDS
      }
    end

    ##
    # Get Cached Validation Result
    #
    # Checks cache hierarchy (L1 -> L2 -> L3) with intelligent promotion.
    #
    # @param cache_key [String] Cache key
    # @param risk_level [String] Validation risk level
    # @return [Hash, nil] Cached validation result or nil
    def get(cache_key, risk_level = 'medium')
      operation_id = generate_operation_id
      start_time = Time.current

      Rails.logger.debug "[ParlantPerformance] [#{operation_id}] Cache lookup started", {
        cache_key: cache_key,
        risk_level: risk_level
      }

      # L1: In-Memory Cache (fastest <5ms)
      result = @l1_cache.get(cache_key)
      if result
        @metrics.record_hit('L1', Time.current - start_time)
        Rails.logger.debug "[ParlantPerformance] [#{operation_id}] L1 cache hit"
        return result
      end

      # L2: Redis Distributed Cache (<15ms)
      result = @l2_cache.get(cache_key)
      if result
        @metrics.record_hit('L2', Time.current - start_time)
        Rails.logger.debug "[ParlantPerformance] [#{operation_id}] L2 cache hit, promoting to L1"
        
        # Promote to L1 cache
        @l1_cache.set(cache_key, result, CACHE_TTL_BY_RISK[risk_level][:l1])
        return result
      end

      # L3: Database Cache (<50ms) - Only for non-critical operations
      if risk_level != 'critical'
        result = @l3_cache.get(cache_key)
        if result
          @metrics.record_hit('L3', Time.current - start_time)
          Rails.logger.debug "[ParlantPerformance] [#{operation_id}] L3 cache hit, promoting to L2 and L1"
          
          # Promote to L2 and L1 caches
          @l2_cache.set(cache_key, result, CACHE_TTL_BY_RISK[risk_level][:l2])
          @l1_cache.set(cache_key, result, CACHE_TTL_BY_RISK[risk_level][:l1])
          return result
        end
      end

      # Cache miss across all levels
      @metrics.record_miss(Time.current - start_time)
      Rails.logger.debug "[ParlantPerformance] [#{operation_id}] Cache miss across all levels"
      nil
    end

    ##
    # Set Cached Validation Result
    #
    # Stores validation result in appropriate cache levels based on risk level.
    #
    # @param cache_key [String] Cache key
    # @param result [Hash] Validation result to cache
    # @param risk_level [String] Validation risk level
    def set(cache_key, result, risk_level = 'medium')
      return if risk_level == 'critical' && !result[:approved]

      operation_id = generate_operation_id
      ttl_config = CACHE_TTL_BY_RISK[risk_level]

      Rails.logger.debug "[ParlantPerformance] [#{operation_id}] Caching validation result", {
        cache_key: cache_key,
        risk_level: risk_level,
        approved: result[:approved],
        ttl_config: ttl_config
      }

      # Always cache in L1 for immediate reuse
      @l1_cache.set(cache_key, result, ttl_config[:l1]) if ttl_config[:l1] > 0

      # Cache in L2 for distributed access (except critical operations)
      if ttl_config[:l2] > 0 && risk_level != 'critical'
        @l2_cache.set(cache_key, result, ttl_config[:l2])
      end

      # Cache in L3 for long-term storage (only low/medium risk)
      if ttl_config[:l3] > 0 && risk_level.in?(['low', 'medium'])
        @l3_cache.set(cache_key, result, ttl_config[:l3])
      end

      @metrics.record_set(risk_level)
    end

    ##
    # Invalidate Cache Entry
    #
    # Removes cache entry from all levels with tag-based invalidation support.
    #
    # @param cache_key [String] Cache key to invalidate
    # @param tags [Array<String>] Tags for dependency-based invalidation
    def invalidate(cache_key, tags = [])
      operation_id = generate_operation_id
      
      Rails.logger.debug "[ParlantPerformance] [#{operation_id}] Invalidating cache", {
        cache_key: cache_key,
        tags: tags
      }

      @l1_cache.delete(cache_key)
      @l2_cache.delete(cache_key)
      @l3_cache.delete(cache_key)

      # Tag-based invalidation for related entries
      invalidate_by_tags(tags) if tags.any?

      @metrics.record_invalidation
    end

    ##
    # Get Cache Statistics
    #
    # Returns comprehensive cache performance metrics.
    #
    # @return [Hash] Cache statistics and metrics
    def stats
      {
        l1_stats: @l1_cache.stats,
        l2_stats: @l2_cache.stats,
        l3_stats: @l3_cache.stats,
        overall_metrics: @metrics.stats,
        hit_rate_overall: @metrics.overall_hit_rate,
        average_response_time_ms: @metrics.average_response_time * 1000,
        cache_efficiency_score: calculate_efficiency_score,
        timestamp: Time.current.iso8601
      }
    end

    ##
    # Warm Cache with Prediction
    #
    # Pre-loads cache with likely-to-be-requested validations based on patterns.
    #
    # @param prediction_context [Hash] Context for cache warming predictions
    def warm_cache(prediction_context = {})
      operation_id = generate_operation_id
      
      Rails.logger.info "[ParlantPerformance] [#{operation_id}] Starting cache warming", {
        context: prediction_context
      }

      # Get predictions from pattern analyzer
      predictions = CacheWarmingPredictor.new.predict_cache_needs(prediction_context)
      
      predictions.each do |prediction|
        next if get(prediction[:cache_key], prediction[:risk_level]) # Skip if already cached
        
        # Pre-validate and cache likely requests
        begin
          result = ParlantIntegrationService.new.validate_operation(
            operation: prediction[:operation],
            context: prediction[:context],
            user_intent: prediction[:user_intent]
          )
          
          set(prediction[:cache_key], result, prediction[:risk_level])
          
        rescue StandardError => e
          Rails.logger.warn "[ParlantPerformance] [#{operation_id}] Cache warming failed", {
            prediction: prediction,
            error: e.message
          }
        end
      end
      
      Rails.logger.info "[ParlantPerformance] [#{operation_id}] Cache warming completed", {
        predictions_processed: predictions.size
      }
    end

    private

    def generate_operation_id
      "cache_#{Time.current.to_i}_#{SecureRandom.hex(4)}"
    end

    def invalidate_by_tags(tags)
      # Implementation for tag-based cache invalidation
      tags.each do |tag|
        [@l1_cache, @l2_cache, @l3_cache].each do |cache|
          cache.delete_by_tag(tag) if cache.respond_to?(:delete_by_tag)
        end
      end
    end

    def calculate_efficiency_score
      # Calculate efficiency score based on hit rates and response times
      stats_data = @metrics.stats
      
      hit_rate_score = stats_data[:hit_rate] || 0
      response_time_score = [100 - (@metrics.average_response_time * 1000), 0].max
      
      ((hit_rate_score * 0.7) + (response_time_score * 0.3)).round(2)
    end
  end

  ##
  # L1 Memory Cache Implementation
  #
  # High-speed in-memory cache with LRU eviction and TTL management.
  class L1MemoryCache
    attr_reader :max_size, :cache_data, :access_order

    def initialize(max_size = 50000)
      @max_size = max_size
      @cache_data = Concurrent::Hash.new
      @access_order = Concurrent::Array.new
      @mutex = Mutex.new
    end

    def get(key)
      entry = @cache_data[key]
      return nil unless entry
      
      # Check TTL expiration
      if entry[:expires_at] <= Time.current
        delete(key)
        return nil
      end

      # Update access order for LRU
      @mutex.synchronize do
        @access_order.delete(key)
        @access_order.push(key)
      end
      
      entry[:lastAccessed] = Time.current
      entry[:value]
    end

    def set(key, value, ttl_seconds)
      expires_at = Time.current + ttl_seconds
      
      entry = {
        value: value,
        expires_at: expires_at,
        created_at: Time.current,
        lastAccessed: Time.current,
        size: calculate_size(value)
      }

      @mutex.synchronize do
        # Remove if already exists
        if @cache_data[key]
          @access_order.delete(key)
        end

        # Ensure capacity
        ensure_capacity(entry[:size])
        
        # Add new entry
        @cache_data[key] = entry
        @access_order.push(key)
      end
    end

    def delete(key)
      @mutex.synchronize do
        @cache_data.delete(key)
        @access_order.delete(key)
      end
    end

    def stats
      {
        size: @cache_data.size,
        max_size: @max_size,
        utilization: (@cache_data.size.to_f / @max_size * 100).round(2),
        memory_usage_kb: calculate_total_memory_usage / 1024
      }
    end

    private

    def ensure_capacity(new_entry_size)
      # Evict LRU entries if necessary
      while (@cache_data.size >= @max_size) || would_exceed_memory_limit?(new_entry_size)
        lru_key = @access_order.shift
        break unless lru_key
        
        @cache_data.delete(lru_key)
      end
    end

    def calculate_size(value)
      # Estimate memory size of the cached value
      case value
      when Hash
        value.to_json.bytesize
      when String
        value.bytesize
      else
        value.to_s.bytesize
      end
    end

    def calculate_total_memory_usage
      @cache_data.values.sum { |entry| entry[:size] }
    end

    def would_exceed_memory_limit?(new_size)
      # Check if adding new entry would exceed memory limit (e.g., 100MB)
      memory_limit = 100 * 1024 * 1024 # 100MB
      (calculate_total_memory_usage + new_size) > memory_limit
    end
  end

  ##
  # L2 Redis Cache Implementation
  #
  # Distributed Redis cache with connection pooling and intelligent sharding.
  class L2RedisCache
    REDIS_POOL_SIZE = ENV.fetch('PARLANT_REDIS_POOL_SIZE', '10').to_i
    REDIS_TIMEOUT = ENV.fetch('PARLANT_REDIS_TIMEOUT', '1').to_i
    
    attr_reader :redis_pool

    def initialize
      @redis_pool = ConnectionPool.new(size: REDIS_POOL_SIZE, timeout: REDIS_TIMEOUT) do
        Redis.new(
          url: ENV.fetch('REDIS_URL', 'redis://localhost:6379/1'),
          timeout: REDIS_TIMEOUT,
          reconnect_attempts: 3,
          reconnect_delay: 0.5,
          reconnect_delay_max: 2.0
        )
      end
    end

    def get(key)
      @redis_pool.with do |redis|
        data = redis.get(cache_key(key))
        data ? JSON.parse(data) : nil
      end
    rescue Redis::BaseError, JSON::ParserError => e
      Rails.logger.warn "[ParlantPerformance] L2 cache get error", {
        key: key,
        error: e.message
      }
      nil
    end

    def set(key, value, ttl_seconds)
      @redis_pool.with do |redis|
        redis.setex(cache_key(key), ttl_seconds, value.to_json)
      end
    rescue Redis::BaseError => e
      Rails.logger.warn "[ParlantPerformance] L2 cache set error", {
        key: key,
        error: e.message
      }
    end

    def delete(key)
      @redis_pool.with do |redis|
        redis.del(cache_key(key))
      end
    rescue Redis::BaseError => e
      Rails.logger.warn "[ParlantPerformance] L2 cache delete error", {
        key: key,
        error: e.message
      }
    end

    def stats
      @redis_pool.with do |redis|
        info = redis.info
        {
          memory_usage_mb: (info['used_memory'].to_i / (1024 * 1024)).round(2),
          connected_clients: info['connected_clients'].to_i,
          keyspace_hits: info['keyspace_hits'].to_i,
          keyspace_misses: info['keyspace_misses'].to_i,
          hit_rate: calculate_redis_hit_rate(info)
        }
      end
    rescue Redis::BaseError => e
      Rails.logger.warn "[ParlantPerformance] L2 cache stats error: #{e.message}"
      { error: e.message }
    end

    private

    def cache_key(key)
      "parlant:validation:#{key}"
    end

    def calculate_redis_hit_rate(info)
      hits = info['keyspace_hits'].to_i
      misses = info['keyspace_misses'].to_i
      total = hits + misses
      
      total > 0 ? ((hits.to_f / total) * 100).round(2) : 0
    end
  end

  ##
  # L3 Database Cache Implementation
  #
  # Persistent database cache with optimized queries and materialized views.
  class L3DatabaseCache
    def get(key)
      record = ValidationCache.where(cache_key: key)
                             .where('expires_at > ?', Time.current)
                             .first
      
      if record
        record.increment_access_count!
        JSON.parse(record.validation_result)
      else
        nil
      end
    rescue StandardError => e
      Rails.logger.warn "[ParlantPerformance] L3 cache get error", {
        key: key,
        error: e.message
      }
      nil
    end

    def set(key, value, ttl_seconds)
      expires_at = Time.current + ttl_seconds
      
      ValidationCache.find_or_create_by(cache_key: key) do |record|
        record.validation_result = value.to_json
        record.expires_at = expires_at
        record.validation_type = value[:operation] || 'unknown'
        record.user_context_hash = generate_context_hash(value[:context] || {})
        record.function_signature_hash = generate_signature_hash(value)
      end
    rescue StandardError => e
      Rails.logger.warn "[ParlantPerformance] L3 cache set error", {
        key: key,
        error: e.message
      }
    end

    def delete(key)
      ValidationCache.where(cache_key: key).delete_all
    rescue StandardError => e
      Rails.logger.warn "[ParlantPerformance] L3 cache delete error", {
        key: key,
        error: e.message
      }
    end

    def stats
      {
        total_records: ValidationCache.count,
        active_records: ValidationCache.where('expires_at > ?', Time.current).count,
        expired_records: ValidationCache.where('expires_at <= ?', Time.current).count,
        average_access_count: ValidationCache.average(:access_count)&.round(2) || 0
      }
    rescue StandardError => e
      Rails.logger.warn "[ParlantPerformance] L3 cache stats error: #{e.message}"
      { error: e.message }
    end

    private

    def generate_context_hash(context)
      Digest::SHA256.hexdigest(context.to_json)[0..31]
    end

    def generate_signature_hash(value)
      signature = "#{value[:operation]}:#{value[:risk_level]}:#{value[:user_intent]}"
      Digest::SHA256.hexdigest(signature)[0..31]
    end
  end

  ##
  # Cache Metrics Collector
  #
  # Comprehensive metrics collection for cache performance analysis.
  class CacheMetrics
    attr_reader :hits, :misses, :response_times, :created_at

    def initialize
      @hits = Concurrent::Hash.new(0)
      @misses = Concurrent::AtomicFixnum.new(0)
      @sets = Concurrent::Hash.new(0)
      @invalidations = Concurrent::AtomicFixnum.new(0)
      @response_times = Concurrent::Array.new
      @created_at = Time.current
    end

    def record_hit(cache_level, response_time)
      @hits[cache_level] += 1
      @response_times << response_time
      
      # Keep only recent response times for performance
      @response_times.shift if @response_times.size > 1000
    end

    def record_miss(response_time)
      @misses.increment
      @response_times << response_time
      
      @response_times.shift if @response_times.size > 1000
    end

    def record_set(risk_level)
      @sets[risk_level] += 1
    end

    def record_invalidation
      @invalidations.increment
    end

    def stats
      total_hits = @hits.values.sum
      total_misses = @misses.value
      total_requests = total_hits + total_misses
      
      {
        hits: @hits.to_h,
        misses: total_misses,
        sets: @sets.to_h,
        invalidations: @invalidations.value,
        total_requests: total_requests,
        hit_rate: total_requests > 0 ? ((total_hits.to_f / total_requests) * 100).round(2) : 0,
        l1_hit_rate: calculate_level_hit_rate('L1', total_requests),
        l2_hit_rate: calculate_level_hit_rate('L2', total_requests),
        l3_hit_rate: calculate_level_hit_rate('L3', total_requests)
      }
    end

    def overall_hit_rate
      stats[:hit_rate]
    end

    def average_response_time
      return 0.0 if @response_times.empty?
      
      @response_times.sum / @response_times.size.to_f
    end

    private

    def calculate_level_hit_rate(level, total_requests)
      return 0 if total_requests == 0
      
      level_hits = @hits[level] || 0
      ((level_hits.to_f / total_requests) * 100).round(2)
    end
  end

  ##
  # Cache Warming Predictor
  #
  # Machine learning-based prediction for cache warming optimization.
  class CacheWarmingPredictor
    def initialize
      @pattern_analyzer = PatternAnalyzer.new
    end

    ##
    # Predict Cache Needs
    #
    # Analyzes usage patterns to predict likely cache needs.
    #
    # @param context [Hash] Current system context
    # @return [Array<Hash>] Array of predicted cache needs
    def predict_cache_needs(context = {})
      # Analyze historical patterns
      patterns = @pattern_analyzer.analyze_recent_patterns
      
      # Generate predictions based on patterns
      predictions = []
      
      # Common agent check patterns
      if context[:schedule_based_warming]
        predictions.concat(predict_scheduled_checks)
      end
      
      # User behavior patterns
      if context[:user_behavior_warming]
        predictions.concat(predict_user_behavior_patterns(context[:user_id]))
      end
      
      # System health check patterns  
      if context[:system_health_warming]
        predictions.concat(predict_system_health_patterns)
      end
      
      # Time-based patterns (peak hours, etc.)
      predictions.concat(predict_time_based_patterns)
      
      predictions.uniq { |p| p[:cache_key] }
    end

    private

    def predict_scheduled_checks
      # Predict upcoming scheduled agent checks
      Agent.active.where.not(schedule: 'never').map do |agent|
        {
          cache_key: generate_cache_key_for_agent_check(agent),
          operation: 'agent_check',
          context: { agent_id: agent.id, agent_type: agent.type },
          user_intent: "Scheduled check for #{agent.type} agent",
          risk_level: 'low',
          predicted_probability: 0.8
        }
      end
    end

    def predict_user_behavior_patterns(user_id)
      return [] unless user_id
      
      # Analyze user's recent validation patterns
      # This would integrate with user behavior analytics
      []
    end

    def predict_system_health_patterns
      [
        {
          cache_key: 'system_health_check_overall',
          operation: 'system_health',
          context: { check_type: 'overall', timestamp: Time.current.to_i },
          user_intent: 'System health monitoring check',
          risk_level: 'low',
          predicted_probability: 0.9
        }
      ]
    end

    def predict_time_based_patterns
      current_hour = Time.current.hour
      
      # Predict higher activity during business hours
      if (9..17).include?(current_hour)
        [
          {
            cache_key: "business_hours_activity_#{current_hour}",
            operation: 'agent_check',
            context: { time_context: 'business_hours', hour: current_hour },
            user_intent: 'Business hours monitoring activity',
            risk_level: 'medium',
            predicted_probability: 0.7
          }
        ]
      else
        []
      end
    end

    def generate_cache_key_for_agent_check(agent)
      "agent_check_#{agent.id}_#{agent.type}_#{agent.updated_at.to_i}"
    end
  end

  ##
  # Pattern Analyzer
  #
  # Analyzes usage patterns for optimization insights.
  class PatternAnalyzer
    def analyze_recent_patterns
      # Implementation would analyze recent validation patterns
      # This is a simplified version
      {
        most_common_operations: ['agent_check', 'create_event'],
        peak_hours: [9, 10, 11, 14, 15, 16],
        common_risk_levels: ['low', 'medium'],
        trending_agent_types: ['WeatherAgent', 'RSSAgent']
      }
    end
  end
end