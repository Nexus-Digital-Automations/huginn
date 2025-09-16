# frozen_string_literal: true

require 'concurrent'
require 'monitor'

module ParlantBridge
  ##
  # Cache Service for Parlant Bridge Integration
  # Provides high-performance multi-level caching with TTL support, 
  # LRU eviction, and thread-safe operations for validation results.
  #
  # @example Basic usage
  #   cache = ParlantBridge::CacheService.new(
  #     ttl: 300,
  #     max_size: 1000,
  #     enable_metrics: true
  #   )
  #   
  #   cache.set('key', { data: 'value' }, ttl: 600)
  #   result = cache.get('key')
  #
  class CacheService
    include MonitorMixin

    # Cache entry structure
    CacheEntry = Struct.new(:value, :expires_at, :created_at, :access_count, :last_accessed) do
      def expired?
        expires_at && Time.now > expires_at
      end

      def touch!
        self.last_accessed = Time.now
        self.access_count += 1
      end
    end

    # Default configuration
    DEFAULT_TTL = 300 # 5 minutes
    DEFAULT_MAX_SIZE = 1000
    DEFAULT_CLEANUP_INTERVAL = 60 # 1 minute
    DEFAULT_MAX_MEMORY_MB = 100

    attr_reader :ttl, :max_size, :metrics, :logger

    ##
    # Initialize cache service
    #
    # @param ttl [Integer] Default time-to-live in seconds
    # @param max_size [Integer] Maximum number of cache entries
    # @param max_memory_mb [Integer] Maximum memory usage in MB
    # @param cleanup_interval [Integer] Cleanup interval in seconds
    # @param enable_metrics [Boolean] Enable performance metrics collection
    # @param logger [Logger] Logger instance for monitoring
    #
    def initialize(ttl: DEFAULT_TTL, max_size: DEFAULT_MAX_SIZE, 
                   max_memory_mb: DEFAULT_MAX_MEMORY_MB, cleanup_interval: DEFAULT_CLEANUP_INTERVAL,
                   enable_metrics: true, logger: nil)
      super() # Initialize MonitorMixin
      
      @ttl = ttl
      @max_size = max_size
      @max_memory_mb = max_memory_mb
      @cleanup_interval = cleanup_interval
      @logger = logger || Logger.new($stdout, level: Logger::INFO)
      
      # Thread-safe cache storage
      @cache = Concurrent::Hash.new
      
      # Metrics collection
      @enable_metrics = enable_metrics
      @metrics = initialize_metrics if @enable_metrics
      
      # Background cleanup task
      @cleanup_task = schedule_cleanup_task
      
      @logger.info("ParlantBridge::CacheService initialized - TTL: #{@ttl}s, Max Size: #{@max_size}")
    end

    ##
    # Store value in cache with optional TTL override
    #
    # @param key [String] Cache key
    # @param value [Object] Value to cache (must be serializable)
    # @param ttl [Integer] Time-to-live override in seconds
    # @return [Boolean] True if successfully stored
    #
    def set(key, value, ttl: nil)
      return false if key.nil? || value.nil?
      
      entry_ttl = ttl || @ttl
      expires_at = entry_ttl.positive? ? Time.now + entry_ttl : nil
      
      synchronize do
        # Enforce size limits before adding
        enforce_size_limits
        
        # Create cache entry
        entry = CacheEntry.new(
          deep_dup(value),
          expires_at,
          Time.now,
          0,
          Time.now
        )
        
        # Store in cache
        @cache[key.to_s] = entry
        
        # Update metrics
        @metrics&.dig(:operations, :sets)&.increment
        @metrics&.dig(:current, :size)&.set(@cache.size)
        
        @logger.debug("Cache set - Key: #{key}, TTL: #{entry_ttl}s, Size: #{@cache.size}")
        true
      end
      
    rescue StandardError => e
      @logger.error("Cache set failed - Key: #{key}, Error: #{e.message}")
      @metrics&.dig(:operations, :errors)&.increment
      false
    end

    ##
    # Retrieve value from cache
    #
    # @param key [String] Cache key
    # @return [Object, nil] Cached value or nil if not found/expired
    #
    def get(key)
      return nil if key.nil?
      
      synchronize do
        entry = @cache[key.to_s]
        
        # Handle cache miss
        unless entry
          @metrics&.dig(:operations, :misses)&.increment
          @logger.debug("Cache miss - Key: #{key}")
          return nil
        end
        
        # Handle expired entry
        if entry.expired?
          @cache.delete(key.to_s)
          @metrics&.dig(:operations, :expiries)&.increment
          @metrics&.dig(:current, :size)&.set(@cache.size)
          @logger.debug("Cache expired - Key: #{key}")
          return nil
        end
        
        # Update access tracking
        entry.touch!
        
        # Update metrics
        @metrics&.dig(:operations, :hits)&.increment
        
        @logger.debug("Cache hit - Key: #{key}, Access Count: #{entry.access_count}")
        deep_dup(entry.value)
      end
      
    rescue StandardError => e
      @logger.error("Cache get failed - Key: #{key}, Error: #{e.message}")
      @metrics&.dig(:operations, :errors)&.increment
      nil
    end

    ##
    # Check if key exists in cache (without retrieving value)
    #
    # @param key [String] Cache key
    # @return [Boolean] True if key exists and not expired
    #
    def exists?(key)
      return false if key.nil?
      
      synchronize do
        entry = @cache[key.to_s]
        return false unless entry
        
        if entry.expired?
          @cache.delete(key.to_s)
          @metrics&.dig(:current, :size)&.set(@cache.size)
          false
        else
          true
        end
      end
    end

    ##
    # Remove specific key from cache
    #
    # @param key [String] Cache key to remove
    # @return [Boolean] True if key was removed
    #
    def delete(key)
      return false if key.nil?
      
      synchronize do
        result = @cache.delete(key.to_s)
        if result
          @metrics&.dig(:operations, :deletes)&.increment
          @metrics&.dig(:current, :size)&.set(@cache.size)
          @logger.debug("Cache delete - Key: #{key}")
          true
        else
          false
        end
      end
    end

    ##
    # Clear all cache entries
    #
    # @return [Integer] Number of entries cleared
    #
    def clear
      synchronize do
        count = @cache.size
        @cache.clear
        @metrics&.dig(:operations, :clears)&.increment
        @metrics&.dig(:current, :size)&.set(0)
        @logger.info("Cache cleared - #{count} entries removed")
        count
      end
    end

    ##
    # Get cache statistics
    #
    # @return [Hash] Comprehensive cache statistics
    #
    def stats
      synchronize do
        total_operations = calculate_total_operations
        hit_rate = calculate_hit_rate(total_operations)
        
        {
          size: @cache.size,
          max_size: @max_size,
          hit_rate: hit_rate,
          memory_usage: calculate_memory_usage,
          max_memory_mb: @max_memory_mb,
          operations: @enable_metrics ? extract_operation_metrics : {},
          oldest_entry: find_oldest_entry&.created_at,
          most_accessed: find_most_accessed_entry,
          expired_entries: count_expired_entries,
          timestamp: Time.now.iso8601
        }
      end
    end

    ##
    # Perform manual cleanup of expired entries
    #
    # @return [Integer] Number of entries cleaned up
    #
    def cleanup!
      synchronize do
        initial_size = @cache.size
        expired_keys = []
        
        @cache.each do |key, entry|
          expired_keys << key if entry.expired?
        end
        
        expired_keys.each { |key| @cache.delete(key) }
        
        cleaned_count = initial_size - @cache.size
        @metrics&.dig(:current, :size)&.set(@cache.size)
        @logger.info("Cache cleanup completed - #{cleaned_count} expired entries removed")
        cleaned_count
      end
    end

    ##
    # Get cache health status
    #
    # @return [Hash] Health status information
    #
    def health_status
      stats_data = stats
      
      {
        status: determine_health_status(stats_data),
        size_utilization: (stats_data[:size].to_f / @max_size * 100).round(2),
        memory_utilization: (stats_data[:memory_usage][:used_mb].to_f / @max_memory_mb * 100).round(2),
        hit_rate: stats_data[:hit_rate],
        expired_entries: stats_data[:expired_entries],
        cleanup_task_active: @cleanup_task&.running?
      }
    end

    ##
    # Shutdown cache service and cleanup resources
    #
    def shutdown
      @logger.info("Shutting down ParlantBridge::CacheService")
      @cleanup_task&.shutdown
      clear
    end

    private

    ##
    # Initialize performance metrics
    #
    def initialize_metrics
      {
        operations: {
          hits: Concurrent::AtomicFixnum.new(0),
          misses: Concurrent::AtomicFixnum.new(0),
          sets: Concurrent::AtomicFixnum.new(0),
          deletes: Concurrent::AtomicFixnum.new(0),
          clears: Concurrent::AtomicFixnum.new(0),
          expiries: Concurrent::AtomicFixnum.new(0),
          errors: Concurrent::AtomicFixnum.new(0)
        },
        current: {
          size: Concurrent::AtomicFixnum.new(0)
        }
      }
    end

    ##
    # Schedule background cleanup task
    #
    def schedule_cleanup_task
      Concurrent::TimerTask.new(execution_interval: @cleanup_interval) do
        begin
          cleanup!
        rescue StandardError => e
          @logger.error("Background cleanup failed: #{e.message}")
        end
      end.tap(&:execute)
    end

    ##
    # Enforce cache size and memory limits
    #
    def enforce_size_limits
      # Size-based eviction
      while @cache.size >= @max_size
        evict_lru_entry
      end
      
      # Memory-based eviction
      memory_usage = calculate_memory_usage
      while memory_usage[:used_mb] > @max_memory_mb && @cache.size > 0
        evict_lru_entry
        memory_usage = calculate_memory_usage
      end
    end

    ##
    # Evict least recently used entry
    #
    def evict_lru_entry
      return if @cache.empty?
      
      lru_key = @cache.min_by { |_, entry| entry.last_accessed }&.first
      if lru_key
        @cache.delete(lru_key)
        @metrics&.dig(:operations, :evictions)&.increment
        @logger.debug("Cache eviction - Key: #{lru_key}")
      end
    end

    ##
    # Calculate total operations count
    #
    def calculate_total_operations
      return 0 unless @enable_metrics
      
      @metrics[:operations].values.sum(&:value)
    end

    ##
    # Calculate cache hit rate
    #
    def calculate_hit_rate(total_operations)
      return 0.0 unless @enable_metrics && total_operations > 0
      
      hits = @metrics[:operations][:hits].value
      misses = @metrics[:operations][:misses].value
      total_read_ops = hits + misses
      
      return 0.0 if total_read_ops.zero?
      
      (hits.to_f / total_read_ops * 100).round(2)
    end

    ##
    # Calculate memory usage
    #
    def calculate_memory_usage
      total_bytes = 0
      
      @cache.each_value do |entry|
        total_bytes += estimate_object_size(entry.value)
      end
      
      {
        used_mb: (total_bytes / (1024.0 * 1024.0)).round(2),
        entries: @cache.size,
        avg_entry_kb: @cache.empty? ? 0 : (total_bytes / @cache.size / 1024.0).round(2)
      }
    end

    ##
    # Estimate object size in bytes
    #
    def estimate_object_size(obj)
      case obj
      when String
        obj.bytesize
      when Hash
        obj.to_s.bytesize * 2 # Rough estimate
      when Array
        obj.to_s.bytesize * 1.5 # Rough estimate
      else
        obj.to_s.bytesize
      end
    rescue StandardError
      100 # Default estimate
    end

    ##
    # Extract operation metrics for stats
    #
    def extract_operation_metrics
      return {} unless @enable_metrics
      
      @metrics[:operations].transform_values(&:value)
    end

    ##
    # Find oldest cache entry
    #
    def find_oldest_entry
      @cache.values.min_by(&:created_at)
    end

    ##
    # Find most accessed cache entry
    #
    def find_most_accessed_entry
      entry = @cache.values.max_by(&:access_count)
      return nil unless entry
      
      {
        access_count: entry.access_count,
        created_at: entry.created_at,
        last_accessed: entry.last_accessed
      }
    end

    ##
    # Count expired entries without removing them
    #
    def count_expired_entries
      @cache.count { |_, entry| entry.expired? }
    end

    ##
    # Determine cache health status
    #
    def determine_health_status(stats_data)
      size_util = stats_data[:size].to_f / @max_size
      hit_rate = stats_data[:hit_rate]
      expired_count = stats_data[:expired_entries]
      
      if size_util < 0.8 && hit_rate > 70 && expired_count < (@max_size * 0.1)
        'healthy'
      elsif size_util < 0.95 && hit_rate > 50
        'warning'
      else
        'critical'
      end
    end

    ##
    # Deep duplicate object for safe caching
    #
    def deep_dup(obj)
      case obj
      when Hash
        obj.transform_values { |v| deep_dup(v) }
      when Array
        obj.map { |v| deep_dup(v) }
      when String
        obj.dup
      else
        obj
      end
    rescue StandardError
      obj
    end
  end
end