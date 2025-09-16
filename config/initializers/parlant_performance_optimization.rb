# frozen_string_literal: true

##
# Parlant Performance Optimization Initializer
#
# Configures and initializes the comprehensive performance optimization system
# for Parlant integration in Huginn. Sets up multi-level caching, async processing,
# selective validation, and performance monitoring.
#
# This initializer runs at Rails startup to configure all performance optimization
# components and establish the high-performance validation infrastructure.
#
# @author Parlant Performance Team
# @since 2.0.0

# Load performance optimization components
require_relative '../lib/parlant_performance_optimization'
require_relative '../lib/parlant_async_processing'
require_relative '../lib/parlant_selective_validation'

Rails.application.configure do
  # Performance Optimization Configuration
  config.parlant_performance = ActiveSupport::OrderedOptions.new
  
  # Multi-Level Cache Configuration
  config.parlant_performance.cache = ActiveSupport::OrderedOptions.new
  config.parlant_performance.cache.l1_max_size = ENV.fetch('PARLANT_L1_CACHE_SIZE', '50000').to_i
  config.parlant_performance.cache.l2_ttl_seconds = ENV.fetch('PARLANT_L2_CACHE_TTL', '900').to_i
  config.parlant_performance.cache.l3_ttl_seconds = ENV.fetch('PARLANT_L3_CACHE_TTL', '3600').to_i
  config.parlant_performance.cache.enabled = ENV.fetch('PARLANT_CACHE_ENABLED', 'true') == 'true'
  
  # Async Processing Configuration
  config.parlant_performance.async = ActiveSupport::OrderedOptions.new
  config.parlant_performance.async.max_concurrent = ENV.fetch('PARLANT_MAX_CONCURRENT', '50').to_i
  config.parlant_performance.async.batch_size = ENV.fetch('PARLANT_BATCH_SIZE', '10').to_i
  config.parlant_performance.async.enabled = ENV.fetch('PARLANT_ASYNC_ENABLED', 'true') == 'true'
  
  # Selective Validation Configuration
  config.parlant_performance.selective = ActiveSupport::OrderedOptions.new
  config.parlant_performance.selective.enabled = ENV.fetch('PARLANT_SELECTIVE_ENABLED', 'true') == 'true'
  config.parlant_performance.selective.auto_approve_low_risk = ENV.fetch('PARLANT_AUTO_APPROVE_LOW_RISK', 'true') == 'true'
  config.parlant_performance.selective.risk_threshold_adjustment = ENV.fetch('PARLANT_RISK_THRESHOLD_ADJUSTMENT', '0.0').to_f
  
  # Emergency Bypass Configuration
  config.parlant_performance.bypass = ActiveSupport::OrderedOptions.new
  config.parlant_performance.bypass.enabled = ENV.fetch('PARLANT_EMERGENCY_BYPASS_ENABLED', 'true') == 'true'
  config.parlant_performance.bypass.cpu_threshold = ENV.fetch('PARLANT_BYPASS_CPU_THRESHOLD', '90').to_f
  config.parlant_performance.bypass.memory_threshold = ENV.fetch('PARLANT_BYPASS_MEMORY_THRESHOLD', '95').to_f
  
  # Performance Monitoring Configuration
  config.parlant_performance.monitoring = ActiveSupport::OrderedOptions.new
  config.parlant_performance.monitoring.enabled = ENV.fetch('PARLANT_MONITORING_ENABLED', 'true') == 'true'
  config.parlant_performance.monitoring.reporting_interval = ENV.fetch('PARLANT_MONITORING_INTERVAL', '30').to_i
  config.parlant_performance.monitoring.metrics_retention_days = ENV.fetch('PARLANT_METRICS_RETENTION_DAYS', '7').to_i
end

# Initialize performance optimization after Rails application loads
Rails.application.config.after_initialize do
  # Only initialize if Parlant integration is enabled
  if ENV.fetch('PARLANT_ENABLED', 'true') == 'true'
    Rails.logger.info "[ParlantPerformance] Initializing performance optimization system"
    
    begin
      # Initialize global performance optimization components
      ParlantPerformanceOptimization.configure do |config|
        config.cache_enabled = Rails.application.config.parlant_performance.cache.enabled
        config.l1_max_size = Rails.application.config.parlant_performance.cache.l1_max_size
        config.l2_ttl_seconds = Rails.application.config.parlant_performance.cache.l2_ttl_seconds
        config.l3_ttl_seconds = Rails.application.config.parlant_performance.cache.l3_ttl_seconds
        
        config.async_enabled = Rails.application.config.parlant_performance.async.enabled
        config.max_concurrent = Rails.application.config.parlant_performance.async.max_concurrent
        config.batch_size = Rails.application.config.parlant_performance.async.batch_size
        
        config.selective_enabled = Rails.application.config.parlant_performance.selective.enabled
        config.auto_approve_low_risk = Rails.application.config.parlant_performance.selective.auto_approve_low_risk
        
        config.bypass_enabled = Rails.application.config.parlant_performance.bypass.enabled
        config.cpu_threshold = Rails.application.config.parlant_performance.bypass.cpu_threshold
        config.memory_threshold = Rails.application.config.parlant_performance.bypass.memory_threshold
        
        config.monitoring_enabled = Rails.application.config.parlant_performance.monitoring.enabled
        config.reporting_interval = Rails.application.config.parlant_performance.monitoring.reporting_interval
      end
      
      # Initialize global performance-optimized service instance
      Rails.application.config.parlant_performance_service = ParlantPerformanceOptimizedService.new(
        performance_mode: ENV.fetch('PARLANT_PERFORMANCE_MODE', 'balanced').to_sym
      )
      
      # Set up background tasks for cache warming and cleanup
      setup_background_tasks if Rails.application.config.parlant_performance.monitoring.enabled
      
      # Register performance monitoring endpoints if in development
      setup_performance_monitoring_endpoints if Rails.env.development?
      
      Rails.logger.info "[ParlantPerformance] Performance optimization system initialized successfully", {
        cache_enabled: Rails.application.config.parlant_performance.cache.enabled,
        async_enabled: Rails.application.config.parlant_performance.async.enabled,
        selective_enabled: Rails.application.config.parlant_performance.selective.enabled,
        bypass_enabled: Rails.application.config.parlant_performance.bypass.enabled,
        monitoring_enabled: Rails.application.config.parlant_performance.monitoring.enabled,
        performance_mode: ENV.fetch('PARLANT_PERFORMANCE_MODE', 'balanced')
      }
      
    rescue StandardError => e
      Rails.logger.error "[ParlantPerformance] Failed to initialize performance optimization", {
        error: e.message,
        backtrace: e.backtrace&.first(5)
      }
      
      # Fall back to basic Parlant integration without performance optimizations
      Rails.logger.warn "[ParlantPerformance] Falling back to basic Parlant integration"
    end
  else
    Rails.logger.info "[ParlantPerformance] Parlant integration disabled, skipping performance optimization"
  end
end

# Performance optimization configuration methods
module ParlantPerformanceOptimization
  class << self
    attr_accessor :configuration

    def configure
      self.configuration ||= Configuration.new
      yield(configuration) if block_given?
      configuration
    end
  end

  class Configuration
    attr_accessor :cache_enabled, :l1_max_size, :l2_ttl_seconds, :l3_ttl_seconds,
                  :async_enabled, :max_concurrent, :batch_size,
                  :selective_enabled, :auto_approve_low_risk,
                  :bypass_enabled, :cpu_threshold, :memory_threshold,
                  :monitoring_enabled, :reporting_interval

    def initialize
      @cache_enabled = true
      @l1_max_size = 50000
      @l2_ttl_seconds = 900
      @l3_ttl_seconds = 3600
      @async_enabled = true
      @max_concurrent = 50
      @batch_size = 10
      @selective_enabled = true
      @auto_approve_low_risk = true
      @bypass_enabled = true
      @cpu_threshold = 90.0
      @memory_threshold = 95.0
      @monitoring_enabled = true
      @reporting_interval = 30
    end
  end
end

# Background task setup
def setup_background_tasks
  # Cache warming task
  Thread.new do
    loop do
      begin
        if Rails.application.config.parlant_performance_service.respond_to?(:multi_level_cache)
          cache = Rails.application.config.parlant_performance_service.multi_level_cache
          cache.warm_cache({ schedule_based_warming: true, system_health_warming: true })
        end
        sleep 1800 # Warm cache every 30 minutes
      rescue StandardError => e
        Rails.logger.error "[ParlantPerformance] Cache warming error: #{e.message}"
        sleep 3600 # Back off to 1 hour on error
      end
    end
  end

  # Database cleanup task for L3 cache
  Thread.new do
    loop do
      begin
        ValidationCache.cleanup_expired_entries if defined?(ValidationCache)
        sleep 3600 # Clean up every hour
      rescue StandardError => e
        Rails.logger.error "[ParlantPerformance] Cache cleanup error: #{e.message}"
        sleep 7200 # Back off to 2 hours on error
      end
    end
  end

  # Performance monitoring task
  Thread.new do
    loop do
      begin
        if Rails.application.config.parlant_performance_service
          stats = Rails.application.config.parlant_performance_service.performance_statistics
          
          Rails.logger.info "[ParlantPerformance] Performance metrics", {
            cache_hit_rate: stats[:cache_statistics][:hit_rate_overall],
            avg_response_time: stats[:performance_achievements][:average_response_time_ms],
            concurrent_capacity: stats[:async_processing_stats][:available_capacity],
            timestamp: Time.current.iso8601
          }
        end
        
        sleep Rails.application.config.parlant_performance.monitoring.reporting_interval
      rescue StandardError => e
        Rails.logger.error "[ParlantPerformance] Monitoring error: #{e.message}"
        sleep 300 # Back off to 5 minutes on error
      end
    end
  end

  Rails.logger.info "[ParlantPerformance] Background tasks initialized"
end

# Development monitoring endpoints
def setup_performance_monitoring_endpoints
  return unless defined?(Rails::Server)

  Rails.application.routes.append do
    namespace :parlant_performance do
      get 'stats', to: proc { |env|
        if Rails.application.config.parlant_performance_service
          stats = Rails.application.config.parlant_performance_service.performance_statistics
          [200, { 'Content-Type' => 'application/json' }, [stats.to_json]]
        else
          [503, { 'Content-Type' => 'application/json' }, [{ error: 'Performance service not available' }.to_json]]
        end
      }
      
      get 'health', to: proc { |env|
        if Rails.application.config.parlant_performance_service
          health = Rails.application.config.parlant_performance_service.health_status_with_performance
          status = health[:performance_optimization][:performance_targets_met][:overall_health] == 'healthy' ? 200 : 503
          [status, { 'Content-Type' => 'application/json' }, [health.to_json]]
        else
          [503, { 'Content-Type' => 'application/json' }, [{ error: 'Performance service not available' }.to_json]]
        end
      }
    end
  end

  Rails.logger.info "[ParlantPerformance] Development monitoring endpoints registered"
  Rails.logger.info "[ParlantPerformance] Access performance stats at: /parlant_performance/stats"
  Rails.logger.info "[ParlantPerformance] Access performance health at: /parlant_performance/health"
end

# Performance monitoring helpers
class ParlantPerformanceMonitor
  class << self
    def current_stats
      return {} unless Rails.application.config.parlant_performance_service
      
      Rails.application.config.parlant_performance_service.performance_statistics
    rescue StandardError => e
      Rails.logger.error "[ParlantPerformance] Stats retrieval error: #{e.message}"
      {}
    end

    def health_check
      return { status: 'unavailable' } unless Rails.application.config.parlant_performance_service
      
      health = Rails.application.config.parlant_performance_service.health_status_with_performance
      {
        status: health[:performance_optimization][:performance_targets_met][:overall_health],
        details: health[:performance_optimization]
      }
    rescue StandardError => e
      Rails.logger.error "[ParlantPerformance] Health check error: #{e.message}"
      { status: 'error', error: e.message }
    end

    def emergency_optimization
      return false unless Rails.application.config.parlant_performance_service
      
      Rails.application.config.parlant_performance_service.enable_emergency_performance_mode(
        'Manual emergency optimization triggered',
        3600 # 1 hour
      )
      true
    rescue StandardError => e
      Rails.logger.error "[ParlantPerformance] Emergency optimization error: #{e.message}"
      false
    end
  end
end

# Add performance monitoring to Rails console
if defined?(Rails::Console)
  Rails.logger.info "[ParlantPerformance] Performance monitoring available in console:"
  Rails.logger.info "[ParlantPerformance] Use ParlantPerformanceMonitor.current_stats for metrics"
  Rails.logger.info "[ParlantPerformance] Use ParlantPerformanceMonitor.health_check for health status"
  Rails.logger.info "[ParlantPerformance] Use ParlantPerformanceMonitor.emergency_optimization for emergency mode"
end