# frozen_string_literal: true

require 'json'
require 'fileutils'

module PerformanceMonitoring
  ##
  # ResourceMonitor provides comprehensive system resource monitoring with optimization recommendations.
  # 
  # This class continuously monitors CPU usage, memory consumption, database connections,
  # garbage collection performance, and other system resources. It provides intelligent
  # analysis and actionable optimization recommendations based on usage patterns.
  #
  # @example Monitor system resources
  #   monitor = PerformanceMonitoring::ResourceMonitor.new
  #   
  #   # Get current resource snapshot
  #   snapshot = monitor.take_snapshot
  #   puts "Memory usage: #{snapshot.memory_usage_mb}MB"
  #   puts "CPU usage: #{snapshot.cpu_percentage}%"
  #   
  #   # Get optimization recommendations
  #   recommendations = monitor.optimization_recommendations
  #   recommendations.each { |rec| puts "#{rec.priority}: #{rec.description}" }
  #
  # @example Configure monitoring thresholds  
  #   ResourceMonitor.configure do |config|
  #     config.memory_warning_threshold = 80 # 80% memory usage warning
  #     config.cpu_warning_threshold = 85    # 85% CPU usage warning
  #     config.gc_frequency_threshold = 100   # GC runs per minute threshold
  #     config.monitoring_interval = 30      # Take snapshots every 30 seconds
  #   end
  #
  # @author Performance Monitoring Specialist
  # @since 2025-09-05
  class ResourceMonitor
    ##
    # Configuration for resource monitoring
    class Configuration
      attr_accessor :memory_warning_threshold, :memory_critical_threshold,
                    :cpu_warning_threshold, :cpu_critical_threshold,
                    :gc_frequency_threshold, :database_connection_threshold,
                    :monitoring_interval, :history_retention_days,
                    :logger, :storage_directory, :alert_callback

      def initialize
        @memory_warning_threshold = 75    # 75% memory usage warning
        @memory_critical_threshold = 90   # 90% memory usage critical
        @cpu_warning_threshold = 80       # 80% CPU usage warning  
        @cpu_critical_threshold = 95      # 95% CPU usage critical
        @gc_frequency_threshold = 50      # GC runs per minute threshold
        @database_connection_threshold = 80 # 80% of max connections
        @monitoring_interval = 60         # 60 seconds between snapshots
        @history_retention_days = 7       # Keep 7 days of history
        @logger = Rails.logger
        @storage_directory = Rails.root.join('development/reports/resource_monitoring')
      end
    end

    ##
    # Resource snapshot containing system metrics at a point in time
    class ResourceSnapshot
      attr_reader :timestamp, :memory_usage_bytes, :memory_usage_percentage,
                  :cpu_percentage, :load_average, :gc_stats, :database_stats,
                  :process_stats, :disk_usage, :network_stats

      def initialize(data = {})
        @timestamp = data[:timestamp] || Time.current
        @memory_usage_bytes = data[:memory_usage_bytes] || 0
        @memory_usage_percentage = data[:memory_usage_percentage] || 0.0
        @cpu_percentage = data[:cpu_percentage] || 0.0
        @load_average = data[:load_average] || [0.0, 0.0, 0.0]
        @gc_stats = data[:gc_stats] || {}
        @database_stats = data[:database_stats] || {}
        @process_stats = data[:process_stats] || {}
        @disk_usage = data[:disk_usage] || {}
        @network_stats = data[:network_stats] || {}
      end

      ##
      # Get memory usage in megabytes
      # @return [Float] memory usage in MB
      def memory_usage_mb
        memory_usage_bytes / 1024.0 / 1024.0
      end

      ##
      # Get memory usage in gigabytes  
      # @return [Float] memory usage in GB
      def memory_usage_gb
        memory_usage_mb / 1024.0
      end

      ##
      # Check if memory usage is at warning level
      # @return [Boolean] true if memory usage exceeds warning threshold
      def memory_warning?
        memory_usage_percentage > ResourceMonitor.configuration.memory_warning_threshold
      end

      ##
      # Check if memory usage is at critical level
      # @return [Boolean] true if memory usage exceeds critical threshold  
      def memory_critical?
        memory_usage_percentage > ResourceMonitor.configuration.memory_critical_threshold
      end

      ##
      # Check if CPU usage is at warning level
      # @return [Boolean] true if CPU usage exceeds warning threshold
      def cpu_warning?
        cpu_percentage > ResourceMonitor.configuration.cpu_warning_threshold
      end

      ##
      # Check if CPU usage is at critical level
      # @return [Boolean] true if CPU usage exceeds critical threshold
      def cpu_critical?
        cpu_percentage > ResourceMonitor.configuration.cpu_critical_threshold
      end

      ##
      # Get garbage collection frequency (collections per minute)
      # @return [Float] GC frequency
      def gc_frequency_per_minute
        return 0.0 unless gc_stats[:count] && gc_stats[:time_since_last_measurement]
        
        time_minutes = gc_stats[:time_since_last_measurement] / 60.0
        return 0.0 if time_minutes <= 0
        
        gc_stats[:count] / time_minutes
      end

      ##
      # Check if GC frequency is excessive
      # @return [Boolean] true if GC frequency exceeds threshold
      def excessive_gc_frequency?
        gc_frequency_per_minute > ResourceMonitor.configuration.gc_frequency_threshold
      end

      ##
      # Convert snapshot to hash for serialization
      # @return [Hash] snapshot data as hash
      def to_hash
        {
          timestamp: timestamp.iso8601,
          memory_usage_bytes: memory_usage_bytes,
          memory_usage_percentage: memory_usage_percentage,
          memory_usage_mb: memory_usage_mb,
          cpu_percentage: cpu_percentage,
          load_average: load_average,
          gc_stats: gc_stats,
          database_stats: database_stats,
          process_stats: process_stats,
          disk_usage: disk_usage,
          network_stats: network_stats,
          alerts: {
            memory_warning: memory_warning?,
            memory_critical: memory_critical?,
            cpu_warning: cpu_warning?,
            cpu_critical: cpu_critical?,
            excessive_gc: excessive_gc_frequency?
          }
        }
      end
    end

    ##
    # Optimization recommendation with priority and description
    class OptimizationRecommendation
      attr_reader :category, :priority, :title, :description, :impact,
                  :implementation_effort, :resource_metrics, :confidence_score

      def initialize(category:, priority:, title:, description:, impact: :medium,
                     implementation_effort: :medium, resource_metrics: {}, confidence_score: 0.8)
        @category = category
        @priority = priority
        @title = title
        @description = description
        @impact = impact
        @implementation_effort = implementation_effort
        @resource_metrics = resource_metrics
        @confidence_score = confidence_score
      end

      ##
      # Convert recommendation to hash
      # @return [Hash] recommendation data as hash
      def to_hash
        {
          category: category,
          priority: priority,
          title: title,
          description: description,
          impact: impact,
          implementation_effort: implementation_effort,
          resource_metrics: resource_metrics,
          confidence_score: confidence_score
        }
      end
    end

    class_attribute :configuration
    self.configuration = Configuration.new

    ##
    # Configure the resource monitor
    # @yield [Configuration] configuration object
    def self.configure
      yield configuration
    end

    ##
    # Initialize resource monitor
    # @param logger [Logger] custom logger instance (optional)
    def initialize(logger: nil)
      @logger = logger || configuration.logger
      @monitoring_thread = nil
      @snapshots_history = []
      @last_gc_stats = GC.stat.dup
      @last_measurement_time = Time.current
      ensure_storage_directory_exists
    end

    ##
    # Start continuous monitoring in background thread
    def start_monitoring
      return if monitoring_active?

      @logger&.info("[RESOURCE] Starting continuous resource monitoring")
      
      @monitoring_thread = Thread.new do
        loop do
          begin
            take_snapshot
            sleep configuration.monitoring_interval
          rescue StandardError => e
            @logger&.error("[RESOURCE] Monitoring error: #{e.message}")
            sleep 30 # Wait before retrying
          end
        end
      end
    end

    ##
    # Stop continuous monitoring
    def stop_monitoring
      return unless monitoring_active?

      @logger&.info("[RESOURCE] Stopping resource monitoring")
      @monitoring_thread&.kill
      @monitoring_thread = nil
    end

    ##
    # Check if monitoring is currently active
    # @return [Boolean] true if monitoring is active
    def monitoring_active?
      @monitoring_thread&.alive? || false
    end

    ##
    # Take a resource snapshot
    # @return [ResourceSnapshot] current resource snapshot
    def take_snapshot
      current_time = Time.current
      
      snapshot = ResourceSnapshot.new(
        timestamp: current_time,
        memory_usage_bytes: get_memory_usage_bytes,
        memory_usage_percentage: get_memory_usage_percentage,
        cpu_percentage: get_cpu_percentage,
        load_average: get_load_average,
        gc_stats: get_gc_stats,
        database_stats: get_database_stats,
        process_stats: get_process_stats,
        disk_usage: get_disk_usage,
        network_stats: get_network_stats
      )

      # Add to history
      @snapshots_history << snapshot
      cleanup_old_snapshots

      # Save snapshot if configured
      save_snapshot(snapshot)

      # Check for alerts
      check_resource_alerts(snapshot)

      snapshot
    end

    ##
    # Get optimization recommendations based on resource usage patterns
    # @param analysis_window [Integer] hours of data to analyze (default: 24)
    # @return [Array<OptimizationRecommendation>] array of recommendations
    def optimization_recommendations(analysis_window: 24)
      recommendations = []
      
      # Get recent snapshots for analysis
      cutoff_time = Time.current - analysis_window.hours
      recent_snapshots = @snapshots_history.select { |s| s.timestamp > cutoff_time }
      
      if recent_snapshots.empty?
        @logger&.warn("[RESOURCE] No recent snapshots available for analysis")
        return recommendations
      end

      # Memory optimization recommendations
      recommendations.concat(analyze_memory_usage(recent_snapshots))
      
      # CPU optimization recommendations  
      recommendations.concat(analyze_cpu_usage(recent_snapshots))
      
      # Garbage collection optimization recommendations
      recommendations.concat(analyze_gc_performance(recent_snapshots))
      
      # Database optimization recommendations
      recommendations.concat(analyze_database_performance(recent_snapshots))
      
      # General performance recommendations
      recommendations.concat(analyze_general_performance(recent_snapshots))

      # Sort by priority and confidence
      recommendations.sort_by { |r| [priority_score(r.priority), -r.confidence_score] }
    end

    ##
    # Get comprehensive resource usage report
    # @param hours [Integer] hours of data to include in report
    # @return [Hash] detailed resource usage report
    def resource_usage_report(hours: 24)
      cutoff_time = Time.current - hours.hours
      recent_snapshots = @snapshots_history.select { |s| s.timestamp > cutoff_time }
      
      return { error: 'Insufficient data' } if recent_snapshots.empty?

      {
        report_period: "#{hours} hours",
        generated_at: Time.current.iso8601,
        summary: generate_usage_summary(recent_snapshots),
        memory_analysis: analyze_memory_trends(recent_snapshots),
        cpu_analysis: analyze_cpu_trends(recent_snapshots),
        gc_analysis: analyze_gc_trends(recent_snapshots),
        database_analysis: analyze_database_trends(recent_snapshots),
        alerts: recent_alerts(recent_snapshots),
        optimization_recommendations: optimization_recommendations(analysis_window: hours),
        raw_snapshots: recent_snapshots.map(&:to_hash)
      }
    end

    private

    ##
    # Get current memory usage in bytes
    # @return [Integer] memory usage in bytes
    def get_memory_usage_bytes
      # Use RSS (Resident Set Size) for accurate memory measurement
      rss_kb = `ps -o rss= -p #{Process.pid}`.to_i
      rss_kb * 1024
    rescue
      0
    end

    ##
    # Get memory usage as percentage of available system memory
    # @return [Float] memory usage percentage
    def get_memory_usage_percentage
      return 0.0 unless RUBY_PLATFORM.include?('linux') || RUBY_PLATFORM.include?('darwin')

      begin
        if RUBY_PLATFORM.include?('linux')
          meminfo = File.read('/proc/meminfo')
          total_memory = meminfo.match(/MemTotal:\s*(\d+) kB/)[1].to_i * 1024
        else # macOS
          total_memory = `sysctl -n hw.memsize`.to_i
        end
        
        return 0.0 if total_memory <= 0
        
        (get_memory_usage_bytes.to_f / total_memory * 100).round(2)
      rescue
        0.0
      end
    end

    ##
    # Get current CPU usage percentage
    # @return [Float] CPU usage percentage
    def get_cpu_percentage
      # This is a simplified CPU calculation - for production use, consider
      # implementing more sophisticated CPU monitoring with process sampling
      begin
        if RUBY_PLATFORM.include?('linux')
          cpu_usage = `ps -o %cpu= -p #{Process.pid}`.to_f
        else
          cpu_usage = `ps -o %cpu= -p #{Process.pid}`.to_f
        end
        
        cpu_usage.round(2)
      rescue
        0.0
      end
    end

    ##
    # Get system load average
    # @return [Array<Float>] load averages for 1, 5, and 15 minutes
    def get_load_average
      return [0.0, 0.0, 0.0] unless File.exist?('/proc/loadavg') || RUBY_PLATFORM.include?('darwin')

      begin
        if File.exist?('/proc/loadavg')
          File.read('/proc/loadavg').split[0..2].map(&:to_f)
        else
          uptime = `uptime`
          match = uptime.match(/load averages?:\s*([\d.]+)\s+([\d.]+)\s+([\d.]+)/)
          match ? match[1..3].map(&:to_f) : [0.0, 0.0, 0.0]
        end
      rescue
        [0.0, 0.0, 0.0]
      end
    end

    ##
    # Get garbage collection statistics with delta calculation
    # @return [Hash] GC statistics with deltas
    def get_gc_stats
      current_stats = GC.stat.dup
      current_time = Time.current
      
      time_delta = current_time - @last_measurement_time
      
      gc_deltas = {}
      current_stats.each do |key, value|
        if value.is_a?(Numeric) && @last_gc_stats[key].is_a?(Numeric)
          gc_deltas["#{key}_delta"] = value - @last_gc_stats[key]
        end
      end

      result = current_stats.merge(gc_deltas)
      result[:time_since_last_measurement] = time_delta
      
      # Update for next calculation
      @last_gc_stats = current_stats
      @last_measurement_time = current_time
      
      result
    end

    ##
    # Get database connection statistics
    # @return [Hash] database connection statistics
    def get_database_stats
      return {} unless defined?(ActiveRecord)

      begin
        connection_pool = ActiveRecord::Base.connection_pool
        
        {
          size: connection_pool.size,
          connections: connection_pool.connections.size,
          busy: connection_pool.connections.count(&:in_use?),
          dead: connection_pool.connections.count { |c| !c.active? },
          idle: connection_pool.connections.count { |c| c.active? && !c.in_use? },
          waiting: connection_pool.num_waiting_in_queue,
          usage_percentage: (connection_pool.connections.count(&:in_use?).to_f / connection_pool.size * 100).round(2)
        }
      rescue
        {}
      end
    end

    ##
    # Get process-specific statistics
    # @return [Hash] process statistics
    def get_process_stats
      begin
        {
          pid: Process.pid,
          threads: Thread.list.count,
          open_files: Dir["/proc/#{Process.pid}/fd/*"].count,
          uptime: Process.clock_gettime(Process::CLOCK_MONOTONIC)
        }
      rescue
        {
          pid: Process.pid,
          threads: Thread.list.count
        }
      end
    end

    ##
    # Get disk usage statistics
    # @return [Hash] disk usage information
    def get_disk_usage
      begin
        df_output = `df -h #{Rails.root}`.lines.last
        parts = df_output.split
        
        {
          filesystem: parts[0],
          size: parts[1],
          used: parts[2],
          available: parts[3],
          usage_percentage: parts[4].to_i,
          mount_point: parts[5]
        }
      rescue
        {}
      end
    end

    ##
    # Get network statistics (simplified)
    # @return [Hash] network statistics
    def get_network_stats
      # This is a placeholder for network statistics
      # In production, you might want to implement more detailed network monitoring
      begin
        {
          connections: `netstat -an 2>/dev/null | wc -l`.to_i,
          timestamp: Time.current.iso8601
        }
      rescue
        {}
      end
    end

    ##
    # Clean up old snapshots based on retention policy
    def cleanup_old_snapshots
      cutoff_time = Time.current - configuration.history_retention_days.days
      @snapshots_history.reject! { |snapshot| snapshot.timestamp < cutoff_time }
    end

    ##
    # Save snapshot to storage if configured
    # @param snapshot [ResourceSnapshot] snapshot to save
    def save_snapshot(snapshot)
      return unless configuration.storage_directory

      filename = configuration.storage_directory.join(
        "resource_snapshot_#{snapshot.timestamp.strftime('%Y%m%d_%H%M%S')}.json"
      )

      File.write(filename, JSON.pretty_generate(snapshot.to_hash))
    rescue StandardError => e
      @logger&.error("[RESOURCE] Failed to save snapshot: #{e.message}")
    end

    ##
    # Check for resource alerts and trigger callbacks
    # @param snapshot [ResourceSnapshot] snapshot to check
    def check_resource_alerts(snapshot)
      alerts = []

      alerts << { level: :critical, type: :memory, value: snapshot.memory_usage_percentage } if snapshot.memory_critical?
      alerts << { level: :warning, type: :memory, value: snapshot.memory_usage_percentage } if snapshot.memory_warning?
      alerts << { level: :critical, type: :cpu, value: snapshot.cpu_percentage } if snapshot.cpu_critical?
      alerts << { level: :warning, type: :cpu, value: snapshot.cpu_percentage } if snapshot.cpu_warning?
      alerts << { level: :warning, type: :gc, value: snapshot.gc_frequency_per_minute } if snapshot.excessive_gc_frequency?

      # Trigger alert callback for each alert
      alerts.each do |alert|
        @logger&.warn("[RESOURCE] #{alert[:level].upcase} #{alert[:type]} alert: #{alert[:value]}")
        configuration.alert_callback&.call(alert, snapshot)
      end
    end

    ##
    # Analyze memory usage patterns and generate recommendations
    # @param snapshots [Array<ResourceSnapshot>] snapshots to analyze
    # @return [Array<OptimizationRecommendation>] memory optimization recommendations
    def analyze_memory_usage(snapshots)
      recommendations = []
      
      avg_memory = snapshots.sum(&:memory_usage_percentage) / snapshots.length.to_f
      max_memory = snapshots.max_by(&:memory_usage_percentage).memory_usage_percentage
      memory_trend = calculate_trend(snapshots.map(&:memory_usage_percentage))

      # High memory usage recommendation
      if avg_memory > configuration.memory_warning_threshold
        recommendations << OptimizationRecommendation.new(
          category: :memory,
          priority: max_memory > configuration.memory_critical_threshold ? :critical : :high,
          title: 'High Memory Usage Detected',
          description: "Average memory usage is #{avg_memory.round(1)}%. Consider implementing memory optimization strategies such as object pooling, caching optimization, or memory leak investigation.",
          impact: :high,
          implementation_effort: :medium,
          resource_metrics: { average_memory: avg_memory, max_memory: max_memory },
          confidence_score: 0.9
        )
      end

      # Memory leak detection
      if memory_trend == :increasing
        memory_growth = snapshots.last.memory_usage_percentage - snapshots.first.memory_usage_percentage
        if memory_growth > 10 # 10% growth over analysis period
          recommendations << OptimizationRecommendation.new(
            category: :memory,
            priority: :critical,
            title: 'Potential Memory Leak Detected',
            description: "Memory usage has grown by #{memory_growth.round(1)}% over the analysis period. Investigate for memory leaks in long-running processes, unclosed resources, or accumulating caches.",
            impact: :critical,
            implementation_effort: :high,
            resource_metrics: { memory_growth: memory_growth, trend: memory_trend },
            confidence_score: 0.85
          )
        end
      end

      recommendations
    end

    ##
    # Analyze CPU usage patterns and generate recommendations
    # @param snapshots [Array<ResourceSnapshot>] snapshots to analyze
    # @return [Array<OptimizationRecommendation>] CPU optimization recommendations
    def analyze_cpu_usage(snapshots)
      recommendations = []
      
      avg_cpu = snapshots.sum(&:cpu_percentage) / snapshots.length.to_f
      max_cpu = snapshots.max_by(&:cpu_percentage).cpu_percentage
      high_cpu_count = snapshots.count { |s| s.cpu_warning? }

      # High CPU usage recommendation
      if avg_cpu > configuration.cpu_warning_threshold
        recommendations << OptimizationRecommendation.new(
          category: :cpu,
          priority: max_cpu > configuration.cpu_critical_threshold ? :critical : :high,
          title: 'High CPU Usage Detected',
          description: "Average CPU usage is #{avg_cpu.round(1)}%. Consider optimizing algorithms, implementing caching, using background jobs for heavy processing, or scaling horizontally.",
          impact: :high,
          implementation_effort: :medium,
          resource_metrics: { average_cpu: avg_cpu, max_cpu: max_cpu, high_cpu_occurrences: high_cpu_count },
          confidence_score: 0.88
        )
      end

      # CPU spike analysis
      if high_cpu_count > snapshots.length * 0.3 # More than 30% of snapshots show high CPU
        recommendations << OptimizationRecommendation.new(
          category: :cpu,
          priority: :medium,
          title: 'Frequent CPU Spikes Detected',
          description: "Frequent CPU spikes detected. Consider implementing request throttling, optimizing database queries, or distributing processing across multiple workers.",
          impact: :medium,
          implementation_effort: :medium,
          resource_metrics: { cpu_spike_frequency: high_cpu_count.to_f / snapshots.length },
          confidence_score: 0.75
        )
      end

      recommendations
    end

    ##
    # Analyze garbage collection performance
    # @param snapshots [Array<ResourceSnapshot>] snapshots to analyze  
    # @return [Array<OptimizationRecommendation>] GC optimization recommendations
    def analyze_gc_performance(snapshots)
      recommendations = []
      
      gc_frequencies = snapshots.map(&:gc_frequency_per_minute)
      avg_gc_frequency = gc_frequencies.sum / gc_frequencies.length.to_f
      high_gc_count = snapshots.count(&:excessive_gc_frequency?)

      # Excessive GC frequency
      if avg_gc_frequency > configuration.gc_frequency_threshold
        recommendations << OptimizationRecommendation.new(
          category: :gc,
          priority: :high,
          title: 'Excessive Garbage Collection Activity',
          description: "Garbage collection is running #{avg_gc_frequency.round(1)} times per minute on average. Consider optimizing object allocation, implementing object pooling, or tuning GC parameters.",
          impact: :high,
          implementation_effort: :medium,
          resource_metrics: { avg_gc_frequency: avg_gc_frequency, threshold: configuration.gc_frequency_threshold },
          confidence_score: 0.82
        )
      end

      recommendations
    end

    ##
    # Analyze database performance
    # @param snapshots [Array<ResourceSnapshot>] snapshots to analyze
    # @return [Array<OptimizationRecommendation>] database optimization recommendations  
    def analyze_database_performance(snapshots)
      recommendations = []
      
      db_snapshots = snapshots.select { |s| s.database_stats.any? }
      return recommendations if db_snapshots.empty?

      avg_connection_usage = db_snapshots.sum { |s| s.database_stats[:usage_percentage] || 0 } / db_snapshots.length.to_f

      # High database connection usage
      if avg_connection_usage > configuration.database_connection_threshold
        recommendations << OptimizationRecommendation.new(
          category: :database,
          priority: :medium,
          title: 'High Database Connection Usage',
          description: "Average database connection usage is #{avg_connection_usage.round(1)}%. Consider optimizing query performance, implementing connection pooling, or increasing the connection pool size.",
          impact: :medium,
          implementation_effort: :low,
          resource_metrics: { avg_connection_usage: avg_connection_usage },
          confidence_score: 0.78
        )
      end

      recommendations
    end

    ##
    # Analyze general performance patterns
    # @param snapshots [Array<ResourceSnapshot>] snapshots to analyze
    # @return [Array<OptimizationRecommendation>] general performance recommendations
    def analyze_general_performance(snapshots)
      recommendations = []
      
      # Load average analysis
      load_averages = snapshots.map { |s| s.load_average[0] } # 1-minute load average
      avg_load = load_averages.sum / load_averages.length.to_f
      cpu_count = `nproc`.to_i rescue 1

      if avg_load > cpu_count * 0.8
        recommendations << OptimizationRecommendation.new(
          category: :performance,
          priority: :medium,
          title: 'High System Load Average',
          description: "System load average (#{avg_load.round(2)}) is high relative to CPU count (#{cpu_count}). Consider investigating I/O bottlenecks, CPU-intensive processes, or implementing load balancing.",
          impact: :medium,
          implementation_effort: :medium,
          resource_metrics: { avg_load: avg_load, cpu_count: cpu_count },
          confidence_score: 0.7
        )
      end

      recommendations
    end

    ##
    # Calculate trend direction from numeric data
    # @param values [Array<Numeric>] array of values
    # @return [Symbol] trend direction (:increasing, :decreasing, :stable)
    def calculate_trend(values)
      return :stable if values.length < 2
      
      # Simple linear trend calculation
      n = values.length
      sum_x = (0...n).sum
      sum_y = values.sum
      sum_xy = values.each_with_index.sum { |y, x| x * y }
      sum_x2 = (0...n).sum { |x| x * x }
      
      slope = (n * sum_xy - sum_x * sum_y).to_f / (n * sum_x2 - sum_x * sum_x)
      
      if slope > 0.1
        :increasing
      elsif slope < -0.1
        :decreasing
      else
        :stable
      end
    rescue
      :stable
    end

    ##
    # Convert priority to numeric score for sorting
    # @param priority [Symbol] priority level
    # @return [Integer] numeric priority score
    def priority_score(priority)
      case priority
      when :critical then 1
      when :high then 2
      when :medium then 3
      when :low then 4
      else 5
      end
    end

    ##
    # Generate usage summary from snapshots
    # @param snapshots [Array<ResourceSnapshot>] snapshots to analyze
    # @return [Hash] usage summary
    def generate_usage_summary(snapshots)
      memory_values = snapshots.map(&:memory_usage_percentage)
      cpu_values = snapshots.map(&:cpu_percentage)

      {
        total_snapshots: snapshots.length,
        time_range: {
          start: snapshots.first.timestamp.iso8601,
          end: snapshots.last.timestamp.iso8601
        },
        memory: {
          average: memory_values.sum / memory_values.length.to_f,
          maximum: memory_values.max,
          minimum: memory_values.min
        },
        cpu: {
          average: cpu_values.sum / cpu_values.length.to_f,
          maximum: cpu_values.max,
          minimum: cpu_values.min
        }
      }
    end

    ##
    # Analyze memory usage trends
    # @param snapshots [Array<ResourceSnapshot>] snapshots to analyze
    # @return [Hash] memory trend analysis
    def analyze_memory_trends(snapshots)
      memory_values = snapshots.map(&:memory_usage_percentage)
      
      {
        trend_direction: calculate_trend(memory_values),
        volatility: calculate_volatility(memory_values),
        peak_usage_times: identify_peak_times(snapshots, :memory_usage_percentage)
      }
    end

    ##
    # Analyze CPU usage trends
    # @param snapshots [Array<ResourceSnapshot>] snapshots to analyze
    # @return [Hash] CPU trend analysis
    def analyze_cpu_trends(snapshots)
      cpu_values = snapshots.map(&:cpu_percentage)
      
      {
        trend_direction: calculate_trend(cpu_values),
        volatility: calculate_volatility(cpu_values),
        peak_usage_times: identify_peak_times(snapshots, :cpu_percentage)
      }
    end

    ##
    # Analyze GC trends
    # @param snapshots [Array<ResourceSnapshot>] snapshots to analyze
    # @return [Hash] GC trend analysis
    def analyze_gc_trends(snapshots)
      gc_frequencies = snapshots.map(&:gc_frequency_per_minute)
      
      {
        average_frequency: gc_frequencies.sum / gc_frequencies.length.to_f,
        max_frequency: gc_frequencies.max,
        trend_direction: calculate_trend(gc_frequencies)
      }
    end

    ##
    # Analyze database trends
    # @param snapshots [Array<ResourceSnapshot>] snapshots to analyze
    # @return [Hash] database trend analysis
    def analyze_database_trends(snapshots)
      db_snapshots = snapshots.select { |s| s.database_stats.any? }
      return {} if db_snapshots.empty?

      connection_usage = db_snapshots.map { |s| s.database_stats[:usage_percentage] || 0 }
      
      {
        average_connection_usage: connection_usage.sum / connection_usage.length.to_f,
        max_connection_usage: connection_usage.max,
        trend_direction: calculate_trend(connection_usage)
      }
    end

    ##
    # Get recent alerts from snapshots
    # @param snapshots [Array<ResourceSnapshot>] snapshots to check
    # @return [Array] array of recent alerts
    def recent_alerts(snapshots)
      alerts = []
      
      snapshots.each do |snapshot|
        alerts << { type: :memory_critical, timestamp: snapshot.timestamp, value: snapshot.memory_usage_percentage } if snapshot.memory_critical?
        alerts << { type: :cpu_critical, timestamp: snapshot.timestamp, value: snapshot.cpu_percentage } if snapshot.cpu_critical?
        alerts << { type: :excessive_gc, timestamp: snapshot.timestamp, value: snapshot.gc_frequency_per_minute } if snapshot.excessive_gc_frequency?
      end
      
      alerts
    end

    ##
    # Calculate volatility (standard deviation) of values
    # @param values [Array<Numeric>] array of values
    # @return [Float] volatility measure
    def calculate_volatility(values)
      return 0.0 if values.length < 2
      
      mean = values.sum / values.length.to_f
      variance = values.sum { |v| (v - mean) ** 2 } / values.length.to_f
      Math.sqrt(variance)
    end

    ##
    # Identify times when resource usage peaks
    # @param snapshots [Array<ResourceSnapshot>] snapshots to analyze
    # @param metric [Symbol] metric to analyze for peaks
    # @return [Array] array of peak usage times
    def identify_peak_times(snapshots, metric)
      values = snapshots.map { |s| s.public_send(metric) }
      threshold = values.max * 0.8 # Consider top 20% as peaks
      
      peaks = []
      snapshots.each_with_index do |snapshot, index|
        if values[index] >= threshold
          peaks << {
            timestamp: snapshot.timestamp.iso8601,
            value: values[index],
            hour: snapshot.timestamp.hour
          }
        end
      end
      
      peaks
    end

    ##
    # Ensure storage directory exists
    def ensure_storage_directory_exists
      return unless configuration.storage_directory
      
      FileUtils.mkdir_p(configuration.storage_directory)
    end
  end
end