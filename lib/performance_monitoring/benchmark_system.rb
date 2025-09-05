# frozen_string_literal: true

require 'benchmark'
require 'json'
require 'fileutils'

module PerformanceMonitoring
  ##
  # BenchmarkSystem provides automated performance benchmarking with alerting capabilities.
  # 
  # This class runs comprehensive performance benchmarks on critical system components,
  # compares results against baseline metrics, and triggers alerts when performance
  # degrades beyond acceptable thresholds.
  #
  # @example Run automated benchmarks
  #   benchmark_system = PerformanceMonitoring::BenchmarkSystem.new
  #   
  #   # Register benchmark suites
  #   benchmark_system.register_benchmark('agent_processing') do |bench|
  #     bench.measure('create_agent') { Agent.create!(name: 'test', type: 'TestAgent') }
  #     bench.measure('process_event') { agent.process_event(test_event) }
  #   end
  #   
  #   # Run all benchmarks and get results
  #   results = benchmark_system.run_all_benchmarks
  #   puts "Performance regression detected!" if results.any?(&:performance_degraded?)
  #
  # @example Configure alerting thresholds
  #   BenchmarkSystem.configure do |config|
  #     config.performance_degradation_threshold = 0.20 # 20% degradation triggers alert
  #     config.critical_degradation_threshold = 0.50    # 50% degradation triggers critical alert
  #     config.baseline_file = Rails.root.join('config/performance_baseline.json')
  #   end
  #
  # @author Performance Monitoring Specialist  
  # @since 2025-09-05
  class BenchmarkSystem
    ##
    # Configuration for benchmark system
    class Configuration
      attr_accessor :performance_degradation_threshold, :critical_degradation_threshold,
                    :baseline_file, :results_directory, :alert_callback, :logger,
                    :warmup_iterations, :benchmark_iterations, :auto_update_baseline

      def initialize
        @performance_degradation_threshold = 0.15 # 15% degradation threshold
        @critical_degradation_threshold = 0.30    # 30% critical degradation threshold
        @baseline_file = Rails.root.join('config/performance_baseline.json')
        @results_directory = Rails.root.join('development/reports/benchmarks')
        @logger = Rails.logger
        @warmup_iterations = 3
        @benchmark_iterations = 10
        @auto_update_baseline = false
      end
    end

    ##
    # Benchmark result with comparison analysis
    class BenchmarkResult
      attr_reader :name, :current_time, :baseline_time, :iterations,
                  :memory_usage, :gc_stats, :timestamp, :metadata

      def initialize(name:, current_time:, baseline_time: nil, iterations: 1, 
                     memory_usage: {}, gc_stats: {}, metadata: {})
        @name = name
        @current_time = current_time
        @baseline_time = baseline_time
        @iterations = iterations
        @memory_usage = memory_usage
        @gc_stats = gc_stats
        @timestamp = Time.current
        @metadata = metadata
      end

      ##
      # Check if performance has degraded compared to baseline
      # @return [Boolean] true if performance degraded beyond threshold
      def performance_degraded?
        return false unless baseline_time && current_time

        degradation_percentage > BenchmarkSystem.configuration.performance_degradation_threshold
      end

      ##
      # Check if performance degradation is critical
      # @return [Boolean] true if performance degradation is critical
      def critical_degradation?
        return false unless baseline_time && current_time

        degradation_percentage > BenchmarkSystem.configuration.critical_degradation_threshold
      end

      ##
      # Calculate performance degradation percentage
      # @return [Float] degradation percentage (positive = worse, negative = better)
      def degradation_percentage
        return 0.0 unless baseline_time && current_time && baseline_time > 0

        (current_time - baseline_time) / baseline_time
      end

      ##
      # Get human-readable performance change description
      # @return [String] performance change description
      def performance_change_description
        return 'No baseline available' unless baseline_time

        if critical_degradation?
          "CRITICAL: #{(degradation_percentage * 100).round(1)}% slower than baseline"
        elsif performance_degraded?
          "WARNING: #{(degradation_percentage * 100).round(1)}% slower than baseline"
        elsif degradation_percentage < -0.05 # 5% improvement threshold
          "IMPROVEMENT: #{(-degradation_percentage * 100).round(1)}% faster than baseline"
        else
          "Performance within acceptable range"
        end
      end

      ##
      # Convert result to hash for storage/serialization
      # @return [Hash] result data as hash
      def to_hash
        {
          name: name,
          current_time: current_time,
          baseline_time: baseline_time,
          iterations: iterations,
          degradation_percentage: degradation_percentage,
          performance_degraded: performance_degraded?,
          critical_degradation: critical_degradation?,
          memory_usage: memory_usage,
          gc_stats: gc_stats,
          timestamp: timestamp.iso8601,
          metadata: metadata
        }
      end
    end

    ##
    # Benchmark suite containing multiple related benchmarks
    class BenchmarkSuite
      attr_reader :name, :benchmarks, :setup_block, :teardown_block

      def initialize(name)
        @name = name
        @benchmarks = {}
        @setup_block = nil
        @teardown_block = nil
      end

      ##
      # Add benchmark to suite
      # @param benchmark_name [String] name of the benchmark
      # @param block [Proc] benchmark code block
      def measure(benchmark_name, &block)
        @benchmarks[benchmark_name] = block
      end

      ##
      # Set suite setup code
      # @param block [Proc] setup code block
      def setup(&block)
        @setup_block = block
      end

      ##
      # Set suite teardown code
      # @param block [Proc] teardown code block  
      def teardown(&block)
        @teardown_block = block
      end
    end

    class_attribute :configuration
    self.configuration = Configuration.new

    ##
    # Configure the benchmark system
    # @yield [Configuration] configuration object
    def self.configure
      yield configuration
    end

    ##
    # Initialize benchmark system
    # @param logger [Logger] custom logger instance (optional)
    def initialize(logger: nil)
      @logger = logger || configuration.logger
      @benchmark_suites = {}
      @baseline_data = load_baseline_data
      ensure_results_directory_exists
    end

    ##
    # Register a new benchmark suite
    # @param suite_name [String] name of the benchmark suite
    # @yield [BenchmarkSuite] benchmark suite for configuration
    def register_benchmark(suite_name, &block)
      suite = BenchmarkSuite.new(suite_name)
      block.call(suite)
      @benchmark_suites[suite_name] = suite
    end

    ##
    # Run all registered benchmarks
    # @return [Array<BenchmarkResult>] array of benchmark results
    def run_all_benchmarks
      results = []

      @benchmark_suites.each do |suite_name, suite|
        suite_results = run_benchmark_suite(suite)
        results.concat(suite_results)
      end

      # Process results (alerting, logging, storage)
      process_benchmark_results(results)

      results
    end

    ##
    # Run specific benchmark suite
    # @param suite_name [String] name of benchmark suite to run
    # @return [Array<BenchmarkResult>] benchmark results
    def run_benchmark_suite(suite_name)
      suite = @benchmark_suites[suite_name]
      raise ArgumentError, "Benchmark suite '#{suite_name}' not found" unless suite

      run_benchmark_suite(suite)
    end

    ##
    # Update baseline with current performance data
    # @param results [Array<BenchmarkResult>] benchmark results to use as baseline
    def update_baseline(results)
      baseline_data = {}

      results.each do |result|
        baseline_data[result.name] = {
          time: result.current_time,
          iterations: result.iterations,
          memory_usage: result.memory_usage,
          gc_stats: result.gc_stats,
          timestamp: result.timestamp.iso8601
        }
      end

      save_baseline_data(baseline_data)
      @baseline_data = baseline_data
      
      @logger&.info("[BENCHMARK] Baseline updated with #{results.length} benchmarks")
    end

    ##
    # Get benchmark history for analysis
    # @param benchmark_name [String] name of benchmark (optional)
    # @param limit [Integer] maximum number of results to return
    # @return [Array<Hash>] historical benchmark data
    def benchmark_history(benchmark_name: nil, limit: 50)
      history_files = Dir.glob(configuration.results_directory.join('*.json'))
                        .sort_by { |f| File.mtime(f) }
                        .reverse
                        .first(limit)

      history = []
      
      history_files.each do |file|
        data = JSON.parse(File.read(file))
        next unless data['results']

        data['results'].each do |result|
          next if benchmark_name && result['name'] != benchmark_name
          history << result
        end
      end

      history
    end

    ##
    # Generate comprehensive benchmark report
    # @return [Hash] detailed benchmark analysis report
    def generate_report
      recent_results = benchmark_history(limit: 1).first
      return { error: 'No benchmark results available' } unless recent_results

      all_history = benchmark_history(limit: 100)
      
      {
        summary: generate_summary_report(recent_results),
        trends: analyze_performance_trends(all_history),
        alerts: identify_performance_alerts(recent_results),
        recommendations: generate_optimization_recommendations(all_history),
        baseline_comparison: compare_with_baseline(recent_results),
        generated_at: Time.current.iso8601
      }
    end

    private

    ##
    # Run a specific benchmark suite
    # @param suite [BenchmarkSuite] benchmark suite to run
    # @return [Array<BenchmarkResult>] benchmark results
    def run_benchmark_suite(suite)
      results = []

      @logger&.info("[BENCHMARK] Running benchmark suite: #{suite.name}")

      # Execute setup if provided
      suite.setup_block&.call

      begin
        suite.benchmarks.each do |benchmark_name, benchmark_block|
          result = run_single_benchmark(benchmark_name, benchmark_block)
          results << result
        end
      ensure
        # Execute teardown if provided
        suite.teardown_block&.call
      end

      results
    end

    ##
    # Run a single benchmark with proper measurement
    # @param benchmark_name [String] name of the benchmark
    # @param benchmark_block [Proc] benchmark code block
    # @return [BenchmarkResult] benchmark result
    def run_single_benchmark(benchmark_name, benchmark_block)
      @logger&.debug("[BENCHMARK] Running benchmark: #{benchmark_name}")

      # Warmup iterations
      configuration.warmup_iterations.times { benchmark_block.call }
      
      # Force garbage collection before measurement
      GC.start
      
      # Capture initial memory and GC stats
      memory_before = get_memory_usage
      gc_stats_before = GC.stat.dup

      # Run actual benchmark
      times = []
      configuration.benchmark_iterations.times do
        time = Benchmark.realtime { benchmark_block.call }
        times << time
      end

      # Capture final memory and GC stats
      memory_after = get_memory_usage
      gc_stats_after = GC.stat.dup

      # Calculate average time
      average_time = times.sum / times.length

      # Get baseline for comparison
      baseline_time = @baseline_data.dig(benchmark_name, 'time')

      # Create result object
      BenchmarkResult.new(
        name: benchmark_name,
        current_time: average_time,
        baseline_time: baseline_time,
        iterations: configuration.benchmark_iterations,
        memory_usage: {
          before: memory_before,
          after: memory_after,
          delta: memory_after - memory_before
        },
        gc_stats: calculate_gc_delta(gc_stats_before, gc_stats_after),
        metadata: {
          individual_times: times,
          warmup_iterations: configuration.warmup_iterations
        }
      )
    end

    ##
    # Process benchmark results (logging, alerting, storage)
    # @param results [Array<BenchmarkResult>] benchmark results
    def process_benchmark_results(results)
      # Log results
      log_benchmark_results(results)
      
      # Save results to file
      save_benchmark_results(results)
      
      # Handle performance alerts
      handle_performance_alerts(results)
      
      # Auto-update baseline if configured
      update_baseline(results) if configuration.auto_update_baseline
    end

    ##
    # Log benchmark results with appropriate detail level
    # @param results [Array<BenchmarkResult>] benchmark results to log
    def log_benchmark_results(results)
      return unless @logger

      @logger.info("[BENCHMARK] Completed #{results.length} benchmarks")

      results.each do |result|
        if result.critical_degradation?
          @logger.error("[BENCHMARK] 🚨 #{result.name}: #{result.performance_change_description}")
        elsif result.performance_degraded?
          @logger.warn("[BENCHMARK] ⚠️  #{result.name}: #{result.performance_change_description}")
        else
          @logger.info("[BENCHMARK] ✅ #{result.name}: #{(result.current_time * 1000).round(2)}ms")
        end
      end
    end

    ##
    # Save benchmark results to file for historical analysis
    # @param results [Array<BenchmarkResult>] benchmark results to save
    def save_benchmark_results(results)
      timestamp = Time.current.strftime('%Y%m%d_%H%M%S')
      filename = configuration.results_directory.join("benchmark_results_#{timestamp}.json")

      result_data = {
        timestamp: Time.current.iso8601,
        results: results.map(&:to_hash),
        configuration: {
          performance_degradation_threshold: configuration.performance_degradation_threshold,
          critical_degradation_threshold: configuration.critical_degradation_threshold,
          benchmark_iterations: configuration.benchmark_iterations
        }
      }

      File.write(filename, JSON.pretty_generate(result_data))
      @logger&.debug("[BENCHMARK] Results saved to: #{filename}")
    end

    ##
    # Handle performance alerts based on benchmark results
    # @param results [Array<BenchmarkResult>] benchmark results
    def handle_performance_alerts(results)
      alerts = results.select { |r| r.performance_degraded? || r.critical_degradation? }
      return if alerts.empty?

      alerts.each do |result|
        alert_level = result.critical_degradation? ? :critical : :warning
        
        # Execute configured alert callback if present
        if configuration.alert_callback
          configuration.alert_callback.call(result, alert_level)
        end
      end
    end

    ##
    # Load baseline performance data
    # @return [Hash] baseline performance data
    def load_baseline_data
      return {} unless File.exist?(configuration.baseline_file)

      JSON.parse(File.read(configuration.baseline_file))
    rescue JSON::ParserError => e
      @logger&.warn("[BENCHMARK] Failed to load baseline data: #{e.message}")
      {}
    end

    ##
    # Save baseline performance data
    # @param data [Hash] baseline data to save
    def save_baseline_data(data)
      FileUtils.mkdir_p(File.dirname(configuration.baseline_file))
      File.write(configuration.baseline_file, JSON.pretty_generate(data))
    end

    ##
    # Ensure results directory exists
    def ensure_results_directory_exists
      FileUtils.mkdir_p(configuration.results_directory)
    end

    ##
    # Get current memory usage in bytes
    # @return [Integer] current memory usage
    def get_memory_usage
      # Use RSS (Resident Set Size) for accurate memory measurement
      `ps -o rss= -p #{Process.pid}`.to_i * 1024
    rescue
      0
    end

    ##
    # Calculate garbage collection statistics delta
    # @param before [Hash] GC stats before benchmark
    # @param after [Hash] GC stats after benchmark
    # @return [Hash] GC stats delta
    def calculate_gc_delta(before, after)
      delta = {}
      
      after.each do |key, value|
        if value.is_a?(Numeric) && before[key].is_a?(Numeric)
          delta[key] = value - before[key]
        end
      end
      
      delta
    end

    ##
    # Generate summary report from benchmark results
    # @param results [Hash] recent benchmark results
    # @return [Hash] summary report data
    def generate_summary_report(results)
      return {} unless results.is_a?(Array)
      
      total_benchmarks = results.length
      degraded_benchmarks = results.count { |r| r.dig('performance_degraded') }
      critical_benchmarks = results.count { |r| r.dig('critical_degradation') }
      
      {
        total_benchmarks: total_benchmarks,
        degraded_benchmarks: degraded_benchmarks,
        critical_benchmarks: critical_benchmarks,
        success_rate: ((total_benchmarks - degraded_benchmarks).to_f / total_benchmarks * 100).round(2)
      }
    end

    ##
    # Analyze performance trends from historical data
    # @param history [Array] historical benchmark data
    # @return [Hash] trend analysis
    def analyze_performance_trends(history)
      trends = {}
      
      # Group by benchmark name and analyze trends
      history.group_by { |h| h['name'] }.each do |name, benchmark_history|
        next if benchmark_history.length < 2
        
        recent_times = benchmark_history.first(10).map { |h| h['current_time'] }
        trend_direction = calculate_trend_direction(recent_times)
        
        trends[name] = {
          direction: trend_direction,
          recent_average: recent_times.sum / recent_times.length,
          sample_count: recent_times.length
        }
      end
      
      trends
    end

    ##
    # Calculate trend direction from time series data
    # @param times [Array<Float>] array of execution times
    # @return [String] trend direction ('improving', 'degrading', 'stable')
    def calculate_trend_direction(times)
      return 'stable' if times.length < 2
      
      # Simple linear trend calculation
      x_values = (0...times.length).to_a
      n = times.length
      
      sum_x = x_values.sum
      sum_y = times.sum
      sum_xy = x_values.zip(times).sum { |x, y| x * y }
      sum_x2 = x_values.sum { |x| x * x }
      
      slope = (n * sum_xy - sum_x * sum_y).to_f / (n * sum_x2 - sum_x * sum_x)
      
      if slope > 0.01  # Significant degradation
        'degrading'
      elsif slope < -0.01  # Significant improvement
        'improving'
      else
        'stable'
      end
    end

    ##
    # Identify performance alerts from results
    # @param results [Hash] benchmark results
    # @return [Array] array of alert information
    def identify_performance_alerts(results)
      alerts = []
      
      return alerts unless results.is_a?(Array)
      
      results.each do |result|
        if result.dig('critical_degradation')
          alerts << {
            level: 'critical',
            benchmark: result['name'],
            message: "Critical performance degradation detected",
            degradation: result['degradation_percentage']
          }
        elsif result.dig('performance_degraded')
          alerts << {
            level: 'warning',
            benchmark: result['name'],
            message: "Performance degradation detected",
            degradation: result['degradation_percentage']
          }
        end
      end
      
      alerts
    end

    ##
    # Generate optimization recommendations
    # @param history [Array] historical benchmark data
    # @return [Array] array of optimization recommendations
    def generate_optimization_recommendations(history)
      recommendations = []
      
      # Analyze patterns and suggest optimizations
      consistently_slow = history.group_by { |h| h['name'] }
                               .select { |_, h| h.first(5).all? { |r| r.dig('performance_degraded') } }
      
      consistently_slow.each do |benchmark_name, _|
        recommendations << {
          benchmark: benchmark_name,
          priority: 'high',
          recommendation: "Consistently slow performance detected. Consider optimization or caching strategies."
        }
      end
      
      recommendations
    end

    ##
    # Compare current results with baseline
    # @param results [Array] current benchmark results
    # @return [Hash] baseline comparison data
    def compare_with_baseline(results)
      return {} unless results.is_a?(Array)
      
      comparison = {
        total_comparisons: 0,
        improvements: 0,
        degradations: 0,
        no_baseline: 0
      }
      
      results.each do |result|
        if result['baseline_time']
          comparison[:total_comparisons] += 1
          
          if result['degradation_percentage'] < -0.05  # 5% improvement
            comparison[:improvements] += 1
          elsif result['performance_degraded']
            comparison[:degradations] += 1
          end
        else
          comparison[:no_baseline] += 1
        end
      end
      
      comparison
    end
  end
end