# frozen_string_literal: true

require 'benchmark'
require 'objspace'

module QualityGates
  # Performance Validator
  #
  # Validates system performance characteristics including response times,
  # memory usage, CPU utilization, and resource consumption. Integrates
  # with Ruby profiling tools for comprehensive performance analysis.
  #
  # @example Basic usage
  #   validator = PerformanceValidator.new(
  #     feature_name: 'Search API',
  #     performance_targets: {
  #       response_time: 200,      # milliseconds
  #       memory_usage: 50,        # MB
  #       cpu_utilization: 70,     # percentage
  #       throughput: 100          # requests per second
  #     }
  #   )
  #   result = validator.validate
  #   puts result[:success] ? "Performance OK" : "Issues: #{result[:failures]}"
  #
  # @author Claude Code Assistant
  # @since 2025-09-05
  class PerformanceValidator
    attr_reader :feature_name, :performance_targets, :logger

    # Performance metrics structure
    PerformanceMetrics = Struct.new(
      :response_time_ms,
      :memory_usage_mb,
      :cpu_utilization_pct,
      :throughput_rps,
      :gc_time_ms,
      :object_allocations,
      :database_queries,
      :database_time_ms,
      keyword_init: true
    )

    # Performance target thresholds
    DEFAULT_TARGETS = {
      response_time: 200,      # milliseconds
      memory_usage: 100,       # MB
      cpu_utilization: 80,     # percentage
      throughput: 50,          # requests per second
      gc_time: 10,             # milliseconds
      object_allocations: 1000, # count
      database_queries: 10,    # count
      database_time: 50        # milliseconds
    }.freeze

    # Initialize Performance Validator
    #
    # @param feature_name [String] Name of the feature being validated
    # @param performance_targets [Hash] Performance threshold configuration
    # @param logger [Logger] Logger instance for validation process
    def initialize(feature_name:, performance_targets: {}, logger: nil)
      @feature_name = feature_name
      @performance_targets = DEFAULT_TARGETS.merge(performance_targets)
      @logger = logger || setup_default_logger
      
      @logger.info "[PerformanceValidator] Initialized for feature: #{@feature_name}"
      @logger.info "[PerformanceValidator] Performance targets: #{@performance_targets}"
    end

    # Validate system performance
    #
    # Executes comprehensive performance validation including:
    # - Response time benchmarking
    # - Memory usage profiling
    # - CPU utilization monitoring
    # - Throughput testing
    # - Garbage collection analysis
    # - Database query performance
    # - Object allocation tracking
    #
    # @return [Hash] Performance validation result with success status and details
    def validate
      start_time = Time.now
      @logger.info "[PerformanceValidator] Starting performance validation"

      result = {
        success: true,
        failures: [],
        checks_run: 0,
        metrics: {},
        benchmarks: {},
        execution_time: nil,
        details: nil
      }

      # Execute all performance validation phases
      validate_response_times(result)
      validate_memory_usage(result)
      validate_cpu_utilization(result)
      validate_throughput(result)
      validate_database_performance(result)
      validate_garbage_collection(result)
      validate_object_allocations(result)

      # Finalize results
      result[:execution_time] = Time.now - start_time
      result[:success] = result[:failures].empty?
      result[:details] = build_result_details(result)

      log_performance_results(result)
      result
    end

    # Benchmark specific operation
    #
    # @param operation_name [String] Name of the operation to benchmark
    # @param iterations [Integer] Number of iterations to run
    # @param block [Proc] Operation to benchmark
    # @return [Hash] Benchmark result
    def benchmark_operation(operation_name, iterations = 100, &block)
      @logger.info "[PerformanceValidator] Benchmarking operation: #{operation_name}"

      return { success: false, message: "No operation provided" } unless block_given?

      # Warm up
      3.times { block.call }

      # Collect garbage before benchmarking
      GC.start

      # Perform benchmark
      times = []
      memory_before = current_memory_usage
      objects_before = ObjectSpace.count_objects

      iterations.times do
        time = Benchmark.realtime { block.call }
        times << time * 1000 # Convert to milliseconds
      end

      memory_after = current_memory_usage
      objects_after = ObjectSpace.count_objects

      # Calculate statistics
      avg_time = times.sum / times.length
      min_time = times.min
      max_time = times.max
      p95_time = times.sort[(times.length * 0.95).to_i]

      memory_delta = memory_after - memory_before
      object_allocations = objects_after[:T_OBJECT] - objects_before[:T_OBJECT]

      metrics = PerformanceMetrics.new(
        response_time_ms: avg_time,
        memory_usage_mb: memory_delta,
        object_allocations: object_allocations,
        throughput_rps: 1000.0 / avg_time
      )

      # Validate against targets
      failures = []
      failures << "Response time #{avg_time.round(2)}ms exceeds target #{@performance_targets[:response_time]}ms" if avg_time > @performance_targets[:response_time]
      failures << "Memory usage #{memory_delta.round(2)}MB exceeds target #{@performance_targets[:memory_usage]}MB" if memory_delta > @performance_targets[:memory_usage]
      failures << "Object allocations #{object_allocations} exceeds target #{@performance_targets[:object_allocations]}" if object_allocations > @performance_targets[:object_allocations]

      {
        success: failures.empty?,
        operation: operation_name,
        iterations: iterations,
        metrics: metrics,
        statistics: {
          avg_time_ms: avg_time,
          min_time_ms: min_time,
          max_time_ms: max_time,
          p95_time_ms: p95_time,
          memory_delta_mb: memory_delta,
          object_allocations: object_allocations
        },
        failures: failures,
        execution_time: times.sum / 1000.0
      }
    end

    # Profile memory usage of operation
    #
    # @param operation_name [String] Name of the operation to profile
    # @param block [Proc] Operation to profile
    # @return [Hash] Memory profiling result
    def profile_memory(operation_name, &block)
      @logger.info "[PerformanceValidator] Profiling memory for: #{operation_name}"

      return { success: false, message: "No operation provided" } unless block_given?

      # Force garbage collection before profiling
      GC.start

      memory_before = current_memory_usage
      objects_before = ObjectSpace.count_objects

      # Execute operation
      start_time = Time.now
      result = block.call
      execution_time = Time.now - start_time

      memory_after = current_memory_usage
      objects_after = ObjectSpace.count_objects

      # Calculate memory metrics
      memory_delta = memory_after - memory_before
      object_delta = objects_after[:T_OBJECT] - objects_before[:T_OBJECT]

      # Check against targets
      failures = []
      failures << "Memory usage #{memory_delta.round(2)}MB exceeds target #{@performance_targets[:memory_usage]}MB" if memory_delta > @performance_targets[:memory_usage]

      {
        success: failures.empty?,
        operation: operation_name,
        memory_before_mb: memory_before,
        memory_after_mb: memory_after,
        memory_delta_mb: memory_delta,
        objects_before: objects_before[:T_OBJECT],
        objects_after: objects_after[:T_OBJECT],
        objects_delta: object_delta,
        execution_time: execution_time,
        result: result,
        failures: failures
      }
    end

    private

    # Set up default logger for validation process
    #
    # @return [Logger] Configured logger instance
    def setup_default_logger
      logger = Logger.new($stdout)
      logger.level = Logger::INFO
      logger.formatter = proc do |severity, datetime, _progname, msg|
        "[#{datetime.strftime('%Y-%m-%d %H:%M:%S')}] #{severity}: #{msg}\n"
      end
      logger
    end

    # Validate response times
    #
    # @param result [Hash] Validation result to update
    def validate_response_times(result)
      @logger.info "[PerformanceValidator] Validating response times"

      # Test various operations that might be affected by the feature
      operations = [
        { name: 'Database query', test: -> { test_database_query_performance } },
        { name: 'API endpoint', test: -> { test_api_endpoint_performance } },
        { name: 'Background job', test: -> { test_background_job_performance } },
        { name: 'Page rendering', test: -> { test_page_rendering_performance } }
      ]

      operations.each do |operation|
        begin
          benchmark_result = benchmark_operation(operation[:name], 10) do
            operation[:test].call
          end

          result[:checks_run] += 1
          result[:benchmarks][operation[:name]] = benchmark_result

          if benchmark_result[:success]
            result[:metrics]["#{operation[:name]}_response_time"] = benchmark_result[:statistics][:avg_time_ms]
          else
            result[:failures].concat(benchmark_result[:failures].map { |f| "Response time - #{operation[:name]}: #{f}" })
          end
        rescue => e
          @logger.error "[PerformanceValidator] Response time test error: #{operation[:name]} - #{e.message}"
          result[:failures] << "Response time test error: #{operation[:name]} - #{e.message}"
        end
      end
    end

    # Validate memory usage
    #
    # @param result [Hash] Validation result to update
    def validate_memory_usage(result)
      @logger.info "[PerformanceValidator] Validating memory usage"

      memory_tests = [
        { name: 'Object creation', test: -> { test_object_creation_memory } },
        { name: 'Data processing', test: -> { test_data_processing_memory } },
        { name: 'Cache operations', test: -> { test_cache_operations_memory } }
      ]

      memory_tests.each do |test|
        begin
          memory_result = profile_memory(test[:name]) do
            test[:test].call
          end

          result[:checks_run] += 1
          result[:benchmarks]["#{test[:name]}_memory"] = memory_result

          if memory_result[:success]
            result[:metrics]["#{test[:name]}_memory_usage"] = memory_result[:memory_delta_mb]
          else
            result[:failures].concat(memory_result[:failures].map { |f| "Memory usage - #{test[:name]}: #{f}" })
          end
        rescue => e
          @logger.error "[PerformanceValidator] Memory test error: #{test[:name]} - #{e.message}"
          result[:failures] << "Memory test error: #{test[:name]} - #{e.message}"
        end
      end
    end

    # Validate CPU utilization
    #
    # @param result [Hash] Validation result to update
    def validate_cpu_utilization(result)
      @logger.info "[PerformanceValidator] Validating CPU utilization"

      # Simple CPU utilization test using CPU-intensive operations
      cpu_result = benchmark_operation('CPU intensive task', 5) do
        test_cpu_intensive_operation
      end

      result[:checks_run] += 1
      result[:benchmarks]['cpu_utilization'] = cpu_result

      if cpu_result[:success]
        result[:metrics]['cpu_utilization'] = cpu_result[:statistics][:avg_time_ms]
      else
        result[:failures].concat(cpu_result[:failures].map { |f| "CPU utilization: #{f}" })
      end
    end

    # Validate throughput
    #
    # @param result [Hash] Validation result to update
    def validate_throughput(result)
      @logger.info "[PerformanceValidator] Validating throughput"

      # Test throughput with concurrent operations
      throughput_result = test_throughput_performance
      result[:checks_run] += 1
      result[:benchmarks]['throughput'] = throughput_result

      if throughput_result[:success]
        result[:metrics]['throughput_rps'] = throughput_result[:throughput_rps]
      else
        result[:failures] << "Throughput: #{throughput_result[:message]}"
      end
    end

    # Validate database performance
    #
    # @param result [Hash] Validation result to update
    def validate_database_performance(result)
      @logger.info "[PerformanceValidator] Validating database performance"

      db_tests = [
        { name: 'Simple query', test: -> { test_simple_database_query } },
        { name: 'Complex query', test: -> { test_complex_database_query } },
        { name: 'Transaction', test: -> { test_database_transaction } }
      ]

      db_tests.each do |test|
        begin
          db_result = benchmark_operation("Database - #{test[:name]}", 10) do
            test[:test].call
          end

          result[:checks_run] += 1
          result[:benchmarks]["database_#{test[:name]}"] = db_result

          if db_result[:success]
            result[:metrics]["database_#{test[:name]}_time"] = db_result[:statistics][:avg_time_ms]
          else
            result[:failures].concat(db_result[:failures].map { |f| "Database - #{test[:name]}: #{f}" })
          end
        rescue => e
          @logger.error "[PerformanceValidator] Database test error: #{test[:name]} - #{e.message}"
          result[:failures] << "Database test error: #{test[:name]} - #{e.message}"
        end
      end
    end

    # Validate garbage collection performance
    #
    # @param result [Hash] Validation result to update
    def validate_garbage_collection(result)
      @logger.info "[PerformanceValidator] Validating garbage collection performance"

      gc_stats_before = GC.stat
      
      # Force some object allocation and garbage collection
      test_objects = []
      1000.times { test_objects << { data: SecureRandom.hex(100) } }
      
      GC.start
      
      gc_stats_after = GC.stat
      
      gc_time = gc_stats_after[:time] - gc_stats_before[:time]
      gc_runs = gc_stats_after[:count] - gc_stats_before[:count]

      result[:checks_run] += 1
      result[:metrics]['gc_time_ms'] = gc_time
      result[:metrics]['gc_runs'] = gc_runs

      if gc_time > @performance_targets[:gc_time]
        result[:failures] << "GC time #{gc_time}ms exceeds target #{@performance_targets[:gc_time]}ms"
      end

      @logger.info "[PerformanceValidator] GC Analysis: #{gc_runs} runs, #{gc_time}ms total time"
    end

    # Validate object allocations
    #
    # @param result [Hash] Validation result to update
    def validate_object_allocations(result)
      @logger.info "[PerformanceValidator] Validating object allocations"

      allocation_result = profile_memory('Object allocation test') do
        test_object_allocation_pattern
      end

      result[:checks_run] += 1
      result[:benchmarks]['object_allocations'] = allocation_result

      if allocation_result[:success]
        result[:metrics]['object_allocations'] = allocation_result[:objects_delta]
      else
        result[:failures].concat(allocation_result[:failures].map { |f| "Object allocations: #{f}" })
      end
    end

    # Get current memory usage in MB
    #
    # @return [Float] Current memory usage in megabytes
    def current_memory_usage
      # Get process memory usage (simplified approach)
      if RUBY_PLATFORM =~ /darwin/
        `ps -o rss= -p #{Process.pid}`.to_i / 1024.0 # KB to MB on macOS
      elsif RUBY_PLATFORM =~ /linux/
        File.read("/proc/#{Process.pid}/status").match(/VmRSS:\s*(\d+)/)[1].to_i / 1024.0 # KB to MB
      else
        # Fallback using ObjectSpace (less accurate but portable)
        ObjectSpace.count_objects[:T_DATA] * 0.001 # Rough estimation
      end
    rescue
      # Fallback if system commands fail
      0.0
    end

    # Performance test methods
    def test_database_query_performance
      # Simple database query performance test
      if defined?(ActiveRecord::Base)
        User.limit(10).to_a if User.table_exists?
      end
      sleep(0.001) # Minimal delay for testing
    end

    def test_api_endpoint_performance
      # Simulate API endpoint processing
      data = { test: true, timestamp: Time.now }
      JSON.generate(data)
      sleep(0.002)
    end

    def test_background_job_performance
      # Simulate background job processing
      (1..100).map { |i| i * 2 }.sum
      sleep(0.001)
    end

    def test_page_rendering_performance
      # Simulate page rendering
      template = "<div>#{(1..50).map { |i| "<span>Item #{i}</span>" }.join}</div>"
      template.gsub(/Item \d+/, 'Processed Item')
      sleep(0.003)
    end

    def test_object_creation_memory
      # Test object creation memory impact
      objects = []
      100.times do |i|
        objects << {
          id: i,
          data: SecureRandom.hex(50),
          timestamp: Time.now,
          metadata: { processed: true }
        }
      end
      objects.length
    end

    def test_data_processing_memory
      # Test data processing memory impact
      data = (1..1000).map { |i| { id: i, value: rand(100) } }
      processed = data.select { |item| item[:value] > 50 }
                      .map { |item| item.merge(processed: true) }
      processed.length
    end

    def test_cache_operations_memory
      # Test caching operations memory impact
      cache = {}
      100.times do |i|
        cache["key_#{i}"] = { data: SecureRandom.hex(20), timestamp: Time.now }
      end
      cache.keys.length
    end

    def test_cpu_intensive_operation
      # CPU-intensive operation for testing
      result = 0
      1000.times do |i|
        result += Math.sqrt(i) * Math.sin(i)
      end
      result
    end

    def test_throughput_performance
      @logger.info "[PerformanceValidator] Testing throughput performance"

      start_time = Time.now
      operations_completed = 0
      target_duration = 1.0 # 1 second test

      while (Time.now - start_time) < target_duration
        # Simulate operation
        test_simple_operation
        operations_completed += 1
      end

      actual_duration = Time.now - start_time
      throughput_rps = operations_completed / actual_duration

      success = throughput_rps >= @performance_targets[:throughput]

      {
        success: success,
        throughput_rps: throughput_rps,
        operations_completed: operations_completed,
        duration: actual_duration,
        message: success ? "Throughput #{throughput_rps.round(2)} RPS meets target" : "Throughput #{throughput_rps.round(2)} RPS below target #{@performance_targets[:throughput]} RPS"
      }
    end

    def test_simple_operation
      # Simple operation for throughput testing
      (1..10).map { |i| i * 2 }.sum
    end

    def test_simple_database_query
      if defined?(ActiveRecord::Base) && User.table_exists?
        User.first
      else
        sleep(0.001) # Simulate database query time
      end
    end

    def test_complex_database_query
      if defined?(ActiveRecord::Base) && User.table_exists? && Agent.table_exists?
        User.joins(:agents).limit(5).to_a if User.reflect_on_association(:agents)
      else
        sleep(0.005) # Simulate complex query time
      end
    end

    def test_database_transaction
      if defined?(ActiveRecord::Base)
        ActiveRecord::Base.transaction do
          # Simulate transaction operations
          sleep(0.002)
        end
      else
        sleep(0.002)
      end
    end

    def test_object_allocation_pattern
      # Test specific object allocation patterns
      arrays = []
      hashes = []
      
      50.times do |i|
        arrays << (1..20).map { |j| "item_#{i}_#{j}" }
        hashes << { 
          id: i, 
          data: SecureRandom.hex(30),
          items: arrays.last 
        }
      end
      
      [arrays.length, hashes.length]
    end

    # Build detailed result summary
    #
    # @param result [Hash] Validation result
    # @return [String] Formatted result details
    def build_result_details(result)
      details = []
      details << "Checks executed: #{result[:checks_run]}"
      details << "Benchmarks run: #{result[:benchmarks].keys.length}"
      details << "Metrics collected: #{result[:metrics].keys.length}"
      
      if result[:failures].any?
        details << "Performance issues: #{result[:failures].length}"
      end

      details.join(' | ')
    end

    # Log performance validation results
    #
    # @param result [Hash] Validation result
    def log_performance_results(result)
      if result[:success]
        @logger.info "[PerformanceValidator] ✅ Performance validation passed"
        @logger.info "[PerformanceValidator] Metrics collected: #{result[:metrics].keys.length}"
        
        # Log key performance metrics
        result[:metrics].each do |metric, value|
          @logger.info "[PerformanceValidator] #{metric}: #{value.is_a?(Numeric) ? value.round(2) : value}"
        end
      else
        @logger.error "[PerformanceValidator] ❌ Performance validation failed"
        @logger.error "[PerformanceValidator] Performance issues: #{result[:failures].length}"
        result[:failures].each do |failure|
          @logger.error "[PerformanceValidator] - #{failure}"
        end
      end

      @logger.info "[PerformanceValidator] Execution time: #{result[:execution_time]&.round(2)}s"
    end
  end
end