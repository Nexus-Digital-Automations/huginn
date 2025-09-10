# frozen_string_literal: true

require 'json'
require 'fileutils'
require 'digest'

module PerformanceMonitoring
  ##
  # RegressionDetector provides automated performance regression detection for CI/CD integration.
  # 
  # This class analyzes performance metrics across code changes, detects significant
  # performance regressions, and integrates with CI/CD pipelines to prevent
  # performance degradations from being deployed to production.
  #
  # @example Detect performance regressions in CI/CD
  #   detector = PerformanceMonitoring::RegressionDetector.new
  #   
  #   # Run performance tests and analyze results
  #   test_results = run_performance_test_suite
  #   analysis = detector.analyze_performance_change(test_results)
  #   
  #   if analysis.regression_detected?
  #     puts "Performance regression detected!"
  #     puts analysis.regression_summary
  #     exit 1 # Fail CI/CD pipeline
  #   end
  #
  # @example Configure regression detection thresholds
  #   RegressionDetector.configure do |config|
  #     config.regression_threshold = 0.10      # 10% performance degradation threshold
  #     config.critical_regression_threshold = 0.25  # 25% critical regression threshold
  #     config.minimum_sample_size = 5         # Minimum test runs for statistical significance
  #     config.confidence_level = 0.95         # 95% confidence level for statistical tests
  #   end
  #
  # @author Performance Monitoring Specialist
  # @since 2025-09-05
  class RegressionDetector
    ##
    # Configuration for regression detection
    class Configuration
      attr_accessor :regression_threshold, :critical_regression_threshold,
                    :improvement_threshold, :minimum_sample_size, :confidence_level,
                    :baseline_storage_path, :results_storage_path, :logger,
                    :statistical_test_method, :outlier_detection_enabled,
                    :warmup_runs, :measurement_runs

      def initialize
        @regression_threshold = 0.08          # 8% performance degradation threshold
        @critical_regression_threshold = 0.20 # 20% critical regression threshold  
        @improvement_threshold = 0.05         # 5% improvement detection threshold
        @minimum_sample_size = 3              # Minimum test runs for analysis
        @confidence_level = 0.90              # 90% confidence level
        @baseline_storage_path = Rails.root.join('config/performance_baselines')
        @results_storage_path = Rails.root.join('development/reports/regression_detection')
        @logger = Rails.logger
        @statistical_test_method = :welch_t_test  # Options: :welch_t_test, :mann_whitney
        @outlier_detection_enabled = true
        @warmup_runs = 2
        @measurement_runs = 5
      end
    end

    ##
    # Performance test result for a specific test case
    class PerformanceTestResult
      attr_reader :test_name, :execution_times, :memory_usage, :metadata,
                  :timestamp, :commit_hash, :branch_name, :environment_info

      def initialize(test_name:, execution_times:, memory_usage: [], metadata: {})
        @test_name = test_name
        @execution_times = Array(execution_times)
        @memory_usage = Array(memory_usage)
        @metadata = metadata
        @timestamp = Time.current
        @commit_hash = get_current_commit_hash
        @branch_name = get_current_branch
        @environment_info = collect_environment_info
      end

      ##
      # Get average execution time
      # @return [Float] average execution time in seconds
      def average_execution_time
        return 0.0 if execution_times.empty?
        
        execution_times.sum / execution_times.length.to_f
      end

      ##
      # Get median execution time
      # @return [Float] median execution time in seconds  
      def median_execution_time
        return 0.0 if execution_times.empty?
        
        sorted_times = execution_times.sort
        mid = sorted_times.length / 2
        
        if sorted_times.length.odd?
          sorted_times[mid]
        else
          (sorted_times[mid - 1] + sorted_times[mid]) / 2.0
        end
      end

      ##
      # Get standard deviation of execution times
      # @return [Float] standard deviation
      def execution_time_std_dev
        return 0.0 if execution_times.length < 2
        
        mean = average_execution_time
        variance = execution_times.sum { |time| (time - mean) ** 2 } / execution_times.length.to_f
        Math.sqrt(variance)
      end

      ##
      # Get coefficient of variation (std dev / mean)
      # @return [Float] coefficient of variation
      def coefficient_of_variation
        return 0.0 if average_execution_time == 0.0
        
        execution_time_std_dev / average_execution_time
      end

      ##
      # Check if result has sufficient data for analysis
      # @return [Boolean] true if sufficient data available
      def sufficient_data?
        execution_times.length >= RegressionDetector.configuration.minimum_sample_size
      end

      ##
      # Convert result to hash for storage
      # @return [Hash] result data as hash
      def to_hash
        {
          test_name: test_name,
          execution_times: execution_times,
          memory_usage: memory_usage,
          average_execution_time: average_execution_time,
          median_execution_time: median_execution_time,
          std_dev: execution_time_std_dev,
          coefficient_of_variation: coefficient_of_variation,
          timestamp: timestamp.iso8601,
          commit_hash: commit_hash,
          branch_name: branch_name,
          environment_info: environment_info,
          metadata: metadata
        }
      end

      private

      def get_current_commit_hash
        `git rev-parse HEAD 2>/dev/null`.strip
      rescue
        'unknown'
      end

      def get_current_branch
        `git rev-parse --abbrev-ref HEAD 2>/dev/null`.strip
      rescue
        'unknown'
      end

      def collect_environment_info
        {
          ruby_version: RUBY_VERSION,
          rails_version: Rails.version,
          platform: RUBY_PLATFORM,
          hostname: get_hostname,
          cpu_count: get_cpu_count
        }
      rescue
        {}
      end
      
      def get_hostname
        `hostname`.strip
      rescue
        'unknown'
      end
      
      def get_cpu_count
        `nproc`.to_i
      rescue
        1
      end
    end

    ##
    # Analysis result comparing current performance with baseline
    class RegressionAnalysis
      attr_reader :test_name, :current_result, :baseline_result, :statistical_analysis,
                  :regression_detected, :improvement_detected, :confidence_score,
                  :performance_change_percentage, :analysis_timestamp

      def initialize(test_name:, current_result:, baseline_result:, statistical_analysis: {})
        @test_name = test_name
        @current_result = current_result
        @baseline_result = baseline_result
        @statistical_analysis = statistical_analysis
        @analysis_timestamp = Time.current
        
        analyze_performance_change
      end

      ##
      # Check if regression was detected
      # @return [Boolean] true if regression detected
      def regression_detected?
        @regression_detected
      end

      ##
      # Check if improvement was detected
      # @return [Boolean] true if improvement detected
      def improvement_detected?
        @improvement_detected
      end

      ##
      # Check if regression is critical
      # @return [Boolean] true if critical regression detected
      def critical_regression?
        regression_detected? && 
          performance_change_percentage > RegressionDetector.configuration.critical_regression_threshold
      end

      ##
      # Get human-readable regression summary
      # @return [String] regression summary
      def regression_summary
        return 'No baseline available for comparison' unless baseline_result

        if critical_regression?
          "CRITICAL REGRESSION: #{test_name} performance degraded by #{(performance_change_percentage * 100).round(1)}%"
        elsif regression_detected?
          "REGRESSION: #{test_name} performance degraded by #{(performance_change_percentage * 100).round(1)}%"
        elsif improvement_detected?
          "IMPROVEMENT: #{test_name} performance improved by #{(-performance_change_percentage * 100).round(1)}%"
        else
          "NO SIGNIFICANT CHANGE: #{test_name} performance within acceptable range"
        end
      end

      ##
      # Get detailed analysis report
      # @return [Hash] detailed analysis data
      def detailed_report
        {
          test_name: test_name,
          analysis_timestamp: analysis_timestamp.iso8601,
          regression_detected: regression_detected?,
          improvement_detected: improvement_detected?,
          critical_regression: critical_regression?,
          performance_change_percentage: performance_change_percentage,
          confidence_score: confidence_score,
          current_performance: {
            average_time: current_result.average_execution_time,
            median_time: current_result.median_execution_time,
            std_dev: current_result.execution_time_std_dev,
            sample_size: current_result.execution_times.length
          },
          baseline_performance: baseline_result ? {
            average_time: baseline_result.average_execution_time,
            median_time: baseline_result.median_execution_time,
            std_dev: baseline_result.execution_time_std_dev,
            sample_size: baseline_result.execution_times.length
          } : nil,
          statistical_analysis: statistical_analysis,
          summary: regression_summary
        }
      end

      private

      def analyze_performance_change
        if baseline_result.nil?
          @regression_detected = false
          @improvement_detected = false
          @confidence_score = 0.0
          @performance_change_percentage = 0.0
          return
        end

        # Calculate performance change percentage
        baseline_time = baseline_result.average_execution_time
        current_time = current_result.average_execution_time
        
        @performance_change_percentage = baseline_time > 0 ? 
          (current_time - baseline_time) / baseline_time : 0.0

        # Determine if change is statistically significant
        @confidence_score = calculate_statistical_confidence

        # Apply thresholds with statistical significance
        config = RegressionDetector.configuration
        
        if @performance_change_percentage > config.regression_threshold && @confidence_score >= config.confidence_level
          @regression_detected = true
          @improvement_detected = false
        elsif @performance_change_percentage < -config.improvement_threshold && @confidence_score >= config.confidence_level
          @regression_detected = false
          @improvement_detected = true
        else
          @regression_detected = false
          @improvement_detected = false
        end
      end

      def calculate_statistical_confidence
        return 0.0 unless baseline_result&.sufficient_data? && current_result&.sufficient_data?

        case RegressionDetector.configuration.statistical_test_method
        when :welch_t_test
          welch_t_test_confidence
        when :mann_whitney
          mann_whitney_test_confidence
        else
          simple_confidence_estimate
        end
      end

      def welch_t_test_confidence
        # Welch's t-test for unequal variances
        baseline_times = baseline_result.execution_times
        current_times = current_result.execution_times
        
        n1, n2 = baseline_times.length, current_times.length
        mean1, mean2 = baseline_result.average_execution_time, current_result.average_execution_time
        var1, var2 = baseline_result.execution_time_std_dev ** 2, current_result.execution_time_std_dev ** 2
        
        return 0.0 if var1 == 0 && var2 == 0
        
        # Calculate Welch's t-statistic
        pooled_variance = var1/n1 + var2/n2
        return 0.0 if pooled_variance == 0
        
        t_stat = (mean2 - mean1) / Math.sqrt(pooled_variance)
        pooled_variance ** 2 / ((var1/n1)**2/(n1-1) + (var2/n2)**2/(n2-1))
        
        # Simplified confidence calculation (for production, use proper statistical library)
        # This is a rough approximation
        confidence = [1.0 - 2 * Math.exp(-t_stat.abs), 0.0].max
        
        [confidence, 1.0].min
      rescue
        simple_confidence_estimate
      end

      def mann_whitney_test_confidence
        # Simplified Mann-Whitney U test approximation
        # For production use, implement proper non-parametric test
        baseline_times = baseline_result.execution_times.sort
        current_times = current_result.execution_times.sort
        
        # Calculate U statistic approximation
        n1, n2 = baseline_times.length, current_times.length
        
        rank_sum = 0
        all_times = (baseline_times + current_times).sort
        
        current_times.each do |time|
          rank_sum += all_times.index(time) + 1
        end
        
        u_stat = rank_sum - n2 * (n2 + 1) / 2
        expected_u = n1 * n2 / 2.0
        variance_u = n1 * n2 * (n1 + n2 + 1) / 12.0
        
        return 0.0 if variance_u == 0
        
        z_score = (u_stat - expected_u) / Math.sqrt(variance_u)
        
        # Rough confidence approximation
        confidence = [1.0 - 2 * Math.exp(-z_score.abs / 2), 0.0].max
        [confidence, 1.0].min
      rescue
        simple_confidence_estimate
      end

      def simple_confidence_estimate
        # Simple confidence based on sample sizes and variance
        baseline_cv = baseline_result.coefficient_of_variation
        current_cv = current_result.coefficient_of_variation
        
        # Lower confidence for high variance
        variance_penalty = [baseline_cv + current_cv, 1.0].min
        sample_size_bonus = [current_result.execution_times.length.to_f / 10, 1.0].min
        
        base_confidence = 0.7
        confidence = base_confidence * (1 - variance_penalty * 0.3) * (0.5 + sample_size_bonus * 0.5)
        
        [confidence, 1.0].min
      end
    end

    class_attribute :configuration
    self.configuration = Configuration.new

    ##
    # Configure the regression detector
    # @yield [Configuration] configuration object
    def self.configure
      yield configuration
    end

    ##
    # Initialize regression detector
    # @param logger [Logger] custom logger instance (optional)
    def initialize(logger: nil)
      @logger = logger || configuration.logger
      ensure_storage_directories_exist
    end

    ##
    # Analyze performance change for a single test result
    # @param current_result [PerformanceTestResult] current test result
    # @param baseline_name [String] baseline identifier (optional)
    # @return [RegressionAnalysis] analysis result
    def analyze_performance_change(current_result, baseline_name: 'default')
      baseline_result = load_baseline_result(current_result.test_name, baseline_name)
      
      statistical_analysis = perform_statistical_analysis(current_result, baseline_result)
      
      analysis = RegressionAnalysis.new(
        test_name: current_result.test_name,
        current_result: current_result,
        baseline_result: baseline_result,
        statistical_analysis: statistical_analysis
      )

      # Log analysis result
      log_analysis_result(analysis)
      
      # Save analysis result
      save_analysis_result(analysis)

      analysis
    end

    ##
    # Analyze performance changes for multiple test results
    # @param test_results [Array<PerformanceTestResult>] array of test results
    # @param baseline_name [String] baseline identifier (optional)
    # @return [Array<RegressionAnalysis>] array of analysis results
    def analyze_performance_changes(test_results, baseline_name: 'default')
      analyses = test_results.map { |result| analyze_performance_change(result, baseline_name: baseline_name) }
      
      # Generate summary report
      summary = generate_analysis_summary(analyses)
      save_summary_report(summary, baseline_name)
      
      analyses
    end

    ##
    # Update baseline with current performance results
    # @param test_results [Array<PerformanceTestResult>] test results to use as baseline
    # @param baseline_name [String] baseline identifier (default: 'default')
    def update_baseline(test_results, baseline_name: 'default')
      test_results.each do |result|
        save_baseline_result(result, baseline_name)
      end
      
      @logger&.info("[REGRESSION] Updated baseline '#{baseline_name}' with #{test_results.length} test results")
    end

    ##
    # Run performance regression tests for CI/CD integration
    # @param test_suite_block [Proc] block containing performance tests
    # @param baseline_name [String] baseline identifier (optional)
    # @return [Hash] CI/CD integration result
    def run_ci_cd_performance_check(baseline_name: 'default', &test_suite_block)
      @logger&.info("[REGRESSION] Running CI/CD performance regression check")
      
      # Execute test suite
      test_results = []
      test_suite = TestSuite.new
      test_suite_block.call(test_suite)
      
      test_suite.tests.each do |test_name, test_block|
        result = run_performance_test(test_name, &test_block)
        test_results << result
      end
      
      # Analyze results
      analyses = analyze_performance_changes(test_results, baseline_name: baseline_name)
      
      # Generate CI/CD report
      generate_ci_cd_report(analyses)
    end

    ##
    # Generate comprehensive regression detection report
    # @param hours [Integer] hours of historical data to include (default: 168 = 1 week)
    # @return [Hash] comprehensive report
    def generate_regression_report(hours: 168)
      cutoff_time = Time.current - hours.hours
      
      # Load recent analysis results
      recent_analyses = load_recent_analyses(cutoff_time)
      
      {
        report_period: "#{hours} hours",
        generated_at: Time.current.iso8601,
        summary: generate_report_summary(recent_analyses),
        regression_trends: analyze_regression_trends(recent_analyses),
        performance_stability: analyze_performance_stability(recent_analyses),
        baseline_coverage: analyze_baseline_coverage,
        recommendations: generate_regression_recommendations(recent_analyses)
      }
    end

    private

    ##
    # Test suite container for organizing performance tests
    class TestSuite
      attr_reader :tests

      def initialize
        @tests = {}
      end

      def test(test_name, &block)
        @tests[test_name] = block
      end
    end

    ##
    # Run a single performance test with proper measurement
    # @param test_name [String] name of the test
    # @param test_block [Proc] test code block
    # @return [PerformanceTestResult] test result
    def run_performance_test(test_name, &test_block)
      @logger&.debug("[REGRESSION] Running performance test: #{test_name}")

      # Warmup runs
      configuration.warmup_runs.times { test_block.call }
      
      # Force garbage collection before measurement
      GC.start

      # Measurement runs
      execution_times = []
      memory_usage = []
      
      configuration.measurement_runs.times do
        memory_before = get_memory_usage
        
        start_time = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        test_block.call
        end_time = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        
        memory_after = get_memory_usage
        
        execution_times << (end_time - start_time)
        memory_usage << (memory_after - memory_before)
      end

      # Remove outliers if configured
      if configuration.outlier_detection_enabled
        execution_times = remove_outliers(execution_times)
      end

      PerformanceTestResult.new(
        test_name: test_name,
        execution_times: execution_times,
        memory_usage: memory_usage,
        metadata: {
          warmup_runs: configuration.warmup_runs,
          measurement_runs: configuration.measurement_runs,
          outliers_removed: configuration.outlier_detection_enabled
        }
      )
    end

    ##
    # Load baseline result for comparison
    # @param test_name [String] name of the test
    # @param baseline_name [String] baseline identifier
    # @return [PerformanceTestResult, nil] baseline result or nil if not found
    def load_baseline_result(test_name, baseline_name)
      baseline_file = baseline_file_path(test_name, baseline_name)
      return nil unless File.exist?(baseline_file)

      data = JSON.parse(File.read(baseline_file))
      
      PerformanceTestResult.new(
        test_name: data['test_name'],
        execution_times: data['execution_times'],
        memory_usage: data['memory_usage'] || [],
        metadata: data['metadata'] || {}
      )
    rescue JSON::ParserError => e
      @logger&.warn("[REGRESSION] Failed to load baseline for #{test_name}: #{e.message}")
      nil
    end

    ##
    # Save baseline result to storage
    # @param result [PerformanceTestResult] test result to save as baseline
    # @param baseline_name [String] baseline identifier
    def save_baseline_result(result, baseline_name)
      baseline_file = baseline_file_path(result.test_name, baseline_name)
      
      FileUtils.mkdir_p(File.dirname(baseline_file))
      File.write(baseline_file, JSON.pretty_generate(result.to_hash))
    rescue StandardError => e
      @logger&.error("[REGRESSION] Failed to save baseline for #{result.test_name}: #{e.message}")
    end

    ##
    # Perform statistical analysis on test results
    # @param current_result [PerformanceTestResult] current test result
    # @param baseline_result [PerformanceTestResult] baseline test result
    # @return [Hash] statistical analysis data
    def perform_statistical_analysis(current_result, baseline_result)
      return {} unless baseline_result

      {
        current_stats: {
          sample_size: current_result.execution_times.length,
          mean: current_result.average_execution_time,
          median: current_result.median_execution_time,
          std_dev: current_result.execution_time_std_dev,
          coefficient_of_variation: current_result.coefficient_of_variation
        },
        baseline_stats: {
          sample_size: baseline_result.execution_times.length,
          mean: baseline_result.average_execution_time,
          median: baseline_result.median_execution_time,
          std_dev: baseline_result.execution_time_std_dev,
          coefficient_of_variation: baseline_result.coefficient_of_variation
        },
        statistical_test: configuration.statistical_test_method,
        confidence_level: configuration.confidence_level
      }
    end

    ##
    # Log analysis result with appropriate level
    # @param analysis [RegressionAnalysis] analysis result to log
    def log_analysis_result(analysis)
      return unless @logger

      if analysis.critical_regression?
        @logger.error("[REGRESSION] #{analysis.regression_summary}")
      elsif analysis.regression_detected?
        @logger.warn("[REGRESSION] #{analysis.regression_summary}")
      elsif analysis.improvement_detected?
        @logger.info("[REGRESSION] #{analysis.regression_summary}")
      else
        @logger.debug("[REGRESSION] #{analysis.regression_summary}")
      end
    end

    ##
    # Save analysis result to storage
    # @param analysis [RegressionAnalysis] analysis result to save
    def save_analysis_result(analysis)
      timestamp = analysis.analysis_timestamp.strftime('%Y%m%d_%H%M%S')
      filename = configuration.results_storage_path.join(
        "regression_analysis_#{analysis.test_name}_#{timestamp}.json"
      )

      File.write(filename, JSON.pretty_generate(analysis.detailed_report))
    rescue StandardError => e
      @logger&.error("[REGRESSION] Failed to save analysis result: #{e.message}")
    end

    ##
    # Generate summary from multiple analyses
    # @param analyses [Array<RegressionAnalysis>] array of analysis results
    # @return [Hash] summary data
    def generate_analysis_summary(analyses)
      total_tests = analyses.length
      regressions = analyses.count(&:regression_detected?)
      critical_regressions = analyses.count(&:critical_regression?)
      improvements = analyses.count(&:improvement_detected?)
      
      {
        timestamp: Time.current.iso8601,
        total_tests: total_tests,
        regressions_detected: regressions,
        critical_regressions: critical_regressions,
        improvements_detected: improvements,
        stable_tests: total_tests - regressions - improvements,
        success_rate: ((total_tests - regressions).to_f / total_tests * 100).round(2),
        detailed_results: analyses.map(&:detailed_report)
      }
    end

    ##
    # Save summary report to storage
    # @param summary [Hash] summary data
    # @param baseline_name [String] baseline identifier
    def save_summary_report(summary, baseline_name)
      timestamp = Time.current.strftime('%Y%m%d_%H%M%S')
      filename = configuration.results_storage_path.join(
        "regression_summary_#{baseline_name}_#{timestamp}.json"
      )

      File.write(filename, JSON.pretty_generate(summary))
    rescue StandardError => e
      @logger&.error("[REGRESSION] Failed to save summary report: #{e.message}")
    end

    ##
    # Generate CI/CD integration report
    # @param analyses [Array<RegressionAnalysis>] analysis results
    # @return [Hash] CI/CD report with pass/fail status
    def generate_ci_cd_report(analyses)
      summary = generate_analysis_summary(analyses)
      
      # Determine CI/CD status
      has_critical_regressions = analyses.any?(&:critical_regression?)
      has_regressions = analyses.any?(&:regression_detected?)
      
      ci_cd_status = if has_critical_regressions
        'FAILED'
      elsif has_regressions
        'WARNING'  
      else
        'PASSED'
      end

      report = {
        ci_cd_status: ci_cd_status,
        exit_code: has_critical_regressions ? 1 : 0,
        summary: summary,
        recommendations: generate_ci_cd_recommendations(analyses)
      }

      # Log CI/CD result
      @logger&.info("[REGRESSION] CI/CD Performance Check: #{ci_cd_status}")
      if has_critical_regressions
        @logger&.error("[REGRESSION] Critical performance regressions detected - failing build")
      elsif has_regressions
        @logger&.warn("[REGRESSION] Performance regressions detected - proceed with caution")
      end

      report
    end

    ##
    # Remove statistical outliers from execution times
    # @param times [Array<Float>] execution times
    # @return [Array<Float>] times with outliers removed
    def remove_outliers(times)
      return times if times.length < 4

      # Use IQR method for outlier detection
      sorted_times = times.sort
      q1_index = (sorted_times.length * 0.25).floor
      q3_index = (sorted_times.length * 0.75).floor
      
      q1 = sorted_times[q1_index]
      q3 = sorted_times[q3_index]
      iqr = q3 - q1
      
      lower_bound = q1 - 1.5 * iqr
      upper_bound = q3 + 1.5 * iqr
      
      filtered_times = times.select { |time| time >= lower_bound && time <= upper_bound }
      
      # Ensure we keep at least minimum sample size
      if filtered_times.length < configuration.minimum_sample_size
        times
      else
        filtered_times
      end
    end

    ##
    # Get baseline file path
    # @param test_name [String] test name
    # @param baseline_name [String] baseline identifier
    # @return [Pathname] baseline file path
    def baseline_file_path(test_name, baseline_name)
      safe_test_name = test_name.gsub(/[^a-zA-Z0-9_-]/, '_')
      configuration.baseline_storage_path.join("#{baseline_name}_#{safe_test_name}.json")
    end

    ##
    # Get current memory usage in bytes
    # @return [Integer] current memory usage
    def get_memory_usage
      `ps -o rss= -p #{Process.pid}`.to_i * 1024
    rescue
      0
    end

    ##
    # Ensure storage directories exist
    def ensure_storage_directories_exist
      FileUtils.mkdir_p(configuration.baseline_storage_path)
      FileUtils.mkdir_p(configuration.results_storage_path)
    end

    ##
    # Load recent analysis results
    # @param cutoff_time [Time] cutoff time for recent analyses
    # @return [Array<Hash>] array of analysis data
    def load_recent_analyses(cutoff_time)
      analysis_files = Dir.glob(configuration.results_storage_path.join('regression_analysis_*.json'))
                          .select { |f| File.mtime(f) > cutoff_time }
                          .sort_by { |f| File.mtime(f) }
                          .reverse

      analyses = []
      analysis_files.each do |file|
        begin
          data = JSON.parse(File.read(file))
          analyses << data
        rescue JSON::ParserError
          @logger&.warn("[REGRESSION] Failed to parse analysis file: #{file}")
        end
      end

      analyses
    end

    ##
    # Generate report summary from analyses
    # @param analyses [Array<Hash>] analysis data
    # @return [Hash] report summary
    def generate_report_summary(analyses)
      return {} if analyses.empty?

      total_analyses = analyses.length
      regressions = analyses.count { |a| a['regression_detected'] }
      critical_regressions = analyses.count { |a| a['critical_regression'] }
      improvements = analyses.count { |a| a['improvement_detected'] }

      {
        total_analyses: total_analyses,
        regressions: regressions,
        critical_regressions: critical_regressions,
        improvements: improvements,
        regression_rate: (regressions.to_f / total_analyses * 100).round(2),
        improvement_rate: (improvements.to_f / total_analyses * 100).round(2)
      }
    end

    ##
    # Analyze regression trends over time
    # @param analyses [Array<Hash>] analysis data
    # @return [Hash] trend analysis
    def analyze_regression_trends(analyses)
      # Group analyses by test name and analyze trends
      trends = {}
      
      analyses.group_by { |a| a['test_name'] }.each do |test_name, test_analyses|
        sorted_analyses = test_analyses.sort_by { |a| Time.parse(a['analysis_timestamp']) }
        
        recent_changes = sorted_analyses.last(10).map { |a| a['performance_change_percentage'] }
        trend_direction = calculate_trend_direction(recent_changes)
        
        trends[test_name] = {
          trend_direction: trend_direction,
          recent_average_change: recent_changes.sum / recent_changes.length.to_f,
          analysis_count: sorted_analyses.length
        }
      end
      
      trends
    end

    ##
    # Analyze performance stability
    # @param analyses [Array<Hash>] analysis data
    # @return [Hash] stability analysis
    def analyze_performance_stability(analyses)
      stability_scores = {}
      
      analyses.group_by { |a| a['test_name'] }.each do |test_name, test_analyses|
        changes = test_analyses.map { |a| a['performance_change_percentage'].abs }
        
        # Calculate stability score (lower variance = higher stability)
        if changes.length > 1
          mean_change = changes.sum / changes.length.to_f
          variance = changes.sum { |c| (c - mean_change) ** 2 } / changes.length.to_f
          stability_score = [1.0 - Math.sqrt(variance), 0.0].max
        else
          stability_score = 1.0
        end
        
        stability_scores[test_name] = {
          stability_score: stability_score,
          average_absolute_change: changes.sum / changes.length.to_f,
          analysis_count: changes.length
        }
      end
      
      stability_scores
    end

    ##
    # Analyze baseline coverage
    # @return [Hash] baseline coverage information
    def analyze_baseline_coverage
      baseline_files = Dir.glob(configuration.baseline_storage_path.join('*.json'))
      
      {
        total_baselines: baseline_files.length,
        baseline_tests: baseline_files.map { |f| File.basename(f, '.json') },
        storage_path: configuration.baseline_storage_path.to_s
      }
    end

    ##
    # Generate recommendations based on regression analysis
    # @param analyses [Array<Hash>] analysis data
    # @return [Array<Hash>] array of recommendations
    def generate_regression_recommendations(analyses)
      recommendations = []
      
      # Identify consistently regressing tests
      consistently_regressing = analyses.group_by { |a| a['test_name'] }
                                       .select { |_, test_analyses| 
                                         test_analyses.last(3).all? { |a| a['regression_detected'] }
                                       }
      
      consistently_regressing.each do |test_name, _|
        recommendations << {
          priority: 'high',
          category: 'performance',
          test_name: test_name,
          recommendation: "Test '#{test_name}' has been consistently regressing. Investigate and optimize."
        }
      end
      
      # Identify tests without baselines
      tests_without_baselines = analyses.select { |a| !a['baseline_performance'] }
      
      if tests_without_baselines.any?
        recommendations << {
          priority: 'medium',
          category: 'baseline',
          recommendation: "Establish baselines for tests without historical data: #{tests_without_baselines.map { |a| a['test_name'] }.uniq.join(', ')}"
        }
      end
      
      recommendations
    end

    ##
    # Generate CI/CD specific recommendations
    # @param analyses [Array<RegressionAnalysis>] analysis results
    # @return [Array<Hash>] CI/CD recommendations
    def generate_ci_cd_recommendations(analyses)
      recommendations = []
      
      critical_tests = analyses.select(&:critical_regression?)
      regressed_tests = analyses.select(&:regression_detected?)
      
      if critical_tests.any?
        recommendations << {
          priority: 'critical',
          action: 'block_deployment',
          message: "Critical performance regressions detected in: #{critical_tests.map(&:test_name).join(', ')}"
        }
      end
      
      if regressed_tests.any?
        recommendations << {
          priority: 'high',
          action: 'investigate_before_deploy',
          message: "Performance regressions detected in: #{regressed_tests.map(&:test_name).join(', ')}"
        }
      end
      
      recommendations
    end

    ##
    # Calculate trend direction from values
    # @param values [Array<Numeric>] array of values
    # @return [String] trend direction
    def calculate_trend_direction(values)
      return 'stable' if values.length < 2
      
      # Simple linear trend calculation
      n = values.length
      x_values = (0...n).to_a
      
      sum_x = x_values.sum
      sum_y = values.sum
      sum_xy = x_values.zip(values).sum { |x, y| x * y }
      sum_x2 = x_values.sum { |x| x * x }
      
      slope = (n * sum_xy - sum_x * sum_y).to_f / (n * sum_x2 - sum_x * sum_x)
      
      if slope > 0.01
        'worsening'
      elsif slope < -0.01
        'improving'
      else
        'stable'
      end
    rescue
      'stable'
    end
  end
end