# frozen_string_literal: true

require 'json'
require 'erb'
require 'csv'
require 'fileutils'

module QualityGates
  # Unified reporting system for all quality gates metrics and results
  # Generates comprehensive reports in multiple formats with historical tracking
  #
  # Usage:
  #   reporter = QualityGates::Reporter.new(configuration)
  #   report = reporter.generate_comprehensive_report(gate_results, execution_context)
  #   reporter.save_report(report, :html)
  #
  # Output Formats: JSON, HTML, CSV, XML, PDF (if available)
  # Features: Historical tracking, trend analysis, executive summaries
  class Reporter
    attr_reader :configuration, :reports_directory, :template_directory

    # Report formats and their corresponding generators
    REPORT_FORMATS = {
      json: :generate_json_report,
      html: :generate_html_report,
      csv: :generate_csv_report,
      xml: :generate_xml_report,
      markdown: :generate_markdown_report
    }.freeze

    # Report sections for comprehensive reporting
    REPORT_SECTIONS = %i[
      executive_summary
      overall_metrics
      gate_results
      detailed_findings
      recommendations
      historical_trends
      appendix
    ].freeze

    def initialize(configuration)
      @configuration = configuration
      @reports_directory = configuration.reports_directory
      @template_directory = File.join(File.dirname(__FILE__), 'templates')
      
      ensure_directories_exist!
    end

    # Generate comprehensive quality gates report
    # @param gate_results [Hash] - results from all executed gates
    # @param execution_context [Hash] - execution metadata and context
    # @return [QualityGates::Report] - comprehensive report object
    def generate_comprehensive_report(gate_results, execution_context)
      report_data = compile_report_data(gate_results, execution_context)
      
      report = Report.new(
        execution_id: execution_context[:execution_id],
        generated_at: Time.now,
        report_data: report_data,
        configuration: @configuration
      )

      # Generate all requested formats
      generate_report_files(report)
      
      # Update historical tracking
      update_historical_data(report)

      report
    end

    # Save report in specific format
    # @param report [QualityGates::Report] - report to save
    # @param format [Symbol] - output format
    # @return [String] - path to saved report file
    def save_report(report, format = :html)
      unless REPORT_FORMATS.key?(format)
        raise ArgumentError, "Unsupported report format: #{format}"
      end

      filename = generate_report_filename(report, format)
      filepath = File.join(@reports_directory, filename)

      content = send(REPORT_FORMATS[format], report)
      
      File.write(filepath, content)
      
      # Create symlink to latest report
      create_latest_symlink(filepath, format)

      filepath
    end

    # Generate executive summary report
    # @param gate_results [Hash] - gate execution results
    # @return [Hash] - executive summary data
    def generate_executive_summary(gate_results)
      total_gates = gate_results.count
      passed_gates = gate_results.count { |_, result| result.passed? }
      failed_gates = gate_results.count { |_, result| result.failed? }
      
      critical_failures = gate_results.select do |gate_name, result|
        result.failed? && @configuration.get_gate_config(gate_name)[:critical]
      end

      {
        overall_status: critical_failures.empty? ? :passed : :failed,
        success_rate: calculate_success_rate(passed_gates, total_gates),
        total_gates: total_gates,
        passed_gates: passed_gates,
        failed_gates: failed_gates,
        critical_failures: critical_failures.count,
        execution_time: calculate_total_execution_time(gate_results),
        quality_score: calculate_quality_score(gate_results),
        recommendations_count: generate_recommendations(gate_results).count
      }
    end

    # Get historical quality trends
    # @param days [Integer] - number of days to analyze
    # @return [Array<Hash>] - historical trend data
    def get_quality_trends(days = 30)
      historical_files = get_historical_report_files(days)
      
      trends = historical_files.map do |filepath|
        report_data = load_historical_report(filepath)
        extract_trend_data(report_data) if report_data
      end.compact

      analyze_trends(trends)
    end

    # Generate metrics comparison report
    # @param current_results [Hash] - current execution results
    # @param previous_results [Hash] - previous execution results for comparison
    # @return [Hash] - comparison analysis
    def generate_comparison_report(current_results, previous_results = nil)
      previous_results ||= get_latest_historical_results

      {
        current_summary: generate_executive_summary(current_results),
        previous_summary: previous_results ? generate_executive_summary(previous_results) : nil,
        improvements: identify_improvements(current_results, previous_results),
        regressions: identify_regressions(current_results, previous_results),
        new_issues: identify_new_issues(current_results, previous_results),
        resolved_issues: identify_resolved_issues(current_results, previous_results)
      }
    end

    # Available? - Check if reporter can function properly
    # @return [Boolean] - whether reporter is operational
    def available?
      Dir.exist?(@reports_directory) && File.writable?(@reports_directory)
    end

    private

    # Ensure required directories exist
    def ensure_directories_exist!
      FileUtils.mkdir_p(@reports_directory)
      FileUtils.mkdir_p(File.join(@reports_directory, 'archives'))
      FileUtils.mkdir_p(File.join(@reports_directory, 'trends'))
    end

    # Compile comprehensive report data from gate results
    def compile_report_data(gate_results, execution_context)
      {
        metadata: {
          execution_id: execution_context[:execution_id],
          generated_at: Time.now.iso8601,
          huginn_version: get_huginn_version,
          quality_gates_version: '1.0.0',
          environment: @configuration.environment,
          git_commit: get_git_commit_sha
        },
        executive_summary: generate_executive_summary(gate_results),
        overall_metrics: calculate_overall_metrics(gate_results),
        gate_results: compile_gate_results_data(gate_results),
        detailed_findings: compile_detailed_findings(gate_results),
        recommendations: generate_recommendations(gate_results),
        historical_context: get_historical_context,
        configuration_snapshot: @configuration.to_hash
      }
    end

    # Generate report files in all configured formats
    def generate_report_files(report)
      formats = @configuration.reporting_config[:formats] || ['json']
      
      formats.each do |format|
        format_sym = format.to_sym
        save_report(report, format_sym) if REPORT_FORMATS.key?(format_sym)
      end
    end

    # Calculate overall quality metrics
    def calculate_overall_metrics(gate_results)
      {
        total_execution_time: calculate_total_execution_time(gate_results),
        quality_score: calculate_quality_score(gate_results),
        success_rate: calculate_success_rate(
          gate_results.count { |_, r| r.passed? },
          gate_results.count
        ),
        critical_gate_status: calculate_critical_gate_status(gate_results),
        performance_metrics: extract_performance_metrics(gate_results),
        coverage_metrics: extract_coverage_metrics(gate_results),
        security_metrics: extract_security_metrics(gate_results)
      }
    end

    # Compile detailed gate results data
    def compile_gate_results_data(gate_results)
      gate_results.transform_values do |result|
        {
          status: result.status,
          execution_time: result.execution_time,
          details: sanitize_result_details(result.details),
          metrics: result.metrics,
          weight: @configuration.get_gate_config(result.gate_name)[:weight] || 1,
          critical: @configuration.get_gate_config(result.gate_name)[:critical] || false,
          category: @configuration.get_gate_config(result.gate_name)[:category],
          validator: @configuration.get_gate_config(result.gate_name)[:validator]
        }
      end
    end

    # Compile detailed findings from all gate results
    def compile_detailed_findings(gate_results)
      findings = {
        critical_issues: [],
        warnings: [],
        improvements: [],
        metrics: {}
      }

      gate_results.each do |gate_name, result|
        gate_config = @configuration.get_gate_config(gate_name)
        
        if result.failed?
          issue = {
            gate: gate_name,
            severity: gate_config[:critical] ? :critical : :warning,
            message: result.primary_failure_reason,
            details: result.details,
            recommendations: result.recommendations
          }

          if gate_config[:critical]
            findings[:critical_issues] << issue
          else
            findings[:warnings] << issue
          end
        elsif result.has_improvement_suggestions?
          findings[:improvements] << {
            gate: gate_name,
            suggestions: result.improvement_suggestions
          }
        end

        # Collect metrics from each gate
        findings[:metrics][gate_name] = result.metrics if result.metrics&.any?
      end

      findings
    end

    # Generate recommendations based on gate results
    def generate_recommendations(gate_results)
      recommendations = []

      # Critical failure recommendations
      critical_failures = gate_results.select do |gate_name, result|
        result.failed? && @configuration.get_gate_config(gate_name)[:critical]
      end

      critical_failures.each do |gate_name, result|
        recommendations << {
          priority: :high,
          category: :critical_fix,
          gate: gate_name,
          title: "Fix critical #{gate_name} failures",
          description: "Critical quality gate failed: #{result.primary_failure_reason}",
          action_items: generate_action_items_for_gate(gate_name, result)
        }
      end

      # Performance improvement recommendations
      slow_gates = gate_results.select { |_, result| result.execution_time > 30 }
      unless slow_gates.empty?
        recommendations << {
          priority: :medium,
          category: :performance,
          title: 'Optimize slow quality gates',
          description: "#{slow_gates.count} gates are taking longer than 30 seconds",
          gates: slow_gates.keys,
          action_items: ['Review gate configurations', 'Consider parallel execution', 'Optimize validation logic']
        }
      end

      # Configuration recommendations
      if @configuration.enabled_gates.count < DEFAULT_GATE_CATEGORIES.count / 2
        recommendations << {
          priority: :low,
          category: :configuration,
          title: 'Enable additional quality gates',
          description: 'Consider enabling more quality gates for comprehensive coverage',
          action_items: ['Review available gates', 'Enable non-critical gates', 'Gradual rollout approach']
        }
      end

      recommendations
    end

    # Generate action items for a specific failing gate
    def generate_action_items_for_gate(gate_name, result)
      base_actions = [
        "Review #{gate_name} gate configuration",
        "Analyze failure details and root cause",
        "Implement fixes for identified issues"
      ]

      # Add gate-specific actions
      gate_specific_actions = case gate_name.to_sym
      when :code_quality
        ['Run linter fixes', 'Review code style guidelines', 'Update editor configuration']
      when :security
        ['Update dependencies', 'Review security policies', 'Run security audit']
      when :performance
        ['Profile application performance', 'Optimize database queries', 'Review caching strategies']
      when :testing
        ['Increase test coverage', 'Fix failing tests', 'Review test strategies']
      else
        ["Review #{gate_name} specific requirements"]
      end

      base_actions + gate_specific_actions
    end

    # Generate JSON format report
    def generate_json_report(report)
      JSON.pretty_generate(report.report_data)
    end

    # Generate HTML format report
    def generate_html_report(report)
      template_file = File.join(@template_directory, 'report.html.erb')
      
      if File.exist?(template_file)
        template = ERB.new(File.read(template_file))
        template.result(binding)
      else
        generate_simple_html_report(report)
      end
    end

    # Generate simple HTML report (fallback)
    def generate_simple_html_report(report)
      data = report.report_data
      
      <<~HTML
        <!DOCTYPE html>
        <html>
        <head>
          <title>Quality Gates Report - #{data[:metadata][:execution_id]}</title>
          <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            .header { background: #f5f5f5; padding: 15px; border-radius: 5px; }
            .summary { display: flex; gap: 20px; margin: 20px 0; }
            .metric { background: white; border: 1px solid #ddd; padding: 15px; border-radius: 5px; flex: 1; }
            .passed { color: #27ae60; }
            .failed { color: #e74c3c; }
            .gate-result { margin: 10px 0; padding: 10px; border-left: 4px solid #ddd; }
            .gate-passed { border-left-color: #27ae60; }
            .gate-failed { border-left-color: #e74c3c; }
            .recommendations { background: #fff3cd; padding: 15px; border-radius: 5px; margin: 20px 0; }
          </style>
        </head>
        <body>
          <div class="header">
            <h1>Quality Gates Report</h1>
            <p>Execution ID: #{data[:metadata][:execution_id]}</p>
            <p>Generated: #{data[:metadata][:generated_at]}</p>
            <p>Environment: #{data[:metadata][:environment]}</p>
          </div>
          
          <div class="summary">
            <div class="metric">
              <h3>Overall Status</h3>
              <p class="#{data[:executive_summary][:overall_status]}">
                #{data[:executive_summary][:overall_status].to_s.upcase}
              </p>
            </div>
            <div class="metric">
              <h3>Quality Score</h3>
              <p>#{data[:executive_summary][:quality_score]}%</p>
            </div>
            <div class="metric">
              <h3>Success Rate</h3>
              <p>#{data[:executive_summary][:success_rate]}%</p>
            </div>
          </div>

          <h2>Gate Results</h2>
          #{generate_html_gate_results(data[:gate_results])}
          
          #{generate_html_recommendations(data[:recommendations]) if data[:recommendations]&.any?}
        </body>
        </html>
      HTML
    end

    # Generate HTML section for gate results
    def generate_html_gate_results(gate_results)
      gate_results.map do |gate_name, result|
        status_class = result[:status] == :passed ? 'gate-passed' : 'gate-failed'
        status_text_class = result[:status] == :passed ? 'passed' : 'failed'
        
        <<~HTML
          <div class="gate-result #{status_class}">
            <h4>#{gate_name.to_s.humanize} 
              <span class="#{status_text_class}">(#{result[:status].to_s.upcase})</span>
            </h4>
            <p>Execution Time: #{result[:execution_time].round(2)}s</p>
            <p>Weight: #{result[:weight]} | Critical: #{result[:critical] ? 'Yes' : 'No'}</p>
          </div>
        HTML
      end.join("\n")
    end

    # Generate HTML section for recommendations
    def generate_html_recommendations(recommendations)
      return '' if recommendations.empty?

      recommendation_items = recommendations.map do |rec|
        priority_color = case rec[:priority]
                        when :high then '#e74c3c'
                        when :medium then '#f39c12'
                        else '#3498db'
                        end

        <<~HTML
          <div style="border-left: 4px solid #{priority_color}; margin: 10px 0; padding: 10px;">
            <h4>#{rec[:title]} (#{rec[:priority].to_s.upcase} Priority)</h4>
            <p>#{rec[:description]}</p>
            #{rec[:action_items] ? "<ul>#{rec[:action_items].map { |item| "<li>#{item}</li>" }.join}</ul>" : ''}
          </div>
        HTML
      end

      <<~HTML
        <div class="recommendations">
          <h2>Recommendations</h2>
          #{recommendation_items.join("\n")}
        </div>
      HTML
    end

    # Generate CSV format report
    def generate_csv_report(report)
      data = report.report_data
      
      CSV.generate do |csv|
        # Headers
        csv << ['Gate Name', 'Status', 'Execution Time', 'Weight', 'Critical', 'Category']
        
        # Gate results
        data[:gate_results].each do |gate_name, result|
          csv << [
            gate_name,
            result[:status],
            result[:execution_time],
            result[:weight],
            result[:critical],
            result[:category]
          ]
        end
      end
    end

    # Generate XML format report
    def generate_xml_report(report)
      # Simple XML generation - would use builder gem in production
      data = report.report_data
      
      <<~XML
        <?xml version="1.0" encoding="UTF-8"?>
        <quality_gates_report>
          <metadata>
            <execution_id>#{data[:metadata][:execution_id]}</execution_id>
            <generated_at>#{data[:metadata][:generated_at]}</generated_at>
            <environment>#{data[:metadata][:environment]}</environment>
          </metadata>
          <executive_summary>
            <overall_status>#{data[:executive_summary][:overall_status]}</overall_status>
            <quality_score>#{data[:executive_summary][:quality_score]}</quality_score>
            <success_rate>#{data[:executive_summary][:success_rate]}</success_rate>
          </executive_summary>
          <gate_results>
            #{generate_xml_gate_results(data[:gate_results])}
          </gate_results>
        </quality_gates_report>
      XML
    end

    # Generate XML section for gate results
    def generate_xml_gate_results(gate_results)
      gate_results.map do |gate_name, result|
        <<~XML
          <gate name="#{gate_name}">
            <status>#{result[:status]}</status>
            <execution_time>#{result[:execution_time]}</execution_time>
            <weight>#{result[:weight]}</weight>
            <critical>#{result[:critical]}</critical>
            <category>#{result[:category]}</category>
          </gate>
        XML
      end.join("\n")
    end

    # Generate Markdown format report
    def generate_markdown_report(report)
      data = report.report_data
      
      <<~MARKDOWN
        # Quality Gates Report
        
        **Execution ID:** #{data[:metadata][:execution_id]}  
        **Generated:** #{data[:metadata][:generated_at]}  
        **Environment:** #{data[:metadata][:environment]}  
        **Quality Score:** #{data[:executive_summary][:quality_score]}%
        
        ## Executive Summary
        
        - **Overall Status:** #{data[:executive_summary][:overall_status].to_s.upcase}
        - **Success Rate:** #{data[:executive_summary][:success_rate]}%
        - **Total Gates:** #{data[:executive_summary][:total_gates]}
        - **Passed:** #{data[:executive_summary][:passed_gates]}
        - **Failed:** #{data[:executive_summary][:failed_gates]}
        
        ## Gate Results
        
        #{generate_markdown_gate_results(data[:gate_results])}
        
        #{generate_markdown_recommendations(data[:recommendations]) if data[:recommendations]&.any?}
      MARKDOWN
    end

    # Generate Markdown section for gate results
    def generate_markdown_gate_results(gate_results)
      results = gate_results.map do |gate_name, result|
        status_emoji = result[:status] == :passed ? '✅' : '❌'
        critical_badge = result[:critical] ? '🔴 CRITICAL' : ''
        
        <<~MARKDOWN
          ### #{status_emoji} #{gate_name.to_s.humanize} #{critical_badge}
          
          - **Status:** #{result[:status].to_s.upcase}
          - **Execution Time:** #{result[:execution_time].round(2)}s
          - **Weight:** #{result[:weight]}
          - **Category:** #{result[:category]}
        MARKDOWN
      end
      
      results.join("\n")
    end

    # Generate Markdown section for recommendations
    def generate_markdown_recommendations(recommendations)
      return '' if recommendations.empty?

      rec_items = recommendations.map do |rec|
        priority_emoji = case rec[:priority]
                        when :high then '🔥'
                        when :medium then '⚠️'
                        else 'ℹ️'
                        end

        action_items = rec[:action_items] ? rec[:action_items].map { |item| "  - #{item}" }.join("\n") : ''

        <<~MARKDOWN
          ### #{priority_emoji} #{rec[:title]}
          
          #{rec[:description]}
          
          **Action Items:**
          #{action_items}
        MARKDOWN
      end

      <<~MARKDOWN
        
        ## Recommendations
        
        #{rec_items.join("\n")}
      MARKDOWN
    end

    # Helper methods for calculations
    def calculate_success_rate(passed, total)
      return 0 if total.zero?
      ((passed.to_f / total) * 100).round(2)
    end

    def calculate_total_execution_time(gate_results)
      gate_results.values.sum(&:execution_time).round(2)
    end

    def calculate_quality_score(gate_results)
      return 100 if gate_results.empty?

      total_weight = 0
      weighted_score = 0

      gate_results.each do |gate_name, result|
        weight = @configuration.get_gate_config(gate_name)[:weight] || 1
        total_weight += weight
        weighted_score += weight * (result.passed? ? 100 : 0)
      end

      (weighted_score.to_f / total_weight).round(2)
    end

    def calculate_critical_gate_status(gate_results)
      critical_gates = gate_results.select do |gate_name, _|
        @configuration.get_gate_config(gate_name)[:critical]
      end

      {
        total: critical_gates.count,
        passed: critical_gates.count { |_, result| result.passed? },
        failed: critical_gates.count { |_, result| result.failed? }
      }
    end

    def extract_performance_metrics(gate_results)
      performance_result = gate_results[:performance]
      return {} unless performance_result&.metrics

      performance_result.metrics.slice(:response_time, :memory_usage, :cpu_usage)
    end

    def extract_coverage_metrics(gate_results)
      testing_result = gate_results[:testing]
      return {} unless testing_result&.metrics

      testing_result.metrics.slice(:line_coverage, :branch_coverage, :test_count)
    end

    def extract_security_metrics(gate_results)
      security_result = gate_results[:security]
      return {} unless security_result&.metrics

      security_result.metrics.slice(:vulnerabilities, :security_score, :audit_findings)
    end

    def sanitize_result_details(details)
      # Remove sensitive information from result details
      return details unless details.is_a?(Hash)
      
      details.deep_dup.tap do |sanitized|
        sanitized.delete(:credentials)
        sanitized.delete(:tokens)
        sanitized.delete(:passwords)
      end
    end

    def generate_report_filename(report, format)
      timestamp = report.generated_at.strftime('%Y%m%d_%H%M%S')
      "quality_gates_report_#{report.execution_id}_#{timestamp}.#{format}"
    end

    def create_latest_symlink(filepath, format)
      link_path = File.join(@reports_directory, "latest_report.#{format}")
      
      # Remove existing symlink
      File.unlink(link_path) if File.symlink?(link_path)
      
      # Create new symlink
      File.symlink(File.basename(filepath), link_path)
    end

    # Historical data methods
    def update_historical_data(report)
      # Archive old reports
      archive_old_reports
      
      # Store summary for trend analysis
      store_trend_data(report)
    end

    def archive_old_reports
      retention_days = @configuration.reporting_config[:retention_days] || 30
      cutoff_date = Date.current - retention_days.days

      Dir.glob(File.join(@reports_directory, 'quality_gates_report_*.{json,html,csv}')).each do |filepath|
        next unless File.mtime(filepath) < cutoff_date

        archive_path = File.join(@reports_directory, 'archives', File.basename(filepath))
        FileUtils.mv(filepath, archive_path)
      end
    end

    def store_trend_data(report)
      trend_data = {
        timestamp: report.generated_at,
        execution_id: report.execution_id,
        quality_score: report.report_data[:executive_summary][:quality_score],
        success_rate: report.report_data[:executive_summary][:success_rate],
        total_gates: report.report_data[:executive_summary][:total_gates],
        critical_failures: report.report_data[:executive_summary][:critical_failures]
      }

      trends_file = File.join(@reports_directory, 'trends', 'quality_trends.jsonl')
      File.open(trends_file, 'a') do |f|
        f.puts(JSON.generate(trend_data))
      end
    end

    def get_historical_report_files(days)
      cutoff_date = Date.current - days.days
      
      Dir.glob(File.join(@reports_directory, 'quality_gates_report_*.json'))
         .select { |f| File.mtime(f) >= cutoff_date }
         .sort_by { |f| File.mtime(f) }
    end

    def load_historical_report(filepath)
      JSON.parse(File.read(filepath)).with_indifferent_access
    rescue StandardError
      nil
    end

    def extract_trend_data(report_data)
      return nil unless report_data[:executive_summary]

      {
        timestamp: report_data[:metadata][:generated_at],
        quality_score: report_data[:executive_summary][:quality_score],
        success_rate: report_data[:executive_summary][:success_rate]
      }
    end

    def analyze_trends(trend_data)
      return [] if trend_data.count < 2

      # Simple trend analysis - calculate moving averages and detect patterns
      quality_scores = trend_data.map { |d| d[:quality_score] }
      success_rates = trend_data.map { |d| d[:success_rate] }

      {
        quality_score_trend: calculate_trend_direction(quality_scores),
        success_rate_trend: calculate_trend_direction(success_rates),
        data_points: trend_data.count,
        latest_quality_score: quality_scores.last,
        average_quality_score: (quality_scores.sum.to_f / quality_scores.count).round(2)
      }
    end

    def calculate_trend_direction(values)
      return :stable if values.count < 3

      recent_avg = values.last(3).sum.to_f / 3
      older_avg = values.first(3).sum.to_f / 3

      diff = recent_avg - older_avg

      case diff
      when -Float::INFINITY..-2.0 then :declining
      when -2.0..2.0 then :stable
      else :improving
      end
    end

    # Utility methods
    def get_huginn_version
      File.read(File.join(Rails.root, 'VERSION')).strip
    rescue StandardError
      'unknown'
    end

    def get_git_commit_sha
      `git rev-parse HEAD`.strip
    rescue StandardError
      'unknown'
    end

    def get_historical_context
      trend_analysis = get_quality_trends(7) # Last 7 days
      
      {
        recent_trend: trend_analysis,
        baseline_metrics: get_baseline_metrics
      }
    end

    def get_baseline_metrics
      # Load baseline metrics from configuration or previous successful runs
      {
        target_quality_score: 85,
        target_success_rate: 95,
        baseline_execution_time: 120
      }
    end

    # Comparison methods for trend analysis
    def identify_improvements(current, previous)
      return [] unless previous

      improvements = []
      
      current.each do |gate_name, current_result|
        previous_result = previous[gate_name]
        next unless previous_result

        if current_result.passed? && previous_result.failed?
          improvements << {
            gate: gate_name,
            type: :status_improvement,
            description: "#{gate_name} now passing (was failing)"
          }
        elsif current_result.execution_time < previous_result.execution_time * 0.8
          improvements << {
            gate: gate_name,
            type: :performance_improvement,
            description: "#{gate_name} execution time improved by #{((previous_result.execution_time - current_result.execution_time) / previous_result.execution_time * 100).round(1)}%"
          }
        end
      end

      improvements
    end

    def identify_regressions(current, previous)
      return [] unless previous

      regressions = []
      
      current.each do |gate_name, current_result|
        previous_result = previous[gate_name]
        next unless previous_result

        if current_result.failed? && previous_result.passed?
          regressions << {
            gate: gate_name,
            type: :status_regression,
            description: "#{gate_name} now failing (was passing)"
          }
        elsif current_result.execution_time > previous_result.execution_time * 1.5
          regressions << {
            gate: gate_name,
            type: :performance_regression,
            description: "#{gate_name} execution time increased by #{((current_result.execution_time - previous_result.execution_time) / previous_result.execution_time * 100).round(1)}%"
          }
        end
      end

      regressions
    end

    def identify_new_issues(current, previous)
      return current.select { |_, result| result.failed? }.keys unless previous

      new_failing_gates = current.keys - previous.keys
      new_failing_gates.select { |gate| current[gate].failed? }
    end

    def identify_resolved_issues(current, previous)
      return [] unless previous

      resolved_gates = previous.keys - current.keys
      resolved_gates.select { |gate| previous[gate].failed? }
    end

    def get_latest_historical_results
      latest_file = get_historical_report_files(30).last
      return nil unless latest_file

      report_data = load_historical_report(latest_file)
      return nil unless report_data

      # Convert report data back to gate results format
      report_data[:gate_results]&.transform_values do |result_data|
        # Create a simple result object for comparison
        OpenStruct.new(
          status: result_data[:status]&.to_sym,
          execution_time: result_data[:execution_time],
          passed?: result_data[:status] == :passed,
          failed?: result_data[:status] != :passed
        )
      end
    end
  end

  # Report data container class
  class Report
    attr_reader :execution_id, :generated_at, :report_data, :configuration

    def initialize(execution_id:, generated_at:, report_data:, configuration:)
      @execution_id = execution_id
      @generated_at = generated_at
      @report_data = report_data
      @configuration = configuration
    end

    def success?
      report_data[:executive_summary][:overall_status] == :passed
    end

    def quality_score
      report_data[:executive_summary][:quality_score]
    end

    def summary
      report_data[:executive_summary]
    end
  end
end