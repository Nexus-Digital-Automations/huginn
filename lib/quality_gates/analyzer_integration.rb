# frozen_string_literal: true

require_relative 'analyzers/context_analyzer'
require_relative 'analyzers/impact_analyzer'
require_relative 'analyzers/resource_planner'
require_relative 'analyzers/security_analyzer'
require_relative 'analyzers/performance_analyzer'

module QualityGates
  # Analyzer Integration Module
  #
  # Provides integration layer between the main PreImplementation system
  # and the specialized analyzer modules. This integration ensures consistent
  # interfaces, shared configuration, and coordinated analysis workflows.
  #
  # Key Responsibilities:
  # - Initialize and configure specialized analyzers
  # - Coordinate multi-analyzer workflows
  # - Aggregate and normalize analysis results
  # - Provide unified reporting interface
  # - Handle analyzer dependencies and sequencing
  class AnalyzerIntegration
    attr_reader :rails_root, :logger, :config
    
    def initialize(rails_root:, logger:, config: {})
      @rails_root = rails_root
      @logger = logger
      @config = config
      
      initialize_analyzers
    end
    
    # Run integrated context assessment
    def run_integrated_context_assessment
      @logger.info "[ANALYZER_INTEGRATION] Running integrated context assessment"
      
      begin
        results = @context_analyzer.analyze
        
        # Normalize results for main system compatibility
        normalized = normalize_context_results(results)
        
        @logger.info "[ANALYZER_INTEGRATION] Context assessment completed with score: #{normalized[:score]}"
        normalized
        
      rescue StandardError => e
        @logger.error "[ANALYZER_INTEGRATION] Context assessment failed: #{e.message}"
        
        {
          score: 0,
          max_score: 100,
          details: { error: e.message },
          recommendations: ["Fix context assessment error: #{e.message}"],
          errors: [e.message],
          passed: false
        }
      end
    end
    
    # Run integrated impact analysis
    def run_integrated_impact_analysis(proposed_changes = {})
      @logger.info "[ANALYZER_INTEGRATION] Running integrated impact analysis"
      
      begin
        results = @impact_analyzer.analyze(proposed_changes)
        
        # Normalize results for main system compatibility
        normalized = normalize_impact_results(results)
        
        @logger.info "[ANALYZER_INTEGRATION] Impact analysis completed with score: #{normalized[:score]}"
        normalized
        
      rescue StandardError => e
        @logger.error "[ANALYZER_INTEGRATION] Impact analysis failed: #{e.message}"
        
        {
          score: 0,
          max_score: 100,
          details: { error: e.message },
          recommendations: ["Fix impact analysis error: #{e.message}"],
          errors: [e.message],
          passed: false
        }
      end
    end
    
    # Run integrated resource planning
    def run_integrated_resource_planning(implementation_spec = {})
      @logger.info "[ANALYZER_INTEGRATION] Running integrated resource planning"
      
      begin
        results = @resource_planner.plan_resources(implementation_spec)
        
        # Normalize results for main system compatibility
        normalized = normalize_resource_results(results)
        
        @logger.info "[ANALYZER_INTEGRATION] Resource planning completed with score: #{normalized[:score]}"
        normalized
        
      rescue StandardError => e
        @logger.error "[ANALYZER_INTEGRATION] Resource planning failed: #{e.message}"
        
        {
          score: 0,
          max_score: 100,
          details: { error: e.message },
          recommendations: ["Fix resource planning error: #{e.message}"],
          errors: [e.message],
          passed: false
        }
      end
    end
    
    # Run integrated security review
    def run_integrated_security_review(implementation_spec = {})
      @logger.info "[ANALYZER_INTEGRATION] Running integrated security review"
      
      begin
        results = @security_analyzer.analyze(implementation_spec)
        
        # Normalize results for main system compatibility
        normalized = normalize_security_results(results)
        
        @logger.info "[ANALYZER_INTEGRATION] Security review completed with score: #{normalized[:score]}"
        normalized
        
      rescue StandardError => e
        @logger.error "[ANALYZER_INTEGRATION] Security review failed: #{e.message}"
        
        {
          score: 0,
          max_score: 100,
          details: { error: e.message },
          recommendations: ["Fix security review error: #{e.message}"],
          errors: [e.message],
          passed: false
        }
      end
    end
    
    # Run integrated performance baseline capture
    def run_integrated_performance_baseline(implementation_spec = {})
      @logger.info "[ANALYZER_INTEGRATION] Running integrated performance baseline capture"
      
      begin
        results = @performance_analyzer.capture_baseline(implementation_spec)
        
        # Normalize results for main system compatibility
        normalized = normalize_performance_results(results)
        
        @logger.info "[ANALYZER_INTEGRATION] Performance baseline completed with score: #{normalized[:score]}"
        normalized
        
      rescue StandardError => e
        @logger.error "[ANALYZER_INTEGRATION] Performance baseline failed: #{e.message}"
        
        {
          score: 0,
          max_score: 100,
          details: { error: e.message },
          recommendations: ["Fix performance baseline error: #{e.message}"],
          errors: [e.message],
          passed: false
        }
      end
    end
    
    private
    
    # Initialize specialized analyzers
    def initialize_analyzers
      analyzer_config = {
        rails_root: @rails_root,
        logger: @logger,
        config: @config
      }
      
      @context_analyzer = QualityGates::Analyzers::ContextAnalyzer.new(**analyzer_config)
      @impact_analyzer = QualityGates::Analyzers::ImpactAnalyzer.new(**analyzer_config)
      @resource_planner = QualityGates::Analyzers::ResourcePlanner.new(**analyzer_config)
      @security_analyzer = QualityGates::Analyzers::SecurityAnalyzer.new(**analyzer_config)
      @performance_analyzer = QualityGates::Analyzers::PerformanceAnalyzer.new(**analyzer_config)
      
      @logger.debug "[ANALYZER_INTEGRATION] Specialized analyzers initialized"
    end
    
    # Normalize context analysis results
    def normalize_context_results(results)
      score = results[:overall_score] || 0
      
      {
        score: [score.to_f, 100].min.round,
        max_score: 100,
        details: {
          analysis_timestamp: results[:timestamp],
          agent_ecosystem: results[:agent_ecosystem],
          event_processing: results[:event_processing],
          user_management: results[:user_management],
          scenario_architecture: results[:scenario_architecture],
          external_integrations: results[:external_integrations],
          database_optimization: results[:database_optimization],
          security_posture: results[:security_posture],
          performance_characteristics: results[:performance_characteristics]
        },
        recommendations: results[:recommendations] || [],
        errors: [],
        passed: score >= (@config.dig('quality_thresholds', 'context_assessment') || 70)
      }
    end
    
    # Normalize impact analysis results
    def normalize_impact_results(results)
      # Calculate score based on risk level
      risk_level = results[:risk_assessment][:level] rescue 'medium'
      
      score = case risk_level
             when 'low' then 90
             when 'medium' then 70
             when 'high' then 45
             when 'critical' then 20
             else 60
             end
      
      {
        score: score,
        max_score: 100,
        details: {
          analysis_timestamp: results[:timestamp],
          risk_assessment: results[:risk_assessment],
          impact_severity: results[:impact_severity],
          dependency_impact: results[:dependency_impact],
          event_flow_impact: results[:event_flow_impact],
          database_impact: results[:database_impact],
          api_impact: results[:api_impact],
          external_service_impact: results[:external_service_impact],
          user_workflow_impact: results[:user_workflow_impact],
          integration_point_impact: results[:integration_point_impact],
          performance_impact: results[:performance_impact]
        },
        recommendations: [
          *results[:mitigation_strategies]&.map { |s| s[:strategy] },
          *results[:rollback_requirements]
        ].compact,
        errors: [],
        passed: score >= (@config.dig('quality_thresholds', 'impact_analysis') || 75)
      }
    end
    
    # Normalize resource planning results
    def normalize_resource_results(results)
      # Calculate score based on resource complexity and feasibility
      timeline_estimate = results[:timeline_estimates][:total_timeline] rescue '70 hours'
      hours_match = timeline_estimate.match(/(\d+)/)
      estimated_hours = hours_match ? hours_match[1].to_i : 70
      
      # Score based on resource requirements complexity
      score = case estimated_hours
             when 0..40 then 100
             when 41..80 then 90
             when 81..120 then 80
             when 121..200 then 70
             when 201..300 then 60
             else 50
             end
      
      # Adjust for risk factors
      risk_count = results[:risk_factors]&.count || 0
      score -= (risk_count * 10)
      score = [score, 0].max
      
      {
        score: score,
        max_score: 100,
        details: {
          planning_timestamp: results[:timestamp],
          api_requirements: results[:api_requirements],
          data_requirements: results[:data_requirements],
          infrastructure_requirements: results[:infrastructure_requirements],
          external_service_requirements: results[:external_service_requirements],
          development_resources: results[:development_resources],
          testing_resources: results[:testing_resources],
          deployment_resources: results[:deployment_resources],
          monitoring_requirements: results[:monitoring_requirements],
          resource_summary: results[:resource_summary],
          timeline_estimates: results[:timeline_estimates],
          cost_estimates: results[:cost_estimates]
        },
        recommendations: [
          *results[:optimization_opportunities]&.map { |o| o[:benefit] },
          *results[:risk_factors]&.map { |r| "Address #{r[:type]} risk: #{r[:description]}" }
        ].compact,
        errors: [],
        passed: score >= (@config.dig('quality_thresholds', 'resource_planning') || 70)
      }
    end
    
    # Normalize security analysis results
    def normalize_security_results(results)
      score = results[:overall_security_score] || 0
      
      # Collect all security vulnerabilities
      vulnerabilities = []
      vulnerability_assessment = results[:vulnerability_assessment] || {}
      
      %w[critical high medium low].each do |severity|
        count = vulnerability_assessment["#{severity}_count"] || 0
        vulnerabilities << "#{count} #{severity} severity vulnerabilities" if count > 0
      end
      
      {
        score: score.to_f.round,
        max_score: 100,
        details: {
          analysis_timestamp: results[:timestamp],
          authentication_security: results[:authentication_security],
          authorization_security: results[:authorization_security],
          data_protection_security: results[:data_protection_security],
          input_validation_security: results[:input_validation_security],
          output_sanitization_security: results[:output_sanitization_security],
          external_service_security: results[:external_service_security],
          agent_specific_security: results[:agent_specific_security],
          vulnerability_assessment: results[:vulnerability_assessment],
          risk_level: results[:risk_level],
          compliance_status: results[:compliance_status]
        },
        recommendations: [
          *results[:security_recommendations]&.map { |r| r[:recommendation] },
          *results[:remediation_priorities]&.map { |p| "#{p[:priority]} priority: #{p[:action]}" },
          *vulnerabilities
        ].compact,
        errors: [],
        passed: score >= (@config.dig('quality_thresholds', 'security_review') || 85)
      }
    end
    
    # Normalize performance analysis results
    def normalize_performance_results(results)
      score = results[:overall_performance_score] || 0
      
      # Collect performance bottlenecks
      bottlenecks = results[:performance_bottlenecks] || []
      bottleneck_descriptions = bottlenecks.map { |b| "#{b[:severity]} #{b[:type]} bottleneck: #{b[:description]}" }
      
      {
        score: score.to_i,
        max_score: 100,
        details: {
          baseline_timestamp: results[:timestamp],
          application_performance: results[:application_performance],
          database_performance: results[:database_performance],
          memory_baseline: results[:memory_baseline],
          system_resource_baseline: results[:system_resource_baseline],
          agent_performance: results[:agent_performance],
          job_queue_performance: results[:job_queue_performance],
          external_api_performance: results[:external_api_performance],
          load_testing_results: results[:load_testing_results],
          capacity_analysis: results[:capacity_analysis]
        },
        recommendations: [
          *results[:optimization_recommendations]&.map { |r| r[:recommendation] },
          *bottleneck_descriptions,
          *results[:monitoring_alerts]&.map { |a| "Monitor #{a[:metric]} with #{a[:threshold]} threshold" }
        ].compact,
        errors: [],
        passed: score >= (@config.dig('quality_thresholds', 'performance_baseline') || 70)
      }
    end
  end
end