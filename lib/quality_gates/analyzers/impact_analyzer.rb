# frozen_string_literal: true

require 'pathname'
require 'open3'

module QualityGates
  module Analyzers
    # Impact Analyzer for Huginn Implementation Changes
    #
    # Automated analysis system that identifies downstream effects and dependencies
    # when implementing changes in the Huginn ecosystem. This analyzer understands
    # the interconnected nature of agents, events, scenarios, and user workflows.
    #
    # Key Analysis Areas:
    # - Agent interdependency mapping and cascade analysis
    # - Event flow impact assessment and disruption prediction
    # - Database schema change impact on existing agents
    # - API endpoint changes and client compatibility
    # - External service dependency risk assessment
    # - User workflow disruption analysis
    class ImpactAnalyzer
      # Include statements removed for compatibility
      # Include statements removed for compatibility
      # Include statements removed for compatibility
      # Include statements removed for compatibility
      
      attr_reader :rails_root, :logger, :change_manifest
      
      def initialize(rails_root:, logger:, change_manifest: nil)
        @rails_root = Pathname.new(rails_root)
        @logger = logger
        @change_manifest = change_manifest || {}
      end
      
      # Run comprehensive impact analysis
      def analyze(proposed_changes = {})
        @logger.info "[IMPACT_ANALYZER] Starting downstream impact analysis"
        
        analysis = {
          timestamp: Time.now.iso8601,
          proposed_changes: proposed_changes,
          dependency_impact: analyze_dependency_impact(proposed_changes),
          event_flow_impact: analyze_event_flow_impact(proposed_changes),
          database_impact: analyze_database_impact(proposed_changes),
          api_impact: analyze_api_impact(proposed_changes),
          external_service_impact: analyze_external_service_impact(proposed_changes),
          user_workflow_impact: analyze_user_workflow_impact(proposed_changes),
          integration_point_impact: analyze_integration_point_impact(proposed_changes),
          performance_impact: analyze_performance_impact(proposed_changes)
        }
        
        # Calculate risk assessment and impact severity
        analysis[:risk_assessment] = calculate_risk_assessment(analysis)
        analysis[:impact_severity] = calculate_impact_severity(analysis)
        analysis[:mitigation_strategies] = generate_mitigation_strategies(analysis)
        analysis[:rollback_requirements] = generate_rollback_requirements(analysis)
        
        @logger.info "[IMPACT_ANALYZER] Impact analysis completed. Risk level: #{analysis[:risk_assessment][:level]}"
        
        analysis
      end
      
      private
      
      # Analyze dependency impact across the system
      def analyze_dependency_impact(proposed_changes)
        @logger.debug "Analyzing dependency impact"
        
        impact = {
          internal_dependencies: analyze_internal_dependencies(proposed_changes),
          gem_dependencies: analyze_gem_dependencies(proposed_changes),
          file_dependencies: analyze_file_dependencies(proposed_changes),
          circular_dependencies: detect_circular_dependencies(proposed_changes),
          breaking_changes: identify_breaking_changes(proposed_changes)
        }
        
        impact[:severity_score] = calculate_dependency_severity(impact)
        impact[:affected_components] = identify_affected_components(impact)
        impact
      end
      
      # Analyze internal code dependencies
      def analyze_internal_dependencies(proposed_changes)
        dependencies = {
          model_dependencies: analyze_model_dependencies(proposed_changes),
          controller_dependencies: analyze_controller_dependencies(proposed_changes),
          agent_dependencies: analyze_agent_dependencies(proposed_changes),
          concern_dependencies: analyze_concern_dependencies(proposed_changes),
          job_dependencies: analyze_job_dependencies(proposed_changes)
        }
        
        dependencies[:high_risk_changes] = identify_high_risk_dependencies(dependencies)
        dependencies
      end
      
      # Analyze agent-to-agent dependencies
      def analyze_agent_dependencies(proposed_changes)
        agents_path = @rails_root.join('app', 'models', 'agents')
        
        return { analyzed: false, reason: 'agents directory not found' } unless agents_path.exist?
        
        agent_dependencies = {}
        direct_references = {}
        inheritance_chains = {}
        
        Dir.glob("#{agents_path}/*.rb").each do |agent_file|
          agent_name = File.basename(agent_file, '.rb')
          content = File.read(agent_file)
          
          # Find direct agent references
          referenced_agents = content.scan(/(\w+Agent)/).flatten.uniq.reject { |a| a == agent_name.classify }
          direct_references[agent_name] = referenced_agents
          
          # Find inheritance chain
          if content.match(/class\s+(\w+)\s*<\s*(\w+)/)
            parent_class = content.match(/class\s+(\w+)\s*<\s*(\w+)/)[2]
            inheritance_chains[agent_name] = parent_class unless parent_class == 'Agent'
          end
          
          # Analyze event dependencies
          event_types_emitted = extract_event_types_emitted(content)
          event_types_consumed = extract_event_types_consumed(content)
          
          agent_dependencies[agent_name] = {
            direct_references: referenced_agents,
            events_emitted: event_types_emitted,
            events_consumed: event_types_consumed,
            inherits_from: inheritance_chains[agent_name],
            concerns_used: extract_concerns_used(content),
            external_apis: extract_external_apis(content)
          }
        end
        
        # Calculate impact if agents are modified
        impact_analysis = {}
        proposed_changes.each do |change_type, changes|
          next unless change_type.to_s.include?('agent') || change_type == :models
          
          changes.each do |changed_file|
            agent_name = extract_agent_name_from_file(changed_file)
            next unless agent_name
            
            impact_analysis[agent_name] = {
              directly_affected: find_agents_referencing(agent_name, direct_references),
              event_flow_affected: find_agents_consuming_events(agent_name, agent_dependencies),
              inheritance_affected: find_agents_inheriting_from(agent_name, inheritance_chains)
            }
          end
        end
        
        {
          agent_count: agent_dependencies.keys.count,
          dependency_map: agent_dependencies,
          impact_analysis: impact_analysis,
          high_risk_agents: identify_high_risk_agents(agent_dependencies),
          coupling_score: calculate_coupling_score(agent_dependencies)
        }
      end
      
      # Analyze event flow impact
      def analyze_event_flow_impact(proposed_changes)
        @logger.debug "Analyzing event flow impact"
        
        impact = {
          event_emission_changes: analyze_event_emission_changes(proposed_changes),
          event_consumption_changes: analyze_event_consumption_changes(proposed_changes),
          event_schema_changes: analyze_event_schema_changes(proposed_changes),
          flow_disruption_risk: assess_flow_disruption_risk(proposed_changes),
          pipeline_integrity: assess_pipeline_integrity(proposed_changes)
        }
        
        impact[:severity_score] = calculate_event_flow_severity(impact)
        impact[:affected_pipelines] = identify_affected_pipelines(impact)
        impact
      end
      
      # Analyze database schema impact
      def analyze_database_impact(proposed_changes)
        @logger.debug "Analyzing database schema impact"
        
        impact = {
          migration_impact: analyze_migration_impact(proposed_changes),
          model_changes: analyze_model_changes(proposed_changes),
          index_impact: analyze_index_impact(proposed_changes),
          foreign_key_impact: analyze_foreign_key_impact(proposed_changes),
          data_migration_risk: assess_data_migration_risk(proposed_changes)
        }
        
        impact[:severity_score] = calculate_database_severity(impact)
        impact[:downtime_risk] = assess_downtime_risk(impact)
        impact
      end
      
      # Analyze API impact on external clients
      def analyze_api_impact(proposed_changes)
        @logger.debug "Analyzing API impact"
        
        impact = {
          endpoint_changes: analyze_endpoint_changes(proposed_changes),
          response_format_changes: analyze_response_format_changes(proposed_changes),
          authentication_changes: analyze_authentication_changes(proposed_changes),
          rate_limiting_impact: analyze_rate_limiting_impact(proposed_changes),
          webhook_impact: analyze_webhook_impact(proposed_changes)
        }
        
        impact[:severity_score] = calculate_api_severity(impact)
        impact[:client_compatibility] = assess_client_compatibility(impact)
        impact
      end
      
      # Analyze external service dependency impact
      def analyze_external_service_impact(proposed_changes)
        @logger.debug "Analyzing external service impact"
        
        impact = {
          service_dependency_changes: analyze_service_dependency_changes(proposed_changes),
          oauth_provider_impact: analyze_oauth_provider_impact(proposed_changes),
          webhook_provider_impact: analyze_webhook_provider_impact(proposed_changes),
          api_client_impact: analyze_api_client_impact(proposed_changes),
          service_availability_risk: assess_service_availability_risk(proposed_changes)
        }
        
        impact[:severity_score] = calculate_external_service_severity(impact)
        impact[:fallback_requirements] = identify_fallback_requirements(impact)
        impact
      end
      
      # Analyze user workflow disruption
      def analyze_user_workflow_impact(proposed_changes)
        @logger.debug "Analyzing user workflow impact"
        
        impact = {
          scenario_disruption: analyze_scenario_disruption(proposed_changes),
          agent_configuration_impact: analyze_agent_configuration_impact(proposed_changes),
          ui_changes_impact: analyze_ui_changes_impact(proposed_changes),
          data_loss_risk: assess_data_loss_risk(proposed_changes),
          user_experience_impact: assess_user_experience_impact(proposed_changes)
        }
        
        impact[:severity_score] = calculate_workflow_severity(impact)
        impact[:user_communication_required] = assess_communication_requirements(impact)
        impact
      end
      
      # Analyze integration point impact
      def analyze_integration_point_impact(proposed_changes)
        @logger.debug "Analyzing integration point impact"
        
        impact = {
          webhook_endpoints: analyze_webhook_endpoint_impact(proposed_changes),
          email_integration: analyze_email_integration_impact(proposed_changes),
          file_handling: analyze_file_handling_impact(proposed_changes),
          external_apis: analyze_external_api_integration_impact(proposed_changes),
          third_party_services: analyze_third_party_service_impact(proposed_changes)
        }
        
        impact[:severity_score] = calculate_integration_severity(impact)
        impact[:testing_requirements] = identify_integration_testing_requirements(impact)
        impact
      end
      
      # Analyze performance impact
      def analyze_performance_impact(proposed_changes)
        @logger.debug "Analyzing performance impact"
        
        impact = {
          query_performance: analyze_query_performance_impact(proposed_changes),
          memory_usage: analyze_memory_usage_impact(proposed_changes),
          processing_time: analyze_processing_time_impact(proposed_changes),
          scalability: analyze_scalability_impact(proposed_changes),
          resource_utilization: analyze_resource_utilization_impact(proposed_changes)
        }
        
        impact[:severity_score] = calculate_performance_severity(impact)
        impact[:monitoring_requirements] = identify_monitoring_requirements(impact)
        impact
      end
      
      # Helper methods for dependency analysis
      def extract_event_types_emitted(content)
        # Look for create_event calls and event payload patterns
        event_types = []
        
        # Direct create_event calls
        event_types.concat(content.scan(/create_event\s*\(\s*:?(\w+)/).flatten)
        event_types.concat(content.scan(/create_event\s*\(\s*["'](\w+)["']/).flatten)
        
        # Event payload analysis
        payload_matches = content.scan(/create_event.*?payload\s*:\s*\{([^}]+)\}/)
        payload_matches.each do |payload|
          # Extract meaningful event type indicators from payload
          event_types << 'data_event' if payload.include?('data')
          event_types << 'status_event' if payload.include?('status')
          event_types << 'notification_event' if payload.include?('notification')
        end
        
        event_types.uniq
      end
      
      def extract_event_types_consumed(content)
        # Look for event handling patterns
        event_types = []
        
        # receive method analysis
        if content.include?('def receive')
          # Analyze receive method content for event type handling
          receive_method = content[/def receive.*?(?=def|\z)/m]
          if receive_method
            event_types << 'generic_event' # Most agents handle generic events
            event_types << 'webhook_event' if receive_method.include?('webhook')
            event_types << 'scheduled_event' if receive_method.include?('schedule')
          end
        end
        
        event_types.uniq
      end
      
      def extract_concerns_used(content)
        content.scan(/include\s+(\w+)/).flatten
      end
      
      def extract_external_apis(content)
        apis = []
        
        # HTTP client patterns
        apis << 'faraday' if content.include?('Faraday')
        apis << 'httparty' if content.include?('HTTParty')
        apis << 'rest_client' if content.include?('RestClient')
        apis << 'net_http' if content.include?('Net::HTTP')
        
        # Specific service patterns
        apis << 'twitter' if content.match?/(twitter|oauth)/i)
        apis << 'email' if content.match?/(smtp|imap|pop3)/i)
        apis << 'webhook' if content.include?('webhook')
        
        apis.uniq
      end
      
      def extract_agent_name_from_file(file_path)
        return nil unless file_path.include?('agents/')
        
        File.basename(file_path, '.rb') if file_path.end_with?('.rb')
      end
      
      def find_agents_referencing(agent_name, reference_map)
        referring_agents = []
        agent_class = agent_name.classify
        
        reference_map.each do |agent, references|
          referring_agents << agent if references.include?(agent_class)
        end
        
        referring_agents
      end
      
      def find_agents_consuming_events(agent_name, dependency_map)
        consuming_agents = []
        agent_events = dependency_map[agent_name]&.dig(:events_emitted) || []
        
        return consuming_agents if agent_events.empty?
        
        dependency_map.each do |agent, deps|
          consumed_events = deps[:events_consumed] || []
          if (agent_events & consumed_events).any?
            consuming_agents << agent
          end
        end
        
        consuming_agents
      end
      
      def find_agents_inheriting_from(agent_name, inheritance_map)
        inheriting_agents = []
        agent_class = agent_name.classify
        
        inheritance_map.each do |agent, parent|
          inheriting_agents << agent if parent == agent_class
        end
        
        inheriting_agents
      end
      
      def identify_high_risk_agents(agent_dependencies)
        high_risk = []
        
        agent_dependencies.each do |agent_name, deps|
          risk_score = 0
          
          # High coupling risk
          risk_score += (deps[:direct_references]&.count || 0) * 2
          risk_score += (deps[:events_emitted]&.count || 0) * 1
          risk_score += (deps[:external_apis]&.count || 0) * 3
          
          high_risk << { agent: agent_name, score: risk_score } if risk_score > 10
        end
        
        high_risk.sort_by { |item| -item[:score] }
      end
      
      def calculate_coupling_score(agent_dependencies)
        return 0 if agent_dependencies.empty?
        
        total_coupling = 0
        agent_dependencies.each do |_agent_name, deps|
          coupling = 0
          coupling += (deps[:direct_references]&.count || 0)
          coupling += (deps[:events_emitted]&.count || 0) * 0.5
          coupling += (deps[:concerns_used]&.count || 0) * 0.3
          coupling += (deps[:external_apis]&.count || 0) * 2
          
          total_coupling += coupling
        end
        
        (total_coupling / agent_dependencies.count).round(2)
      end
      
      # Risk assessment and scoring methods
      def calculate_risk_assessment(analysis)
        risk_scores = [
          analysis[:dependency_impact][:severity_score] || 0,
          analysis[:event_flow_impact][:severity_score] || 0,
          analysis[:database_impact][:severity_score] || 0,
          analysis[:api_impact][:severity_score] || 0,
          analysis[:external_service_impact][:severity_score] || 0,
          analysis[:user_workflow_impact][:severity_score] || 0,
          analysis[:integration_point_impact][:severity_score] || 0,
          analysis[:performance_impact][:severity_score] || 0
        ]
        
        overall_score = risk_scores.sum.to_f / risk_scores.count
        
        level = case overall_score
               when 0..30 then 'low'
               when 31..60 then 'medium'
               when 61..80 then 'high'
               else 'critical'
               end
        
        {
          overall_score: overall_score.round(1),
          level: level,
          component_scores: {
            dependency: risk_scores[0],
            event_flow: risk_scores[1],
            database: risk_scores[2],
            api: risk_scores[3],
            external_service: risk_scores[4],
            workflow: risk_scores[5],
            integration: risk_scores[6],
            performance: risk_scores[7]
          }
        }
      end
      
      def calculate_impact_severity(analysis)
        # Weighted severity calculation based on business impact
        weights = {
          user_workflow_impact: 0.25,
          database_impact: 0.20,
          api_impact: 0.15,
          event_flow_impact: 0.15,
          external_service_impact: 0.10,
          dependency_impact: 0.10,
          performance_impact: 0.05
        }
        
        weighted_score = 0
        weights.each do |component, weight|
          score = analysis[component]&.dig(:severity_score) || 0
          weighted_score += score * weight
        end
        
        case weighted_score
        when 0..25 then 'minimal'
        when 26..50 then 'moderate'
        when 51..75 then 'significant'
        else 'severe'
        end
      end
      
      def generate_mitigation_strategies(analysis)
        strategies = []
        
        # Database impact mitigation
        if (analysis[:database_impact][:severity_score] || 0) > 60
          strategies << {
            type: 'database',
            strategy: 'Implement blue-green deployment with database migration rollback capability',
            priority: 'high'
          }
        end
        
        # API impact mitigation  
        if (analysis[:api_impact][:severity_score] || 0) > 50
          strategies << {
            type: 'api',
            strategy: 'Implement API versioning and deprecation notices for breaking changes',
            priority: 'high'
          }
        end
        
        # Event flow mitigation
        if (analysis[:event_flow_impact][:severity_score] || 0) > 50
          strategies << {
            type: 'event_flow',
            strategy: 'Implement event schema versioning and backward compatibility',
            priority: 'medium'
          }
        end
        
        # Performance impact mitigation
        if (analysis[:performance_impact][:severity_score] || 0) > 40
          strategies << {
            type: 'performance',
            strategy: 'Implement performance monitoring and gradual rollout',
            priority: 'medium'
          }
        end
        
        strategies
      end
      
      def generate_rollback_requirements(analysis)
        requirements = []
        
        risk_level = analysis[:risk_assessment][:level]
        
        case risk_level
        when 'critical', 'high'
          requirements << 'Automated rollback capability required'
          requirements << 'Database backup and restore procedures'
          requirements << 'Feature flag implementation for instant disable'
          requirements << 'Monitoring and alerting for immediate issue detection'
        when 'medium'
          requirements << 'Manual rollback procedures documented'
          requirements << 'Database backup before deployment'
          requirements << 'Monitoring for 24 hours post-deployment'
        when 'low'
          requirements << 'Standard rollback procedures sufficient'
        end
        
        requirements
      end
      
      # Placeholder implementations for detailed analysis methods
      # (These can be expanded with specific implementation logic as needed)
      
      def analyze_model_dependencies(proposed_changes)
        { affected_models: [], breaking_changes: [], risk_level: 'low' }
      end
      
      def analyze_controller_dependencies(proposed_changes)
        { affected_controllers: [], endpoint_changes: [], risk_level: 'low' }
      end
      
      def analyze_concern_dependencies(proposed_changes)
        { affected_concerns: [], usage_impact: [], risk_level: 'low' }
      end
      
      def analyze_job_dependencies(proposed_changes)
        { affected_jobs: [], queue_impact: [], risk_level: 'low' }
      end
      
      def analyze_gem_dependencies(proposed_changes)
        { new_gems: [], updated_gems: [], removed_gems: [], risk_level: 'low' }
      end
      
      def analyze_file_dependencies(proposed_changes)
        { file_changes: [], dependency_updates: [], risk_level: 'low' }
      end
      
      def detect_circular_dependencies(proposed_changes)
        { detected: false, cycles: [], risk_level: 'low' }
      end
      
      def identify_breaking_changes(proposed_changes)
        { breaking_changes: [], impact_assessment: 'low' }
      end
      
      def calculate_dependency_severity(impact)
        50  # Placeholder score
      end
      
      def identify_affected_components(impact)
        []  # Placeholder list
      end
      
      def identify_high_risk_dependencies(dependencies)
        []  # Placeholder list
      end
      
      # Additional placeholder implementations
      def analyze_event_emission_changes(proposed_changes); { changes: [], risk: 'low' }; end
      def analyze_event_consumption_changes(proposed_changes); { changes: [], risk: 'low' }; end  
      def analyze_event_schema_changes(proposed_changes); { changes: [], risk: 'low' }; end
      def assess_flow_disruption_risk(proposed_changes); { risk: 'low', affected_flows: [] }; end
      def assess_pipeline_integrity(proposed_changes); { integrity: 'maintained', issues: [] }; end
      def calculate_event_flow_severity(impact); 40; end
      def identify_affected_pipelines(impact); []; end
      
      def analyze_migration_impact(proposed_changes); { migrations: [], risk: 'low' }; end
      def analyze_model_changes(proposed_changes); { changes: [], risk: 'low' }; end
      def analyze_index_impact(proposed_changes); { indexes: [], risk: 'low' }; end
      def analyze_foreign_key_impact(proposed_changes); { keys: [], risk: 'low' }; end
      def assess_data_migration_risk(proposed_changes); { risk: 'low', data_loss: false }; end
      def calculate_database_severity(impact); 30; end
      def assess_downtime_risk(impact); { risk: 'low', estimated_minutes: 0 }; end
      
      def analyze_endpoint_changes(proposed_changes); { endpoints: [], risk: 'low' }; end
      def analyze_response_format_changes(proposed_changes); { formats: [], risk: 'low' }; end
      def analyze_authentication_changes(proposed_changes); { auth: [], risk: 'low' }; end
      def analyze_rate_limiting_impact(proposed_changes); { limits: [], risk: 'low' }; end
      def analyze_webhook_impact(proposed_changes); { webhooks: [], risk: 'low' }; end
      def calculate_api_severity(impact); 35; end
      def assess_client_compatibility(impact); { compatible: true, issues: [] }; end
      
      def analyze_service_dependency_changes(proposed_changes); { services: [], risk: 'low' }; end
      def analyze_oauth_provider_impact(proposed_changes); { providers: [], risk: 'low' }; end
      def analyze_webhook_provider_impact(proposed_changes); { providers: [], risk: 'low' }; end
      def analyze_api_client_impact(proposed_changes); { clients: [], risk: 'low' }; end
      def assess_service_availability_risk(proposed_changes); { risk: 'low', services: [] }; end
      def calculate_external_service_severity(impact); 25; end
      def identify_fallback_requirements(impact); []; end
      
      def analyze_scenario_disruption(proposed_changes); { scenarios: [], risk: 'low' }; end
      def analyze_agent_configuration_impact(proposed_changes); { configs: [], risk: 'low' }; end
      def analyze_ui_changes_impact(proposed_changes); { ui: [], risk: 'low' }; end
      def assess_data_loss_risk(proposed_changes); { risk: 'low', data: [] }; end
      def assess_user_experience_impact(proposed_changes); { impact: 'minimal', areas: [] }; end
      def calculate_workflow_severity(impact); 45; end
      def assess_communication_requirements(impact); { required: false, channels: [] }; end
      
      def analyze_webhook_endpoint_impact(proposed_changes); { endpoints: [], risk: 'low' }; end
      def analyze_email_integration_impact(proposed_changes); { email: [], risk: 'low' }; end
      def analyze_file_handling_impact(proposed_changes); { files: [], risk: 'low' }; end
      def analyze_external_api_integration_impact(proposed_changes); { apis: [], risk: 'low' }; end
      def analyze_third_party_service_impact(proposed_changes); { services: [], risk: 'low' }; end
      def calculate_integration_severity(impact); 30; end
      def identify_integration_testing_requirements(impact); []; end
      
      def analyze_query_performance_impact(proposed_changes); { queries: [], risk: 'low' }; end
      def analyze_memory_usage_impact(proposed_changes); { memory: [], risk: 'low' }; end
      def analyze_processing_time_impact(proposed_changes); { processing: [], risk: 'low' }; end
      def analyze_scalability_impact(proposed_changes); { scalability: [], risk: 'low' }; end
      def analyze_resource_utilization_impact(proposed_changes); { resources: [], risk: 'low' }; end
      def calculate_performance_severity(impact); 35; end
      def identify_monitoring_requirements(impact); []; end
    end
    
