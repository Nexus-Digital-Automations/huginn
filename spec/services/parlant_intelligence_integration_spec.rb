# frozen_string_literal: true

require 'rails_helper'
require 'rspec/benchmark'
require 'concurrent'

##
# Comprehensive Integration Test Suite for Huginn Parlant Intelligence Enhancement
#
# Tests all Phase 4 Intelligence Enhancement features with performance validation,
# cross-language integration testing, and enterprise audit capabilities.
# Validates <300ms performance targets across all intelligent operations.
#
# @rspec_tag integration
# @rspec_tag performance
# @rspec_tag parlant_intelligence

RSpec.describe 'Huginn Parlant Intelligence Integration', type: :integration do
  include RSpec::Benchmark::Matchers

  # Test Configuration
  let(:performance_target_ms) { 300 }
  let(:strict_performance_target_ms) { 250 }
  let(:audit_performance_target_ms) { 50 }
  
  # Service Instances
  let(:intelligence_service) { ParlantIntelligenceWorkflowService.new }
  let(:autonomous_service) { ParlantAutonomousDecisionService.new }
  let(:audit_service) { ParlantEnterpriseAuditService.new }
  let(:bridge_service) { ParlantCrossLanguageBridge.new }

  # Test Data
  let(:sample_workflow_config) do
    {
      name: 'Test Intelligence Workflow',
      agents: [create_test_agent, create_test_agent],
      validation_level: 'high',
      autonomous_approval: true,
      intelligence_params: {
        threat_threshold: 7.5,
        auto_response: true,
        escalation_rules: { high_risk: 'require_human_approval' }
      }
    }
  end

  let(:sample_decision_context) do
    {
      decision_type: 'create_monitoring_agent',
      risk_factors: ['production_environment', 'external_api_access'],
      confidence_threshold: 0.85,
      business_impact: 'medium',
      user_context: {
        user_id: 'test_user_001',
        roles: ['admin'],
        session_id: 'session_123',
        ip_address: '127.0.0.1'
      }
    }
  end

  let(:sample_intelligence_data) do
    {
      data_type: 'threat_intelligence',
      payload: { threat_level: 'elevated', confidence: 0.92 },
      classification: 'confidential',
      sources: ['internal_scanner', 'threat_feed'],
      governance_requirements: {
        retention_period: '2_years',
        access_control: 'restricted'
      }
    }
  end

  before(:each) do
    # Setup test environment
    Rails.cache.clear
    stub_parlant_api_responses
    initialize_test_agents
  end

  describe 'Phase 4 Intelligence Enhancement Features' do
    context 'Intelligent Workflow Automation' do
      it 'creates intelligent workflows with conversational validation within performance target' do
        expect {
          result = intelligence_service.create_intelligent_workflow(sample_workflow_config)
          
          expect(result).to be_present
          expect(result[:workflow_id]).to be_present
          expect(result[:agents]).to have_attributes(length: 2)
          expect(result[:validation_metadata]).to be_present
        }.to perform_under(performance_target_ms).ms
      end

      it 'executes agent communication coordination efficiently' do
        coordination_config = {
          agents: [create_test_agent, create_test_agent],
          communication_type: 'workflow_sync',
          workflow_context: { workflow_id: 'test_workflow_001' },
          real_time_validation: true
        }

        expect {
          result = intelligence_service.execute_agent_communication_coordination(coordination_config)
          
          expect(result).to be_present
          expect(result[:operation_id]).to be_present
          expect(result[:performance_achieved]).to be true
        }.to perform_under(performance_target_ms).ms
      end

      it 'processes intelligence data with governance validation' do
        expect {
          result = intelligence_service.process_intelligence_data(sample_intelligence_data)
          
          expect(result).to be_present
          expect(result[:processed_data]).to be_present
          expect(result[:governance_validation][:valid]).to be true
          expect(result[:compliance_audit_id]).to be_present
        }.to perform_under(performance_target_ms).ms
      end
    end

    context 'Autonomous Decision Validation' do
      it 'validates autonomous decisions with ML-enhanced risk assessment' do
        expect {
          result = autonomous_service.validate_autonomous_decision(sample_decision_context)
          
          expect(result).to be_present
          expect(result[:decision_id]).to be_present
          expect(result[:risk_assessment]).to be_present
          expect(result[:ml_confidence]).to be >= 0.0
          expect(result[:ml_confidence]).to be <= 1.0
        }.to perform_under(strict_performance_target_ms).ms
      end

      it 'handles high-risk decisions with escalation workflows' do
        high_risk_context = {
          decision_context: sample_decision_context.merge(
            decision_type: 'deploy_production_agent',
            risk_factors: ['production_environment', 'system_wide_impact', 'irreversible_action']
          ),
          required_approvals: ['security_team', 'ops_manager'],
          escalation_timeout: 1800,
          emergency_override: false
        }

        result = autonomous_service.process_high_risk_decision(high_risk_context)
        
        expect(result).to be_present
        expect(result[:escalation_id]).to be_present
        expect(result[:escalation_workflow]).to be_present
      end

      it 'executes real-time decision monitoring with performance metrics' do
        monitoring_config = {
          monitoring_window: 3600,
          decision_types: ['create_monitoring_agent', 'modify_agent_configuration'],
          include_performance: true
        }

        result = autonomous_service.execute_real_time_decision_monitoring(monitoring_config)
        
        expect(result).to be_present
        expect(result[:decision_metrics]).to be_present
        expect(result[:performance_metrics]).to be_present
        expect(result[:system_health]).to be_present
      end
    end

    context 'Cross-Language Integration' do
      it 'calls TypeScript services with type conversion and validation' do
        typescript_call_config = {
          package: 'shared',
          service: 'ParlantIntegrationService',
          method: 'validateFunction',
          parameters: {
            operationId: 'test_ts_001',
            functionName: 'create_intelligent_workflow',
            packageName: 'huginn',
            description: 'Test TypeScript integration',
            userContext: sample_decision_context[:user_context],
            securityLevel: 'medium'
          }
        }

        expect {
          result = bridge_service.call_typescript_service(typescript_call_config)
          
          expect(result).to be_present
          expect(result[:success]).to be true
          expect(result[:language_bridge_metadata][:type_conversions_applied]).to be true
        }.to perform_under(performance_target_ms).ms
      end

      it 'calls Python ML services for enhanced analytics' do
        python_call_config = {
          module: 'ml_risk_engine',
          function: 'assess_decision_risk',
          parameters: {
            decision_context: sample_decision_context,
            model_version: 'v2.1.0',
            confidence_threshold: 0.85
          },
          ml_context: {
            training_data_version: 'huginn_decisions_2024',
            feature_engineering: 'advanced'
          }
        }

        expect {
          result = bridge_service.call_python_service(python_call_config)
          
          expect(result).to be_present
          expect(result[:success]).to be true
          expect(result[:language_bridge_metadata][:ml_context_applied]).to be true
        }.to perform_under(performance_target_ms).ms
      end

      it 'executes multi-language workflows with unified validation' do
        multi_language_workflow = {
          workflow_name: 'intelligence_risk_assessment',
          steps: [
            {
              language: 'typescript',
              package: 'shared',
              service: 'ParlantIntegrationService',
              method: 'validateFunction',
              parameters: { function_name: 'risk_assessment' },
              depends_on: []
            },
            {
              language: 'python',
              module: 'ml_risk_engine', 
              function: 'assess_risk',
              parameters: sample_decision_context,
              depends_on: ['step_0']
            },
            {
              language: 'ruby',
              service: 'ParlantIntelligenceWorkflowService',
              method: 'create_intelligent_workflow',
              parameters: sample_workflow_config,
              depends_on: ['step_0', 'step_1']
            }
          ],
          parallel_execution: true,
          shared_context: { user_id: 'test_user_001', session_id: 'session_123' }
        }

        result = bridge_service.execute_multi_language_workflow(multi_language_workflow)
        
        expect(result).to be_present
        expect(result[:success]).to be true
        expect(result[:workflow_metadata][:languages_involved]).to include('typescript', 'python', 'ruby')
        expect(result[:workflow_metadata][:validation_applied]).to be true
      end
    end

    context 'Enterprise Audit System' do
      it 'creates comprehensive decision audit entries with minimal overhead' do
        audit_context = {
          decision_id: 'test_decision_001',
          decision_type: 'agent_deployment',
          user_context: sample_decision_context[:user_context],
          decision_context: sample_decision_context,
          validation_result: { approved: true, confidence: 0.95 },
          business_impact: 'high',
          compliance_requirements: ['sox', 'gdpr'],
          data_classification: 'confidential'
        }

        expect {
          result = audit_service.create_decision_audit_entry(audit_context)
          
          expect(result).to be_present
          expect(result[:audit_id]).to be_present
          expect(result[:tamper_proof_id]).to be_present
          expect(result[:performance_achieved]).to be true
          expect(result[:forensic_capabilities][:investigation_ready]).to be true
        }.to perform_under(audit_performance_target_ms).ms
      end

      it 'generates comprehensive compliance reports' do
        report_config = {
          report_type: 'sox_quarterly',
          date_range: { start: 3.months.ago, end: Date.current },
          scope: ['autonomous_decisions', 'workflow_modifications'],
          format: 'regulatory_standard',
          compliance_frameworks: ['sox', 'gdpr'],
          include_anomalies: true
        }

        result = audit_service.generate_compliance_report(report_config)
        
        expect(result).to be_present
        expect(result[:report_id]).to be_present
        expect(result[:comprehensive_report]).to be_present
        expect(result[:report_artifacts]).to be_present
        expect(result[:report_metadata][:regulatory_readiness]).to be >= 0.8
      end

      it 'executes forensic investigations with evidence chain documentation' do
        investigation_config = {
          investigation_id: 'forensic_001',
          decision_ids: ['test_decision_001', 'test_decision_002'],
          time_range: { start: 1.week.ago, end: Date.current },
          investigation_type: 'decision_chain_analysis',
          focus_areas: ['autonomous_decisions', 'escalation_patterns']
        }

        result = audit_service.execute_forensic_investigation(investigation_config)
        
        expect(result).to be_present
        expect(result[:investigation_id]).to be_present
        expect(result[:forensic_findings]).to be_present
        expect(result[:evidence_chain]).to be_present
        expect(result[:investigation_metadata][:evidence_integrity_score]).to be >= 0.9
      end
    end
  end

  describe 'Performance Validation and Optimization' do
    context 'Response Time Targets' do
      it 'meets <300ms target for intelligence workflow operations' do
        5.times do
          expect {
            intelligence_service.create_intelligent_workflow(sample_workflow_config)
          }.to perform_under(performance_target_ms).ms
        end
      end

      it 'meets <250ms target for autonomous decision validation' do
        5.times do
          expect {
            autonomous_service.validate_autonomous_decision(sample_decision_context)
          }.to perform_under(strict_performance_target_ms).ms
        end
      end

      it 'meets <50ms target for audit entry creation' do
        audit_context = {
          decision_id: 'perf_test_001',
          decision_type: 'agent_creation',
          user_context: sample_decision_context[:user_context],
          decision_context: { simple: 'context' },
          validation_result: { approved: true }
        }

        5.times do
          expect {
            audit_service.create_decision_audit_entry(audit_context)
          }.to perform_under(audit_performance_target_ms).ms
        end
      end

      it 'maintains performance under concurrent load' do
        concurrent_operations = 10
        results = []

        threads = concurrent_operations.times.map do |i|
          Thread.new do
            start_time = Time.current
            result = intelligence_service.create_intelligent_workflow(
              sample_workflow_config.merge(name: "Concurrent Workflow #{i}")
            )
            end_time = Time.current
            
            results << {
              thread_id: i,
              execution_time: ((end_time - start_time) * 1000).round(2),
              success: result.present?
            }
          end
        end

        threads.each(&:join)
        
        expect(results).to all(have_attributes(success: true))
        expect(results.map { |r| r[:execution_time] }).to all(be < performance_target_ms)
        
        avg_time = results.sum { |r| r[:execution_time] } / results.length
        expect(avg_time).to be < performance_target_ms
      end
    end

    context 'System Integration Health' do
      it 'maintains healthy status across all intelligence services' do
        health_checks = [
          intelligence_service.get_intelligence_workflow_health,
          autonomous_service.get_autonomous_decision_system_health,
          audit_service.get_enterprise_audit_system_health,
          bridge_service.get_cross_language_bridge_health
        ]

        health_checks.each do |health_status|
          expect(health_status).to be_present
          expect(health_status[:timestamp]).to be_present
        end
      end

      it 'reports comprehensive performance metrics' do
        # Execute various operations to generate metrics
        intelligence_service.create_intelligent_workflow(sample_workflow_config)
        autonomous_service.validate_autonomous_decision(sample_decision_context)
        audit_service.create_decision_audit_entry({
          decision_id: 'metrics_test',
          decision_type: 'test_operation',
          user_context: sample_decision_context[:user_context]
        })

        health = intelligence_service.get_intelligence_workflow_health
        
        expect(health[:performance_metrics]).to be_present
        expect(health[:workflow_statistics]).to be_present
        expect(health[:decision_validation_stats]).to be_present
      end
    end
  end

  describe 'Enterprise Compliance and Security' do
    context 'Data Classification and Governance' do
      it 'properly classifies and protects sensitive intelligence data' do
        classified_data = sample_intelligence_data.merge(
          classification: 'top_secret',
          governance_requirements: {
            encryption_required: true,
            access_logging: true,
            retention_period: '25_years'
          }
        )

        result = intelligence_service.process_intelligence_data(classified_data)
        
        expect(result[:security_validation][:classification]).to eq('top_secret')
        expect(result[:governance_validation][:encryption_applied]).to be true
        expect(result[:compliance_audit_id]).to be_present
      end

      it 'maintains tamper-proof audit trails' do
        audit_context = {
          decision_id: 'tamper_test_001',
          decision_type: 'classified_operation',
          user_context: sample_decision_context[:user_context],
          data_classification: 'restricted',
          compliance_requirements: ['fedramp', 'sox']
        }

        result = audit_service.create_decision_audit_entry(audit_context)
        
        expect(result[:tamper_proof_id]).to be_present
        expect(result[:forensic_capabilities][:tamper_detection_enabled]).to be true
        expect(result[:compliance_status][:frameworks_satisfied]).to include('fedramp', 'sox')
      end
    end

    context 'Cross-Language Security' do
      it 'maintains security context across language boundaries' do
        secure_call_config = {
          package: 'shared',
          service: 'ParlantIntegrationService',
          method: 'validateSecureOperation',
          parameters: {
            operation: 'classified_intelligence_processing',
            security_level: 'top_secret',
            user_context: sample_decision_context[:user_context]
          },
          validation_context: {
            security_classification: 'top_secret',
            compliance_required: ['fedramp']
          }
        }

        result = bridge_service.call_typescript_service(secure_call_config)
        
        expect(result[:language_bridge_metadata][:validation_applied]).to be true
        expect(result[:success]).to be true
      end
    end
  end

  private

  def create_test_agent
    double('Agent', 
      id: rand(1000..9999),
      name: "Test Agent #{rand(100..999)}",
      type: 'WeatherAgent',
      schedule: '*/5 * * * *',
      disabled?: false,
      user_id: 'test_user_001'
    )
  end

  def stub_parlant_api_responses
    allow(HTTParty).to receive(:post).and_return(
      double('Response', 
        code: 200, 
        parsed_response: {
          'approved' => true,
          'confidence' => 0.95,
          'reasoning' => 'Test validation passed',
          'conversation_id' => 'test_conv_001'
        }
      )
    )
  end

  def initialize_test_agents
    # Initialize any test agents or mock objects needed
  end
end