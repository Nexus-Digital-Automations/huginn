# frozen_string_literal: true

require 'rails_helper'
require 'webmock/rspec'

describe Agents::AigentTriggerAgent do
  let(:valid_params) do
    {
      'name' => 'AIgent Trigger Agent Test',
      'options' => {
        'orchestrator_url' => 'http://localhost:8080',
        'target_agent' => 'test_agent',
        'goal' => 'Process test event: {{ event.test_data }}',
        'priority' => 'normal',
        'execution_mode' => 'asynchronous',
        'timeout_seconds' => 300,
        'trigger_condition' => 'on_event',
        'condition_rules' => [],
        'context_data' => {
          'source' => 'huginn_agent',
          'environment' => 'test'
        },
        'tags' => ['test', 'automation'],
        'expected_receive_period_in_days' => '1',
        'verify_ssl' => true,
        'retry_attempts' => 3,
        'emit_events' => true,
        'include_execution_metadata' => false,
        'include_original_event' => false,
        'headers' => {
          'User-Agent' => 'Huginn-AIgent-Trigger-Agent/1.0',
          'Content-Type' => 'application/json'
        }
      }
    }
  end

  let(:test_event) do
    Event.new.tap do |event|
      event.agent = agents(:bob_rain_notifier_agent)
      event.payload = {
        'test_data' => 'sample data',
        'severity' => 5,
        'timestamp' => Time.current.iso8601
      }
    end
  end

  before do
    @checker = Agents::AigentTriggerAgent.new(valid_params)
    @checker.user = users(:bob)
    WebMock.disable_net_connect!(allow_localhost: true)
  end

  after do
    WebMock.reset!
    WebMock.allow_net_connect!
  end

  describe 'validation' do
    context 'when all required fields are present' do
      it 'should be valid' do
        expect(@checker).to be_valid
      end
    end

    describe 'required field validation' do
      it 'requires orchestrator_url' do
        @checker.options.delete('orchestrator_url')
        expect(@checker).not_to be_valid
        expect(@checker.errors[:base]).to include(match(/orchestrator_url is required/))
      end

      it 'requires target_agent' do
        @checker.options.delete('target_agent')
        expect(@checker).not_to be_valid
        expect(@checker.errors[:base]).to include(match(/target_agent is required/))
      end

      it 'requires goal' do
        @checker.options.delete('goal')
        expect(@checker).not_to be_valid
        expect(@checker.errors[:base]).to include(match(/goal is required/))
      end

      it 'validates empty orchestrator_url' do
        @checker.options['orchestrator_url'] = ''
        expect(@checker).not_to be_valid
      end

      it 'validates empty target_agent' do
        @checker.options['target_agent'] = ''
        expect(@checker).not_to be_valid
      end

      it 'validates empty goal' do
        @checker.options['goal'] = ''
        expect(@checker).not_to be_valid
      end
    end

    describe 'orchestrator_url validation' do
      it 'accepts valid HTTP URLs' do
        @checker.options['orchestrator_url'] = 'http://localhost:8080'
        expect(@checker).to be_valid
      end

      it 'accepts valid HTTPS URLs' do
        @checker.options['orchestrator_url'] = 'https://orchestrator.example.com'
        expect(@checker).to be_valid
      end

      it 'rejects URLs without scheme' do
        @checker.options['orchestrator_url'] = 'localhost:8080'
        expect(@checker).not_to be_valid
        expect(@checker.errors[:base]).to include(match(/not a valid URL/))
      end

      it 'rejects URLs with invalid scheme' do
        @checker.options['orchestrator_url'] = 'ftp://localhost:8080'
        expect(@checker).not_to be_valid
        expect(@checker.errors[:base]).to include(match(/must use http or https scheme/))
      end

      it 'rejects URLs without host' do
        @checker.options['orchestrator_url'] = 'http://'
        expect(@checker).not_to be_valid
        expect(@checker.errors[:base]).to include(match(/must include a valid host/))
      end

      it 'rejects malformed URLs' do
        @checker.options['orchestrator_url'] = 'not-a-url'
        expect(@checker).not_to be_valid
        expect(@checker.errors[:base]).to include(match(/not a valid URL/))
      end
    end

    describe 'target_agent validation' do
      it 'accepts valid agent names' do
        @checker.options['target_agent'] = 'valid_agent_name'
        expect(@checker).to be_valid
      end

      it 'accepts agent names with numbers' do
        @checker.options['target_agent'] = 'agent123'
        expect(@checker).to be_valid
      end

      it 'accepts agent names with underscores' do
        @checker.options['target_agent'] = 'data_processing_agent'
        expect(@checker).to be_valid
      end

      it 'rejects agent names with spaces' do
        @checker.options['target_agent'] = 'invalid agent name'
        expect(@checker).not_to be_valid
        expect(@checker.errors[:base]).to include(match(/must contain only lowercase letters, numbers, and underscores/))
      end

      it 'rejects agent names with uppercase letters' do
        @checker.options['target_agent'] = 'InvalidAgent'
        expect(@checker).not_to be_valid
        expect(@checker.errors[:base]).to include(match(/must contain only lowercase letters, numbers, and underscores/))
      end

      it 'rejects agent names with special characters' do
        @checker.options['target_agent'] = 'agent-name!'
        expect(@checker).not_to be_valid
        expect(@checker.errors[:base]).to include(match(/must contain only lowercase letters, numbers, and underscores/))
      end

      it 'rejects overly long agent names' do
        @checker.options['target_agent'] = 'a' * 101
        expect(@checker).not_to be_valid
        expect(@checker.errors[:base]).to include(match(/must be 100 characters or less/))
      end
    end

    describe 'goal template validation' do
      it 'accepts valid Liquid templates' do
        @checker.options['goal'] = 'Process {{ event.data }} with priority {{ priority }}'
        expect(@checker).to be_valid
      end

      it 'accepts simple text goals' do
        @checker.options['goal'] = 'Process the incoming data'
        expect(@checker).to be_valid
      end

      it 'rejects empty goals' do
        @checker.options['goal'] = '   '
        expect(@checker).not_to be_valid
        expect(@checker.errors[:base]).to include(match(/goal cannot be empty/))
      end

      it 'rejects goals with invalid Liquid syntax' do
        @checker.options['goal'] = 'Process {{ unclosed template'
        expect(@checker).not_to be_valid
        expect(@checker.errors[:base]).to include(match(/invalid Liquid template syntax/))
      end

      it 'rejects goals with dangerous function calls' do
        @checker.options['goal'] = 'Execute system("rm -rf /")'
        expect(@checker).not_to be_valid
        expect(@checker.errors[:base]).to include(match(/potentially dangerous function calls/))
      end

      it 'rejects goals with exec calls' do
        @checker.options['goal'] = 'Run exec("malicious command")'
        expect(@checker).not_to be_valid
        expect(@checker.errors[:base]).to include(match(/potentially dangerous function calls/))
      end

      it 'rejects goals with eval calls' do
        @checker.options['goal'] = 'Execute eval("dangerous code")'
        expect(@checker).not_to be_valid
        expect(@checker.errors[:base]).to include(match(/potentially dangerous function calls/))
      end
    end

    describe 'priority validation' do
      Agents::AigentTriggerAgent::VALID_PRIORITY_LEVELS.each do |priority|
        it "accepts '#{priority}' as valid priority" do
          @checker.options['priority'] = priority
          expect(@checker).to be_valid
        end
      end

      it 'rejects invalid priority levels' do
        @checker.options['priority'] = 'invalid'
        expect(@checker).not_to be_valid
        expect(@checker.errors[:base]).to include(match(/priority must be one of/))
      end

      it 'accepts priority in different case' do
        @checker.options['priority'] = 'HIGH'
        expect(@checker).to be_valid
      end
    end

    describe 'execution_mode validation' do
      Agents::AigentTriggerAgent::VALID_EXECUTION_MODES.each do |mode|
        it "accepts '#{mode}' as valid execution mode" do
          @checker.options['execution_mode'] = mode
          expect(@checker).to be_valid
        end
      end

      it 'rejects invalid execution modes' do
        @checker.options['execution_mode'] = 'invalid'
        expect(@checker).not_to be_valid
        expect(@checker.errors[:base]).to include(match(/execution_mode must be one of/))
      end
    end

    describe 'trigger_condition validation' do
      Agents::AigentTriggerAgent::VALID_TRIGGER_CONDITIONS.each do |condition|
        it "accepts '#{condition}' as valid trigger condition" do
          @checker.options['trigger_condition'] = condition
          expect(@checker).to be_valid
        end
      end

      it 'rejects invalid trigger conditions' do
        @checker.options['trigger_condition'] = 'invalid'
        expect(@checker).not_to be_valid
        expect(@checker.errors[:base]).to include(match(/trigger_condition must be one of/))
      end
    end

    describe 'timeout_seconds validation' do
      it 'accepts valid timeout values' do
        [30, 300, 3600].each do |timeout|
          @checker.options['timeout_seconds'] = timeout
          expect(@checker).to be_valid
        end
      end

      it 'rejects timeout values below minimum' do
        @checker.options['timeout_seconds'] = 29
        expect(@checker).not_to be_valid
        expect(@checker.errors[:base]).to include(match(/timeout_seconds must be between 30 and 3600/))
      end

      it 'rejects timeout values above maximum' do
        @checker.options['timeout_seconds'] = 3601
        expect(@checker).not_to be_valid
        expect(@checker.errors[:base]).to include(match(/timeout_seconds must be between 30 and 3600/))
      end
    end

    describe 'retry_attempts validation' do
      it 'accepts valid retry values' do
        (0..10).each do |retries|
          @checker.options['retry_attempts'] = retries
          expect(@checker).to be_valid
        end
      end

      it 'rejects negative retry attempts' do
        @checker.options['retry_attempts'] = -1
        expect(@checker).not_to be_valid
        expect(@checker.errors[:base]).to include(match(/retry_attempts must be between 0 and 10/))
      end

      it 'rejects excessive retry attempts' do
        @checker.options['retry_attempts'] = 11
        expect(@checker).not_to be_valid
        expect(@checker.errors[:base]).to include(match(/retry_attempts must be between 0 and 10/))
      end
    end

    describe 'condition_rules validation' do
      it 'accepts empty condition rules' do
        @checker.options['condition_rules'] = []
        expect(@checker).to be_valid
      end

      it 'accepts valid Liquid template rules' do
        @checker.options['condition_rules'] = [
          "{{ event.severity | plus: 0 | at_least: 5 }}"
        ]
        expect(@checker).to be_valid
      end

      it 'accepts valid structured condition rules' do
        @checker.options['condition_rules'] = [
          {
            'field' => 'severity',
            'operator' => '>=',
            'value' => 5
          }
        ]
        expect(@checker).to be_valid
      end

      it 'rejects rules that are not arrays' do
        @checker.options['condition_rules'] = 'not an array'
        expect(@checker).not_to be_valid
        expect(@checker.errors[:base]).to include(match(/condition_rules must be an array/))
      end

      it 'rejects rules with invalid Liquid syntax' do
        @checker.options['condition_rules'] = [
          "{{ unclosed liquid template"
        ]
        expect(@checker).not_to be_valid
        expect(@checker.errors[:base]).to include(match(/invalid Liquid syntax/))
      end

      it 'rejects structured rules missing required keys' do
        @checker.options['condition_rules'] = [
          {
            'field' => 'severity'
            # missing operator and value
          }
        ]
        expect(@checker).not_to be_valid
        expect(@checker.errors[:base]).to include(match(/missing required keys/))
      end

      it 'rejects rules that are neither strings nor hashes' do
        @checker.options['condition_rules'] = [123]
        expect(@checker).not_to be_valid
        expect(@checker.errors[:base]).to include(match(/must be a string .* or hash/))
      end
    end

    describe 'context_data validation' do
      it 'accepts valid hash context data' do
        @checker.options['context_data'] = { 'key' => 'value' }
        expect(@checker).to be_valid
      end

      it 'rejects context_data that is not a hash' do
        @checker.options['context_data'] = 'not a hash'
        expect(@checker).not_to be_valid
        expect(@checker.errors[:base]).to include(match(/context_data must be a hash/))
      end
    end

    describe 'tags validation' do
      it 'accepts valid string arrays' do
        @checker.options['tags'] = ['tag1', 'tag2']
        expect(@checker).to be_valid
      end

      it 'rejects tags that are not arrays' do
        @checker.options['tags'] = 'not an array'
        expect(@checker).not_to be_valid
        expect(@checker.errors[:base]).to include(match(/tags must be an array/))
      end

      it 'rejects non-string elements in tags array' do
        @checker.options['tags'] = ['valid', 123]
        expect(@checker).not_to be_valid
        expect(@checker.errors[:base]).to include(match(/must be a string/))
      end
    end

    describe 'headers validation' do
      it 'accepts valid header hash' do
        @checker.options['headers'] = { 'Authorization' => 'Bearer token' }
        expect(@checker).to be_valid
      end

      it 'rejects headers that are not hashes' do
        @checker.options['headers'] = 'not a hash'
        expect(@checker).not_to be_valid
        expect(@checker.errors[:base]).to include(match(/headers must be a hash/))
      end

      it 'rejects headers with non-string keys or values' do
        @checker.options['headers'] = { 123 => 'value' }
        expect(@checker).not_to be_valid
        expect(@checker.errors[:base]).to include(match(/all headers keys and values must be strings/))
      end
    end

    describe 'boolean options validation' do
      %w[emit_events include_execution_metadata include_original_event].each do |option|
        it "accepts 'true' for #{option}" do
          @checker.options[option] = 'true'
          expect(@checker).to be_valid
        end

        it "accepts 'false' for #{option}" do
          @checker.options[option] = 'false'
          expect(@checker).to be_valid
        end

        it "rejects invalid boolean values for #{option}" do
          @checker.options[option] = 'maybe'
          expect(@checker).not_to be_valid
          expect(@checker.errors[:base]).to include(match(/#{option} must be true or false/))
        end
      end
    end

    describe 'verify_ssl validation' do
      it 'accepts true for verify_ssl' do
        @checker.options['verify_ssl'] = true
        expect(@checker).to be_valid
      end

      it 'accepts false for verify_ssl' do
        @checker.options['verify_ssl'] = false
        expect(@checker).to be_valid
      end

      it 'rejects invalid verify_ssl values' do
        @checker.options['verify_ssl'] = 'maybe'
        expect(@checker).not_to be_valid
        expect(@checker.errors[:base]).to include(match(/verify_ssl must be true or false/))
      end
    end

    describe 'api_key validation' do
      it 'accepts sufficiently long API keys' do
        @checker.options['api_key'] = 'a' * 20
        expect(@checker).to be_valid
      end

      it 'rejects very short API keys' do
        @checker.options['api_key'] = 'short'
        expect(@checker).not_to be_valid
        expect(@checker.errors[:base]).to include(match(/api_key appears to be too short/))
      end
    end
  end

  describe '#working?' do
    before do
      @checker.save!
    end

    it 'returns false when there are recent error logs' do
      allow(@checker).to receive(:recent_error_logs?).and_return(true)
      expect(@checker).not_to be_working
    end

    it 'returns false when last_receive_at is too old' do
      @checker.update!(last_receive_at: 3.days.ago)
      expect(@checker).not_to be_working
    end

    it 'returns true when conditions are met' do
      @checker.update!(last_receive_at: 1.hour.ago)
      allow(@checker).to receive(:recent_error_logs?).and_return(false)
      expect(@checker).to be_working
    end

    it 'returns true when expected_receive_period_in_days is not set' do
      @checker.options.delete('expected_receive_period_in_days')
      @checker.save!
      allow(@checker).to receive(:recent_error_logs?).and_return(false)
      expect(@checker).to be_working
    end
  end

  describe '#default_options' do
    it 'provides sensible defaults' do
      agent = Agents::AigentTriggerAgent.new
      defaults = agent.default_options

      expect(defaults['orchestrator_url']).to eq('http://localhost:8080')
      expect(defaults['target_agent']).to eq('general_purpose_agent')
      expect(defaults['priority']).to eq('normal')
      expect(defaults['execution_mode']).to eq('asynchronous')
      expect(defaults['timeout_seconds']).to eq(300)
      expect(defaults['trigger_condition']).to eq('on_event')
      expect(defaults['verify_ssl']).to be true
      expect(defaults['retry_attempts']).to eq(3)
      expect(defaults['emit_events']).to be true
    end
  end

  describe '#dry_run' do
    before do
      @checker.save!
    end

    it 'returns simulation results without making actual requests' do
      result = @checker.dry_run(test_event)

      expect(result[:status]).to eq('dry_run_success')
      expect(result[:target_agent]).to eq('test_agent')
      expect(result[:processed_goal]).to include('sample data')
      expect(result[:priority]).to eq('normal')
      expect(result[:would_trigger]).to be true
      expect(result).to have_key(:timestamp)
    end

    it 'processes Liquid templates in goal' do
      @checker.options['goal'] = 'Process: {{ event.test_data }}'
      @checker.save!

      result = @checker.dry_run(test_event)
      expect(result[:processed_goal]).to eq('Process: sample data')
    end

    it 'includes context data when present' do
      result = @checker.dry_run(test_event)
      expect(result[:context_data]).to eq(@checker.options['context_data'])
    end
  end

  describe '#should_trigger?' do
    before do
      @checker.save!
    end

    context 'with trigger_condition set to on_event' do
      it 'always returns true' do
        @checker.options['trigger_condition'] = 'on_event'
        expect(@checker.send(:should_trigger?, test_event)).to be true
      end
    end

    context 'with trigger_condition set to on_condition_met' do
      it 'evaluates condition rules' do
        @checker.options['trigger_condition'] = 'on_condition_met'
        @checker.options['condition_rules'] = [
          {
            'field' => 'severity',
            'operator' => '>=',
            'value' => 3
          }
        ]

        expect(@checker.send(:should_trigger?, test_event)).to be true
      end

      it 'returns false when conditions are not met' do
        @checker.options['trigger_condition'] = 'on_condition_met'
        @checker.options['condition_rules'] = [
          {
            'field' => 'severity',
            'operator' => '>=',
            'value' => 10
          }
        ]

        expect(@checker.send(:should_trigger?, test_event)).to be false
      end

      it 'returns true when rules are empty' do
        @checker.options['trigger_condition'] = 'on_condition_met'
        @checker.options['condition_rules'] = []

        expect(@checker.send(:should_trigger?, test_event)).to be true
      end
    end

    context 'with advanced trigger conditions' do
      it 'handles threshold exceeded conditions' do
        @checker.options['trigger_condition'] = 'on_threshold_exceeded'
        @checker.options['condition_rules'] = [
          {
            'type' => 'threshold',
            'field' => 'severity',
            'threshold' => 3
          }
        ]

        expect(@checker.send(:should_trigger?, test_event)).to be true
      end

      it 'handles pattern match conditions' do
        @checker.options['trigger_condition'] = 'on_pattern_match'
        @checker.options['condition_rules'] = [
          {
            'type' => 'pattern',
            'field' => 'test_data',
            'pattern' => 'sample.*'
          }
        ]

        expect(@checker.send(:should_trigger?, test_event)).to be true
      end
    end
  end

  describe '#evaluate_condition_rules' do
    before do
      @checker.save!
    end

    it 'evaluates Liquid template rules correctly' do
      rules = ["{{ event.severity | plus: 0 | at_least: 5 }}"]
      result = @checker.send(:evaluate_condition_rules, test_event, rules)
      expect(result).to be true
    end

    it 'evaluates structured condition rules correctly' do
      rules = [
        {
          'field' => 'severity',
          'operator' => '==',
          'value' => 5
        }
      ]
      result = @checker.send(:evaluate_condition_rules, test_event, rules)
      expect(result).to be true
    end

    it 'requires all rules to be true (AND logic)' do
      rules = [
        {
          'field' => 'severity',
          'operator' => '>=',
          'value' => 3
        },
        {
          'field' => 'severity',
          'operator' => '<=',
          'value' => 10
        }
      ]
      result = @checker.send(:evaluate_condition_rules, test_event, rules)
      expect(result).to be true
    end

    it 'returns false if any rule fails' do
      rules = [
        {
          'field' => 'severity',
          'operator' => '>=',
          'value' => 3
        },
        {
          'field' => 'severity',
          'operator' => '>=',
          'value' => 10
        }
      ]
      result = @checker.send(:evaluate_condition_rules, test_event, rules)
      expect(result).to be false
    end
  end

  describe '#evaluate_structured_condition' do
    before do
      @checker.save!
    end

    context 'equality operators' do
      it 'handles == operator' do
        rule = { 'field' => 'severity', 'operator' => '==', 'value' => 5 }
        result = @checker.send(:evaluate_structured_condition, test_event, rule)
        expect(result).to be true
      end

      it 'handles != operator' do
        rule = { 'field' => 'severity', 'operator' => '!=', 'value' => 3 }
        result = @checker.send(:evaluate_structured_condition, test_event, rule)
        expect(result).to be true
      end
    end

    context 'comparison operators' do
      it 'handles > operator' do
        rule = { 'field' => 'severity', 'operator' => '>', 'value' => 3 }
        result = @checker.send(:evaluate_structured_condition, test_event, rule)
        expect(result).to be true
      end

      it 'handles >= operator' do
        rule = { 'field' => 'severity', 'operator' => '>=', 'value' => 5 }
        result = @checker.send(:evaluate_structured_condition, test_event, rule)
        expect(result).to be true
      end

      it 'handles < operator' do
        rule = { 'field' => 'severity', 'operator' => '<', 'value' => 10 }
        result = @checker.send(:evaluate_structured_condition, test_event, rule)
        expect(result).to be true
      end

      it 'handles <= operator' do
        rule = { 'field' => 'severity', 'operator' => '<=', 'value' => 5 }
        result = @checker.send(:evaluate_structured_condition, test_event, rule)
        expect(result).to be true
      end
    end

    context 'string operators' do
      it 'handles contains operator' do
        rule = { 'field' => 'test_data', 'operator' => 'contains', 'value' => 'sample' }
        result = @checker.send(:evaluate_structured_condition, test_event, rule)
        expect(result).to be true
      end

      it 'handles matches operator with regex' do
        rule = { 'field' => 'test_data', 'operator' => 'matches', 'value' => 'sample.*' }
        result = @checker.send(:evaluate_structured_condition, test_event, rule)
        expect(result).to be true
      end
    end

    it 'returns false for unknown operators' do
      rule = { 'field' => 'severity', 'operator' => 'unknown', 'value' => 5 }
      result = @checker.send(:evaluate_structured_condition, test_event, rule)
      expect(result).to be false
    end
  end

  describe '#build_aigent_request' do
    before do
      @checker.save!
    end

    it 'builds correct request structure' do
      request = @checker.send(:build_aigent_request, test_event)

      expect(request[:target_agent]).to eq('test_agent')
      expect(request[:goal]).to include('sample data')
      expect(request[:priority]).to eq('normal')
      expect(request[:execution_mode]).to eq('asynchronous')
      expect(request[:timeout_seconds]).to eq(300)
      expect(request[:context_data]).to be_a(Hash)
      expect(request[:tags]).to eq(['test', 'automation'])
      expect(request[:metadata]).to be_a(Hash)
    end

    it 'includes proper metadata' do
      request = @checker.send(:build_aigent_request, test_event)
      metadata = request[:metadata]

      expect(metadata[:source]).to eq('huginn_aigent_trigger_agent')
      expect(metadata[:agent_id]).to eq(@checker.id)
      expect(metadata[:event_id]).to eq(test_event.id)
      expect(metadata).to have_key(:timestamp)
    end

    it 'processes Liquid templates in goal' do
      @checker.options['goal'] = 'Process {{ event.test_data }}'
      request = @checker.send(:build_aigent_request, test_event)

      expect(request[:goal]).to eq('Process sample data')
    end
  end

  describe '#build_context_data' do
    before do
      @checker.save!
    end

    it 'merges base context with event context' do
      context = @checker.send(:build_context_data, test_event)

      expect(context['source']).to eq('huginn_agent')
      expect(context['environment']).to eq('test')
      expect(context['triggering_event']).to eq(test_event.payload)
      expect(context['agent_name']).to eq(@checker.name)
      expect(context).to have_key('event_timestamp')
    end

    it 'includes original event data when requested' do
      @checker.options['include_original_event'] = true
      context = @checker.send(:build_context_data, test_event)

      expect(context['original_event_data']).to eq(test_event.payload)
    end

    it 'excludes original event data by default' do
      @checker.options['include_original_event'] = false
      context = @checker.send(:build_context_data, test_event)

      expect(context).not_to have_key('original_event_data')
    end
  end

  describe '#build_request_headers' do
    before do
      @checker.save!
    end

    it 'builds basic headers' do
      headers = @checker.send(:build_request_headers)

      expect(headers['Content-Type']).to eq('application/json')
      expect(headers['User-Agent']).to eq('Huginn-AIgent-Trigger-Agent/1.0')
      expect(headers['Accept']).to eq('application/json')
    end

    it 'includes API key when present' do
      @checker.options['api_key'] = 'test-api-key'
      headers = @checker.send(:build_request_headers)

      expect(headers['Authorization']).to eq('Bearer test-api-key')
    end

    it 'merges custom headers' do
      @checker.options['headers'] = { 'Custom-Header' => 'custom-value' }
      headers = @checker.send(:build_request_headers)

      expect(headers['Custom-Header']).to eq('custom-value')
      expect(headers['Content-Type']).to eq('application/json')
    end
  end

  describe 'HTTP request handling' do
    before do
      @checker.save!
    end

    describe '#submit_to_orchestrator' do
      let(:request_data) do
        {
          target_agent: 'test_agent',
          goal: 'test goal',
          priority: 'normal'
        }
      end

      it 'makes successful HTTP requests' do
        stub_request(:post, 'http://localhost:8080/api/v1/aigent/execute')
          .with(
            body: request_data.to_json,
            headers: hash_including('Content-Type' => 'application/json')
          )
          .to_return(
            status: 200,
            body: { status: 'success', execution_id: 'test-id' }.to_json,
            headers: { 'Content-Type' => 'application/json' }
          )

        response = @checker.send(:submit_to_orchestrator, request_data)

        expect(response[:status]).to eq(200)
        expect(response[:parsed_body]['status']).to eq('success')
        expect(response[:parsed_body]['execution_id']).to eq('test-id')
        expect(response[:response_time_ms]).to be > 0
      end

      it 'handles HTTP errors' do
        stub_request(:post, 'http://localhost:8080/api/v1/aigent/execute')
          .to_return(status: 500, body: 'Internal Server Error')

        expect {
          @checker.send(:submit_to_orchestrator, request_data)
        }.to raise_error(/HTTP 500/)
      end

      it 'handles JSON parsing errors gracefully' do
        stub_request(:post, 'http://localhost:8080/api/v1/aigent/execute')
          .to_return(status: 200, body: 'invalid json')

        response = @checker.send(:submit_to_orchestrator, request_data)

        expect(response[:status]).to eq(200)
        expect(response[:parsed_body]).to be_nil
        expect(response[:body]).to eq('invalid json')
      end

      it 'includes proper SSL configuration' do
        @checker.options['verify_ssl'] = false
        
        # Mock Net::HTTP to verify SSL settings
        http_mock = double('Net::HTTP')
        allow(Net::HTTP).to receive(:new).and_return(http_mock)
        allow(http_mock).to receive(:use_ssl=)
        allow(http_mock).to receive(:verify_mode=)
        allow(http_mock).to receive(:open_timeout=)
        allow(http_mock).to receive(:read_timeout=)

        request_mock = double('Net::HTTP::Post')
        allow(Net::HTTP::Post).to receive(:new).and_return(request_mock)
        allow(request_mock).to receive(:[]=)
        allow(request_mock).to receive(:body=)

        response_mock = double('Net::HTTPSuccess')
        allow(response_mock).to receive(:is_a?).with(Net::HTTPSuccess).and_return(true)
        allow(response_mock).to receive(:code).and_return('200')
        allow(response_mock).to receive(:to_hash).and_return({})
        allow(response_mock).to receive(:body).and_return('{}')

        allow(http_mock).to receive(:request).and_return(response_mock)

        @checker.send(:submit_to_orchestrator, request_data)

        expect(http_mock).to have_received(:verify_mode=).with(OpenSSL::SSL::VERIFY_NONE)
      end
    end

    describe '#submit_with_retries' do
      let(:request_data) { { test: 'data' } }

      it 'succeeds on first attempt' do
        expect(@checker).to receive(:submit_to_orchestrator)
          .once
          .with(request_data)
          .and_return({ status: 200 })

        result = @checker.send(:submit_with_retries, request_data)
        expect(result[:status]).to eq(200)
      end

      it 'retries on failure and eventually succeeds' do
        expect(@checker).to receive(:submit_to_orchestrator)
          .twice
          .with(request_data)
          .and_raise(StandardError.new('Network error'))
          .then
          .return({ status: 200 })

        expect(@checker).to receive(:sleep).with(2)

        result = @checker.send(:submit_with_retries, request_data)
        expect(result[:status]).to eq(200)
      end

      it 'fails after maximum retries' do
        @checker.options['retry_attempts'] = 2

        expect(@checker).to receive(:submit_to_orchestrator)
          .exactly(3).times  # initial + 2 retries
          .and_raise(StandardError.new('Persistent error'))

        expect(@checker).to receive(:sleep).twice

        expect {
          @checker.send(:submit_with_retries, request_data)
        }.to raise_error('Persistent error')
      end
    end
  end

  describe '#perform_health_check' do
    before do
      @checker.save!
    end

    it 'performs successful health check' do
      stub_request(:get, 'http://localhost:8080/health')
        .to_return(status: 200, body: 'OK')

      result = @checker.send(:perform_health_check, 'http://localhost:8080')

      expect(result[:status]).to eq(200)
      expect(result[:response_time_ms]).to be > 0
      expect(result[:message]).to eq('OK')
    end

    it 'handles health check failures' do
      stub_request(:get, 'http://localhost:8080/health')
        .to_timeout

      expect {
        @checker.send(:perform_health_check, 'http://localhost:8080')
      }.to raise_error(Net::TimeoutError)
    end
  end

  describe '#receive' do
    before do
      @checker.save!
    end

    context 'when events should trigger' do
      it 'processes events successfully' do
        stub_request(:post, 'http://localhost:8080/api/v1/aigent/execute')
          .to_return(
            status: 200,
            body: { status: 'success', execution_id: 'test-123' }.to_json
          )

        expect {
          @checker.receive([test_event])
        }.to change { Event.count }.by(1)

        created_event = Event.last
        expect(created_event.payload['status']).to eq('success')
        expect(created_event.payload['target_agent']).to eq('test_agent')
        expect(created_event.payload['execution_id']).to eq('test-123')
      end

      it 'handles processing errors gracefully' do
        stub_request(:post, 'http://localhost:8080/api/v1/aigent/execute')
          .to_return(status: 500, body: 'Server Error')

        expect {
          @checker.receive([test_event])
        }.to change { Event.count }.by(1)

        created_event = Event.last
        expect(created_event.payload['status']).to eq('failed')
        expect(created_event.payload['error']).to be_present
      end

      it 'skips events that should not trigger' do
        @checker.options['trigger_condition'] = 'on_condition_met'
        @checker.options['condition_rules'] = [
          {
            'field' => 'severity',
            'operator' => '>',
            'value' => 10
          }
        ]
        @checker.save!

        expect {
          @checker.receive([test_event])
        }.not_to change { Event.count }
      end

      it 'processes multiple events' do
        stub_request(:post, 'http://localhost:8080/api/v1/aigent/execute')
          .to_return(
            status: 200,
            body: { status: 'success' }.to_json
          )

        event2 = Event.new.tap do |e|
          e.agent = agents(:bob_weather_agent)
          e.payload = { 'different_data' => 'value2' }
        end

        expect {
          @checker.receive([test_event, event2])
        }.to change { Event.count }.by(2)
      end

      it 'does not emit events when configured not to' do
        @checker.options['emit_events'] = false
        @checker.save!

        stub_request(:post, 'http://localhost:8080/api/v1/aigent/execute')
          .to_return(status: 200, body: { status: 'success' }.to_json)

        expect {
          @checker.receive([test_event])
        }.not_to change { Event.count }
      end
    end
  end

  describe '#check' do
    before do
      @checker.save!
    end

    it 'performs health check and emits success event' do
      stub_request(:get, 'http://localhost:8080/health')
        .to_return(status: 200, body: 'OK')

      expect {
        @checker.check
      }.to change { Event.count }.by(1)

      created_event = Event.last
      expect(created_event.payload['status']).to eq('health_check_success')
      expect(created_event.payload['orchestrator_url']).to eq('http://localhost:8080')
      expect(created_event.payload['response_time_ms']).to be > 0
    end

    it 'handles health check failures and emits error event' do
      stub_request(:get, 'http://localhost:8080/health')
        .to_return(status: 500, body: 'Error')

      expect {
        @checker.check
      }.to change { Event.count }.by(1)

      created_event = Event.last
      expect(created_event.payload['status']).to eq('health_check_failed')
      expect(created_event.payload['error']).to be_present
    end

    it 'does not emit events when configured not to' do
      @checker.options['emit_events'] = false
      @checker.save!

      stub_request(:get, 'http://localhost:8080/health')
        .to_return(status: 200, body: 'OK')

      expect {
        @checker.check
      }.not_to change { Event.count }
    end
  end

  describe '#handle_aigent_response' do
    before do
      @checker.save!
    end

    let(:request_data) do
      {
        target_agent: 'test_agent',
        goal: 'test goal',
        priority: 'normal',
        execution_mode: 'asynchronous'
      }
    end

    let(:successful_response) do
      {
        status: 200,
        parsed_body: {
          'execution_id' => 'exec-123',
          'status' => 'completed',
          'result' => { 'data' => 'processed' }
        },
        response_time_ms: 150.5
      }
    end

    it 'creates success events with proper structure' do
      expect {
        @checker.send(:handle_aigent_response, test_event, request_data, successful_response)
      }.to change { Event.count }.by(1)

      event = Event.last
      payload = event.payload

      expect(payload['status']).to eq('success')
      expect(payload['target_agent']).to eq('test_agent')
      expect(payload['goal']).to eq('test goal')
      expect(payload['priority']).to eq('normal')
      expect(payload['execution_id']).to eq('exec-123')
      expect(payload['result']).to eq({ 'data' => 'processed' })
      expect(payload['response_time_ms']).to eq(150.5)
      expect(payload).to have_key('timestamp')
    end

    it 'includes execution metadata when requested' do
      @checker.options['include_execution_metadata'] = true

      @checker.send(:handle_aigent_response, test_event, request_data, successful_response)

      event = Event.last
      metadata = event.payload['metadata']

      expect(metadata['request_data']).to eq(request_data)
      expect(metadata['response_status']).to eq(200)
      expect(metadata).to have_key('response_headers')
    end

    it 'includes original event when requested' do
      @checker.options['include_original_event'] = true

      @checker.send(:handle_aigent_response, test_event, request_data, successful_response)

      event = Event.last
      expect(event.payload['original_event']).to eq(test_event.payload)
    end

    it 'does not create events when emit_events is false' do
      @checker.options['emit_events'] = false

      expect {
        @checker.send(:handle_aigent_response, test_event, request_data, successful_response)
      }.not_to change { Event.count }
    end
  end

  describe '#emit_error_event' do
    before do
      @checker.save!
    end

    let(:test_error) { StandardError.new('Test error message') }

    it 'creates error events with proper structure' do
      expect {
        @checker.send(:emit_error_event, test_event, test_error)
      }.to change { Event.count }.by(1)

      event = Event.last
      payload = event.payload

      expect(payload['status']).to eq('failed')
      expect(payload['target_agent']).to eq('test_agent')
      expect(payload['goal']).to include('sample data')
      expect(payload['error']['type']).to eq('StandardError')
      expect(payload['error']['message']).to eq('Test error message')
      expect(payload).to have_key('timestamp')
    end

    it 'includes original event when requested' do
      @checker.options['include_original_event'] = true

      @checker.send(:emit_error_event, test_event, test_error)

      event = Event.last
      expect(event.payload['original_event']).to eq(test_event.payload)
    end

    it 'includes backtrace in development environment' do
      allow(Rails.env).to receive(:development?).and_return(true)
      test_error.set_backtrace(['line1', 'line2', 'line3'])

      @checker.send(:emit_error_event, test_event, test_error)

      event = Event.last
      expect(event.payload['error']['backtrace']).to be_present
      expect(event.payload['error']['backtrace']).to be_an(Array)
    end

    it 'does not create events when emit_events is false' do
      @checker.options['emit_events'] = false

      expect {
        @checker.send(:emit_error_event, test_event, test_error)
      }.not_to change { Event.count }
    end
  end

  describe '#boolify helper method' do
    before do
      @checker.save!
    end

    it 'converts truthy strings to true' do
      expect(@checker.send(:boolify, 'true')).to be true
      expect(@checker.send(:boolify, 'TRUE')).to be true
      expect(@checker.send(:boolify, '1')).to be true
      expect(@checker.send(:boolify, 'yes')).to be true
      expect(@checker.send(:boolify, 'on')).to be true
    end

    it 'converts falsy strings to false' do
      expect(@checker.send(:boolify, 'false')).to be false
      expect(@checker.send(:boolify, 'FALSE')).to be false
      expect(@checker.send(:boolify, '0')).to be false
      expect(@checker.send(:boolify, 'no')).to be false
      expect(@checker.send(:boolify, 'off')).to be false
      expect(@checker.send(:boolify, '')).to be false
    end

    it 'converts other values based on truthiness' do
      expect(@checker.send(:boolify, 'anything else')).to be true
      expect(@checker.send(:boolify, nil)).to be false
      expect(@checker.send(:boolify, 42)).to be true
    end
  end

  describe 'integration scenarios' do
    before do
      @checker.save!
    end

    context 'end-to-end processing' do
      it 'handles complete workflow successfully' do
        # Mock successful orchestrator response
        stub_request(:post, 'http://localhost:8080/api/v1/aigent/execute')
          .with(
            body: hash_including(
              'target_agent' => 'test_agent',
              'priority' => 'normal'
            ),
            headers: hash_including('Content-Type' => 'application/json')
          )
          .to_return(
            status: 200,
            body: {
              status: 'success',
              execution_id: 'exec-abc-123',
              result: {
                processed_data: 'successfully processed sample data',
                metrics: { processing_time: '2.3s', records_handled: 1 }
              }
            }.to_json,
            headers: { 'Content-Type' => 'application/json' }
          )

        # Process the event
        @checker.receive([test_event])

        # Verify the request was made correctly
        expect(WebMock).to have_requested(:post, 'http://localhost:8080/api/v1/aigent/execute')
          .with { |request|
            body = JSON.parse(request.body)
            expect(body['goal']).to include('sample data')
            expect(body['context_data']).to include('triggering_event')
            expect(body['metadata']).to include('source', 'agent_id', 'event_id')
            true
          }

        # Verify event creation
        expect(Event.count).to eq(1)
        created_event = Event.last

        expect(created_event.payload).to include(
          'status' => 'success',
          'target_agent' => 'test_agent',
          'execution_id' => 'exec-abc-123'
        )

        expect(created_event.payload['result']).to include(
          'processed_data' => 'successfully processed sample data',
          'metrics' => { 'processing_time' => '2.3s', 'records_handled' => 1 }
        )
      end

      it 'handles retry scenarios correctly' do
        @checker.options['retry_attempts'] = 2
        @checker.save!

        # Mock first two attempts fail, third succeeds
        stub_request(:post, 'http://localhost:8080/api/v1/aigent/execute')
          .to_timeout.times(2)
          .then
          .to_return(
            status: 200,
            body: { status: 'success', execution_id: 'retry-success' }.to_json
          )

        expect(@checker).to receive(:sleep).twice

        @checker.receive([test_event])

        expect(Event.count).to eq(1)
        expect(Event.last.payload['execution_id']).to eq('retry-success')
      end

      it 'handles complex conditional triggering' do
        @checker.options.update(
          'trigger_condition' => 'on_condition_met',
          'condition_rules' => [
            {
              'field' => 'severity',
              'operator' => '>=',
              'value' => 5
            },
            "{{ event.test_data | size | at_least: 5 }}"
          ]
        )
        @checker.save!

        stub_request(:post, 'http://localhost:8080/api/v1/aigent/execute')
          .to_return(status: 200, body: { status: 'success' }.to_json)

        # This should trigger (severity = 5 >= 5, test_data length = 11 >= 5)
        @checker.receive([test_event])
        expect(Event.count).to eq(1)

        # This should not trigger
        low_severity_event = Event.new.tap do |e|
          e.agent = test_event.agent
          e.payload = { 'severity' => 2, 'test_data' => 'abc' }
        end

        @checker.receive([low_severity_event])
        expect(Event.count).to eq(1) # No new event created
      end
    end

    context 'error handling scenarios' do
      it 'handles network timeout gracefully' do
        @checker.options['retry_attempts'] = 1
        @checker.save!

        stub_request(:post, 'http://localhost:8080/api/v1/aigent/execute')
          .to_timeout

        expect(@checker).to receive(:sleep).once

        @checker.receive([test_event])

        expect(Event.count).to eq(1)
        error_event = Event.last
        expect(error_event.payload['status']).to eq('failed')
        expect(error_event.payload['error']['type']).to include('Timeout')
      end

      it 'handles orchestrator service unavailable' do
        stub_request(:post, 'http://localhost:8080/api/v1/aigent/execute')
          .to_return(status: 503, body: 'Service Unavailable')

        @checker.receive([test_event])

        expect(Event.count).to eq(1)
        error_event = Event.last
        expect(error_event.payload['status']).to eq('failed')
        expect(error_event.payload['error']['message']).to include('HTTP 503')
      end

      it 'handles malformed orchestrator responses' do
        stub_request(:post, 'http://localhost:8080/api/v1/aigent/execute')
          .to_return(status: 200, body: 'invalid json response')

        @checker.receive([test_event])

        expect(Event.count).to eq(1)
        success_event = Event.last
        expect(success_event.payload['status']).to eq('success')
        # Should still create event, just without parsed response data
      end
    end
  end
end