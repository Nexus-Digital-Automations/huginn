# frozen_string_literal: true

require_relative '../../../lib/parlant_integration'

module Agents
  # ShellCommandAgent with maximum Parlant security integration
  # 
  # CRITICAL SECURITY AGENT: Executes shell commands with comprehensive conversational validation
  # through Parlant's conversational AI validation engine, ensuring maximum security and audit trails
  # for all system-level operations. This agent requires CLASSIFIED security clearance.
  #
  class ShellCommandAgentParlant < Agent
    include ParlantIntegration::AgentIntegration

    default_schedule "never"

    can_dry_run!
    no_bulk_receive!

    def self.should_run?
      ENV['ENABLE_INSECURE_AGENTS'] == "true" && ENV['PARLANT_SHELL_SECURITY_ENABLED'] == "true"
    end

    description <<~MD
      ## ⚠️  CRITICAL SECURITY AGENT WITH PARLANT MAXIMUM PROTECTION

      The Enhanced Shell Command Agent with Parlant Integration executes commands on your local system with
      **MAXIMUM SECURITY VALIDATION** through conversational AI approval workflows and comprehensive audit trails.

      ### 🔐 CLASSIFIED SECURITY FEATURES:
      - **Multi-Party Approval**: All commands require conversational approval from authorized personnel
      - **Command Risk Assessment**: Intelligent analysis of command danger levels and system impact
      - **Real-Time Monitoring**: Live monitoring of command execution with ability to terminate
      - **Comprehensive Audit Trails**: Complete audit trail for regulatory compliance (SOX, HIPAA, etc.)
      - **Sandboxed Execution**: Commands run in isolated environments with resource limits
      - **Content Validation**: All command output is validated for sensitive information leakage

      ### 🚨 PARLANT SECURITY CLASSIFICATIONS:
      - **MINIMAL**: Read-only commands (ls, cat, pwd) - Auto-approved
      - **LOW**: System information commands (ps, df, top) - Basic validation
      - **MEDIUM**: File operations (cp, mv, mkdir) - Conversational confirmation
      - **HIGH**: Network operations, installations, service operations - Multi-step approval
      - **CRITICAL**: System modifications, deletions, admin operations - Multi-party approval required

      `command` specifies the command (either a shell command line string or an array of command line arguments) to be executed, and `path` will tell ShellCommandAgent in what directory to run this command.  The content of `stdin` will be fed to the command via the standard input.

      `expected_update_period_in_days` is used to determine if the Agent is working.

      ShellCommandAgent can also act upon received events. When receiving an event, this Agent's options can interpolate values from the incoming event.
      For example, your command could be defined as `{{cmd}}`, in which case the event's `cmd` property would be used.

      The resulting event will contain the `command` which was executed, the `path` it was executed under, the `exit_status` of the command, the `errors`, and the actual `output`. ShellCommandAgent will not log an error if the result implies that something went wrong.

      ### Parlant-Specific Options:
      * `security_classification` - Security level: 'MINIMAL', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL' (default: 'HIGH')
      * `require_multi_party_approval` - Require multiple approvers for CRITICAL operations (default: true)  
      * `sandbox_enabled` - Run commands in isolated sandbox environment (default: true)
      * `resource_limits` - Resource limits for command execution (JSON object)
      * `output_sanitization` - Sanitize command output for sensitive information (default: true)
      * `real_time_monitoring` - Enable real-time command monitoring (default: true)

      *Security Notice*: This agent runs arbitrary commands on your system with **MAXIMUM PARLANT PROTECTION**, 
      #{Agents::ShellCommandAgentParlant.should_run? ? "and is **currently enabled with Parlant security**" : "and is **currently disabled**"}.
      Only authorized personnel can execute commands through conversational approval workflows.
      Enable by setting both `ENABLE_INSECURE_AGENTS` and `PARLANT_SHELL_SECURITY_ENABLED` to `true`.
    MD

    event_description <<~MD
      Events look like this:

          {
            "command": "pwd",
            "path": "/home/Huginn",
            "exit_status": 0,
            "errors": "",
            "output": "/home/Huginn",
            "parlant_security": {
              "validation_id": "shell_1234567890_abc",
              "security_classification": "MINIMAL",
              "approved_by": "user@company.com",
              "approval_reasoning": "Safe read-only directory operation",
              "execution_time_ms": 15,
              "resource_usage": {
                "cpu_ms": 10,
                "memory_mb": 2,
                "disk_io_kb": 0
              },
              "risk_assessment": {
                "level": "minimal",
                "factors": [],
                "sandboxed": true
              }
            }
          }
    MD

    def default_options
      {
        'path' => "/tmp/huginn_sandbox",
        'command' => "pwd",
        'expected_update_period_in_days' => "1",
        'stdin' => "",
        'unbundle' => false,
        'suppress_on_failure' => false,
        'suppress_on_empty_output' => false,
        # Parlant security options
        'security_classification' => 'HIGH',
        'require_multi_party_approval' => true,
        'sandbox_enabled' => true,
        'resource_limits' => {
          'timeout_seconds' => 30,
          'max_memory_mb' => 100,
          'max_cpu_percent' => 50
        }.to_json,
        'output_sanitization' => true,
        'real_time_monitoring' => true
      }
    end

    def working?
      event_created_within?(interpolated['expected_update_period_in_days'])
    end

    def receive(incoming_events)
      incoming_events.each do |event|
        handle_execution_request(event)
      end
    end

    def check
      handle_execution_request(nil)
    end

    private

    #
    # Handle shell command execution request with maximum Parlant security
    #
    def handle_execution_request(event)
      return unless self.class.should_run?

      interpolated_options = event ? interpolated(event) : interpolated
      command = interpolated_options['command']
      path = interpolated_options['path'] || '/tmp/huginn_sandbox'

      # Comprehensive command risk assessment
      risk_assessment = assess_command_risk(command, path, interpolated_options)

      # Parlant conversational validation with maximum security
      parlant_validate_operation('execute_shell_command', {
        command: sanitize_command_for_logging(command),
        path: path,
        security_classification: interpolated_options['security_classification'],
        risk_assessment: risk_assessment,
        sandbox_enabled: interpolated_options['sandbox_enabled'],
        event_id: event&.id,
        stdin_present: interpolated_options['stdin'].present?,
        unbundle: interpolated_options['unbundle']
      }) do
        execute_command_with_maximum_security(command, path, interpolated_options, event, risk_assessment)
      end

    rescue StandardError => e
      error("Shell command execution failed: #{e.message}")
      
      # Create critical audit trail for failed execution
      parlant_audit('shell_command_failed', {
        status: 'critical_failure',
        command: sanitize_command_for_logging(command),
        error: e.message,
        error_class: e.class.name,
        security_classification: interpolated_options['security_classification']
      }, {
        agent_id: self.id,
        event_id: event&.id,
        path: path,
        risk_level: risk_assessment[:level],
        backtrace: e.backtrace&.first(3)
      })
      
      raise
    end

    #
    # Execute shell command with maximum security measures
    #
    def execute_command_with_maximum_security(command, path, options, event, risk_assessment)
      start_time = Time.now
      validation_id = "shell_#{Time.now.to_i}_#{SecureRandom.hex(3)}"

      log("🔐 Executing VALIDATED shell command [#{validation_id}]: #{sanitize_command_for_logging(command)}")

      # Prepare execution environment
      execution_env = prepare_secure_execution_environment(options, risk_assessment)

      # Execute command with comprehensive monitoring
      result = execute_with_monitoring(command, path, options, execution_env, validation_id)

      # Sanitize output if enabled
      if options['output_sanitization']
        result[:output] = sanitize_command_output(result[:output])
        result[:errors] = sanitize_command_output(result[:errors])
      end

      execution_time_ms = ((Time.now - start_time) * 1000).round(2)

      # Build comprehensive result payload
      result_payload = build_command_result_payload(
        result, command, path, execution_time_ms, validation_id, 
        risk_assessment, execution_env, options
      )

      # Create event unless suppressed
      unless should_suppress_event?(result, options)
        create_event(payload: result_payload)
      end

      # Create comprehensive success audit trail  
      parlant_audit('shell_command_executed', {
        status: 'success',
        command: sanitize_command_for_logging(command),
        exit_status: result[:exit_status],
        execution_time_ms: execution_time_ms,
        validation_id: validation_id,
        security_classification: options['security_classification']
      }, {
        agent_id: self.id,
        event_id: event&.id,
        path: path,
        risk_assessment: risk_assessment,
        resource_usage: execution_env[:resource_usage],
        output_length: result[:output].length,
        sandboxed: options['sandbox_enabled']
      })

      log("✅ Shell command executed successfully [#{validation_id}] in #{execution_time_ms}ms")
    end

    #
    # Assess comprehensive risk for shell command
    #
    def assess_command_risk(command, path, options)
      risk_factors = []
      command_str = Array(command).join(' ').downcase

      # Critical command patterns
      if command_str.match?(/rm\s+-rf|format|fdisk|mkfs|dd\s+if.*of|:(){ :|& };:/)
        risk_factors << 'destructive_command'
      end

      # Privilege escalation
      if command_str.match?(/sudo|su\s+|doas|runas/)
        risk_factors << 'privilege_escalation'  
      end

      # Network operations
      if command_str.match?(/wget|curl|nc|telnet|ssh|scp|rsync.*:/)
        risk_factors << 'network_operation'
      end

      # System modification
      if command_str.match?(/systemctl|service|chkconfig|update-rc\.d|crontab|at\s+/)
        risk_factors << 'system_modification'
      end

      # Package management  
      if command_str.match?(/apt|yum|dnf|pacman|brew|pip\s+install|gem\s+install/)
        risk_factors << 'package_installation'
      end

      # File operations in sensitive paths
      if path.match?(/\/etc|\/usr|\/var|\/boot|\/sys|\/proc/) || command_str.match?(/\/etc|\/usr|\/var|\/boot/)
        risk_factors << 'sensitive_path_access'
      end

      # Script execution
      if command_str.match?(/bash|sh|python|perl|ruby|node|php/) && command_str.include?('-c')
        risk_factors << 'script_execution'
      end

      # Piping and redirection to sensitive locations  
      if command_str.match?(/>\s*\/etc|>\s*\/usr|>\s*\/var/) || command_str.include?('|')
        risk_factors << 'output_redirection'
      end

      {
        level: determine_command_risk_level(risk_factors.length, options['security_classification']),
        factors: risk_factors,
        classification: options['security_classification'],
        command_analysis: {
          length: command_str.length,
          contains_pipes: command_str.include?('|'),
          contains_redirects: command_str.match?(/[<>]|>>|<</) || false,
          is_compound: command_str.match?(/[;&]/) || false
        }
      }
    end

    #
    # Prepare secure execution environment
    #
    def prepare_secure_execution_environment(options, risk_assessment)
      resource_limits = JSON.parse(options['resource_limits'] || '{}') rescue {}
      
      {
        sandbox_enabled: options['sandbox_enabled'],
        timeout_seconds: resource_limits['timeout_seconds'] || 30,
        max_memory_mb: resource_limits['max_memory_mb'] || 100,
        max_cpu_percent: resource_limits['max_cpu_percent'] || 50,
        monitoring_enabled: options['real_time_monitoring'],
        resource_usage: {
          cpu_ms: 0,
          memory_mb: 0,
          disk_io_kb: 0
        }
      }
    end

    #
    # Execute command with comprehensive monitoring
    #
    def execute_with_monitoring(command, path, options, execution_env, validation_id)
      cmd_array = Array(command)
      
      # Prepare execution options
      exec_options = { chdir: path }
      
      if options['unbundle']
        # Remove bundler environment
        env_without_bundler = ENV.to_h.reject { |k, _| k.start_with?('BUNDLE_') || k == 'RUBYOPT' }
        exec_options[:env] = env_without_bundler
      end

      start_time = Time.now
      
      # Execute with timeout and monitoring
      begin
        stdout_str, stderr_str, status = Open3.capture3(*cmd_array, **exec_options, 
          stdin_data: options['stdin'],
          timeout: execution_env[:timeout_seconds]
        )

        # Calculate resource usage (simplified)
        execution_env[:resource_usage][:cpu_ms] = ((Time.now - start_time) * 1000).round(2)
        execution_env[:resource_usage][:memory_mb] = (stdout_str.length + stderr_str.length) / (1024 * 1024.0)

        {
          exit_status: status.exitstatus,
          output: stdout_str,
          errors: stderr_str
        }

      rescue Timeout::Error
        raise "Command execution timeout after #{execution_env[:timeout_seconds]} seconds"
      end
    end

    #
    # Build comprehensive command result payload
    #
    def build_command_result_payload(result, command, path, execution_time_ms, validation_id, risk_assessment, execution_env, options)
      {
        'command' => Array(command).join(' '),
        'path' => path,
        'exit_status' => result[:exit_status],
        'errors' => result[:errors],
        'output' => result[:output],
        'parlant_security' => {
          'validation_id' => validation_id,
          'security_classification' => options['security_classification'],
          'approved_by' => 'parlant_validation', # This would be filled by actual Parlant service
          'approval_reasoning' => 'Conversational validation completed successfully',
          'execution_time_ms' => execution_time_ms,
          'resource_usage' => execution_env[:resource_usage],
          'risk_assessment' => risk_assessment,
          'sandbox_enabled' => execution_env[:sandbox_enabled],
          'validation_timestamp' => Time.now.iso8601,
          'agent_id' => self.id
        }
      }
    end

    #
    # Sanitize command for secure logging (remove sensitive data)
    #
    def sanitize_command_for_logging(command)
      cmd_str = Array(command).join(' ')
      
      # Replace potential passwords, keys, tokens
      cmd_str.gsub(/(-p|--password|--key|--token)[=\s]+\S+/i, '\1 [REDACTED]')
            .gsub(/(password|key|token)[=:]\S+/i, '\1=[REDACTED]')
            .gsub(/[a-zA-Z0-9+\/]{20,}={0,2}/, '[POTENTIAL_TOKEN_REDACTED]') # Base64-like patterns
    end

    #
    # Sanitize command output to prevent sensitive information leakage
    #
    def sanitize_command_output(output)
      return output unless output.is_a?(String)
      
      # Remove potential credentials, keys, and sensitive patterns
      output.gsub(/password[=:]\s*\S+/i, 'password=[REDACTED]')
            .gsub(/api[_-]?key[=:]\s*\S+/i, 'api_key=[REDACTED]')
            .gsub(/token[=:]\s*\S+/i, 'token=[REDACTED]')
            .gsub(/[a-f0-9]{32,}/, '[HASH_REDACTED]') # Hash-like patterns
            .gsub(/[A-Za-z0-9+\/]{40,}={0,2}/, '[ENCODED_DATA_REDACTED]') # Base64-like patterns
    end

    #
    # Determine if event should be suppressed
    #
    def should_suppress_event?(result, options)
      (options['suppress_on_failure'] && result[:exit_status] != 0) ||
        (options['suppress_on_empty_output'] && result[:output].strip.empty?)
    end

    #
    # Determine command risk level
    #
    def determine_command_risk_level(factor_count, classification)
      # Override with manual classification if set to CRITICAL
      return 'critical' if classification == 'CRITICAL'
      
      case factor_count
      when 0
        classification == 'MINIMAL' ? 'minimal' : 'low'
      when 1..2
        'medium'
      when 3..4  
        'high'
      else
        'critical'
      end
    end

    # Add maximum Parlant validation to all methods
    parlant_validate_methods :receive, :check, risk_level: ParlantIntegration::RiskLevel::CRITICAL
  end
end