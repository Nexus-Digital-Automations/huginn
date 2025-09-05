# frozen_string_literal: true

module QualityGates
  module Validators
    # Base class for all quality gate validators
    # Provides common interface and functionality for validation operations
    class BaseValidator
      attr_reader :gate_config, :execution_context, :gate_name

      def initialize(gate_config, execution_context)
        @gate_config = gate_config || {}
        @execution_context = execution_context || {}
        @gate_name = extract_gate_name
        @start_time = nil
        @metrics = {}
        
        validate_configuration!
      end

      # Main validation method - must be implemented by subclasses
      def validate
        raise NotImplementedError, "#{self.class} must implement #validate"
      end

      # Check if validator is available for execution
      def available?
        required_commands_available? && required_files_exist?
      end

      # Get validator description
      def description
        @gate_config[:description] || "#{self.class.name} validation"
      end

      # Get validator timeout
      def timeout
        @gate_config[:timeout] || 300
      end

      protected

      # Template method for validation execution
      def execute_validation
        @start_time = Time.current
        log_info("Starting #{gate_name} validation")

        begin
          result = perform_validation
          
          if result.success?
            log_info("#{gate_name} validation passed", { 
              execution_time: execution_time,
              metrics_collected: @metrics.keys.count
            })
          else
            log_warning("#{gate_name} validation failed", {
              execution_time: execution_time,
              error_count: result.errors&.count || 0
            })
          end

          result
        rescue StandardError => e
          log_error("#{gate_name} validation error", {
            error: e.message,
            execution_time: execution_time
          })
          
          ValidationResult.new(
            success: false,
            errors: [e.message],
            details: { exception: e.class.name, backtrace: e.backtrace&.first(5) },
            metrics: @metrics
          )
        end
      end

      # Perform the actual validation - implement in subclasses
      def perform_validation
        raise NotImplementedError, "#{self.class} must implement #perform_validation"
      end

      # Add metric to collection
      def add_metric(key, value, description = nil)
        @metrics[key] = {
          value: value,
          description: description,
          collected_at: Time.current
        }
      end

      # Execute shell command with timeout and error handling
      def execute_command(command, timeout: self.timeout, working_dir: nil)
        log_info("Executing command", { command: sanitize_command(command), timeout: timeout })
        
        full_command = build_full_command(command, working_dir, timeout)
        
        output = `#{full_command} 2>&1`
        exit_status = $?.exitstatus
        
        CommandResult.new(
          command: command,
          output: output,
          exit_status: exit_status,
          success: exit_status == 0,
          execution_time: 0 # Would need to time the actual execution
        )
      end

      # Check if required commands are available
      def required_commands_available?
        required_commands.all? { |cmd| command_available?(cmd) }
      end

      # Check if required files exist
      def required_files_exist?
        required_files.all? { |file| File.exist?(resolve_path(file)) }
      end

      # Get list of required commands - override in subclasses
      def required_commands
        []
      end

      # Get list of required files - override in subclasses  
      def required_files
        []
      end

      # Check if command is available in PATH
      def command_available?(command)
        system("which #{command} > /dev/null 2>&1")
      end

      # Resolve path relative to project root
      def resolve_path(path)
        if File.absolute?(path)
          path
        else
          File.join(project_root, path)
        end
      end

      # Get project root directory
      def project_root
        @execution_context[:project_path] || Rails.root.to_s
      end

      # Get execution time since start
      def execution_time
        return 0 unless @start_time
        Time.current - @start_time
      end

      # Extract gate name from class or config
      def extract_gate_name
        @gate_config[:gate_name] || 
        self.class.name.demodulize.underscore.gsub('_validator', '').to_sym
      end

      # Validate validator configuration
      def validate_configuration!
        # Base validation - subclasses should call super and add their own
        unless @gate_config.is_a?(Hash)
          raise ArgumentError, "Gate configuration must be a hash"
        end
      end

      # Build full command with working directory and timeout
      def build_full_command(command, working_dir, command_timeout)
        cmd_parts = []
        
        # Add timeout wrapper
        cmd_parts << "timeout #{command_timeout}s" if command_timeout > 0
        
        # Add working directory change
        if working_dir
          cmd_parts << "cd #{Shellwords.escape(working_dir)} &&"
        end
        
        cmd_parts << command
        cmd_parts.join(' ')
      end

      # Sanitize command for logging (remove sensitive data)
      def sanitize_command(command)
        # Remove tokens, passwords, keys, etc.
        sanitized = command.dup
        sanitized.gsub!(/--?(?:token|password|key|secret)[\s=]\S+/i, '--\1=***')
        sanitized.gsub!(/(https?:\/\/)[^:]+:[^@]+@/, '\1***:***@')
        sanitized
      end

      # Parse threshold configuration
      def get_threshold(key, default = nil)
        thresholds = @gate_config[:thresholds] || {}
        thresholds[key] || default
      end

      # Check if value meets threshold requirement
      def meets_threshold?(value, threshold_key, comparison = :<=)
        threshold = get_threshold(threshold_key)
        return true unless threshold

        case comparison
        when :<= then value <= threshold
        when :>= then value >= threshold
        when :< then value < threshold
        when :> then value > threshold
        when :== then value == threshold
        else false
        end
      end

      # Logging helpers
      def log_info(message, data = {})
        Rails.logger&.info("#{self.class.name} - #{message}: #{data}")
      end

      def log_warning(message, data = {})
        Rails.logger&.warn("#{self.class.name} - #{message}: #{data}")
      end

      def log_error(message, data = {})
        Rails.logger&.error("#{self.class.name} - #{message}: #{data}")
      end
    end

    # Result object for validation operations
    class ValidationResult
      attr_reader :success, :errors, :warnings, :details, :metrics, :recommendations

      def initialize(success:, errors: [], warnings: [], details: {}, metrics: {}, recommendations: [])
        @success = success
        @errors = errors || []
        @warnings = warnings || []
        @details = details || {}
        @metrics = metrics || {}
        @recommendations = recommendations || []
      end

      def success?
        @success == true
      end

      def failed?
        !success?
      end

      def has_errors?
        @errors.any?
      end

      def has_warnings?
        @warnings.any?
      end

      def primary_error
        @errors.first
      end

      def error_count
        @errors.count
      end

      def warning_count
        @warnings.count
      end
    end

    # Result object for command execution
    class CommandResult
      attr_reader :command, :output, :exit_status, :success, :execution_time

      def initialize(command:, output: '', exit_status: 0, success: true, execution_time: 0)
        @command = command
        @output = output || ''
        @exit_status = exit_status
        @success = success
        @execution_time = execution_time
      end

      def failed?
        !@success
      end

      def lines
        @output.lines.map(&:chomp)
      end

      def stderr_lines
        # Would need to capture stderr separately
        []
      end
    end
  end
end