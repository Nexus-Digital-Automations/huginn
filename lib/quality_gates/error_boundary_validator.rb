# frozen_string_literal: true

require_relative 'utils'

module QualityGates
  # Validates error boundary patterns and graceful failure handling
  # Ensures robust error handling throughout the application
  class ErrorBoundaryValidator
    include Utils

    attr_reader :project_root, :logger

    # Common error handling patterns to detect
    ERROR_PATTERNS = {
      rescue_clause: /rescue\s+(\w+(?:::\w+)*)?(?:\s*=>\s*\w+)?\s*$/,
      ensure_block: /ensure\s*$/,
      raise_statement: /raise\s+/,
      circuit_breaker: /circuit.*?breaker|breaker.*?circuit/i,
      timeout_handling: /timeout|Timeout\.|time.*?out/i,
      retry_logic: /retry|retries|attempt/i,
      fallback_method: /fallback|fall.*?back/i,
      error_boundary: /error.*?boundary|boundary.*?error/i
    }.freeze

    def initialize(project_root = Rails.root)
      @project_root = Pathname.new(project_root)
      @logger = setup_logger
    end

    # Main validation entry point
    # @return [ValidationResult] Results of error boundary validation
    def validate
      log_operation_start('Error boundary validation')
      start_time = Time.now

      errors = []
      warnings = []
      details = {
        files_analyzed: 0,
        error_patterns: {},
        circuit_breakers: [],
        timeout_configurations: [],
        retry_mechanisms: [],
        fallback_strategies: []
      }

      # Analyze Ruby files for error handling patterns
      ruby_files = find_ruby_files
      ruby_files.each do |file_path|
        file_result = validate_file_error_handling(file_path)
        details[:files_analyzed] += 1
        
        merge_file_results(file_result, errors, warnings, details, file_path)
      end

      # Validate Rails-specific error handling
      if rails_application?
        rails_result = validate_rails_error_handling
        merge_results(rails_result, errors, warnings, details, 'rails_error_handling')
      end

      # Validate Huginn Agent error handling
      agent_result = validate_agent_error_handling
      merge_results(agent_result, errors, warnings, details, 'agent_error_handling')

      # Validate infrastructure error handling
      infra_result = validate_infrastructure_error_handling
      merge_results(infra_result, errors, warnings, details, 'infrastructure_error_handling')

      result = ValidationResult.new(
        passed: errors.empty?,
        errors: errors,
        warnings: warnings,
        details: details
      )

      log_validation_completion('Error boundary validation', start_time, result)
      result
    end

    private

    def setup_logger
      Logger.new($stdout).tap do |logger|
        logger.level = Logger::INFO
        logger.formatter = proc do |severity, datetime, progname, msg|
          "[#{datetime.strftime('%H:%M:%S')}] [ErrorBoundaryValidator] #{severity}: #{msg}\n"
        end
      end
    end

    def log_operation_start(operation)
      logger.info("🛡️  Starting: #{operation}")
    end

    def log_validation_completion(operation, start_time, result)
      duration = ((Time.now - start_time) * 1000).round(2)
      status = result.passed? ? '✅ PASSED' : '❌ FAILED'
      logger.info("🏁 Completed: #{operation} in #{duration}ms - #{status}")
    end

    # Find all Ruby files in the project
    def find_ruby_files
      patterns = %w[app/**/*.rb lib/**/*.rb config/**/*.rb]
      patterns.flat_map { |pattern| Dir.glob(project_root.join(pattern)) }
               .map { |path| Pathname.new(path) }
               .select(&:file?)
    end

    # Check if this is a Rails application
    def rails_application?
      project_root.join('config/application.rb').exist?
    end

    # Validate error handling in a single file
    def validate_file_error_handling(file_path)
      content = file_path.read
      errors = []
      warnings = []
      details = {
        error_patterns: analyze_error_patterns(content),
        method_error_coverage: analyze_method_error_coverage(content),
        exception_specificity: analyze_exception_specificity(content),
        circuit_breaker_usage: detect_circuit_breakers(content),
        timeout_handling: detect_timeout_handling(content),
        retry_mechanisms: detect_retry_mechanisms(content)
      }

      validate_error_handling_quality(details, errors, warnings)

      { errors: errors, warnings: warnings, details: details }
    end

    # Analyze error handling patterns in file content
    def analyze_error_patterns(content)
      patterns = {}
      ERROR_PATTERNS.each do |name, regex|
        matches = content.scan(regex).length
        patterns[name] = matches if matches > 0
      end
      patterns
    end

    # Analyze error coverage for methods
    def analyze_method_error_coverage(content)
      methods = content.scan(/def\s+(\w+)/)
      covered_methods = []
      
      methods.each do |method_match|
        method_name = method_match[0]
        method_content = extract_method_content(content, method_name)
        
        if method_content.match?(/rescue|ensure/)
          covered_methods << method_name
        end
      end

      {
        total_methods: methods.length,
        covered_methods: covered_methods.length,
        coverage_percentage: methods.empty? ? 0 : (covered_methods.length.to_f / methods.length * 100).round(2)
      }
    end

    # Extract method content for analysis
    def extract_method_content(content, method_name)
      # Simple extraction - find method definition and content until next def or end
      method_start = content.index("def #{method_name}")
      return '' unless method_start

      method_section = content[method_start..]
      
      # Find the end of this method (naive approach)
      lines = method_section.lines
      indent_level = lines[0]&.match(/^(\s*)/)[1].length || 0
      
      method_lines = [lines[0]]
      lines[1..].each do |line|
        current_indent = line.match(/^(\s*)/)[1].length
        if line.strip.start_with?('def ') && current_indent <= indent_level
          break
        end
        method_lines << line
      end

      method_lines.join
    end

    # Analyze exception handling specificity
    def analyze_exception_specificity(content)
      rescue_clauses = content.scan(/rescue\s+(\w+(?:::\w+)*)/)
      generic_rescues = content.scan(/rescue\s*$/).length
      specific_rescues = rescue_clauses.length

      {
        generic_rescues: generic_rescues,
        specific_rescues: specific_rescues,
        exception_types: rescue_clauses.flatten.uniq,
        specificity_ratio: (generic_rescues + specific_rescues).zero? ? 0 : 
                          (specific_rescues.to_f / (generic_rescues + specific_rescues) * 100).round(2)
      }
    end

    # Detect circuit breaker patterns
    def detect_circuit_breakers(content)
      breakers = []
      
      # Look for circuit breaker implementations
      if content.match?(/circuit.*?breaker/i)
        breakers << {
          type: 'circuit_breaker_pattern',
          lines: content.lines.each_with_index
                       .select { |line, _| line.match?(/circuit.*?breaker/i) }
                       .map { |_, index| index + 1 }
        }
      end

      # Look for manual failure detection
      if content.include?('failure_count') || content.include?('error_threshold')
        breakers << {
          type: 'manual_circuit_breaker',
          indicators: ['failure_count', 'error_threshold'].select { |term| content.include?(term) }
        }
      end

      breakers
    end

    # Detect timeout handling patterns
    def detect_timeout_handling(content)
      timeouts = []

      # Standard timeout usage
      timeout_matches = content.scan(/Timeout\.timeout\(([^)]+)\)|timeout.*?(\d+)/)
      timeouts.concat(timeout_matches.map do |match|
        {
          type: 'timeout_block',
          duration: match.compact.first,
          line: content.lines.find_index { |line| line.include?(match.compact.first) }&.+(1)
        }
      end)

      # HTTP client timeouts
      %w[read_timeout open_timeout].each do |timeout_type|
        if content.include?(timeout_type)
          timeouts << {
            type: timeout_type,
            context: 'http_client'
          }
        end
      end

      timeouts
    end

    # Detect retry mechanisms
    def detect_retry_mechanisms(content)
      retries = []

      # Standard retry blocks
      retry_matches = content.scan(/retry|retries\s*[:=]\s*(\d+)/)
      retries.concat(retry_matches.map do |match|
        {
          type: 'retry_block',
          max_retries: match[0] || 'default'
        }
      end)

      # Exponential backoff
      if content.match?(/sleep.*?\*|backoff|exponential/i)
        retries << {
          type: 'exponential_backoff',
          detected: true
        }
      end

      retries
    end

    # Validate error handling quality
    def validate_error_handling_quality(details, errors, warnings)
      # Check error coverage
      coverage = details[:method_error_coverage][:coverage_percentage]
      if coverage < 30
        errors << "Low error handling coverage: #{coverage}% of methods have error handling"
      elsif coverage < 60
        warnings << "Moderate error handling coverage: #{coverage}% of methods have error handling"
      end

      # Check exception specificity
      specificity = details[:exception_specificity][:specificity_ratio]
      if specificity < 50
        warnings << "Low exception specificity: #{specificity}% of rescue clauses specify exception types"
      end

      # Check for missing timeout handling in network operations
      if details[:error_patterns][:timeout_handling].to_i.zero? && 
         details[:error_patterns].any? { |k, _| k.to_s.include?('http') }
        warnings << "Network operations detected but no timeout handling found"
      end
    end

    # Validate Rails-specific error handling
    def validate_rails_error_handling
      errors = []
      warnings = []
      details = {
        rescue_from_usage: check_rescue_from_usage,
        error_pages: check_error_pages,
        exception_notification: check_exception_notification,
        application_controller_errors: check_application_controller_errors
      }

      # Validate rescue_from usage in controllers
      if details[:rescue_from_usage][:count].zero?
        warnings << "No rescue_from statements found in controllers - consider global error handling"
      end

      # Check for custom error pages
      unless details[:error_pages][:has_custom_pages]
        warnings << "Default error pages detected - consider custom error pages for better UX"
      end

      { errors: errors, warnings: warnings, details: details }
    end

    # Check rescue_from usage in controllers
    def check_rescue_from_usage
      controller_files = Dir.glob(project_root.join('app/controllers/**/*.rb'))
      rescue_from_count = 0
      
      controller_files.each do |file|
        content = File.read(file)
        rescue_from_count += content.scan(/rescue_from/).length
      end

      {
        count: rescue_from_count,
        controllers_checked: controller_files.length
      }
    end

    # Check for custom error pages
    def check_error_pages
      error_files = %w[404.html 422.html 500.html].map do |file|
        project_root.join('public', file)
      end

      has_custom = error_files.any? do |file_path|
        file_path.exist? && File.read(file_path).length > 1000 # Assume custom if > 1KB
      end

      {
        has_custom_pages: has_custom,
        error_files_present: error_files.select(&:exist?).map(&:basename)
      }
    end

    # Check for exception notification setup
    def check_exception_notification
      gemfile_path = project_root.join('Gemfile')
      initializer_path = project_root.join('config/initializers/exception_notification.rb')

      has_gem = gemfile_path.exist? && File.read(gemfile_path).include?('exception_notification')
      has_config = initializer_path.exist?

      {
        gem_installed: has_gem,
        configured: has_config
      }
    end

    # Check ApplicationController error handling
    def check_application_controller_errors
      app_controller = project_root.join('app/controllers/application_controller.rb')
      return { exists: false } unless app_controller.exist?

      content = File.read(app_controller)
      
      {
        exists: true,
        has_rescue_from: content.include?('rescue_from'),
        has_error_handlers: content.match?(/def.*?error|handle.*?error/),
        protect_from_forgery: content.include?('protect_from_forgery')
      }
    end

    # Validate Agent-specific error handling
    def validate_agent_error_handling
      errors = []
      warnings = []
      details = { agents_analyzed: 0, error_handling_patterns: {} }

      agent_files = Dir.glob(project_root.join('app/models/agents/*.rb'))
      
      agent_files.each do |file_path|
        content = File.read(file_path)
        next unless content.include?('< Agent')

        details[:agents_analyzed] += 1
        agent_name = File.basename(file_path, '.rb')

        # Check for proper error handling in Agent methods
        error_handling = analyze_agent_error_handling(content)
        details[:error_handling_patterns][agent_name] = error_handling

        # Validate critical Agent methods have error handling
        validate_agent_critical_methods(content, agent_name, errors, warnings)
      end

      { errors: errors, warnings: warnings, details: details }
    end

    # Analyze error handling in Agent classes
    def analyze_agent_error_handling(content)
      {
        check_method_errors: method_has_error_handling(content, 'check'),
        receive_method_errors: method_has_error_handling(content, 'receive'),
        working_method_errors: method_has_error_handling(content, 'working?'),
        event_creation_errors: content.include?('create_event') && 
                              content.match?(/create_event.*?rescue|rescue.*?create_event/m)
      }
    end

    # Check if specific method has error handling
    def method_has_error_handling(content, method_name)
      method_content = extract_method_content(content, method_name)
      method_content.match?(/rescue|ensure/)
    end

    # Validate critical Agent methods have proper error handling
    def validate_agent_critical_methods(content, agent_name, errors, warnings)
      critical_methods = %w[check receive validate_options]
      
      critical_methods.each do |method|
        next unless content.include?("def #{method}")
        
        unless method_has_error_handling(content, method)
          warnings << "Agent #{agent_name}: #{method} method lacks error handling"
        end
      end

      # Check for proper error logging
      unless content.match?(/error.*?log|log.*?error/i)
        warnings << "Agent #{agent_name}: No error logging detected"
      end
    end

    # Validate infrastructure error handling
    def validate_infrastructure_error_handling
      errors = []
      warnings = []
      details = {
        database_error_handling: check_database_error_handling,
        job_error_handling: check_job_error_handling,
        external_service_handling: check_external_service_handling
      }

      # Database connection and query error handling
      unless details[:database_error_handling][:has_connection_handling]
        warnings << "No database connection error handling detected"
      end

      # Background job error handling
      unless details[:job_error_handling][:has_retry_configuration]
        warnings << "Background jobs lack retry configuration"
      end

      { errors: errors, warnings: warnings, details: details }
    end

    # Check database error handling patterns
    def check_database_error_handling
      config_files = Dir.glob(project_root.join('config/**/*.rb'))
      model_files = Dir.glob(project_root.join('app/models/**/*.rb'))
      
      all_files = config_files + model_files
      has_connection_handling = all_files.any? do |file|
        content = File.read(file)
        content.match?(/ActiveRecord.*?Error|rescue.*?ActiveRecord/i)
      end

      has_transaction_handling = all_files.any? do |file|
        content = File.read(file)
        content.include?('transaction') && content.match?(/rescue|rollback/)
      end

      {
        has_connection_handling: has_connection_handling,
        has_transaction_handling: has_transaction_handling
      }
    end

    # Check background job error handling
    def check_job_error_handling
      job_files = Dir.glob(project_root.join('app/jobs/**/*.rb'))
      
      has_retry_configuration = job_files.any? do |file|
        content = File.read(file)
        content.match?(/retry_on|discard_on|queue_with_priority/)
      end

      has_error_handling = job_files.any? do |file|
        content = File.read(file)
        content.match?(/rescue|ensure/)
      end

      {
        jobs_analyzed: job_files.length,
        has_retry_configuration: has_retry_configuration,
        has_error_handling: has_error_handling
      }
    end

    # Check external service error handling
    def check_external_service_handling
      all_files = Dir.glob(project_root.join('{app,lib}/**/*.rb'))
      
      has_http_timeouts = all_files.any? do |file|
        content = File.read(file)
        content.match?(/timeout|read_timeout|open_timeout/i)
      end

      has_circuit_breakers = all_files.any? do |file|
        content = File.read(file)
        content.match?(/circuit.*?breaker|breaker.*?circuit/i)
      end

      has_retry_logic = all_files.any? do |file|
        content = File.read(file)
        content.match?(/retry|retries|attempt/i)
      end

      {
        has_http_timeouts: has_http_timeouts,
        has_circuit_breakers: has_circuit_breakers,
        has_retry_logic: has_retry_logic
      }
    end

    # Helper methods for merging results
    def merge_file_results(file_result, errors, warnings, details, file_path)
      relative_path = file_path.relative_path_from(project_root).to_s
      
      errors.concat(file_result[:errors].map { |e| "#{relative_path}: #{e}" })
      warnings.concat(file_result[:warnings].map { |w| "#{relative_path}: #{w}" })
      
      details[:error_patterns][relative_path] = file_result[:details]
    end

    def merge_results(result, errors, warnings, details, key)
      errors.concat(result[:errors])
      warnings.concat(result[:warnings])
      details[key] = result[:details]
    end
  end
end