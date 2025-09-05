# frozen_string_literal: true

require_relative 'utils'

module QualityGates
  # Validates interface-first development patterns in Ruby classes
  # Ensures public APIs are well-defined before implementation details
  class InterfaceValidator
    include Utils

    attr_reader :project_root, :logger

    def initialize(project_root = Rails.root)
      @project_root = Pathname.new(project_root)
      @logger = setup_logger
    end

    # Main validation entry point
    # @return [ValidationResult] Results of interface validation
    def validate
      log_operation_start('Interface-first validation')
      start_time = Time.now

      errors = []
      warnings = []
      details = {}

      # Analyze Ruby classes and modules
      ruby_files = find_ruby_files
      ruby_files.each do |file_path|
        file_result = validate_file_interfaces(file_path)
        
        if file_result[:errors].any?
          errors.concat(file_result[:errors].map { |e| "#{file_path.relative_path_from(project_root)}: #{e}" })
        end
        
        if file_result[:warnings].any?
          warnings.concat(file_result[:warnings].map { |w| "#{file_path.relative_path_from(project_root)}: #{w}" })
        end

        details[file_path.relative_path_from(project_root).to_s] = file_result[:details]
      end

      # Validate API endpoints if Rails application
      if rails_application?
        api_result = validate_api_endpoints
        errors.concat(api_result[:errors])
        warnings.concat(api_result[:warnings])
        details[:api_endpoints] = api_result[:details]
      end

      # Validate Agent interface patterns (Huginn-specific)
      agent_result = validate_agent_interfaces
      errors.concat(agent_result[:errors])
      warnings.concat(agent_result[:warnings])
      details[:agent_interfaces] = agent_result[:details]

      result = ValidationResult.new(
        passed: errors.empty?,
        errors: errors,
        warnings: warnings,
        details: details
      )

      log_validation_completion('Interface validation', start_time, result)
      result
    end

    # Validate public interface compliance for specific file
    # @param file_path [Pathname] Path to Ruby file
    def validate_file_interfaces(file_path)
      log_operation_step("Validating interfaces in #{file_path.basename}")
      
      content = file_path.read
      errors = []
      warnings = []
      details = {
        classes: [],
        modules: [],
        public_methods: [],
        private_methods: [],
        interface_score: 0
      }

      # Parse class and module definitions
      class_matches = content.scan(/^\s*class\s+(\w+)(?:\s*<\s*(\w+(?:::\w+)*))?\s*$/)
      module_matches = content.scan(/^\s*module\s+(\w+)\s*$/)

      details[:classes] = class_matches.map { |name, parent| { name: name, parent: parent } }
      details[:modules] = module_matches.map { |name| { name: name } }

      # Validate each class/module
      (class_matches + module_matches.map { |name| [name, nil] }).each do |name, parent|
        interface_result = validate_class_interface(content, name)
        
        errors.concat(interface_result[:errors])
        warnings.concat(interface_result[:warnings])
        
        details[:public_methods].concat(interface_result[:public_methods])
        details[:private_methods].concat(interface_result[:private_methods])
      end

      # Calculate interface quality score
      details[:interface_score] = calculate_interface_score(details)

      # Add interface-specific validations
      validate_interface_patterns(content, errors, warnings, details)

      { errors: errors, warnings: warnings, details: details }
    end

    private

    def setup_logger
      Logger.new($stdout).tap do |logger|
        logger.level = Logger::INFO
        logger.formatter = proc do |severity, datetime, progname, msg|
          "[#{datetime.strftime('%H:%M:%S')}] [InterfaceValidator] #{severity}: #{msg}\n"
        end
      end
    end

    def log_operation_start(operation)
      logger.info("🔍 Starting: #{operation}")
    end

    def log_operation_step(step)
      logger.info("  ⚙️  #{step}")
    end

    def log_validation_completion(operation, start_time, result)
      duration = ((Time.now - start_time) * 1000).round(2)
      status = result.passed? ? '✅ PASSED' : '❌ FAILED'
      logger.info("🏁 Completed: #{operation} in #{duration}ms - #{status}")
    end

    # Find all Ruby files in the project
    def find_ruby_files
      patterns = %w[app/**/*.rb lib/**/*.rb]
      patterns.flat_map { |pattern| Dir.glob(project_root.join(pattern)) }
               .map { |path| Pathname.new(path) }
               .select(&:file?)
    end

    # Check if this is a Rails application
    def rails_application?
      project_root.join('config/application.rb').exist? && defined?(Rails)
    end

    # Validate interface patterns within class content
    def validate_class_interface(content, class_name)
      errors = []
      warnings = []
      public_methods = []
      private_methods = []

      # Extract method definitions
      method_matches = content.scan(/^\s*def\s+(self\.)?(\w+)(\(.*?\))?\s*$/)
      
      # Categorize methods based on visibility
      in_private_section = false
      in_protected_section = false
      
      content.lines.each_with_index do |line, index|
        line = line.strip
        
        # Track visibility sections
        in_private_section = true if line == 'private'
        in_protected_section = true if line == 'protected'
        in_private_section = in_protected_section = false if line.match?(/^\s*public\s*$/)
        
        # Identify method definitions
        if (match = line.match(/^\s*def\s+(self\.)?(\w+)(\(.*?\))?\s*$/))
          method_info = {
            name: match[2],
            class_method: !match[1].nil?,
            parameters: match[3] || '()',
            line_number: index + 1,
            visibility: visibility_for_context(in_private_section, in_protected_section)
          }
          
          if in_private_section || in_protected_section
            private_methods << method_info
          else
            public_methods << method_info
          end
        end
      end

      # Validate interface design patterns
      validate_method_interfaces(public_methods, errors, warnings)
      validate_private_method_organization(private_methods, errors, warnings)

      {
        errors: errors,
        warnings: warnings,
        public_methods: public_methods,
        private_methods: private_methods
      }
    end

    # Determine method visibility based on context
    def visibility_for_context(in_private, in_protected)
      return 'private' if in_private
      return 'protected' if in_protected
      'public'
    end

    # Validate public method interface design
    def validate_method_interfaces(public_methods, errors, warnings)
      public_methods.each do |method|
        # Check for clear parameter definitions
        if method[:parameters] == '()'
          # Methods without parameters are acceptable
        elsif method[:parameters].include?('*')
          warnings << "Method '#{method[:name]}' uses variadic parameters - consider explicit parameters for clarity"
        end

        # Check for conventional naming
        unless method[:name].match?(/\A[a-z_]\w*[?!]?\z/)
          errors << "Method '#{method[:name]}' does not follow Ruby naming conventions"
        end

        # Check for overly complex method signatures
        param_count = method[:parameters].scan(/\w+:/).count + method[:parameters].scan(/,\s*\w+/).count
        if param_count > 5
          warnings << "Method '#{method[:name]}' has #{param_count} parameters - consider parameter object pattern"
        end
      end

      # Check for missing essential methods
      method_names = public_methods.map { |m| m[:name] }
      
      if method_names.any? { |name| name.include?('initialize') } && 
         !method_names.include?('to_s')
        warnings << "Class has initializer but no custom to_s method - consider adding for better debugging"
      end
    end

    # Validate private method organization
    def validate_private_method_organization(private_methods, errors, warnings)
      if private_methods.empty?
        warnings << "No private methods found - consider if internal logic should be extracted"
      elsif private_methods.length > 10
        warnings << "#{private_methods.length} private methods found - consider breaking into multiple classes"
      end
    end

    # Validate interface design patterns in the code
    def validate_interface_patterns(content, errors, warnings, details)
      # Check for dependency injection patterns
      unless content.include?('initialize') && content.match?(/def initialize.*?\n.*?@\w+.*?=/m)
        warnings << "No dependency injection detected - consider injecting dependencies via constructor"
      end

      # Check for factory method patterns where appropriate
      if content.include?('class') && content.scan(/def self\.\w+/).length > 3
        details[:factory_methods] = content.scan(/def (self\.\w+)/).flatten
      end

      # Validate interface segregation
      public_method_count = details[:public_methods].length
      if public_method_count > 12
        warnings << "#{public_method_count} public methods - consider interface segregation principle"
      end

      # Check for command/query separation
      query_methods = details[:public_methods].select { |m| m[:name].end_with?('?') }
      command_methods = details[:public_methods].reject { |m| m[:name].end_with?('?') }
      
      if query_methods.empty? && command_methods.length > 3
        warnings << "No query methods found - consider command/query separation"
      end
    end

    # Calculate interface quality score
    def calculate_interface_score(details)
      score = 100

      # Deduct for interface violations
      score -= details[:classes].empty? && details[:modules].empty? ? 20 : 0
      score -= details[:public_methods].empty? ? 15 : 0
      score -= details[:public_methods].length > 10 ? 10 : 0
      score -= details[:private_methods].empty? ? 5 : 0

      [score, 0].max
    end

    # Validate Rails API endpoints
    def validate_api_endpoints
      errors = []
      warnings = []
      details = { controllers: [], routes: [] }

      # Find controller files
      controller_files = Dir.glob(project_root.join('app/controllers/**/*.rb'))
      
      controller_files.each do |file_path|
        content = File.read(file_path)
        controller_name = File.basename(file_path, '.rb')
        
        # Check for proper API structure
        if content.include?('ApplicationController')
          details[:controllers] << {
            name: controller_name,
            actions: extract_controller_actions(content),
            api_versioned: content.include?('Api::') || content.include?('API::')
          }
        end
      end

      # Check routes configuration
      routes_file = project_root.join('config/routes.rb')
      if routes_file.exist?
        routes_content = routes_file.read
        details[:routes] = extract_routes_info(routes_content)
        
        # Validate API versioning
        unless routes_content.include?('namespace :api') || routes_content.include?('scope :api')
          warnings << "No API namespace detected in routes - consider API versioning strategy"
        end
      end

      { errors: errors, warnings: warnings, details: details }
    end

    # Extract controller actions from content
    def extract_controller_actions(content)
      content.scan(/def (\w+)/).flatten.reject { |action| %w[private protected].include?(action) }
    end

    # Extract routes information
    def extract_routes_info(routes_content)
      routes = {
        resources: routes_content.scan(/resources? :(\w+)/).flatten,
        namespaces: routes_content.scan(/namespace :(\w+)/).flatten,
        custom_routes: routes_content.scan(/(?:get|post|put|patch|delete) ['"](.+?)['"]/).flatten
      }
      routes
    end

    # Validate Huginn Agent interfaces
    def validate_agent_interfaces
      errors = []
      warnings = []
      details = { agents: [], interface_compliance: {} }

      # Find Agent classes
      agent_files = Dir.glob(project_root.join('app/models/agents/*.rb'))
      
      agent_files.each do |file_path|
        content = File.read(file_path)
        agent_name = File.basename(file_path, '.rb')
        
        next unless content.include?('< Agent')

        agent_info = validate_agent_interface_compliance(content, agent_name)
        details[:agents] << agent_info[:details]
        
        errors.concat(agent_info[:errors].map { |e| "#{agent_name}: #{e}" })
        warnings.concat(agent_info[:warnings].map { |w| "#{agent_name}: #{w}" })
      end

      { errors: errors, warnings: warnings, details: details }
    end

    # Validate individual Agent class interface compliance
    def validate_agent_interface_compliance(content, agent_name)
      errors = []
      warnings = []
      details = {
        name: agent_name,
        has_description: content.include?('description'),
        has_event_description: content.include?('event_description'),
        implements_check: content.include?('def check'),
        implements_receive: content.include?('def receive'),
        implements_validate_options: content.include?('def validate_options'),
        default_options_defined: content.include?('def default_options')
      }

      # Required interface methods for Agents
      errors << "Missing 'description' class method" unless details[:has_description]
      
      # Check for proper method implementations
      unless details[:implements_check] || details[:implements_receive]
        errors << "Agent must implement either 'check' or 'receive' method"
      end
      
      unless details[:implements_validate_options]
        warnings << "Missing 'validate_options' method - consider adding for better error handling"
      end
      
      unless details[:default_options_defined]
        warnings << "Missing 'default_options' method - consider providing sensible defaults"
      end

      # Check for proper event emission patterns
      unless content.include?('create_event')
        warnings << "No event creation detected - ensure agent emits events when appropriate"
      end

      { errors: errors, warnings: warnings, details: details }
    end
  end
end