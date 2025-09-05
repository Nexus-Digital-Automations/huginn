# frozen_string_literal: true

require_relative 'utils'

module QualityGates
  # Validates incremental integration patterns for testable, deployable increments
  # Ensures features are built in deployable stages with proper integration points
  class IntegrationValidator
    include Utils

    attr_reader :project_root, :logger

    def initialize(project_root = Rails.root)
      @project_root = Pathname.new(project_root)
      @logger = setup_logger
    end

    # Main validation entry point
    # @return [ValidationResult] Results of integration validation
    def validate
      log_operation_start('Incremental integration validation')
      start_time = Time.now

      errors = []
      warnings = []
      details = {
        feature_flags: validate_feature_flags,
        staged_rollout: validate_staged_rollout_patterns,
        database_migrations: validate_database_migrations,
        api_versioning: validate_api_versioning,
        circuit_breakers: validate_circuit_breakers,
        deployment_readiness: validate_deployment_readiness,
        integration_tests: validate_integration_tests,
        rollback_capability: validate_rollback_capability
      }

      # Analyze each validation area
      details.each do |area, result|
        if result[:errors].any?
          errors.concat(result[:errors].map { |e| "#{area.to_s.humanize}: #{e}" })
        end
        
        if result[:warnings].any?
          warnings.concat(result[:warnings].map { |w| "#{area.to_s.humanize}: #{w}" })
        end
      end

      # Overall integration readiness assessment
      readiness_score = calculate_integration_readiness(details)
      details[:overall_readiness_score] = readiness_score

      if readiness_score < 60
        errors << "Overall integration readiness score too low: #{readiness_score}% (minimum: 60%)"
      elsif readiness_score < 80
        warnings << "Integration readiness could be improved: #{readiness_score}% (target: 80%+)"
      end

      result = ValidationResult.new(
        passed: errors.empty?,
        errors: errors,
        warnings: warnings,
        details: details
      )

      log_validation_completion('Integration validation', start_time, result)
      result
    end

    private

    def setup_logger
      Logger.new($stdout).tap do |logger|
        logger.level = Logger::INFO
        logger.formatter = proc do |severity, datetime, progname, msg|
          "[#{datetime.strftime('%H:%M:%S')}] [IntegrationValidator] #{severity}: #{msg}\n"
        end
      end
    end

    def log_operation_start(operation)
      logger.info("🔗 Starting: #{operation}")
    end

    def log_validation_completion(operation, start_time, result)
      duration = ((Time.now - start_time) * 1000).round(2)
      status = result.passed? ? '✅ PASSED' : '❌ FAILED'
      logger.info("🏁 Completed: #{operation} in #{duration}ms - #{status}")
    end

    # Validate feature flag implementation
    def validate_feature_flags
      errors = []
      warnings = []
      details = {
        feature_flag_files: find_feature_flag_files,
        feature_toggles: detect_feature_toggles,
        environment_configs: check_environment_feature_configs,
        usage_patterns: analyze_feature_flag_usage
      }

      # Check for feature flag infrastructure
      if details[:feature_flag_files].empty? && details[:feature_toggles].empty?
        warnings << "No feature flag system detected - consider implementing for safer deployments"
      end

      # Validate feature flag patterns
      validate_feature_flag_patterns(details, errors, warnings)

      { errors: errors, warnings: warnings, details: details }
    end

    # Find files related to feature flags
    def find_feature_flag_files
      patterns = %w[
        config/**/*feature*.rb config/**/*flag*.rb config/**/*toggle*.rb
        lib/**/*feature*.rb lib/**/*flag*.rb lib/**/*toggle*.rb
        app/models/*feature*.rb app/models/*flag*.rb
      ]

      found_files = []
      patterns.each do |pattern|
        found_files.concat(Dir.glob(project_root.join(pattern)))
      end

      found_files.map { |file| Pathname.new(file).relative_path_from(project_root).to_s }
    end

    # Detect feature toggle patterns in code
    def detect_feature_toggles
      ruby_files = Dir.glob(project_root.join('{app,lib,config}/**/*.rb'))
      toggles = []

      ruby_files.each do |file_path|
        content = File.read(file_path)
        relative_path = Pathname.new(file_path).relative_path_from(project_root).to_s

        # Look for common feature toggle patterns
        feature_patterns = [
          /feature.*?enabled?\?/i,
          /enabled.*?feature/i,
          /flag.*?active/i,
          /toggle.*?on/i,
          /if.*?feature.*?flag/i,
          /Rails\.configuration\.feature/i,
          /ENV.*?FEATURE.*?ENABLED/i
        ]

        feature_patterns.each do |pattern|
          matches = content.scan(pattern)
          if matches.any?
            toggles << {
              file: relative_path,
              pattern: pattern.source,
              occurrences: matches.length
            }
          end
        end
      end

      toggles
    end

    # Check environment-specific feature configurations
    def check_environment_feature_configs
      env_files = %w[development.rb test.rb production.rb staging.rb]
      configs = {}

      env_files.each do |env_file|
        path = project_root.join('config/environments', env_file)
        next unless path.exist?

        content = path.read
        feature_config = content.match?(/feature|flag|toggle/i)
        
        configs[env_file.sub('.rb', '')] = {
          has_feature_config: feature_config,
          feature_lines: content.lines.each_with_index
                               .select { |line, _| line.match?(/feature|flag|toggle/i) }
                               .map { |line, index| { line_num: index + 1, content: line.strip } }
        }
      end

      configs
    end

    # Analyze feature flag usage patterns
    def analyze_feature_flag_usage
      all_files = Dir.glob(project_root.join('{app,lib}/**/*.rb'))
      usage_stats = {
        conditional_features: 0,
        permanent_flags: 0,
        environment_dependent: 0,
        database_flags: 0
      }

      all_files.each do |file_path|
        content = File.read(file_path)
        
        usage_stats[:conditional_features] += content.scan(/if.*?feature.*?enabled/i).length
        usage_stats[:permanent_flags] += content.scan(/feature.*?always.*?enabled/i).length
        usage_stats[:environment_dependent] += content.scan(/Rails\.env.*?feature/i).length
        usage_stats[:database_flags] += content.scan(/Feature.*?find|flag.*?find/i).length
      end

      usage_stats
    end

    # Validate feature flag implementation patterns
    def validate_feature_flag_patterns(details, errors, warnings)
      # Check for consistent feature flag usage
      if details[:usage_patterns][:conditional_features] == 0 && 
         details[:feature_toggles].any?
        warnings << "Feature flags defined but not used conditionally in code"
      end

      # Warn about permanent flags
      if details[:usage_patterns][:permanent_flags] > 0
        warnings << "#{details[:usage_patterns][:permanent_flags]} permanent feature flags detected - consider cleanup"
      end

      # Check environment consistency
      env_with_features = details[:environment_configs].select { |_, config| config[:has_feature_config] }
      if env_with_features.length > 0 && env_with_features.length < 3
        warnings << "Feature configuration not consistent across environments"
      end
    end

    # Validate staged rollout patterns
    def validate_staged_rollout_patterns
      errors = []
      warnings = []
      details = {
        canary_deployments: detect_canary_patterns,
        blue_green_setup: detect_blue_green_setup,
        rolling_updates: detect_rolling_update_patterns,
        traffic_splitting: detect_traffic_splitting
      }

      # Check for deployment strategy implementation
      deployment_strategies = details.values.sum { |strategy| strategy[:detected] ? 1 : 0 }
      
      if deployment_strategies == 0
        warnings << "No staged deployment patterns detected - consider canary/blue-green deployment"
      end

      { errors: errors, warnings: warnings, details: details }
    end

    # Detect canary deployment patterns
    def detect_canary_patterns
      deployment_files = find_deployment_files
      canary_indicators = %w[canary gradual percentage traffic weight]

      has_canary = deployment_files.any? do |file|
        content = File.read(file)
        canary_indicators.any? { |indicator| content.downcase.include?(indicator) }
      end

      {
        detected: has_canary,
        files: deployment_files,
        indicators_found: canary_indicators.select do |indicator|
          deployment_files.any? { |file| File.read(file).downcase.include?(indicator) }
        end
      }
    end

    # Find deployment-related files
    def find_deployment_files
      patterns = %w[
        config/deploy*.rb
        docker-compose*.yml
        Dockerfile*
        k8s/**/*.yml
        .github/workflows/**/*.yml
        deployment/**/*
      ]

      found_files = []
      patterns.each do |pattern|
        found_files.concat(Dir.glob(project_root.join(pattern)))
      end

      found_files
    end

    # Detect blue-green deployment setup
    def detect_blue_green_setup
      deployment_files = find_deployment_files
      blue_green_indicators = ['blue', 'green', 'swap', 'switch', 'active', 'standby']

      has_blue_green = deployment_files.any? do |file|
        content = File.read(file).downcase
        blue_green_indicators.count { |indicator| content.include?(indicator) } >= 2
      end

      {
        detected: has_blue_green,
        indicators_found: blue_green_indicators.select do |indicator|
          deployment_files.any? { |file| File.read(file).downcase.include?(indicator) }
        end
      }
    end

    # Detect rolling update patterns
    def detect_rolling_update_patterns
      deployment_files = find_deployment_files
      rolling_indicators = ['rolling', 'gradual', 'batch', 'maxUnavailable', 'maxSurge']

      has_rolling = deployment_files.any? do |file|
        content = File.read(file)
        rolling_indicators.any? { |indicator| content.include?(indicator) }
      end

      {
        detected: has_rolling,
        indicators_found: rolling_indicators.select do |indicator|
          deployment_files.any? { |file| File.read(file).include?(indicator) }
        end
      }
    end

    # Detect traffic splitting mechanisms
    def detect_traffic_splitting
      config_files = Dir.glob(project_root.join('config/**/*.rb'))
      nginx_configs = Dir.glob(project_root.join('config/**/*.conf'))
      
      all_files = config_files + nginx_configs
      traffic_indicators = ['upstream', 'weight', 'split', 'load_balance', 'proxy']

      has_traffic_splitting = all_files.any? do |file|
        content = File.read(file)
        traffic_indicators.any? { |indicator| content.include?(indicator) }
      end

      {
        detected: has_traffic_splitting,
        files_checked: all_files.length,
        indicators_found: traffic_indicators.select do |indicator|
          all_files.any? { |file| File.read(file).include?(indicator) }
        end
      }
    end

    # Validate database migration patterns
    def validate_database_migrations
      errors = []
      warnings = []
      
      migration_dir = project_root.join('db/migrate')
      migrations = migration_dir.exist? ? Dir.glob(migration_dir.join('*.rb')).sort : []
      
      details = {
        total_migrations: migrations.length,
        reversible_migrations: 0,
        data_migrations: 0,
        zero_downtime_patterns: 0,
        migration_analysis: []
      }

      migrations.each do |migration_file|
        analysis = analyze_migration(migration_file)
        details[:migration_analysis] << analysis
        
        details[:reversible_migrations] += 1 if analysis[:reversible]
        details[:data_migrations] += 1 if analysis[:data_migration]
        details[:zero_downtime_patterns] += 1 if analysis[:zero_downtime]
      end

      # Validate migration quality
      if migrations.any?
        reversible_ratio = (details[:reversible_migrations].to_f / migrations.length * 100).round(2)
        if reversible_ratio < 80
          warnings << "#{reversible_ratio}% of migrations are reversible (target: 80%+)"
        end

        if details[:zero_downtime_patterns] == 0 && migrations.length > 5
          warnings << "No zero-downtime migration patterns detected"
        end
      end

      { errors: errors, warnings: warnings, details: details }
    end

    # Analyze individual migration file
    def analyze_migration(migration_file)
      content = File.read(migration_file)
      filename = File.basename(migration_file)

      {
        filename: filename,
        reversible: content.include?('def down') || content.include?('reversible'),
        data_migration: content.match?(/update|delete|insert|execute/i) && 
                       !content.match?(/create_table|add_column|add_index/),
        zero_downtime: analyze_zero_downtime_patterns(content),
        has_safety_checks: content.include?('if') && content.match?(/table_exists|column_exists/),
        migration_type: determine_migration_type(content)
      }
    end

    # Analyze zero-downtime migration patterns
    def analyze_zero_downtime_patterns(content)
      # Check for patterns that indicate zero-downtime awareness
      patterns = [
        /add_column.*default.*null.*false/i,  # Adding non-null columns safely
        /add_index.*concurrent/i,             # Concurrent index creation
        /remove_column.*if.*column_exists/i,  # Safe column removal
        /rename_table.*if.*table_exists/i     # Safe table operations
      ]

      patterns.any? { |pattern| content.match?(pattern) }
    end

    # Determine migration type based on content
    def determine_migration_type(content)
      return 'schema' if content.match?(/create_table|add_column|add_index|drop_table/)
      return 'data' if content.match?(/update|delete|insert|execute/)
      return 'mixed' if content.match?(/create_table|add_column/) && content.match?(/update|insert/)
      'unknown'
    end

    # Validate API versioning patterns
    def validate_api_versioning
      errors = []
      warnings = []
      details = {
        versioning_strategy: detect_api_versioning_strategy,
        version_compatibility: check_version_compatibility,
        deprecation_handling: check_deprecation_handling
      }

      # Check for API versioning implementation
      if details[:versioning_strategy][:type] == 'none'
        warnings << "No API versioning strategy detected - consider implementing for backward compatibility"
      end

      # Check deprecation handling
      unless details[:deprecation_handling][:has_deprecation_warnings]
        warnings << "No API deprecation handling detected"
      end

      { errors: errors, warnings: warnings, details: details }
    end

    # Detect API versioning strategy
    def detect_api_versioning_strategy
      routes_file = project_root.join('config/routes.rb')
      controller_files = Dir.glob(project_root.join('app/controllers/**/*.rb'))

      strategy = { type: 'none', details: {} }

      if routes_file.exist?
        routes_content = routes_file.read

        if routes_content.include?('namespace :v1') || routes_content.include?('namespace :api')
          strategy[:type] = 'namespace'
          strategy[:details][:namespaces] = routes_content.scan(/namespace :(v\d+|api)/).flatten
        elsif routes_content.include?('constraints') && routes_content.include?('version')
          strategy[:type] = 'constraint'
        end
      end

      # Check controllers for version headers
      version_header_usage = controller_files.any? do |file|
        content = File.read(file)
        content.match?(/Accept.*version|API.*Version/i)
      end

      if version_header_usage
        strategy[:type] = 'header' if strategy[:type] == 'none'
        strategy[:details][:uses_headers] = true
      end

      strategy
    end

    # Check version compatibility handling
    def check_version_compatibility
      controller_files = Dir.glob(project_root.join('app/controllers/**/*.rb'))
      
      compatibility_patterns = controller_files.count do |file|
        content = File.read(file)
        content.match?(/respond_to.*version|version.*check|backward.*compatible/i)
      end

      {
        controllers_with_compatibility: compatibility_patterns,
        total_controllers: controller_files.length,
        compatibility_ratio: controller_files.empty? ? 0 : 
                           (compatibility_patterns.to_f / controller_files.length * 100).round(2)
      }
    end

    # Check API deprecation handling
    def check_deprecation_handling
      all_files = Dir.glob(project_root.join('{app,lib}/**/*.rb'))
      
      deprecation_indicators = all_files.count do |file|
        content = File.read(file)
        content.match?(/deprecat.*warning|sunset.*header|x.*deprecat/i)
      end

      {
        has_deprecation_warnings: deprecation_indicators > 0,
        files_with_deprecation: deprecation_indicators
      }
    end

    # Validate circuit breaker implementation
    def validate_circuit_breakers
      errors = []
      warnings = []
      details = {
        circuit_breaker_libraries: detect_circuit_breaker_libraries,
        manual_implementations: detect_manual_circuit_breakers,
        external_service_protection: analyze_external_service_protection
      }

      # Check for circuit breaker implementation
      total_breakers = details[:circuit_breaker_libraries][:count] + 
                      details[:manual_implementations][:count]

      if total_breakers == 0 && has_external_services?
        warnings << "External service calls detected but no circuit breakers implemented"
      end

      { errors: errors, warnings: warnings, details: details }
    end

    # Detect circuit breaker libraries
    def detect_circuit_breaker_libraries
      gemfile_path = project_root.join('Gemfile')
      
      if gemfile_path.exist?
        gemfile_content = gemfile_path.read
        breaker_gems = ['circuitbox', 'circuit_breaker', 'stoplight', 'semian']
        
        found_gems = breaker_gems.select { |gem| gemfile_content.include?(gem) }
        
        {
          count: found_gems.length,
          libraries: found_gems
        }
      else
        { count: 0, libraries: [] }
      end
    end

    # Detect manual circuit breaker implementations
    def detect_manual_circuit_breakers
      all_files = Dir.glob(project_root.join('{app,lib}/**/*.rb'))
      manual_breakers = []

      all_files.each do |file|
        content = File.read(file)
        relative_path = Pathname.new(file).relative_path_from(project_root).to_s

        if content.match?(/circuit.*?breaker|failure.*?threshold|open.*?state/i)
          manual_breakers << {
            file: relative_path,
            indicators: ['circuit_breaker', 'failure_threshold', 'open_state']
                       .select { |term| content.downcase.include?(term.tr('_', ' ')) }
          }
        end
      end

      {
        count: manual_breakers.length,
        implementations: manual_breakers
      }
    end

    # Analyze external service protection
    def analyze_external_service_protection
      service_files = find_external_service_files
      protected_services = 0

      service_files.each do |file|
        content = File.read(file)
        if content.match?(/timeout|circuit|retry|fallback/i)
          protected_services += 1
        end
      end

      {
        total_service_files: service_files.length,
        protected_services: protected_services,
        protection_ratio: service_files.empty? ? 0 : 
                         (protected_services.to_f / service_files.length * 100).round(2)
      }
    end

    # Find files that make external service calls
    def find_external_service_files
      all_files = Dir.glob(project_root.join('{app,lib}/**/*.rb'))
      
      all_files.select do |file|
        content = File.read(file)
        content.match?(/Net::HTTP|HTTParty|Faraday|RestClient|http.*?get|http.*?post/i)
      end
    end

    # Check if application has external services
    def has_external_services?
      find_external_service_files.any?
    end

    # Validate deployment readiness
    def validate_deployment_readiness
      errors = []
      warnings = []
      details = {
        containerization: check_containerization,
        health_checks: check_health_checks,
        configuration_management: check_configuration_management,
        monitoring_setup: check_monitoring_setup
      }

      # Validate containerization
      unless details[:containerization][:has_dockerfile]
        warnings << "No Dockerfile found - consider containerization for consistent deployments"
      end

      # Validate health checks
      unless details[:health_checks][:has_health_endpoint]
        errors << "No health check endpoint detected - required for deployment orchestration"
      end

      { errors: errors, warnings: warnings, details: details }
    end

    # Check containerization setup
    def check_containerization
      {
        has_dockerfile: project_root.join('Dockerfile').exist?,
        has_docker_compose: Dir.glob(project_root.join('docker-compose*.yml')).any?,
        has_dockerignore: project_root.join('.dockerignore').exist?
      }
    end

    # Check health check implementation
    def check_health_checks
      routes_file = project_root.join('config/routes.rb')
      health_endpoint = false

      if routes_file.exist?
        routes_content = routes_file.read
        health_endpoint = routes_content.match?(/health|status|ping|ready/)
      end

      controller_files = Dir.glob(project_root.join('app/controllers/**/*.rb'))
      health_controller = controller_files.any? do |file|
        File.basename(file).match?(/health|status/) || File.read(file).include?('def health')
      end

      {
        has_health_endpoint: health_endpoint,
        has_health_controller: health_controller
      }
    end

    # Check configuration management
    def check_configuration_management
      {
        uses_env_vars: project_root.join('.env').exist? || 
                      Dir.glob(project_root.join('config/**/*.rb')).any? { |f| File.read(f).include?('ENV[') },
        has_secrets_management: check_secrets_management,
        environment_specific_configs: check_environment_configs
      }
    end

    # Check secrets management
    def check_secrets_management
      rails_credentials = project_root.join('config/credentials.yml.enc').exist?
      dotenv_files = Dir.glob(project_root.join('.env*')).any?
      
      rails_credentials || dotenv_files
    end

    # Check environment-specific configurations
    def check_environment_configs
      env_dir = project_root.join('config/environments')
      return false unless env_dir.exist?

      required_envs = %w[development.rb test.rb production.rb]
      existing_envs = required_envs.select { |env| env_dir.join(env).exist? }

      existing_envs.length >= 2
    end

    # Check monitoring setup
    def check_monitoring_setup
      gemfile_path = project_root.join('Gemfile')
      monitoring_gems = []

      if gemfile_path.exist?
        gemfile_content = gemfile_path.read
        potential_gems = ['newrelic', 'datadog', 'scout', 'skylight', 'appsignal']
        monitoring_gems = potential_gems.select { |gem| gemfile_content.include?(gem) }
      end

      {
        monitoring_gems: monitoring_gems,
        has_monitoring: monitoring_gems.any?
      }
    end

    # Validate integration test coverage
    def validate_integration_tests
      errors = []
      warnings = []
      details = {
        integration_test_files: find_integration_test_files,
        api_test_coverage: analyze_api_test_coverage,
        end_to_end_tests: find_end_to_end_tests
      }

      # Check for integration test presence
      if details[:integration_test_files].empty?
        warnings << "No integration tests found - consider adding for deployment confidence"
      end

      # Check API test coverage
      if details[:api_test_coverage][:coverage_ratio] < 50
        warnings << "Low API test coverage: #{details[:api_test_coverage][:coverage_ratio]}%"
      end

      { errors: errors, warnings: warnings, details: details }
    end

    # Find integration test files
    def find_integration_test_files
      test_patterns = %w[
        spec/integration/**/*_spec.rb
        spec/requests/**/*_spec.rb
        test/integration/**/*_test.rb
        features/**/*.feature
      ]

      found_files = []
      test_patterns.each do |pattern|
        found_files.concat(Dir.glob(project_root.join(pattern)))
      end

      found_files.map { |file| Pathname.new(file).relative_path_from(project_root).to_s }
    end

    # Analyze API test coverage
    def analyze_api_test_coverage
      controller_files = Dir.glob(project_root.join('app/controllers/**/*.rb'))
      test_files = Dir.glob(project_root.join('{spec,test}/**/*{_spec.rb,_test.rb}'))

      controller_names = controller_files.map { |file| File.basename(file, '.rb') }
      tested_controllers = test_files.count do |file|
        test_content = File.read(file)
        controller_names.any? { |controller| test_content.include?(controller) }
      end

      {
        total_controllers: controller_files.length,
        tested_controllers: tested_controllers,
        coverage_ratio: controller_files.empty? ? 0 : 
                       (tested_controllers.to_f / controller_files.length * 100).round(2)
      }
    end

    # Find end-to-end test files
    def find_end_to_end_tests
      e2e_patterns = %w[
        spec/features/**/*_spec.rb
        spec/system/**/*_spec.rb
        test/system/**/*_test.rb
        cypress/**/*.spec.js
        playwright/**/*.spec.js
      ]

      found_files = []
      e2e_patterns.each do |pattern|
        found_files.concat(Dir.glob(project_root.join(pattern)))
      end

      found_files.map { |file| Pathname.new(file).relative_path_from(project_root).to_s }
    end

    # Validate rollback capability
    def validate_rollback_capability
      errors = []
      warnings = []
      details = {
        database_rollback: check_database_rollback_capability,
        deployment_rollback: check_deployment_rollback,
        feature_toggles: check_feature_toggle_rollback
      }

      # Check database rollback capability
      unless details[:database_rollback][:reversible_migrations_ratio] > 80
        warnings << "Low reversible migration ratio: #{details[:database_rollback][:reversible_migrations_ratio]}%"
      end

      # Check deployment rollback
      unless details[:deployment_rollback][:has_rollback_strategy]
        warnings << "No deployment rollback strategy detected"
      end

      { errors: errors, warnings: warnings, details: details }
    end

    # Check database rollback capability
    def check_database_rollback_capability
      migration_dir = project_root.join('db/migrate')
      return { reversible_migrations_ratio: 0, total_migrations: 0 } unless migration_dir.exist?

      migrations = Dir.glob(migration_dir.join('*.rb'))
      reversible_count = migrations.count do |migration_file|
        content = File.read(migration_file)
        content.include?('def down') || content.include?('reversible')
      end

      {
        total_migrations: migrations.length,
        reversible_migrations: reversible_count,
        reversible_migrations_ratio: migrations.empty? ? 0 : 
                                    (reversible_count.to_f / migrations.length * 100).round(2)
      }
    end

    # Check deployment rollback strategies
    def check_deployment_rollback
      deployment_files = find_deployment_files
      rollback_indicators = ['rollback', 'revert', 'previous', 'undo', 'restore']

      has_rollback = deployment_files.any? do |file|
        content = File.read(file).downcase
        rollback_indicators.any? { |indicator| content.include?(indicator) }
      end

      {
        has_rollback_strategy: has_rollback,
        deployment_files_checked: deployment_files.length
      }
    end

    # Check feature toggle rollback capability
    def check_feature_toggle_rollback
      feature_files = find_feature_flag_files
      
      has_toggle_rollback = feature_files.any? do |file|
        content = File.read(project_root.join(file)).downcase
        content.include?('disable') || content.include?('rollback') || content.include?('revert')
      end

      {
        has_feature_rollback: has_toggle_rollback,
        feature_files: feature_files.length
      }
    end

    # Calculate overall integration readiness score
    def calculate_integration_readiness(details)
      score = 100
      
      # Feature flags and rollout (20 points)
      score -= 10 unless details[:feature_flags][:details][:feature_toggles].any?
      score -= 10 unless details[:staged_rollout][:details].values.any? { |v| v[:detected] }
      
      # Database migration quality (20 points)
      migration_score = details[:database_migrations][:details][:reversible_migrations]
      total_migrations = details[:database_migrations][:details][:total_migrations]
      if total_migrations > 0
        migration_ratio = (migration_score.to_f / total_migrations) * 100
        score -= (20 * (100 - migration_ratio) / 100).round
      end
      
      # API versioning (15 points)
      score -= 15 if details[:api_versioning][:details][:versioning_strategy][:type] == 'none'
      
      # Circuit breakers (15 points)  
      circuit_breaker_count = details[:circuit_breakers][:details][:circuit_breaker_libraries][:count] +
                             details[:circuit_breakers][:details][:manual_implementations][:count]
      score -= 15 if circuit_breaker_count == 0 && has_external_services?
      
      # Deployment readiness (20 points)
      deployment_score = 20
      deployment_score -= 5 unless details[:deployment_readiness][:details][:containerization][:has_dockerfile]
      deployment_score -= 10 unless details[:deployment_readiness][:details][:health_checks][:has_health_endpoint]
      deployment_score -= 5 unless details[:deployment_readiness][:details][:configuration_management][:uses_env_vars]
      score -= (20 - deployment_score)
      
      # Integration tests (10 points)
      score -= 10 if details[:integration_tests][:details][:integration_test_files].empty?

      [score, 0].max
    end
  end
end