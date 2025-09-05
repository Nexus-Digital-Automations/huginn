# frozen_string_literal: true

require_relative 'utils'

module QualityGates
  # Validates documentation-as-code patterns and auto-generated API documentation
  # Ensures documentation is generated from implementation and stays current
  class DocumentationValidator
    include Utils

    attr_reader :project_root, :logger

    def initialize(project_root = Rails.root)
      @project_root = Pathname.new(project_root)
      @logger = setup_logger
    end

    # Main validation entry point
    # @return [ValidationResult] Results of documentation validation
    def validate
      log_operation_start('Documentation-as-code validation')
      start_time = Time.now

      errors = []
      warnings = []
      details = {
        api_documentation: validate_api_documentation,
        code_comments: validate_code_comments,
        generated_docs: validate_generated_documentation,
        documentation_freshness: validate_documentation_freshness,
        agent_documentation: validate_agent_documentation,
        inline_documentation: validate_inline_documentation,
        markdown_quality: validate_markdown_quality
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

      # Overall documentation quality assessment
      quality_score = calculate_documentation_quality_score(details)
      details[:overall_quality_score] = quality_score

      if quality_score < 60
        errors << "Overall documentation quality too low: #{quality_score}% (minimum: 60%)"
      elsif quality_score < 80
        warnings << "Documentation quality could be improved: #{quality_score}% (target: 80%+)"
      end

      result = ValidationResult.new(
        passed: errors.empty?,
        errors: errors,
        warnings: warnings,
        details: details
      )

      log_validation_completion('Documentation validation', start_time, result)
      result
    end

    private

    def setup_logger
      Logger.new($stdout).tap do |logger|
        logger.level = Logger::INFO
        logger.formatter = proc do |severity, datetime, progname, msg|
          "[#{datetime.strftime('%H:%M:%S')}] [DocumentationValidator] #{severity}: #{msg}\n"
        end
      end
    end

    def log_operation_start(operation)
      logger.info("📚 Starting: #{operation}")
    end

    def log_validation_completion(operation, start_time, result)
      duration = ((Time.now - start_time) * 1000).round(2)
      status = result.passed? ? '✅ PASSED' : '❌ FAILED'
      logger.info("🏁 Completed: #{operation} in #{duration}ms - #{status}")
    end

    # Validate API documentation generation and quality
    def validate_api_documentation
      errors = []
      warnings = []
      details = {
        api_doc_generators: detect_api_doc_generators,
        openapi_spec: validate_openapi_specification,
        api_doc_coverage: calculate_api_doc_coverage,
        documentation_automation: check_documentation_automation
      }

      # Check for API documentation generators
      if details[:api_doc_generators][:generators].empty?
        warnings << "No API documentation generators detected - consider YARD, RDoc, or OpenAPI tools"
      end

      # Validate OpenAPI specification
      if rails_application? && !details[:openapi_spec][:has_openapi_spec]
        warnings << "No OpenAPI specification found - consider generating API schema documentation"
      end

      # Check API documentation coverage
      if details[:api_doc_coverage][:coverage_percentage] < 70
        warnings << "Low API documentation coverage: #{details[:api_doc_coverage][:coverage_percentage]}%"
      end

      { errors: errors, warnings: warnings, details: details }
    end

    # Detect API documentation generators
    def detect_api_doc_generators
      gemfile_path = project_root.join('Gemfile')
      generators = []

      if gemfile_path.exist?
        gemfile_content = gemfile_path.read
        
        doc_gems = {
          'yard' => 'YARD documentation generator',
          'rdoc' => 'RDoc documentation generator', 
          'rswag' => 'RSpec-based OpenAPI documentation',
          'grape-swagger' => 'Grape API documentation',
          'apipie-rails' => 'Rails API documentation DSL',
          'swagger-blocks' => 'Swagger/OpenAPI documentation blocks'
        }

        doc_gems.each do |gem_name, description|
          if gemfile_content.include?(gem_name)
            generators << {
              name: gem_name,
              description: description,
              configured: check_generator_configuration(gem_name)
            }
          end
        end
      end

      {
        generators: generators,
        total_count: generators.length
      }
    end

    # Check if documentation generator is configured
    def check_generator_configuration(gem_name)
      case gem_name
      when 'yard'
        project_root.join('.yardopts').exist? || 
        Dir.glob(project_root.join('lib/tasks/**/*.rake')).any? { |f| File.read(f).include?('yard') }
      when 'rswag'
        project_root.join('spec/swagger_helper.rb').exist?
      when 'apipie-rails'
        Dir.glob(project_root.join('config/**/*.rb')).any? { |f| File.read(f).include?('Apipie') }
      else
        false
      end
    end

    # Validate OpenAPI specification
    def validate_openapi_specification
      openapi_files = find_openapi_files
      
      details = {
        has_openapi_spec: openapi_files.any?,
        openapi_files: openapi_files,
        specification_quality: {}
      }

      openapi_files.each do |file_path|
        details[:specification_quality][file_path] = analyze_openapi_quality(file_path)
      end

      details
    end

    # Find OpenAPI specification files
    def find_openapi_files
      patterns = %w[
        swagger.yml swagger.yaml openapi.yml openapi.yaml
        api-docs.yml api-docs.yaml
        spec/swagger_*.yml spec/swagger_*.yaml
        doc/api/*.yml doc/api/*.yaml
      ]

      found_files = []
      patterns.each do |pattern|
        found_files.concat(Dir.glob(project_root.join(pattern)))
      end

      found_files.map { |file| Pathname.new(file).relative_path_from(project_root).to_s }
    end

    # Analyze OpenAPI specification quality
    def analyze_openapi_quality(file_path)
      full_path = project_root.join(file_path)
      return { valid: false, reason: 'File not found' } unless full_path.exist?

      begin
        content = YAML.load_file(full_path)
        
        quality_checks = {
          has_info: content.key?('info'),
          has_paths: content.key?('paths') && content['paths'].any?,
          has_components: content.key?('components'),
          has_schemas: content.dig('components', 'schemas')&.any? || false,
          has_examples: check_openapi_examples(content),
          version_specified: content.dig('info', 'version').present?
        }

        {
          valid: true,
          quality_score: calculate_openapi_quality_score(quality_checks),
          checks: quality_checks
        }
      rescue StandardError => e
        {
          valid: false,
          reason: "YAML parsing error: #{e.message}"
        }
      end
    end

    # Check for examples in OpenAPI specification
    def check_openapi_examples(content)
      return false unless content['paths']

      content['paths'].any? do |_path, methods|
        methods.any? do |_method, details|
          details.dig('responses')&.any? { |_code, response| response.key?('examples') } ||
          details.dig('requestBody', 'content')&.any? { |_type, body| body.key?('examples') }
        end
      end
    end

    # Calculate OpenAPI specification quality score
    def calculate_openapi_quality_score(checks)
      total_checks = checks.length
      passed_checks = checks.values.count(true)
      
      (passed_checks.to_f / total_checks * 100).round(2)
    end

    # Calculate API documentation coverage
    def calculate_api_doc_coverage
      controller_files = Dir.glob(project_root.join('app/controllers/**/*.rb'))
      documented_controllers = 0

      controller_analysis = controller_files.map do |file_path|
        content = File.read(file_path)
        relative_path = Pathname.new(file_path).relative_path_from(project_root).to_s
        
        documentation_score = calculate_controller_doc_score(content)
        documented_controllers += 1 if documentation_score > 50

        {
          file: relative_path,
          documentation_score: documentation_score,
          has_class_comments: content.match?(/^# .+\nclass/),
          has_method_comments: content.scan(/^\s*# .+\n\s*def /).any?,
          api_doc_annotations: count_api_doc_annotations(content)
        }
      end

      {
        total_controllers: controller_files.length,
        documented_controllers: documented_controllers,
        coverage_percentage: controller_files.empty? ? 0 : 
                           (documented_controllers.to_f / controller_files.length * 100).round(2),
        controller_analysis: controller_analysis
      }
    end

    # Calculate documentation score for a controller
    def calculate_controller_doc_score(content)
      score = 0
      
      # Class-level documentation
      score += 30 if content.match?(/^# .+\nclass/)
      
      # Method documentation
      methods = content.scan(/def (\w+)/).flatten
      documented_methods = content.scan(/^\s*# .+\n\s*def /).length
      
      if methods.any?
        method_doc_ratio = documented_methods.to_f / methods.length
        score += (method_doc_ratio * 50).round
      end
      
      # API-specific documentation
      score += 20 if count_api_doc_annotations(content) > 0
      
      score
    end

    # Count API documentation annotations
    def count_api_doc_annotations(content)
      annotations = [
        /@api\s/,
        /@param\s/,
        /@return\s/,
        /@example\s/,
        /api\s*:\s*:doc/,
        /swagger_/,
        /apipie\s/
      ]

      annotations.sum { |pattern| content.scan(pattern).length }
    end

    # Check documentation automation
    def check_documentation_automation
      ci_files = find_ci_files
      has_doc_automation = false

      ci_files.each do |file_path|
        content = File.read(file_path)
        if content.match?(/yard|rdoc|swagger|openapi.*?generate/i)
          has_doc_automation = true
          break
        end
      end

      rake_files = Dir.glob(project_root.join('lib/tasks/**/*.rake'))
      has_doc_tasks = rake_files.any? do |file|
        content = File.read(file)
        content.match?(/yard|rdoc|doc.*?generate/i)
      end

      {
        has_ci_documentation: has_doc_automation,
        has_rake_doc_tasks: has_doc_tasks,
        ci_files_checked: ci_files.length
      }
    end

    # Find CI configuration files
    def find_ci_files
      patterns = %w[
        .github/workflows/*.yml
        .gitlab-ci.yml
        .travis.yml
        circle.yml
        .circleci/config.yml
        buildkite.yml
      ]

      found_files = []
      patterns.each do |pattern|
        found_files.concat(Dir.glob(project_root.join(pattern)))
      end

      found_files
    end

    # Validate code comments quality
    def validate_code_comments
      errors = []
      warnings = []
      
      ruby_files = find_ruby_files
      comment_analysis = analyze_code_comments(ruby_files)
      
      details = {
        total_files_analyzed: ruby_files.length,
        comment_coverage: comment_analysis[:comment_coverage],
        comment_quality: comment_analysis[:comment_quality],
        outdated_comments: comment_analysis[:outdated_comments]
      }

      # Validate comment coverage
      if details[:comment_coverage][:percentage] < 50
        warnings << "Low comment coverage: #{details[:comment_coverage][:percentage]}% of files have meaningful comments"
      end

      # Check for comment quality issues
      if details[:outdated_comments][:count] > 0
        warnings << "#{details[:outdated_comments][:count]} potentially outdated comments found"
      end

      { errors: errors, warnings: warnings, details: details }
    end

    # Find all Ruby files for analysis
    def find_ruby_files
      patterns = %w[app/**/*.rb lib/**/*.rb]
      patterns.flat_map { |pattern| Dir.glob(project_root.join(pattern)) }
               .map { |path| Pathname.new(path) }
               .select(&:file?)
    end

    # Analyze code comments across files
    def analyze_code_comments(ruby_files)
      total_files = ruby_files.length
      files_with_comments = 0
      total_comment_lines = 0
      total_code_lines = 0
      outdated_comments = []

      ruby_files.each do |file_path|
        content = file_path.read
        lines = content.lines
        
        comment_lines = lines.count { |line| line.strip.start_with?('#') && line.strip.length > 1 }
        code_lines = lines.count { |line| !line.strip.empty? && !line.strip.start_with?('#') }
        
        files_with_comments += 1 if comment_lines > 0
        total_comment_lines += comment_lines
        total_code_lines += code_lines

        # Check for potentially outdated comments
        outdated = detect_outdated_comments(content, file_path)
        outdated_comments.concat(outdated)
      end

      {
        comment_coverage: {
          files_with_comments: files_with_comments,
          total_files: total_files,
          percentage: total_files.zero? ? 0 : (files_with_comments.to_f / total_files * 100).round(2)
        },
        comment_quality: {
          total_comment_lines: total_comment_lines,
          total_code_lines: total_code_lines,
          comment_to_code_ratio: total_code_lines.zero? ? 0 : 
                               (total_comment_lines.to_f / total_code_lines * 100).round(2)
        },
        outdated_comments: {
          count: outdated_comments.length,
          examples: outdated_comments.first(5) # Show first 5 examples
        }
      }
    end

    # Detect potentially outdated comments
    def detect_outdated_comments(content, file_path)
      outdated = []
      
      # Look for TODO/FIXME comments older than 6 months (simplified check)
      todo_comments = content.scan(/# (?:TODO|FIXME|HACK|XXX): (.+)/)
      todo_comments.each do |comment|
        outdated << {
          file: file_path.relative_path_from(project_root).to_s,
          comment: comment[0],
          type: 'action_item'
        }
      end

      # Look for references to old versions or deprecated features
      deprecated_patterns = [
        /# .*?rails [2-5]\./i,
        /# .*?ruby [12]\./i,
        /# .*?deprecated/i,
        /# .*?legacy/i
      ]

      deprecated_patterns.each do |pattern|
        matches = content.scan(pattern)
        matches.each do |match|
          outdated << {
            file: file_path.relative_path_from(project_root).to_s,
            comment: match,
            type: 'deprecated_reference'
          }
        end
      end

      outdated
    end

    # Validate generated documentation
    def validate_generated_documentation
      errors = []
      warnings = []
      details = {
        generated_doc_directories: find_generated_doc_directories,
        documentation_freshness: check_generated_doc_freshness,
        build_process: check_doc_build_process
      }

      # Check if generated documentation exists
      if details[:generated_doc_directories].empty?
        warnings << "No generated documentation directories found"
      end

      # Check documentation freshness
      stale_docs = details[:documentation_freshness][:stale_directories]
      if stale_docs.any?
        warnings << "#{stale_docs.length} generated documentation directories appear stale"
      end

      { errors: errors, warnings: warnings, details: details }
    end

    # Find generated documentation directories
    def find_generated_doc_directories
      doc_patterns = %w[
        doc/
        docs/
        _site/
        public/docs/
        coverage/
        yard_doc/
        api_doc/
      ]

      found_dirs = doc_patterns.select do |pattern|
        dir_path = project_root.join(pattern.chomp('/'))
        dir_path.exist? && dir_path.directory?
      end

      found_dirs
    end

    # Check if generated documentation is fresh
    def check_generated_doc_freshness
      doc_dirs = find_generated_doc_directories
      stale_threshold = 7.days.ago
      stale_directories = []

      doc_dirs.each do |dir_pattern|
        dir_path = project_root.join(dir_pattern.chomp('/'))
        
        # Check modification time of files in the directory
        recent_files = Dir.glob(dir_path.join('**/*')).select do |file_path|
          File.file?(file_path) && File.mtime(file_path) > stale_threshold
        end

        if recent_files.empty?
          stale_directories << dir_pattern
        end
      end

      {
        total_directories: doc_dirs.length,
        stale_directories: stale_directories,
        freshness_threshold: stale_threshold
      }
    end

    # Check documentation build process
    def check_doc_build_process
      has_rake_tasks = Dir.glob(project_root.join('lib/tasks/**/*.rake')).any? do |file|
        content = File.read(file)
        content.match?(/doc|yard|rdoc/i)
      end

      gemfile_path = project_root.join('Gemfile')
      has_doc_gems = false
      if gemfile_path.exist?
        gemfile_content = gemfile_path.read
        doc_gems = %w[yard rdoc kramdown redcarpet]
        has_doc_gems = doc_gems.any? { |gem| gemfile_content.include?(gem) }
      end

      {
        has_rake_doc_tasks: has_rake_tasks,
        has_documentation_gems: has_doc_gems
      }
    end

    # Validate documentation freshness
    def validate_documentation_freshness
      errors = []
      warnings = []
      details = {
        readme_freshness: check_readme_freshness,
        changelog_freshness: check_changelog_freshness,
        api_doc_freshness: check_api_doc_freshness
      }

      # Check README freshness
      if details[:readme_freshness][:days_since_update] > 180
        warnings << "README appears outdated (last updated #{details[:readme_freshness][:days_since_update]} days ago)"
      end

      # Check changelog freshness
      unless details[:changelog_freshness][:has_recent_entries]
        warnings << "No recent changelog entries found"
      end

      { errors: errors, warnings: warnings, details: details }
    end

    # Check README freshness
    def check_readme_freshness
      readme_files = %w[README.md README.rdoc README.txt README].map do |filename|
        project_root.join(filename)
      end

      readme_file = readme_files.find(&:exist?)
      
      if readme_file
        mtime = readme_file.mtime
        days_since_update = (Time.now - mtime) / 1.day
        
        {
          exists: true,
          last_updated: mtime,
          days_since_update: days_since_update.round,
          file_path: readme_file.basename.to_s
        }
      else
        {
          exists: false,
          days_since_update: Float::INFINITY
        }
      end
    end

    # Check changelog freshness  
    def check_changelog_freshness
      changelog_files = %w[CHANGELOG.md CHANGES.md HISTORY.md changelog.md changes.md].map do |filename|
        project_root.join(filename)
      end

      changelog_file = changelog_files.find(&:exist?)
      
      if changelog_file
        content = changelog_file.read
        recent_threshold = 90.days.ago
        
        # Look for recent version entries (simplified)
        recent_entries = content.scan(/## (?:\[)?(?:v?)(\d+\.\d+\.\d+)(?:\])? - (\d{4}-\d{2}-\d{2})/)
                               .select do |version, date_str|
          begin
            Date.parse(date_str) > recent_threshold
          rescue ArgumentError
            false
          end
        end

        {
          exists: true,
          has_recent_entries: recent_entries.any?,
          recent_entries_count: recent_entries.length,
          file_path: changelog_file.basename.to_s
        }
      else
        {
          exists: false,
          has_recent_entries: false
        }
      end
    end

    # Check API documentation freshness
    def check_api_doc_freshness
      openapi_files = find_openapi_files
      fresh_api_docs = []

      openapi_files.each do |file_path|
        full_path = project_root.join(file_path)
        mtime = full_path.mtime
        days_since_update = (Time.now - mtime) / 1.day

        fresh_api_docs << {
          file: file_path,
          days_since_update: days_since_update.round,
          fresh: days_since_update < 30
        }
      end

      {
        api_doc_files: fresh_api_docs,
        fresh_files_count: fresh_api_docs.count { |doc| doc[:fresh] }
      }
    end

    # Validate Huginn Agent documentation
    def validate_agent_documentation
      errors = []
      warnings = []
      
      agent_files = Dir.glob(project_root.join('app/models/agents/*.rb'))
      documented_agents = 0
      agent_documentation_analysis = []

      agent_files.each do |file_path|
        content = File.read(file_path)
        next unless content.include?('< Agent')

        agent_name = File.basename(file_path, '.rb')
        doc_analysis = analyze_agent_documentation(content, agent_name)
        
        documented_agents += 1 if doc_analysis[:documentation_score] > 70
        agent_documentation_analysis << doc_analysis
      end

      details = {
        total_agents: agent_files.length,
        documented_agents: documented_agents,
        documentation_coverage: agent_files.empty? ? 0 : 
                               (documented_agents.to_f / agent_files.length * 100).round(2),
        agent_analysis: agent_documentation_analysis
      }

      # Check Agent documentation coverage
      if details[:documentation_coverage] < 80
        warnings << "Low Agent documentation coverage: #{details[:documentation_coverage]}%"
      end

      { errors: errors, warnings: warnings, details: details }
    end

    # Analyze documentation quality for individual Agent
    def analyze_agent_documentation(content, agent_name)
      score = 0
      
      # Required documentation elements for Agents
      has_description = content.include?('description') && 
                       content.match?(/description\s+(['"])[^'"]*\1/)
      score += 30 if has_description

      has_event_description = content.include?('event_description')
      score += 20 if has_event_description

      has_default_options_docs = content.include?('def default_options') &&
                                 content.match?(/def default_options.*?#/m)
      score += 15 if has_default_options_docs

      has_method_docs = content.scan(/^\s*# .+\n\s*def /).length > 2
      score += 20 if has_method_docs

      has_usage_examples = content.match?(/example|usage|sample/i)
      score += 15 if has_usage_examples

      {
        agent_name: agent_name,
        documentation_score: score,
        has_description: has_description,
        has_event_description: has_event_description,
        has_default_options_docs: has_default_options_docs,
        has_method_docs: has_method_docs,
        has_usage_examples: has_usage_examples
      }
    end

    # Validate inline documentation quality
    def validate_inline_documentation
      errors = []
      warnings = []
      
      ruby_files = find_ruby_files
      inline_doc_analysis = analyze_inline_documentation(ruby_files)
      
      details = {
        files_analyzed: ruby_files.length,
        yard_compliance: inline_doc_analysis[:yard_compliance],
        rdoc_compliance: inline_doc_analysis[:rdoc_compliance],
        documentation_consistency: inline_doc_analysis[:consistency_score]
      }

      # Check documentation consistency
      if details[:documentation_consistency] < 60
        warnings << "Low documentation consistency score: #{details[:documentation_consistency]}%"
      end

      { errors: errors, warnings: warnings, details: details }
    end

    # Analyze inline documentation patterns
    def analyze_inline_documentation(ruby_files)
      yard_compliant_files = 0
      rdoc_compliant_files = 0
      total_files = ruby_files.length

      ruby_files.each do |file_path|
        content = file_path.read
        
        # Check YARD compliance (@param, @return, @example)
        yard_tags = content.scan(/@(?:param|return|example|api|author)/).length
        yard_compliant_files += 1 if yard_tags > 0

        # Check RDoc compliance (# comments above methods)
        rdoc_style_comments = content.scan(/^\s*# .+\n\s*def /).length
        rdoc_compliant_files += 1 if rdoc_style_comments > 0
      end

      {
        yard_compliance: {
          compliant_files: yard_compliant_files,
          compliance_percentage: total_files.zero? ? 0 : 
                                (yard_compliant_files.to_f / total_files * 100).round(2)
        },
        rdoc_compliance: {
          compliant_files: rdoc_compliant_files,
          compliance_percentage: total_files.zero? ? 0 : 
                                (rdoc_compliant_files.to_f / total_files * 100).round(2)
        },
        consistency_score: calculate_documentation_consistency_score(yard_compliant_files, rdoc_compliant_files, total_files)
      }
    end

    # Calculate documentation consistency score
    def calculate_documentation_consistency_score(yard_files, rdoc_files, total_files)
      return 0 if total_files.zero?

      # Prefer consistency in documentation style
      yard_ratio = yard_files.to_f / total_files
      rdoc_ratio = rdoc_files.to_f / total_files

      # Score based on predominant style consistency
      if yard_ratio > 0.7 || rdoc_ratio > 0.7
        [yard_ratio, rdoc_ratio].max * 100
      else
        # Mixed styles reduce consistency score
        ((yard_ratio + rdoc_ratio) / 2 * 80).round(2)
      end
    end

    # Validate markdown documentation quality
    def validate_markdown_quality
      errors = []
      warnings = []
      
      markdown_files = find_markdown_files
      markdown_analysis = analyze_markdown_quality(markdown_files)
      
      details = {
        markdown_files_found: markdown_files.length,
        structure_quality: markdown_analysis[:structure_quality],
        link_validation: markdown_analysis[:link_validation],
        formatting_consistency: markdown_analysis[:formatting_consistency]
      }

      # Check for broken internal links
      broken_links = details[:link_validation][:broken_internal_links]
      if broken_links > 0
        warnings << "#{broken_links} broken internal links found in markdown files"
      end

      { errors: errors, warnings: warnings, details: details }
    end

    # Find markdown files
    def find_markdown_files
      patterns = %w[**/*.md **/*.markdown]
      found_files = []
      
      patterns.each do |pattern|
        found_files.concat(Dir.glob(project_root.join(pattern)))
      end

      found_files.map { |file| Pathname.new(file).relative_path_from(project_root).to_s }
    end

    # Analyze markdown file quality
    def analyze_markdown_quality(markdown_files)
      structure_scores = []
      broken_internal_links = 0
      formatting_issues = 0

      markdown_files.each do |file_path|
        full_path = project_root.join(file_path)
        next unless full_path.exist?

        content = full_path.read
        
        # Analyze structure (headers, lists, etc.)
        structure_score = calculate_markdown_structure_score(content)
        structure_scores << structure_score

        # Check internal links
        internal_links = content.scan(/\[([^\]]+)\]\(([^)]+)\)/)
        internal_links.each do |link_text, link_url|
          next if link_url.start_with?('http')
          
          link_path = project_root.join(link_url.gsub('../', ''))
          broken_internal_links += 1 unless link_path.exist?
        end

        # Check formatting consistency
        formatting_issues += count_formatting_issues(content)
      end

      {
        structure_quality: {
          average_score: structure_scores.empty? ? 0 : (structure_scores.sum.to_f / structure_scores.length).round(2),
          files_analyzed: structure_scores.length
        },
        link_validation: {
          broken_internal_links: broken_internal_links
        },
        formatting_consistency: {
          issues_found: formatting_issues
        }
      }
    end

    # Calculate markdown structure quality score
    def calculate_markdown_structure_score(content)
      score = 0
      
      # Has proper header hierarchy
      headers = content.scan(/^(#+)\s+(.+)/)
      score += 20 if headers.any?
      
      # Has table of contents or navigation
      score += 15 if content.match?(/table of contents|toc|\[.*?\]\(#.*?\)/i)
      
      # Has code blocks with language specification
      code_blocks = content.scan(/```(\w+)/)
      score += 15 if code_blocks.any?
      
      # Has proper list formatting
      score += 10 if content.match?(/^\s*[*-]\s+.+/)
      
      # Has links and references
      score += 10 if content.match?(/\[.+?\]\(.+?\)/)
      
      # Has proper emphasis formatting
      score += 10 if content.match?(/\*\*.+?\*\*|\*.+?\*/)
      
      # Reasonable length (not too short, not too long)
      lines = content.lines.length
      score += 20 if lines > 10 && lines < 500

      score
    end

    # Count markdown formatting issues
    def count_formatting_issues(content)
      issues = 0
      
      # Inconsistent bullet points
      bullet_styles = content.scan(/^\s*([*+-])\s/).map(&:first).uniq
      issues += 1 if bullet_styles.length > 1
      
      # Missing space after headers
      issues += content.scan(/^#+[^ ]/).length
      
      # Inconsistent code block languages
      code_langs = content.scan(/```(\w+)/).flatten.uniq
      issues += 1 if code_langs.include?('') # Empty language spec
      
      issues
    end

    # Check if this is a Rails application
    def rails_application?
      project_root.join('config/application.rb').exist?
    end

    # Calculate overall documentation quality score
    def calculate_documentation_quality_score(details)
      score = 100
      
      # API documentation (25 points)
      api_doc_score = details[:api_documentation][:details][:api_doc_coverage][:coverage_percentage]
      score -= (25 * (100 - api_doc_score) / 100).round
      
      # Code comments (20 points)
      comment_coverage = details[:code_comments][:details][:comment_coverage][:percentage]
      score -= (20 * (100 - comment_coverage) / 100).round
      
      # Generated documentation (15 points)
      score -= 15 if details[:generated_docs][:details][:generated_doc_directories].empty?
      
      # Documentation freshness (15 points)
      freshness_details = details[:documentation_freshness][:details]
      score -= 5 unless freshness_details[:readme_freshness][:exists]
      score -= 5 if freshness_details[:readme_freshness][:days_since_update] > 180
      score -= 5 unless freshness_details[:changelog_freshness][:has_recent_entries]
      
      # Agent documentation (15 points) - Huginn specific
      agent_coverage = details[:agent_documentation][:details][:documentation_coverage]
      score -= (15 * (100 - agent_coverage) / 100).round
      
      # Inline documentation (10 points)
      inline_score = details[:inline_documentation][:details][:documentation_consistency]
      score -= (10 * (100 - inline_score) / 100).round

      [score, 0].max
    end
  end
end