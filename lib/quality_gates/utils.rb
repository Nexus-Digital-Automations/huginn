# frozen_string_literal: true

module QualityGates
  # Shared utilities module for Quality Gates validators
  # Provides common functionality used across all validation components
  module Utils
    extend ActiveSupport::Concern if defined?(ActiveSupport)

    # Module method fallbacks for when ActiveSupport is not available
    module ClassMethods
      def humanize(string)
        string.to_s.tr('_', ' ').split.map(&:capitalize).join(' ')
      end
    end

    # Instance methods available to validators
    def humanize(string)
      if string.respond_to?(:humanize)
        string.humanize
      else
        string.to_s.tr('_', ' ').split.map(&:capitalize).join(' ')
      end
    end

    # Setup structured logger with consistent formatting
    def setup_logger(component_name = 'QualityGates')
      require 'logger' unless defined?(Logger)
      
      Logger.new($stdout).tap do |logger|
        logger.level = Logger::INFO
        logger.formatter = proc do |severity, datetime, progname, msg|
          timestamp = datetime.strftime('%H:%M:%S')
          "[#{timestamp}] [#{component_name}] #{severity}: #{msg}\n"
        end
      end
    end

    # Log operation start with consistent formatting
    def log_operation_start(operation, emoji = '🚀')
      return unless defined?(@logger) && @logger

      @logger.info("#{emoji} Starting: #{operation}")
    end

    # Log operation step
    def log_operation_step(step, emoji = '⚙️')
      return unless defined?(@logger) && @logger

      @logger.info("#{emoji} Step: #{step}")
    end

    # Log operation completion with timing
    def log_operation_completion(operation, start_time, result, emoji = '🏁')
      return unless defined?(@logger) && @logger

      duration = ((Time.now - start_time) * 1000).round(2)
      status = result.respond_to?(:passed?) && result.passed? ? '✅ PASSED' : '❌ FAILED'
      
      @logger.info("#{emoji} Completed: #{operation} in #{duration}ms - #{status}")
      
      if result.respond_to?(:errors) && result.errors.any?
        result.errors.first(3).each { |error| @logger.warn("⚠️  Error: #{error}") }
      end
    end

    # Safe file reading with error handling
    def safe_file_read(file_path)
      return '' unless File.exist?(file_path) && File.readable?(file_path)

      File.read(file_path)
    rescue StandardError => e
      warn "Warning: Could not read file #{file_path}: #{e.message}"
      ''
    end

    # Find files matching patterns with safety checks
    def safe_glob(pattern, base_path = '.')
      full_pattern = File.join(base_path, pattern)
      Dir.glob(full_pattern).select { |path| File.file?(path) && File.readable?(path) }
    rescue StandardError => e
      warn "Warning: Glob pattern failed #{pattern}: #{e.message}"
      []
    end

    # Check if running in Rails environment
    def rails_environment?
      defined?(Rails) && Rails.respond_to?(:root)
    end

    # Get current timestamp in ISO format
    def current_timestamp
      if defined?(Time.now)
        Time.now.iso8601
      else
        Time.now.strftime('%Y-%m-%dT%H:%M:%S%z')
      end
    end

    # Safely require optional dependencies
    def safe_require(gem_name)
      require gem_name
      true
    rescue LoadError
      false
    end

    # Create directory if it doesn't exist
    def ensure_directory(dir_path)
      return if Dir.exist?(dir_path)

      if defined?(FileUtils)
        FileUtils.mkdir_p(dir_path)
      else
        require 'fileutils'
        FileUtils.mkdir_p(dir_path)
      end
    rescue StandardError => e
      warn "Warning: Could not create directory #{dir_path}: #{e.message}"
      false
    end

    # Count lines of code, excluding comments and empty lines
    def count_code_lines(content)
      return 0 if content.nil? || content.empty?

      lines = content.lines
      code_lines = lines.reject do |line|
        stripped = line.strip
        stripped.empty? || stripped.start_with?('#')
      end
      
      code_lines.length
    end

    # Extract method names from Ruby code
    def extract_method_names(content)
      return [] if content.nil? || content.empty?

      method_matches = content.scan(/^\s*def\s+(self\.)?(\w+)/)
      method_matches.map { |match| match[1] } # Return just the method name
    end

    # Calculate percentage with safe division
    def safe_percentage(numerator, denominator)
      return 0.0 if denominator.zero?
      (numerator.to_f / denominator * 100).round(2)
    end

    # Colorize text for terminal output
    def colorize_text(text, color = :default)
      return text unless $stdout.tty?

      color_codes = {
        red: 31,
        green: 32,
        yellow: 33,
        blue: 34,
        magenta: 35,
        cyan: 36,
        white: 37,
        default: 39
      }

      code = color_codes[color] || color_codes[:default]
      "\e[#{code}m#{text}\e[0m"
    end

    # Format validation score with color coding
    def format_score(score)
      case score
      when 90..100
        colorize_text("#{score}%", :green)
      when 70..89
        colorize_text("#{score}%", :yellow)
      else
        colorize_text("#{score}%", :red)
      end
    end

    # Check if a string contains any of the patterns
    def contains_any_pattern?(content, patterns)
      return false if content.nil? || content.empty?
      return false if patterns.nil? || patterns.empty?

      patterns.any? { |pattern| content.include?(pattern) }
    end

    # Check if a string matches any regex patterns
    def matches_any_pattern?(content, regex_patterns)
      return false if content.nil? || content.empty?
      return false if regex_patterns.nil? || regex_patterns.empty?

      regex_patterns.any? { |pattern| content.match?(pattern) }
    end

    # Truncate text to specified length
    def truncate_text(text, max_length = 100)
      return text if text.length <= max_length
      "#{text[0, max_length - 3]}..."
    end

    # Get relative path safely
    def relative_path(file_path, base_path)
      Pathname.new(file_path).relative_path_from(Pathname.new(base_path)).to_s
    rescue ArgumentError
      file_path.to_s
    end

    # Validate that a path exists and is readable
    def valid_readable_path?(path)
      File.exist?(path) && File.readable?(path)
    rescue StandardError
      false
    end

    # Get file modification time safely
    def file_mtime(file_path)
      File.mtime(file_path)
    rescue StandardError
      Time.at(0) # Return epoch time if file doesn't exist or can't be read
    end

    # Calculate days since file modification
    def days_since_modified(file_path)
      mtime = file_mtime(file_path)
      return Float::INFINITY if mtime == Time.at(0)

      current_time = defined?(Time.now) ? Time.now : Time.now
      ((current_time - mtime) / (24 * 3600)).round(1)
    end
  end
end