# frozen_string_literal: true

module QualityGates
  module Middleware
    # Optional middleware for real-time validation during development
    # Monitors file changes and runs targeted validation automatically
    class RealTimeValidator
      
      def initialize(app)
        @app = app
        @file_monitor = setup_file_monitor
        @validation_queue = []
        @last_validation = Time.current
      end

      def call(env)
        # Process validation queue if enough time has passed
        process_validation_queue if should_validate?
        
        @app.call(env)
      end

      private

      def setup_file_monitor
        return nil unless Rails.application.config.quality_gates&.real_time&.enabled

        require 'listen'
        
        patterns = Rails.application.config.quality_gates.real_time.file_patterns
        
        Listen.to(Rails.root) do |modified, added, removed|
          relevant_files = (modified + added + removed).select do |file|
            patterns.any? { |pattern| File.fnmatch?(pattern, file) }
          end
          
          if relevant_files.any?
            queue_validation(relevant_files)
          end
        end.start
        
      rescue LoadError
        Rails.logger.warn "Quality Gates: 'listen' gem not available for real-time validation"
        nil
      end

      def queue_validation(files)
        @validation_queue.concat(files)
        @validation_queue.uniq!
      end

      def should_validate?
        return false if @validation_queue.empty?
        
        delay = Rails.application.config.quality_gates.real_time.validation_delay
        Time.current - @last_validation > delay
      end

      def process_validation_queue
        return if @validation_queue.empty?

        files_to_validate = @validation_queue.dup
        @validation_queue.clear
        @last_validation = Time.current

        # Run validation in background thread to avoid blocking requests
        Thread.new do
          begin
            validate_files(files_to_validate)
          rescue StandardError => e
            Rails.logger.error "Quality Gates real-time validation error: #{e.message}"
          end
        end
      end

      def validate_files(files)
        Rails.logger.info "Quality Gates: Validating #{files.length} changed files"
        
        validator = QualityGates::DuringImplementation.new(Rails.root)
        
        # Convert absolute paths to relative paths
        relative_paths = files.map do |file|
          Pathname.new(file).relative_path_from(Rails.root).to_s
        rescue ArgumentError
          file # Keep original if conversion fails
        end

        results = validator.validate_paths(relative_paths)
        
        if results.failed?
          Rails.logger.warn "Quality Gates: Validation failed for changed files"
          results.errors.each { |error| Rails.logger.warn "  • #{error}" }
        else
          Rails.logger.info "Quality Gates: All changed files passed validation"
        end
      end
    end
  end
end