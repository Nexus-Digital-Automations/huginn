# frozen_string_literal: true

module QualityGates
  # Rails integration for Quality Gates
  class Railtie < Rails::Railtie
    # Load rake tasks
    rake_tasks do
      load 'tasks/quality_gates.rake'
    end

    # Initialize Quality Gates after Rails application is loaded
    initializer 'quality_gates.initialize' do |app|
      # Ensure required directories exist
      ensure_directories_exist(app)
      
      # Set up logging
      setup_logging(app)
    end

    private

    def ensure_directories_exist(app)
      required_dirs = [
        'development/reports',
        'log/quality_gates',
        'tmp/quality_gates'
      ]

      required_dirs.each do |dir|
        full_path = app.root.join(dir)
        FileUtils.mkdir_p(full_path) unless Dir.exist?(full_path)
      end
    end

    def setup_logging(app)
      # Create a dedicated logger for Quality Gates if needed
      log_file = app.root.join('log/quality_gates.log')
      
      unless Rails.env.test?
        QualityGates.instance_variable_set(:@logger, Logger.new(log_file))
      end
    end
  end
end