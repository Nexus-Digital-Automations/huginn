# frozen_string_literal: true

# Error Monitoring System Initializer for Huginn
# Configures and initializes the comprehensive error monitoring system
#
# This initializer:
# - Loads error monitoring configuration
# - Initializes monitoring components
# - Sets up middleware for error capture
# - Configures alerting and recovery systems

Rails.application.configure do
  ##
  # Load Error Monitoring Configuration
  config_path = Rails.root.join('config', 'error_monitoring.yml')
  
  if File.exist?(config_path)
    error_monitoring_config = YAML.safe_load(
      File.read(config_path), 
      permitted_classes: [Symbol], 
      aliases: true
    )[Rails.env] || {}
    Rails.application.config.error_monitoring = error_monitoring_config
    
    Rails.logger.info "[ErrorMonitoring] Configuration loaded from #{config_path}"
  else
    # Use default configuration if file doesn't exist
    Rails.application.config.error_monitoring = {
      'enabled' => Rails.env.production?,
      'error_rate_monitoring' => { 'threshold' => 0.001, 'enabled' => true },
      'circuit_breaker' => { 'enabled' => true },
      'recovery_manager' => { 'enabled' => true }
    }
    
    Rails.logger.warn "[ErrorMonitoring] Configuration file not found, using defaults"
  end

  ##
  # Initialize Error Monitoring Components
  config.after_initialize do
    next unless Rails.application.config.error_monitoring.dig('enabled')
    
    begin
      # Require error monitoring components
      require Rails.root.join('lib', 'error_monitoring', 'error_tracker')
      require Rails.root.join('lib', 'error_monitoring', 'circuit_breaker')
      require Rails.root.join('lib', 'error_monitoring', 'error_categorizer')
      require Rails.root.join('lib', 'error_monitoring', 'recovery_manager')
      require Rails.root.join('lib', 'error_monitoring', 'error_capture_middleware')
      
      # Configure error capture middleware
      if Rails.application.config.error_monitoring.dig('middleware', 'enabled') != false
        ErrorMonitoring::ErrorCaptureMiddleware.configure do |config|
          middleware_config = Rails.application.config.error_monitoring.dig('middleware') || {}
          
          config[:enabled] = middleware_config['enabled'] != false
          config[:sample_rate] = middleware_config['sample_rate'] || 1.0
          config[:performance_threshold] = middleware_config['performance_threshold'] || 5.seconds
          config[:enable_recovery] = middleware_config['enable_recovery'] != false
          config[:max_context_size] = middleware_config['max_context_size'] || 10_000
          
          # Add ignore patterns from configuration
          if middleware_config['ignore_patterns']
            config[:ignore_patterns] = middleware_config['ignore_patterns'].map { |pattern| Regexp.new(pattern) }
          end
        end
        
        # Add middleware to Rails stack
        Rails.application.config.middleware.use ErrorMonitoring::ErrorCaptureMiddleware
        
        Rails.logger.info "[ErrorMonitoring] Error capture middleware initialized"
      end
      
      # Initialize monitoring system health check
      Rails.application.config.after_initialize do
        # Perform initial system health check in a background thread
        Thread.new do
          sleep 5 # Allow Rails to fully initialize
          
          begin
            current_error_rate = ErrorMonitoring::ErrorTracker.current_error_rate
            threshold = ErrorMonitoring::ErrorTracker::PRODUCTION_ERROR_RATE_THRESHOLD
            
            Rails.logger.info "[ErrorMonitoring] System initialized successfully", {
              current_error_rate: current_error_rate,
              threshold: threshold,
              compliant: current_error_rate <= threshold
            }
            
            # Log initial circuit breaker status
            cb_health = ErrorMonitoring::CircuitBreaker.health_status
            Rails.logger.info "[ErrorMonitoring] Circuit breaker system initialized", {
              overall_health: cb_health[:overall_health],
              services_monitored: cb_health[:services].keys.length
            }
            
            # Log recovery manager status
            recovery_health = ErrorMonitoring::RecoveryManager.health_status
            Rails.logger.info "[ErrorMonitoring] Recovery manager initialized", {
              overall_health: recovery_health[:overall_health],
              active_degradations: recovery_health[:active_degradations].length
            }
            
          rescue => e
            Rails.logger.error "[ErrorMonitoring] Initialization health check failed: #{e.message}"
          end
        end
      end
      
      Rails.logger.info "[ErrorMonitoring] Error monitoring system initialized"
      
    rescue => e
      Rails.logger.error "[ErrorMonitoring] Failed to initialize error monitoring system: #{e.message}"
      Rails.logger.error e.backtrace.first(5).join("\n") if Rails.env.development?
      
      # Disable error monitoring if initialization fails
      Rails.application.config.error_monitoring['enabled'] = false
    end
  end

  ##
  # Configure Background Job Error Handling
  if defined?(Delayed::Job)
    Delayed::Worker.logger = Rails.logger
    
    # Hook into Delayed Job error handling
    Delayed::Job.class_eval do
      # Store original method if it exists
      if respond_to?(:handle_failed_job)
        alias_method :original_handle_failed_job, :handle_failed_job
      end
      
      def self.handle_failed_job(job, error)
        # Track job errors with error monitoring system
        if Rails.application.config.error_monitoring&.dig('enabled') && 
           defined?(ErrorMonitoring::ErrorTracker)
          
          ErrorMonitoring::ErrorTracker.track_error(error, {
            source: 'delayed_job',
            category: :background_job,
            severity: :medium,
            metadata: {
              job_id: job.id,
              job_class: job.handler,
              attempts: job.attempts,
              last_error: job.last_error,
              run_at: job.run_at,
              failed_at: job.failed_at
            }
          })
        end
        
        # Call original error handling
        original_handle_failed_job(job, error) if respond_to?(:original_handle_failed_job)
      end
    end
    
    Rails.logger.info "[ErrorMonitoring] Delayed Job error tracking configured"
  end

  ##
  # Configure ActiveRecord Error Handling
  if defined?(ActiveRecord)
    ActiveRecord::Base.class_eval do
      def self.handle_connection_error(error)
        # Track database connection errors
        if Rails.application.config.error_monitoring&.dig('enabled') && 
           defined?(ErrorMonitoring::ErrorTracker)
          
          ErrorMonitoring::ErrorTracker.track_error(error, {
            source: 'active_record',
            category: :database_connection,
            severity: :critical,
            metadata: {
              adapter: connection.adapter_name,
              database: connection.current_database,
              pool_size: connection_pool.size,
              active_connections: connection_pool.connections.count(&:in_use?),
              available_connections: connection_pool.available_connection_count
            }
          })
        end
        
        # Attempt recovery if configured
        if Rails.application.config.error_monitoring&.dig('recovery_manager', 'enabled') && 
           defined?(ErrorMonitoring::RecoveryManager)
          
          ErrorMonitoring::RecoveryManager.attempt_recovery(error, {
            source: 'active_record_connection',
            operation: 'database_connection'
          })
        end
      end
    end
    
    Rails.logger.info "[ErrorMonitoring] ActiveRecord error tracking configured"
  end

  ##
  # Configure ActionController Error Handling for API endpoints
  if defined?(ActionController::API)
    ActionController::API.class_eval do
      rescue_from StandardError do |error|
        # Track API errors
        if Rails.application.config.error_monitoring&.dig('enabled') && 
           defined?(ErrorMonitoring::ErrorTracker)
          
          ErrorMonitoring::ErrorTracker.track_error(error, {
            source: 'api_controller',
            category: :external_api,
            severity: :high,
            metadata: {
              controller: self.class.name,
              action: action_name,
              params: params.except(:password, :token, :secret),
              request_id: request.request_id,
              user_agent: request.user_agent,
              remote_ip: request.remote_ip
            }
          })
        end
        
        # Return appropriate API error response
        render json: { 
          error: 'Internal server error', 
          request_id: request.request_id,
          timestamp: Time.current.iso8601
        }, status: :internal_server_error
      end
    end
    
    Rails.logger.info "[ErrorMonitoring] ActionController::API error tracking configured"
  end

  ##
  # Configure periodic maintenance tasks
  if Rails.env.production? && Rails.application.config.error_monitoring&.dig('enabled')
    # Schedule periodic cleanup and maintenance
    Rails.application.config.after_initialize do
      Thread.new do
        loop do
          sleep 1.hour # Run every hour
          
          begin
            # Perform maintenance tasks
            Rails.logger.debug "[ErrorMonitoring] Running periodic maintenance"
            
            # Check error rate compliance
            current_error_rate = ErrorMonitoring::ErrorTracker.current_error_rate
            threshold = ErrorMonitoring::ErrorTracker::PRODUCTION_ERROR_RATE_THRESHOLD
            
            if current_error_rate > threshold
              Rails.logger.warn "[ErrorMonitoring] Error rate threshold breach detected in maintenance", {
                current_rate: current_error_rate,
                threshold: threshold
              }
              
              # Trigger threshold breach check
              ErrorMonitoring::ErrorTracker.check_threshold_breach
            end
            
            # Check circuit breaker health
            cb_health = ErrorMonitoring::CircuitBreaker.health_status
            if cb_health[:overall_health] == :unhealthy
              Rails.logger.warn "[ErrorMonitoring] Circuit breaker system unhealthy", {
                overall_health: cb_health[:overall_health]
              }
            end
            
            # Check recovery system health
            recovery_health = ErrorMonitoring::RecoveryManager.health_status
            if recovery_health[:overall_health] == :unhealthy
              Rails.logger.warn "[ErrorMonitoring] Recovery system unhealthy", {
                overall_health: recovery_health[:overall_health],
                active_degradations: recovery_health[:active_degradations].length
              }
            end
            
          rescue => e
            Rails.logger.error "[ErrorMonitoring] Periodic maintenance failed: #{e.message}"
          end
        end
      end
      
      Rails.logger.info "[ErrorMonitoring] Periodic maintenance scheduled"
    end
  end
end

##
# Add error monitoring navigation to Rails admin
if defined?(RailsAdmin)
  RailsAdmin.config do |config|
    config.navigation_static_label = "Monitoring"
    config.navigation_static_links = {
      'Error Monitoring' => '/error_monitoring',
      'System Health' => '/error_monitoring/health',
      'Circuit Breakers' => '/error_monitoring/circuit_breakers',
      'Recovery Management' => '/error_monitoring/recovery'
    }
  end
end

##
# Console helpers for development
if Rails.env.development? || Rails.env.test?
  Rails.application.console do
    puts "Error Monitoring System Console Commands:"
    puts "  ErrorMonitoring::ErrorTracker.current_error_rate"
    puts "  ErrorMonitoring::CircuitBreaker.health_status"
    puts "  ErrorMonitoring::RecoveryManager.health_status"
    puts "  ErrorMonitoring::ErrorCategorizer.analyze_patterns"
    puts ""
    puts "Example: Test error tracking"
    puts "  ErrorMonitoring::ErrorTracker.track_error(StandardError.new('Test error'))"
    puts ""
  end
end

Rails.logger.info "[ErrorMonitoring] Initializer completed successfully"