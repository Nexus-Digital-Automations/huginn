# frozen_string_literal: true

require_relative 'http_client_service'
require_relative 'integration_module'
require_relative 'security_integration'

##
# Comprehensive Usage Examples for Parlant Bridge Integration
# Demonstrates practical implementation patterns for Ruby/Huginn agents
# with conversational validation, security integration, and error handling.
#

module ParlantBridge
  module UsageExamples
    ##
    # Example Huginn Agent with Parlant Integration
    # Shows how to integrate conversational validation into existing agents
    #
    class EmailNotificationAgent
      include ParlantBridge::IntegrationModule
      
      # Configure Parlant integration
      configure_parlant(
        server_url: ENV['PARLANT_SERVER_URL'] || 'http://localhost:8080',
        pool_size: 5,
        timeout: 30,
        cache_ttl: 300,
        logger: Logger.new($stdout, level: Logger::INFO)
      )
      
      # Define method security classifications
      parlant_internal :check_email_queue
      parlant_secure :send_notification, confirmation_required: true
      parlant_critical :send_emergency_alert, confirmation_required: true, audit_level: 'detailed'
      parlant_restricted :modify_user_preferences, emergency_bypass: false
      
      attr_reader :id, :user, :logger
      
      def initialize(id: 1, user: nil)
        @id = id
        @user = user || OpenStruct.new(id: 'system', role: 'agent')
        @logger = Logger.new($stdout, level: Logger::INFO)
      end
      
      ##
      # Check email queue - INTERNAL classification
      # Light validation with caching
      #
      def check_email_queue
        @logger.info("Checking email queue")
        
        # Simulate email queue check
        queue_size = rand(0..50)
        
        {
          queue_size: queue_size,
          status: queue_size > 30 ? 'high' : 'normal',
          timestamp: Time.now.iso8601
        }
      end
      
      ##
      # Send notification - CONFIDENTIAL classification  
      # Requires conversational validation with confirmation
      #
      def send_notification(recipient, message, priority = 'normal')
        @logger.info("Sending notification to #{recipient}")
        
        # Simulate notification sending
        notification_id = SecureRandom.hex(8)
        
        # This would be the actual notification logic
        result = {
          notification_id: notification_id,
          recipient: recipient,
          message: message,
          priority: priority,
          sent_at: Time.now.iso8601,
          status: 'sent'
        }
        
        @logger.info("Notification sent - ID: #{notification_id}")
        result
      end
      
      ##
      # Send emergency alert - CLASSIFIED classification
      # Requires conversational validation with detailed audit trail
      #
      def send_emergency_alert(recipients, alert_type, message)
        @logger.warn("Sending emergency alert - Type: #{alert_type}")
        
        # Simulate emergency alert
        alert_id = SecureRandom.hex(10)
        
        result = {
          alert_id: alert_id,
          recipients: recipients,
          alert_type: alert_type,
          message: message,
          sent_at: Time.now.iso8601,
          status: 'sent',
          escalation_level: 'critical'
        }
        
        @logger.warn("Emergency alert sent - ID: #{alert_id}")
        result
      end
      
      ##
      # Modify user preferences - RESTRICTED classification
      # No emergency bypass, always requires validation
      #
      def modify_user_preferences(user_id, preferences)
        @logger.info("Modifying preferences for user #{user_id}")
        
        # Simulate preference modification
        modification_id = SecureRandom.hex(6)
        
        result = {
          modification_id: modification_id,
          user_id: user_id,
          preferences: preferences,
          modified_at: Time.now.iso8601,
          status: 'updated'
        }
        
        @logger.info("Preferences modified - ID: #{modification_id}")
        result
      end
    end
    
    ##
    # Example Data Processing Agent with Custom Validation
    # Shows advanced integration patterns with custom validators
    #
    class DataProcessingAgent
      include ParlantBridge::IntegrationModule
      
      configure_parlant(
        server_url: ENV['PARLANT_SERVER_URL'] || 'http://localhost:8080',
        pool_size: 10,
        timeout: 45,
        cache_ttl: 600
      )
      
      # Custom validator for data operations
      DATA_VALIDATOR = ->(method_name, args, kwargs) do
        # Custom validation logic
        if method_name.to_s.include?('delete') && args.first.is_a?(Hash)
          record_count = args.first[:record_count] || 0
          if record_count > 1000
            # Force conversational validation for large deletions
            return nil # Let Parlant handle validation
          end
        end
        
        # Allow small operations without Parlant validation
        return ValidationResult.new(
          status: 'approved',
          operation_id: SecureRandom.hex(4),
          confidence: 0.8,
          reason: 'Pre-approved by custom validator'
        ) if record_count && record_count < 10
        
        nil # Continue with normal Parlant validation
      end
      
      # Define method validations with custom validator
      parlant_internal :process_data
      parlant_secure :transform_data, custom_validator: DATA_VALIDATOR
      parlant_critical :delete_data, confirmation_required: true, custom_validator: DATA_VALIDATOR
      
      attr_reader :id, :user, :logger
      
      def initialize(id: 2, user: nil)
        @id = id
        @user = user || OpenStruct.new(id: 'data_processor', role: 'service')
        @logger = Logger.new($stdout, level: Logger::INFO)
      end
      
      def process_data(data_source, options = {})
        @logger.info("Processing data from #{data_source}")
        
        # Simulate data processing
        processed_records = rand(100..1000)
        
        {
          source: data_source,
          processed_records: processed_records,
          options: options,
          processing_time: rand(1.0..10.0).round(2),
          status: 'completed'
        }
      end
      
      def transform_data(input_data, transformation_rules)
        @logger.info("Transforming data with #{transformation_rules.keys.size} rules")
        
        # Simulate data transformation
        {
          input_size: input_data.respond_to?(:size) ? input_data.size : 'unknown',
          transformation_rules: transformation_rules.keys,
          output_size: rand(50..500),
          transformed_at: Time.now.iso8601,
          status: 'transformed'
        }
      end
      
      def delete_data(criteria)
        record_count = criteria[:record_count] || rand(1..2000)
        @logger.warn("Deleting #{record_count} records matching criteria")
        
        # Simulate data deletion
        {
          criteria: criteria,
          records_deleted: record_count,
          deleted_at: Time.now.iso8601,
          backup_created: record_count > 100,
          status: 'deleted'
        }
      end
    end
    
    ##
    # Example Security Agent with Authentication Integration
    # Shows security context usage and audit logging
    #
    class SecurityAgent
      include ParlantBridge::IntegrationModule
      include ParlantBridge::SecurityIntegration
      
      configure_parlant(
        server_url: ENV['PARLANT_SERVER_URL'] || 'http://localhost:8080',
        pool_size: 15,
        timeout: 60
      )
      
      # Security operations with appropriate classifications
      parlant_internal :check_user_status
      parlant_secure :update_user_permissions
      parlant_restricted :disable_user_account
      parlant_critical :grant_admin_access, confirmation_required: true, audit_level: 'detailed'
      
      attr_reader :id, :user, :auth_manager, :audit_logger
      
      def initialize(id: 3, user: nil)
        @id = id
        @user = user || OpenStruct.new(id: 'security_agent', role: 'security')
        
        # Initialize security components
        @auth_manager = AuthenticationManager.new(
          jwt_public_key_path: ENV['JWT_PUBLIC_KEY_PATH'],
          logger: Logger.new($stdout, level: Logger::INFO)
        )
        
        @audit_logger = AuditLogger.new(
          retention_days: 90,
          logger: Logger.new($stdout, level: Logger::INFO)
        )
        
        @logger = Logger.new($stdout, level: Logger::INFO)
      end
      
      def check_user_status(user_id)
        @logger.info("Checking status for user #{user_id}")
        
        # Simulate user status check
        {
          user_id: user_id,
          status: ['active', 'inactive', 'suspended', 'locked'].sample,
          last_login: Time.now - rand(1..30) * 24 * 60 * 60,
          failed_login_attempts: rand(0..3),
          account_created: Time.now - rand(30..365) * 24 * 60 * 60
        }
      end
      
      def update_user_permissions(user_id, new_permissions)
        @logger.info("Updating permissions for user #{user_id}")
        
        # Log security event
        @audit_logger.log_security_event(
          'permission_update',
          get_security_context,
          { target_user: user_id, new_permissions: new_permissions },
          'medium'
        )
        
        {
          user_id: user_id,
          previous_permissions: ['read', 'write'], # Simulated
          new_permissions: new_permissions,
          updated_at: Time.now.iso8601,
          updated_by: @user.id,
          status: 'updated'
        }
      end
      
      def disable_user_account(user_id, reason)
        @logger.warn("Disabling account for user #{user_id} - Reason: #{reason}")
        
        # Log critical security event
        @audit_logger.log_security_event(
          'account_disabled',
          get_security_context,
          { target_user: user_id, reason: reason },
          'high'
        )
        
        {
          user_id: user_id,
          disabled_at: Time.now.iso8601,
          disabled_by: @user.id,
          reason: reason,
          status: 'disabled'
        }
      end
      
      def grant_admin_access(user_id, access_level, justification)
        @logger.error("Granting admin access - User: #{user_id}, Level: #{access_level}")
        
        # Log critical security event
        @audit_logger.log_security_event(
          'admin_access_granted',
          get_security_context,
          { 
            target_user: user_id, 
            access_level: access_level, 
            justification: justification 
          },
          'critical'
        )
        
        {
          user_id: user_id,
          access_level: access_level,
          granted_at: Time.now.iso8601,
          granted_by: @user.id,
          justification: justification,
          expires_at: Time.now + 24 * 60 * 60, # 24 hours
          status: 'granted'
        }
      end
      
      private
      
      def get_security_context
        SecurityContext.new(
          user_id: @user.id,
          username: @user.respond_to?(:username) ? @user.username : @user.id,
          roles: [@user.role],
          permissions: ['security_operations'],
          security_level: 'RESTRICTED'
        )
      end
    end
    
    ##
    # Example Usage Runner
    # Shows how to use the agents with proper error handling
    #
    class UsageRunner
      attr_reader :email_agent, :data_agent, :security_agent, :logger
      
      def initialize
        @logger = Logger.new($stdout, level: Logger::INFO)
        
        # Initialize agents
        @email_agent = EmailNotificationAgent.new(id: 1)
        @data_agent = DataProcessingAgent.new(id: 2)
        @security_agent = SecurityAgent.new(id: 3)
        
        @logger.info("UsageRunner initialized with 3 agents")
      end
      
      ##
      # Run comprehensive example scenarios
      #
      def run_examples
        @logger.info("Starting Parlant Bridge usage examples")
        
        # Example 1: Email operations
        run_email_examples
        
        # Example 2: Data processing with custom validation
        run_data_processing_examples
        
        # Example 3: Security operations with audit logging
        run_security_examples
        
        # Example 4: Error handling and recovery
        run_error_handling_examples
        
        # Example 5: Health monitoring
        run_health_monitoring_examples
        
        @logger.info("Parlant Bridge usage examples completed")
      end
      
      private
      
      def run_email_examples
        @logger.info("=== Email Agent Examples ===")
        
        begin
          # Check queue (light validation)
          queue_status = @email_agent.check_email_queue
          @logger.info("Queue status: #{queue_status}")
          
          # Send notification (conversational validation)
          notification_result = @email_agent.send_notification(
            'admin@example.com',
            'System maintenance scheduled',
            'normal'
          )
          @logger.info("Notification result: #{notification_result}")
          
          # Send emergency alert (requires confirmation)
          alert_result = @email_agent.send_emergency_alert(
            ['admin@example.com', 'ops@example.com'],
            'security_breach',
            'Unauthorized access detected'
          )
          @logger.info("Alert result: #{alert_result}")
          
        rescue ParlantBridge::ValidationFailedError => e
          @logger.error("Validation failed: #{e.message}")
        rescue StandardError => e
          @logger.error("Email example failed: #{e.message}")
        end
      end
      
      def run_data_processing_examples
        @logger.info("=== Data Processing Agent Examples ===")
        
        begin
          # Process data (standard validation)
          process_result = @data_agent.process_data('user_events', batch_size: 1000)
          @logger.info("Process result: #{process_result}")
          
          # Transform data (custom validator)
          transform_result = @data_agent.transform_data(
            [1, 2, 3, 4, 5],
            { normalize: true, filter: 'active' }
          )
          @logger.info("Transform result: #{transform_result}")
          
          # Delete small dataset (pre-approved by custom validator)
          small_delete_result = @data_agent.delete_data(
            criteria: { status: 'inactive' },
            record_count: 5
          )
          @logger.info("Small delete result: #{small_delete_result}")
          
          # Delete large dataset (requires conversational validation)
          large_delete_result = @data_agent.delete_data(
            criteria: { created_before: '2023-01-01' },
            record_count: 1500
          )
          @logger.info("Large delete result: #{large_delete_result}")
          
        rescue ParlantBridge::ValidationFailedError => e
          @logger.error("Data processing validation failed: #{e.message}")
        rescue StandardError => e
          @logger.error("Data processing example failed: #{e.message}")
        end
      end
      
      def run_security_examples
        @logger.info("=== Security Agent Examples ===")
        
        begin
          # Check user status (internal)
          user_status = @security_agent.check_user_status('user_123')
          @logger.info("User status: #{user_status}")
          
          # Update permissions (secure, with audit)
          permission_result = @security_agent.update_user_permissions(
            'user_123',
            ['read', 'write', 'admin']
          )
          @logger.info("Permission update: #{permission_result}")
          
          # Disable account (restricted, high audit)
          disable_result = @security_agent.disable_user_account(
            'user_456',
            'Multiple failed login attempts'
          )
          @logger.info("Account disable: #{disable_result}")
          
          # Grant admin access (critical, requires confirmation)
          admin_result = @security_agent.grant_admin_access(
            'user_789',
            'super_admin',
            'Emergency system maintenance required'
          )
          @logger.info("Admin access: #{admin_result}")
          
        rescue ParlantBridge::ValidationFailedError => e
          @logger.error("Security validation failed: #{e.message}")
        rescue StandardError => e
          @logger.error("Security example failed: #{e.message}")
        end
      end
      
      def run_error_handling_examples
        @logger.info("=== Error Handling Examples ===")
        
        begin
          # Simulate network error
          simulate_network_error
          
        rescue ParlantBridge::ConnectionError => e
          @logger.error("Network error handled: #{e.message}")
          
        rescue ParlantBridge::CircuitBreakerOpenError => e
          @logger.error("Circuit breaker active: #{e.message}")
          
        rescue StandardError => e
          @logger.error("Unexpected error: #{e.message}")
        end
      end
      
      def run_health_monitoring_examples
        @logger.info("=== Health Monitoring Examples ===")
        
        begin
          # Check Parlant health
          email_health = @email_agent.parlant_health_status
          @logger.info("Email agent health: #{email_health}")
          
          # Check wrapped methods
          wrapped_methods = @email_agent.class.parlant_wrapped_methods_list
          @logger.info("Wrapped methods: #{wrapped_methods.keys}")
          
          # Manual validation example
          manual_result = @email_agent.validate_operation_manually(
            'custom_operation',
            { param1: 'value1' },
            'CONFIDENTIAL'
          )
          @logger.info("Manual validation: #{manual_result}")
          
        rescue StandardError => e
          @logger.error("Health monitoring failed: #{e.message}")
        end
      end
      
      def simulate_network_error
        # This would trigger various error conditions in a real scenario
        raise ParlantBridge::ConnectionError, "Simulated network error"
      end
    end
  end
end

# Example usage:
if __FILE__ == $0
  # Set up environment
  ENV['PARLANT_SERVER_URL'] ||= 'http://localhost:8080'
  ENV['JWT_PUBLIC_KEY_PATH'] ||= '/path/to/jwt/public/key.pem'
  
  # Run examples
  runner = ParlantBridge::UsageExamples::UsageRunner.new
  runner.run_examples
end