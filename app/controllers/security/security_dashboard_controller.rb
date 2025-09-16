# frozen_string_literal: true

##
# Security Dashboard Controller
#
# Provides RESTful API endpoints for security dashboards, metrics,
# and real-time security monitoring data with role-based access control.
#
# Features:
# - Real-time security metrics and dashboard data
# - Interactive security visualizations and charts
# - Security event streaming and notifications
# - Compliance reporting and audit trail access
# - Threat intelligence and anomaly detection displays
# - Emergency override monitoring and controls
# - Performance metrics and system health indicators
#
# @example API Usage
#   GET /api/v1/security/dashboard/overview
#   GET /api/v1/security/metrics/authentication
#   GET /api/v1/security/alerts/active
#   POST /api/v1/security/emergency/override
#
# @author AIgent Security Team
# @since 1.0.0
class Security::SecurityDashboardController < ApplicationController
  before_action :authenticate_user!
  before_action :authorize_security_dashboard_access!
  before_action :set_security_services
  before_action :log_dashboard_access

  # Dashboard Types and Access Control
  DASHBOARD_ACCESS_ROLES = {
    'security_overview' => %w[security_admin security_officer system_admin],
    'authentication_metrics' => %w[security_admin auth_admin system_admin security_officer],
    'threat_intelligence' => %w[security_admin threat_analyst security_officer],
    'compliance_monitoring' => %w[compliance_officer security_admin legal_admin],
    'emergency_override' => %w[security_admin emergency_coordinator system_admin],
    'audit_trails' => %w[security_admin audit_admin compliance_officer],
    'performance_metrics' => %w[security_admin system_admin operations_admin]
  }.freeze

  ##
  # Security Overview Dashboard
  #
  # Returns comprehensive security overview with current threat level,
  # active sessions, recent alerts, and overall security score.
  #
  # GET /api/v1/security/dashboard/overview
  def overview
    dashboard_request_id = generate_dashboard_request_id
    
    begin
      # Gather real-time security overview data
      security_overview = {
        current_threat_level: @monitoring_service.get_current_threat_level,
        active_secure_sessions: @auth_bridge_service.count_active_sessions,
        recent_security_alerts: @monitoring_service.get_recent_alerts(limit: 10),
        overall_security_score: calculate_overall_security_score,
        conversational_validations_today: @conversational_validator.get_daily_validation_count,
        compliance_status: @compliance_service.get_current_compliance_status,
        emergency_overrides_active: @emergency_override_service.get_active_overrides_count,
        system_health_indicators: gather_system_health_indicators
      }

      # Add trending data
      security_overview[:trends] = {
        threat_level_trend: @monitoring_service.get_threat_level_trend(hours: 24),
        authentication_success_rate_trend: @auth_bridge_service.get_success_rate_trend(hours: 24),
        security_incidents_trend: @monitoring_service.get_incidents_trend(days: 7)
      }

      # Add critical alerts that need attention
      security_overview[:critical_alerts] = @monitoring_service.get_critical_alerts_requiring_attention

      # Record dashboard access for audit
      record_dashboard_access('security_overview', dashboard_request_id, security_overview)

      render json: {
        success: true,
        dashboard_type: 'security_overview',
        dashboard_request_id: dashboard_request_id,
        data: security_overview,
        last_updated: Time.current.iso8601,
        refresh_interval: 30, # seconds
        timestamp: Time.current.iso8601
      }

    rescue StandardError => e
      handle_dashboard_error(e, 'security_overview', dashboard_request_id)
    end
  end

  ##
  # Authentication Metrics Dashboard
  #
  # Returns detailed authentication metrics including login rates,
  # MFA usage, device analysis, and location-based insights.
  #
  # GET /api/v1/security/dashboard/authentication
  def authentication_metrics
    dashboard_request_id = generate_dashboard_request_id
    
    begin
      time_range = params[:time_range] || '24h'
      
      authentication_data = {
        login_statistics: {
          total_attempts: @auth_bridge_service.get_login_attempts_count(time_range),
          successful_logins: @auth_bridge_service.get_successful_logins_count(time_range),
          failed_attempts: @auth_bridge_service.get_failed_attempts_count(time_range),
          success_rate: @auth_bridge_service.calculate_success_rate(time_range)
        },
        mfa_usage: {
          mfa_enabled_users: @auth_bridge_service.count_mfa_enabled_users,
          mfa_challenges_issued: @auth_bridge_service.get_mfa_challenges_count(time_range),
          mfa_success_rate: @auth_bridge_service.get_mfa_success_rate(time_range)
        },
        device_analysis: {
          trusted_devices: @auth_bridge_service.count_trusted_devices,
          new_device_registrations: @auth_bridge_service.get_new_devices_count(time_range),
          suspicious_device_blocks: @auth_bridge_service.get_blocked_devices_count(time_range)
        },
        location_analysis: {
          login_countries: @auth_bridge_service.get_login_locations_summary(time_range),
          suspicious_locations: @auth_bridge_service.get_suspicious_locations(time_range),
          geolocation_blocks: @auth_bridge_service.get_geolocation_blocks_count(time_range)
        },
        session_management: {
          active_sessions: @auth_bridge_service.count_active_sessions,
          average_session_duration: @auth_bridge_service.get_average_session_duration,
          concurrent_sessions_peak: @auth_bridge_service.get_concurrent_sessions_peak(time_range)
        }
      }

      # Add time-series data for charts
      authentication_data[:time_series] = {
        login_attempts_over_time: @auth_bridge_service.get_login_attempts_time_series(time_range),
        authentication_latency_over_time: @auth_bridge_service.get_latency_time_series(time_range),
        failed_attempts_distribution: @auth_bridge_service.get_failure_reasons_distribution(time_range)
      }

      record_dashboard_access('authentication_metrics', dashboard_request_id, authentication_data)

      render json: {
        success: true,
        dashboard_type: 'authentication_metrics',
        dashboard_request_id: dashboard_request_id,
        time_range: time_range,
        data: authentication_data,
        last_updated: Time.current.iso8601,
        refresh_interval: 60,
        timestamp: Time.current.iso8601
      }

    rescue StandardError => e
      handle_dashboard_error(e, 'authentication_metrics', dashboard_request_id)
    end
  end

  ##
  # Threat Intelligence Dashboard
  #
  # Returns threat intelligence data including threat indicators,
  # attack patterns, risk analysis, and detected anomalies.
  #
  # GET /api/v1/security/dashboard/threat_intelligence
  def threat_intelligence
    dashboard_request_id = generate_dashboard_request_id
    
    begin
      threat_data = {
        current_threat_level: @monitoring_service.get_current_threat_level,
        active_threat_indicators: @monitoring_service.get_active_threat_indicators,
        recent_attack_patterns: @monitoring_service.get_recent_attack_patterns(limit: 20),
        risk_analysis: {
          high_risk_users: @monitoring_service.get_high_risk_users,
          suspicious_activities: @monitoring_service.get_suspicious_activities(hours: 24),
          anomaly_detections: @monitoring_service.get_recent_anomalies(hours: 24)
        },
        threat_intelligence_feeds: {
          external_threat_feeds: @monitoring_service.get_external_threat_feed_status,
          threat_indicators_processed: @monitoring_service.get_threat_indicators_count(hours: 24),
          ioc_matches: @monitoring_service.get_ioc_matches(hours: 24)
        },
        behavioral_analysis: {
          user_behavior_anomalies: @monitoring_service.get_user_behavior_anomalies,
          system_behavior_anomalies: @monitoring_service.get_system_behavior_anomalies,
          ml_model_predictions: @monitoring_service.get_ml_predictions
        }
      }

      # Add threat trend analysis
      threat_data[:trends] = {
        threat_level_history: @monitoring_service.get_threat_level_history(days: 30),
        attack_pattern_trends: @monitoring_service.get_attack_pattern_trends(days: 7),
        anomaly_detection_trends: @monitoring_service.get_anomaly_trends(days: 7)
      }

      record_dashboard_access('threat_intelligence', dashboard_request_id, threat_data)

      render json: {
        success: true,
        dashboard_type: 'threat_intelligence',
        dashboard_request_id: dashboard_request_id,
        data: threat_data,
        last_updated: Time.current.iso8601,
        refresh_interval: 120,
        timestamp: Time.current.iso8601
      }

    rescue StandardError => e
      handle_dashboard_error(e, 'threat_intelligence', dashboard_request_id)
    end
  end

  ##
  # Compliance Monitoring Dashboard
  #
  # Returns compliance status, audit coverage, policy violations,
  # and regulatory compliance scores.
  #
  # GET /api/v1/security/dashboard/compliance
  def compliance_monitoring
    dashboard_request_id = generate_dashboard_request_id
    
    begin
      compliance_data = {
        overall_compliance_score: @compliance_service.get_overall_compliance_score,
        framework_compliance: {
          gdpr_compliance: @compliance_service.get_gdpr_compliance_score,
          soc2_compliance: @compliance_service.get_soc2_compliance_score,
          hipaa_compliance: @compliance_service.get_hipaa_compliance_score,
          pci_dss_compliance: @compliance_service.get_pci_dss_compliance_score
        },
        audit_coverage: {
          total_audit_records: @audit_system.get_total_records_count,
          audit_coverage_percentage: @audit_system.get_coverage_percentage,
          recent_audit_activity: @audit_system.get_recent_activity(days: 7)
        },
        policy_violations: {
          active_violations: @compliance_service.get_active_violations,
          resolved_violations_this_month: @compliance_service.get_resolved_violations_count(30),
          violation_trends: @compliance_service.get_violation_trends(days: 30)
        },
        data_subject_rights: {
          pending_requests: @compliance_service.get_pending_dsr_count,
          completed_requests_this_month: @compliance_service.get_completed_dsr_count(30),
          average_response_time: @compliance_service.get_average_dsr_response_time
        }
      }

      # Add compliance trend analysis
      compliance_data[:trends] = {
        compliance_score_history: @compliance_service.get_compliance_score_history(days: 90),
        audit_activity_trends: @audit_system.get_activity_trends(days: 30),
        violation_resolution_trends: @compliance_service.get_resolution_trends(days: 30)
      }

      record_dashboard_access('compliance_monitoring', dashboard_request_id, compliance_data)

      render json: {
        success: true,
        dashboard_type: 'compliance_monitoring',
        dashboard_request_id: dashboard_request_id,
        data: compliance_data,
        last_updated: Time.current.iso8601,
        refresh_interval: 300,
        timestamp: Time.current.iso8601
      }

    rescue StandardError => e
      handle_dashboard_error(e, 'compliance_monitoring', dashboard_request_id)
    end
  end

  ##
  # Emergency Override Dashboard
  #
  # Returns emergency override status, active overrides, approval workflows,
  # and emergency access monitoring data.
  #
  # GET /api/v1/security/dashboard/emergency
  def emergency_override
    dashboard_request_id = generate_dashboard_request_id
    
    begin
      emergency_data = {
        active_overrides: @emergency_override_service.get_active_emergency_overrides,
        pending_approvals: @emergency_override_service.get_pending_approval_requests,
        recent_emergency_activity: @emergency_override_service.get_recent_activity(days: 7),
        emergency_statistics: {
          total_requests_this_month: @emergency_override_service.get_monthly_request_count,
          approval_success_rate: @emergency_override_service.get_approval_success_rate,
          average_approval_time: @emergency_override_service.get_average_approval_time,
          most_common_scenarios: @emergency_override_service.get_common_scenarios
        },
        monitoring_status: {
          active_monitoring_sessions: @emergency_override_service.count_active_monitoring_sessions,
          automated_cleanups_scheduled: @emergency_override_service.count_scheduled_cleanups,
          real_time_alerts_active: @emergency_override_service.count_active_alerts
        }
      }

      # Add emergency trend analysis
      emergency_data[:trends] = {
        request_volume_trends: @emergency_override_service.get_request_volume_trends(days: 30),
        scenario_usage_trends: @emergency_override_service.get_scenario_trends(days: 30),
        approval_time_trends: @emergency_override_service.get_approval_time_trends(days: 30)
      }

      record_dashboard_access('emergency_override', dashboard_request_id, emergency_data)

      render json: {
        success: true,
        dashboard_type: 'emergency_override',
        dashboard_request_id: dashboard_request_id,
        data: emergency_data,
        last_updated: Time.current.iso8601,
        refresh_interval: 30,
        timestamp: Time.current.iso8601
      }

    rescue StandardError => e
      handle_dashboard_error(e, 'emergency_override', dashboard_request_id)
    end
  end

  ##
  # Real-time Security Metrics
  #
  # Returns live security metrics for real-time monitoring displays.
  #
  # GET /api/v1/security/metrics/realtime
  def realtime_metrics
    metrics_request_id = generate_metrics_request_id
    
    begin
      realtime_data = {
        system_status: {
          overall_security_status: determine_overall_security_status,
          authentication_system_status: @auth_bridge_service.health_status[:service_status],
          monitoring_system_status: @monitoring_service.health_status[:monitoring_service_status],
          audit_system_status: @audit_system.health_status[:audit_system_status]
        },
        live_metrics: {
          active_authenticated_users: @auth_bridge_service.count_active_users,
          authentication_attempts_per_minute: @auth_bridge_service.get_attempts_per_minute,
          security_events_per_minute: @monitoring_service.get_events_per_minute,
          current_threat_score: @monitoring_service.get_current_threat_score,
          system_performance: {
            average_auth_latency: @auth_bridge_service.get_current_average_latency,
            system_cpu_usage: get_system_cpu_usage,
            system_memory_usage: get_system_memory_usage,
            database_connection_pool: get_database_pool_status
          }
        },
        alerts_summary: {
          critical_alerts_count: @monitoring_service.count_critical_alerts,
          warning_alerts_count: @monitoring_service.count_warning_alerts,
          recent_alert_types: @monitoring_service.get_recent_alert_types
        }
      }

      render json: {
        success: true,
        metrics_type: 'realtime',
        metrics_request_id: metrics_request_id,
        data: realtime_data,
        timestamp: Time.current.iso8601,
        next_update_in_seconds: 10
      }

    rescue StandardError => e
      handle_metrics_error(e, 'realtime', metrics_request_id)
    end
  end

  ##
  # Security Alerts Management
  #
  # Returns active security alerts with filtering and pagination.
  #
  # GET /api/v1/security/alerts
  def security_alerts
    alerts_request_id = generate_alerts_request_id
    
    begin
      # Parse query parameters
      severity = params[:severity] # critical, warning, info
      status = params[:status] # active, acknowledged, resolved
      limit = (params[:limit] || 50).to_i
      offset = (params[:offset] || 0).to_i
      
      alerts_data = {
        active_alerts: @monitoring_service.get_filtered_alerts(
          severity: severity,
          status: status,
          limit: limit,
          offset: offset
        ),
        alerts_summary: {
          total_active_alerts: @monitoring_service.count_active_alerts,
          alerts_by_severity: @monitoring_service.get_alerts_by_severity_count,
          alerts_by_type: @monitoring_service.get_alerts_by_type_count
        },
        alert_trends: {
          alerts_over_time: @monitoring_service.get_alerts_time_series(hours: 24),
          resolution_times: @monitoring_service.get_alert_resolution_times
        }
      }

      record_dashboard_access('security_alerts', alerts_request_id, { 
        filter_applied: { severity: severity, status: status },
        results_count: alerts_data[:active_alerts].size 
      })

      render json: {
        success: true,
        alerts_request_id: alerts_request_id,
        data: alerts_data,
        pagination: {
          limit: limit,
          offset: offset,
          total_count: alerts_data[:alerts_summary][:total_active_alerts]
        },
        timestamp: Time.current.iso8601
      }

    rescue StandardError => e
      handle_alerts_error(e, alerts_request_id)
    end
  end

  private

  ##
  # Set Security Services
  #
  # Initializes all security service dependencies.
  def set_security_services
    @auth_bridge_service = ParlantAuthBridgeService.new
    @monitoring_service = SecurityMonitoringService.new
    @conversational_validator = ConversationalSecurityValidator.new
    @compliance_service = DataProtectionComplianceService.new
    @emergency_override_service = EmergencyOverrideService.new
    @audit_system = ComprehensiveAuditSystem.new
  rescue StandardError => e
    logger.error "[SecurityDashboard] Failed to initialize security services: #{e.message}"
    render json: { 
      error: 'security_services_unavailable', 
      message: 'Security services temporarily unavailable',
      timestamp: Time.current.iso8601
    }, status: 503
    return
  end

  ##
  # Authorize Security Dashboard Access
  #
  # Checks if current user has access to security dashboard functionality.
  def authorize_security_dashboard_access!
    dashboard_type = action_name
    required_roles = DASHBOARD_ACCESS_ROLES[dashboard_type] || %w[security_admin]
    
    user_roles = current_user.roles.map(&:name)
    has_access = (required_roles & user_roles).any?

    unless has_access
      render json: {
        error: 'insufficient_permissions',
        message: 'Insufficient permissions for security dashboard access',
        required_roles: required_roles,
        timestamp: Time.current.iso8601
      }, status: 403
      return
    end
  end

  ##
  # Log Dashboard Access
  #
  # Records dashboard access for security audit trails.
  def log_dashboard_access
    @audit_system.create_audit_trail(
      event_type: 'data_access',
      user_id: current_user.id,
      operation: 'security_dashboard_access',
      context: {
        dashboard_type: action_name,
        controller: controller_name,
        ip_address: request.remote_ip,
        user_agent: request.user_agent
      },
      risk_level: 'low'
    )
  end

  ##
  # Generate Dashboard Request ID
  #
  # @return [String] Unique dashboard request ID
  def generate_dashboard_request_id
    "dashboard_#{Time.current.to_i}_#{SecureRandom.hex(8)}"
  end

  ##
  # Generate Metrics Request ID
  #
  # @return [String] Unique metrics request ID
  def generate_metrics_request_id
    "metrics_#{Time.current.to_i}_#{SecureRandom.hex(8)}"
  end

  ##
  # Generate Alerts Request ID
  #
  # @return [String] Unique alerts request ID
  def generate_alerts_request_id
    "alerts_#{Time.current.to_i}_#{SecureRandom.hex(8)}"
  end

  ##
  # Calculate Overall Security Score
  #
  # @return [Float] Overall security score (0-100)
  def calculate_overall_security_score
    scores = {
      authentication_security: @auth_bridge_service.get_security_score,
      threat_detection: @monitoring_service.get_threat_detection_score,
      compliance_score: @compliance_service.get_overall_compliance_score,
      audit_coverage: @audit_system.get_coverage_score,
      system_hardening: get_system_hardening_score
    }

    # Weighted average of security components
    weights = {
      authentication_security: 0.25,
      threat_detection: 0.25,
      compliance_score: 0.20,
      audit_coverage: 0.15,
      system_hardening: 0.15
    }

    weighted_score = scores.sum { |component, score| score * weights[component] }
    weighted_score.round(1)
  end

  ##
  # Determine Overall Security Status
  #
  # @return [String] Overall security status
  def determine_overall_security_status
    security_score = calculate_overall_security_score
    critical_alerts = @monitoring_service.count_critical_alerts
    
    return 'critical' if critical_alerts > 0
    return 'warning' if security_score < 70
    return 'good' if security_score < 90
    'excellent'
  end

  ##
  # Gather System Health Indicators
  #
  # @return [Hash] System health indicators
  def gather_system_health_indicators
    {
      database_status: check_database_health,
      redis_status: check_redis_health,
      external_services_status: check_external_services_health,
      system_resources: {
        cpu_usage: get_system_cpu_usage,
        memory_usage: get_system_memory_usage,
        disk_usage: get_system_disk_usage
      }
    }
  end

  ##
  # Record Dashboard Access
  #
  # @param dashboard_type [String] Type of dashboard accessed
  # @param request_id [String] Request ID
  # @param data_summary [Hash] Summary of data accessed
  def record_dashboard_access(dashboard_type, request_id, data_summary)
    logger.info "[SecurityDashboard] Dashboard accessed", {
      dashboard_type: dashboard_type,
      request_id: request_id,
      user_id: current_user.id,
      ip_address: request.remote_ip,
      data_points_accessed: data_summary.keys.size
    }
  end

  ##
  # Handle Dashboard Error
  #
  # @param error [StandardError] The error that occurred
  # @param dashboard_type [String] Type of dashboard
  # @param request_id [String] Request ID
  def handle_dashboard_error(error, dashboard_type, request_id)
    logger.error "[SecurityDashboard] Dashboard error", {
      error: error.message,
      dashboard_type: dashboard_type,
      request_id: request_id,
      user_id: current_user.id,
      backtrace: error.backtrace&.first(3)
    }

    render json: {
      success: false,
      error: 'dashboard_error',
      message: 'Unable to load dashboard data',
      dashboard_type: dashboard_type,
      request_id: request_id,
      timestamp: Time.current.iso8601
    }, status: 500
  end

  ##
  # Handle Metrics Error
  #
  # @param error [StandardError] The error that occurred
  # @param metrics_type [String] Type of metrics
  # @param request_id [String] Request ID
  def handle_metrics_error(error, metrics_type, request_id)
    logger.error "[SecurityDashboard] Metrics error", {
      error: error.message,
      metrics_type: metrics_type,
      request_id: request_id,
      backtrace: error.backtrace&.first(3)
    }

    render json: {
      success: false,
      error: 'metrics_error',
      message: 'Unable to load metrics data',
      metrics_type: metrics_type,
      request_id: request_id,
      timestamp: Time.current.iso8601
    }, status: 500
  end

  ##
  # Handle Alerts Error
  #
  # @param error [StandardError] The error that occurred
  # @param request_id [String] Request ID
  def handle_alerts_error(error, request_id)
    logger.error "[SecurityDashboard] Alerts error", {
      error: error.message,
      request_id: request_id,
      backtrace: error.backtrace&.first(3)
    }

    render json: {
      success: false,
      error: 'alerts_error',
      message: 'Unable to load alerts data',
      request_id: request_id,
      timestamp: Time.current.iso8601
    }, status: 500
  end

  # Additional helper methods for system health checks and metrics
  # would continue here...
end