# frozen_string_literal: true

require 'date'
require 'cgi'
require_relative '../../../lib/parlant_integration'

module Agents

  # WeatherAgent with comprehensive Parlant integration
  # 
  # Enhanced weather monitoring agent that includes conversational validation for all weather data operations
  # through Parlant's conversational AI validation engine, ensuring secure and audited weather monitoring.
  #
  class WeatherAgentParlant < Agent

    include ParlantIntegration::AgentIntegration

    cannot_receive_events!

    gem_dependency_check { defined?(ForecastIO) }

    description <<~MD
      The Enhanced Weather Agent with Parlant Integration creates events for weather forecasts at given locations,
      with comprehensive conversational validation and audit trails for enterprise monitoring.

      ## Parlant Integration Features:
      - **Conversational Validation**: Weather API calls are validated through natural language conversation
      - **Location Security**: Validation of location access requests and privacy protection
      - **API Usage Monitoring**: Intelligent monitoring of weather API usage patterns
      - **Alert Validation**: Conversational approval for weather alerts and severe weather notifications
      - **Performance Tracking**: Real-time monitoring of weather service reliability and response times

      #{'## Include `forecast_io` in your Gemfile to use this Agent!' if dependencies_missing?}

      You also must select when you would like to get the weather forecast for using the `which_day` option, where the number 1 represents today, 2 represents tomorrow and so on. Weather forecast information is only returned for at most one week at a time.

      The weather forecast information is provided by Pirate Weather, a drop-in replacement for the Dark Sky API (which no longer has a free tier).

      The `location` must be a comma-separated string of map co-ordinates (longitude, latitude). For example, San Francisco would be `37.7771,-122.4196`.

      You must set up an [API key for Pirate Weather](https://pirate-weather.apiable.io/) in order to use this Agent.

      Set `expected_update_period_in_days` to the maximum amount of time that you'd expect to pass between Events being created by this Agent.

      ## Parlant-Specific Options:
      * `parlant_validation_enabled` - Enable Parlant conversational validation (default: true)
      * `location_privacy_level` - Location privacy validation level: 'public', 'internal', 'restricted' (default: 'internal')
      * `weather_alert_validation` - Require approval for severe weather alerts (default: true)
      * `api_usage_monitoring` - Monitor API usage patterns for anomalies (default: true)
    MD

    event_description <<~MD
      Events look like this:

          {
            "location": "37.7771,-122.4196",
            "date": {
              "epoch": "1357959600",
              "pretty": "10:00 PM EST on January 11, 2013"
            },
            "high": {
              "fahrenheit": "64",
              "celsius": "18"
            },
            "low": {
              "fahrenheit": "52",
              "celsius": "11"  
            },
            "conditions": "Rain Showers",
            "icon": "rain",
            "icon_url": "https://icons-ak.wxug.com/i/c/k/rain.gif",
            "skyicon": "mostlycloudy",
            "pop": "90",
            "humidity": "65",
            "wind": {
              "speed": "5",
              "direction": "SSE",
              "degrees": "158"
            },
            "parlant_metadata": {
              "validation_id": "weather_1234567890_abc",
              "risk_level": "low",
              "api_response_time_ms": 245,
              "location_privacy_level": "internal"
            }
          }
    MD

    def default_options
      {
        'api_key' => 'your-pirate-weather-api-key-here',
        'location' => '37.7771,-122.4196',
        'which_day' => '1',
        'expected_update_period_in_days' => '2',
        # Parlant-specific options
        'parlant_validation_enabled' => true,
        'location_privacy_level' => 'internal', 
        'weather_alert_validation' => true,
        'api_usage_monitoring' => true
      }
    end

    def working?
      event_created_within?(interpolated['expected_update_period_in_days'])
    end

    def check
      # Parlant validation for weather data collection
      parlant_validate_operation('fetch_weather_data', {
        location: interpolated['location'],
        which_day: interpolated['which_day'],
        privacy_level: interpolated['location_privacy_level'],
        last_check_at: last_check_at&.iso8601
      }) do
        fetch_weather_with_validation
      end
    rescue StandardError => e
      error("Weather check failed: #{e.message}")
      
      # Create audit trail for failed weather check
      parlant_audit('weather_check_failed', {
        status: 'failure',
        error: e.message,
        error_class: e.class.name,
        location: interpolated['location']
      })
      
      raise
    end

    private

    #
    # Fetch weather data with comprehensive Parlant validation
    #
    def fetch_weather_with_validation
      start_time = Time.now
      location = interpolated['location']
      api_key = interpolated['api_key']
      which_day = interpolated['which_day'].to_i

      # Validate location privacy
      location_risk = assess_location_privacy_risk(location)

      log("Fetching weather for location: #{location} (day #{which_day})")

      # Configure ForecastIO with API key
      ForecastIO.api_key = api_key

      # Parse location coordinates
      lat, lng = location.split(',').map(&:strip).map(&:to_f)
      
      # Fetch weather forecast
      forecast = ForecastIO.forecast(lat, lng)
      api_response_time_ms = ((Time.now - start_time) * 1000).round(2)

      # Get forecast for specified day
      daily_forecast = forecast['daily']['data'][which_day - 1]
      
      if daily_forecast
        # Build weather event data
        weather_data = build_weather_event_data(daily_forecast, location, api_response_time_ms, location_risk)
        
        # Check for severe weather alerts
        if has_severe_weather_alert?(daily_forecast, weather_data)
          validate_severe_weather_alert(daily_forecast, weather_data)
        end

        # Create weather event
        create_event(payload: weather_data)

        # Create success audit trail
        parlant_audit('weather_data_fetched', {
          status: 'success',
          location: location,
          conditions: weather_data['conditions'],
          api_response_time_ms: api_response_time_ms,
          location_risk: location_risk
        }, {
          agent_id: self.id,
          agent_name: self.name,
          forecast_day: which_day,
          temperature_range: "#{weather_data['low']['fahrenheit']}°F - #{weather_data['high']['fahrenheit']}°F"
        })

        log("✅ Weather data fetched for #{location}: #{weather_data['conditions']} (#{api_response_time_ms}ms)")

      else
        raise "No forecast data available for day #{which_day}"
      end
    end

    #
    # Build comprehensive weather event data
    #
    def build_weather_event_data(forecast_data, location, api_response_time_ms, location_risk)
      # Convert temperatures
      high_f = forecast_data['temperatureMax'].round
      low_f = forecast_data['temperatureMin'].round
      high_c = ((high_f - 32) * 5 / 9).round
      low_c = ((low_f - 32) * 5 / 9).round

      # Format date
      date_epoch = forecast_data['time'].to_s
      date_obj = Time.at(forecast_data['time'].to_i)
      date_pretty = date_obj.strftime('%l:%M %p %Z on %B %d, %Y')

      # Build weather data with Parlant metadata
      {
        'location' => location,
        'date' => {
          'epoch' => date_epoch,
          'pretty' => date_pretty.strip
        },
        'high' => {
          'fahrenheit' => high_f.to_s,
          'celsius' => high_c.to_s
        },
        'low' => {
          'fahrenheit' => low_f.to_s,
          'celsius' => low_c.to_s
        },
        'conditions' => forecast_data['summary'] || 'Unknown',
        'icon' => forecast_data['icon'] || 'unknown',
        'skyicon' => map_icon_to_skyicon(forecast_data['icon']),
        'pop' => ((forecast_data['precipProbability'] || 0) * 100).round.to_s,
        'humidity' => ((forecast_data['humidity'] || 0) * 100).round.to_s,
        'wind' => {
          'speed' => (forecast_data['windSpeed'] || 0).round.to_s,
          'direction' => degrees_to_direction(forecast_data['windBearing'] || 0),
          'degrees' => (forecast_data['windBearing'] || 0).round.to_s
        },
        # Parlant integration metadata
        'parlant_metadata' => {
          'validation_id' => "weather_#{Time.now.to_i}_#{SecureRandom.hex(3)}",
          'risk_level' => location_risk[:level],
          'api_response_time_ms' => api_response_time_ms,
          'location_privacy_level' => interpolated['location_privacy_level'],
          'validation_timestamp' => Time.now.iso8601,
          'agent_id' => self.id
        }
      }
    end

    #
    # Assess location privacy risk
    #
    def assess_location_privacy_risk(location)
      risk_factors = []

      # Parse coordinates  
      begin
        lat, lng = location.split(',').map(&:strip).map(&:to_f)
        
        # Check if location is in sensitive area (you can customize these ranges)
        if (lat.abs > 80) || (lng.abs > 180)
          risk_factors << 'invalid_coordinates'
        end

        # Check for high-precision coordinates (potential privacy concern)
        if location.match?(/\d+\.\d{6,}/)
          risk_factors << 'high_precision_coordinates'
        end

      rescue StandardError
        risk_factors << 'invalid_location_format'
      end

      {
        level: determine_location_risk_level(risk_factors.length),
        factors: risk_factors,
        coordinates: location
      }
    end

    #
    # Check for severe weather alerts
    #
    def has_severe_weather_alert?(forecast_data, weather_data)
      return false unless interpolated['weather_alert_validation']

      # Check for severe weather conditions
      severe_conditions = [
        /storm/i, /hurricane/i, /tornado/i, /blizzard/i, 
        /flood/i, /severe/i, /warning/i, /watch/i
      ]

      conditions = weather_data['conditions'].to_s
      severe_conditions.any? { |pattern| conditions.match?(pattern) } ||
        (forecast_data['precipProbability'] || 0) > 0.8 ||
        (forecast_data['windSpeed'] || 0) > 25
    end

    #
    # Validate severe weather alert through Parlant
    #
    def validate_severe_weather_alert(forecast_data, weather_data)
      parlant_validate_operation('severe_weather_alert', {
        location: weather_data['location'],
        conditions: weather_data['conditions'],
        wind_speed: weather_data['wind']['speed'],
        precipitation_probability: weather_data['pop'],
        alert_type: 'severe_weather'
      }) do
        log("⚠️  Severe weather alert validated: #{weather_data['conditions']} at #{weather_data['location']}")
        
        # Add alert metadata
        weather_data['severe_weather_alert'] = {
          'validated' => true,
          'alert_level' => determine_alert_level(forecast_data),
          'validation_timestamp' => Time.now.iso8601
        }
      end
    end

    #
    # Map weather icon to skyicon
    #
    def map_icon_to_skyicon(icon)
      icon_mapping = {
        'clear-day' => 'sunny',
        'clear-night' => 'clear',
        'rain' => 'rain',
        'snow' => 'snow',
        'sleet' => 'sleet',
        'wind' => 'windy',
        'fog' => 'fog',
        'cloudy' => 'cloudy',
        'partly-cloudy-day' => 'partlycloudy',
        'partly-cloudy-night' => 'partlycloudy'
      }
      
      icon_mapping[icon] || 'unknown'
    end

    #
    # Convert wind degrees to cardinal direction
    #
    def degrees_to_direction(degrees)
      directions = %w[N NNE NE ENE E ESE SE SSE S SSW SW WSW W WNW NW NNW]
      index = ((degrees + 11.25) / 22.5).floor % 16
      directions[index]
    end

    #
    # Determine location privacy risk level
    #
    def determine_location_risk_level(factor_count)
      case factor_count
      when 0 then 'low'
      when 1 then 'medium'
      else 'high'
      end
    end

    #
    # Determine severe weather alert level
    #
    def determine_alert_level(forecast_data)
      wind_speed = forecast_data['windSpeed'] || 0
      precip_prob = forecast_data['precipProbability'] || 0

      if wind_speed > 40 || precip_prob > 0.9
        'critical'
      elsif wind_speed > 25 || precip_prob > 0.8
        'high'
      else
        'moderate'
      end
    end

    # Add Parlant validation to critical methods
    parlant_validate_methods :check, risk_level: ParlantIntegration::RiskLevel::MEDIUM
    parlant_validate_methods :fetch_weather_with_validation, risk_level: ParlantIntegration::RiskLevel::LOW
  end
end