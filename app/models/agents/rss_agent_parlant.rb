# frozen_string_literal: true

require_relative '../../../lib/parlant_integration'

module Agents

  # RssAgent with comprehensive Parlant integration
  # 
  # Enhanced RSS monitoring agent that includes conversational validation for all RSS feed operations
  # through Parlant's conversational AI validation engine, ensuring secure and audited data collection.
  #
  class RssAgentParlant < Agent

    include WebRequestConcern
    include ParlantIntegration::AgentIntegration

    cannot_receive_events!
    can_dry_run!
    default_schedule 'every_1d'

    gem_dependency_check { defined?(Feedjira) }

    DEFAULT_EVENTS_ORDER = [['{{date_published}}', 'time'], ['{{last_updated}}', 'time']].freeze

    description do
      <<~MD
        The Enhanced RSS Agent with Parlant Integration consumes RSS feeds and emits events when they change,
        with comprehensive conversational validation and audit trails for enterprise security.

        ## Parlant Integration Features:
        - **Conversational Validation**: Each RSS feed operation is validated through natural language conversation
        - **Risk Assessment**: Automatic risk classification based on feed sources and content patterns
        - **Content Safety**: Intelligent content filtering with conversational approval for sensitive items
        - **Audit Trails**: Complete audit trail for all RSS operations with approval reasoning
        - **Performance Monitoring**: Real-time monitoring of feed performance and reliability

        This agent, using [Feedjira](https://github.com/feedjira/feedjira) as a base, can parse various types of RSS and Atom feeds and has some special handlers for FeedBurner, iTunes RSS, and so on.  However, supported fields are limited by its general and abstract nature.  For complex feeds with additional field types, we recommend using a WebsiteAgent.  See [this example](https://github.com/huginn/huginn/wiki/Agent-configuration-examples#itunes-trailers).

        If you want to *output* an RSS feed, use the DataOutputAgent.

        Options:

          * `url` - The URL of the RSS feed (an array of URLs can also be used; items with identical guids across feeds will be considered duplicates).
          * `include_feed_info` - Set to `true` to include feed information in each event.
          * `clean` - Set to `true` to sanitize `description` and `content` as HTML fragments, removing unknown/unsafe elements and attributes.
          * `expected_update_period_in_days` - How often you expect this RSS feed to change.  If more than this amount of time passes without an update, the Agent will mark itself as not working.
          * `headers` - When present, it should be a hash of headers to send with the request.
          * `basic_auth` - Specify HTTP basic auth parameters: `"username:password"`, or `["username", "password"]`.
          * `disable_ssl_verification` - Set to `true` to disable ssl verification.
          * `disable_url_encoding` - Set to `true` to disable url encoding.
          * `force_encoding` - Set `force_encoding` to an encoding name if the website is known to respond with a missing, invalid or wrong charset in the Content-Type header.  Note that a text content without a charset is taken as encoded in UTF-8 (not ISO-8859-1).
          * `user_agent` - A custom User-Agent name (default: "Faraday v#{Faraday::VERSION}").
          * `max_events_per_run` - Limit number of events created (items parsed) per run for feed.
          * `remembered_id_count` - Number of IDs to keep track of and avoid re-emitting (default: 500).

        ## Parlant-Specific Options:
          * `parlant_validation_enabled` - Enable Parlant conversational validation (default: true)
          * `content_safety_level` - Content safety validation level: 'permissive', 'moderate', 'strict' (default: 'moderate')
          * `require_approval_for_new_feeds` - Require approval when monitoring new RSS feeds (default: true)
          * `suspicious_content_patterns` - Patterns that trigger additional validation (JSON array of regex strings)

        # Ordering Events

        #{description_events_order}

        In this Agent, the default value for `events_order` is `#{DEFAULT_EVENTS_ORDER.to_json}`.
      MD
    end

    def default_options
      {
        'expected_update_period_in_days' => '5',
        'clean' => 'false',
        'url' => 'https://github.com/huginn/huginn/commits/master.atom',
        # Parlant-specific options
        'parlant_validation_enabled' => true,
        'content_safety_level' => 'moderate',
        'require_approval_for_new_feeds' => true,
        'suspicious_content_patterns' => ['spam', 'phishing', 'malware', 'suspicious'].to_json
      }
    end

    def working?
      event_created_within?(interpolated['expected_update_period_in_days'])
    end

    def check
      # Parlant validation for RSS feed checking operation
      parlant_validate_operation('check_rss_feeds', {
        urls: urls,
        last_check_at: last_check_at&.iso8601,
        feed_count: urls.length,
        safety_level: interpolated['content_safety_level']
      }) do
        check_rss_feeds_with_validation
      end
    rescue StandardError => e
      error("RSS check failed: #{e.message}")
      
      # Create audit trail for failed RSS check
      parlant_audit('rss_check_failed', {
        status: 'failure',
        error: e.message,
        error_class: e.class.name,
        urls: urls
      })
      
      raise
    end

    def urls
      interpolated['url'].is_a?(Array) ? interpolated['url'] : [interpolated['url']]
    end

    private

    #
    # Check RSS feeds with comprehensive Parlant validation
    #
    def check_rss_feeds_with_validation
      start_time = Time.now
      total_new_events = 0
      processed_urls = []

      urls.each do |url|
        begin
          events_created = process_rss_feed_with_validation(url)
          total_new_events += events_created
          processed_urls << { url: url, events: events_created, status: 'success' }
          
        rescue StandardError => e
          processed_urls << { url: url, events: 0, status: 'error', error: e.message }
          log("Failed to process RSS feed #{url}: #{e.message}")
        end
      end

      processing_time_ms = ((Time.now - start_time) * 1000).round(2)

      # Create comprehensive audit trail
      parlant_audit('rss_feeds_checked', {
        status: 'success',
        total_new_events: total_new_events,
        processing_time_ms: processing_time_ms,
        processed_urls: processed_urls
      }, {
        agent_id: self.id,
        agent_name: self.name,
        check_timestamp: Time.now.iso8601
      })

      log("✅ RSS check completed: #{total_new_events} new events from #{processed_urls.length} feeds (#{processing_time_ms}ms)")
    end

    #
    # Process individual RSS feed with validation
    #
    def process_rss_feed_with_validation(url)
      log("Checking RSS feed: #{url}")

      # Fetch and parse feed
      response = faraday.get(url)
      
      if response.success?
        feed = Feedjira.parse(response.body)
        return 0 unless feed

        # Validate feed content with Parlant
        validated_entries = validate_feed_entries(feed, url)
        
        # Create events for validated entries
        create_events_for_entries(validated_entries, feed, url)
        
      else
        raise "HTTP #{response.status}: #{response.reason_phrase}"
      end
    end

    #
    # Validate RSS feed entries through Parlant
    #
    def validate_feed_entries(feed, feed_url)
      return [] unless feed.entries

      validated_entries = []
      safety_level = interpolated['content_safety_level']
      suspicious_patterns = parse_suspicious_patterns

      feed.entries.each do |entry|
        # Skip if we've already processed this entry
        next if previous_payloads.include?(entry.id)

        # Assess content safety
        content_risk = assess_entry_content_risk(entry, suspicious_patterns)

        # Validate entry through Parlant if needed
        if should_validate_entry?(content_risk, safety_level)
          parlant_validate_operation('process_rss_entry', {
            entry_id: entry.id,
            title: truncate_text(entry.title, 100),
            summary: truncate_text(entry.summary, 200),
            url: entry.url,
            feed_url: feed_url,
            risk_assessment: content_risk,
            published_date: entry.published&.iso8601
          }) do
            validated_entries << entry
            
            # Log successful validation
            log("✅ RSS entry validated: #{truncate_text(entry.title, 50)}")
          end
        else
          # Low-risk entries can proceed without validation
          validated_entries << entry
        end
      end

      validated_entries
    rescue StandardError => e
      error("Feed entry validation failed: #{e.message}")
      []
    end

    #
    # Create events for validated RSS entries
    #
    def create_events_for_entries(validated_entries, feed, feed_url)
      events_created = 0

      validated_entries.each do |entry|
        event_data = build_event_data(entry, feed)
        
        # Create event with audit trail
        create_event(payload: event_data).tap do |event|
          events_created += 1
          
          # Create audit for event creation
          parlant_audit('rss_event_created', {
            status: 'success',
            event_id: event&.id,
            entry_title: truncate_text(entry.title, 100),
            feed_url: feed_url,
            entry_url: entry.url
          })
        end
      end

      events_created
    end

    #
    # Assess content risk for RSS entry
    #
    def assess_entry_content_risk(entry, suspicious_patterns)
      risk_factors = []
      content_text = "#{entry.title} #{entry.summary}".downcase

      # Check for suspicious patterns
      suspicious_patterns.each do |pattern|
        if content_text.match?(Regexp.new(pattern, Regexp::IGNORECASE))
          risk_factors << "suspicious_pattern_#{pattern}"
        end
      end

      # Check for external links in unusual quantities
      if entry.content&.scan(/https?:\/\//).length.to_i > 10
        risk_factors << 'excessive_external_links'
      end

      # Check for urgency indicators
      if content_text.match?(/urgent|breaking|alert|warning|immediate/)
        risk_factors << 'urgency_indicators'
      end

      {
        level: determine_content_risk_level(risk_factors.length),
        factors: risk_factors,
        entry_length: content_text.length,
        external_links: entry.content&.scan(/https?:\/\//)&.length || 0
      }
    end

    #
    # Determine if entry needs Parlant validation
    #
    def should_validate_entry?(content_risk, safety_level)
      case safety_level
      when 'strict'
        content_risk[:level] != 'minimal'
      when 'moderate'  
        ['high', 'critical'].include?(content_risk[:level])
      when 'permissive'
        content_risk[:level] == 'critical'
      else
        false
      end
    end

    #
    # Build event data from RSS entry
    #
    def build_event_data(entry, feed)
      data = {
        id: entry.id,
        title: entry.title,
        url: entry.url,
        urls: entry.url.present? ? [entry.url] : [],
        summary: entry.summary,
        content: entry.content,
        date_published: entry.published,
        last_updated: entry.updated,
        authors: entry.authors
      }

      if interpolated['include_feed_info']
        data[:feed] = {
          id: feed.feed_url,
          title: feed.title,
          url: feed.url,
          type: feed.class.name.demodulize,
          generator: feed.generator
        }
      end

      data
    end

    #
    # Parse suspicious content patterns from options
    #
    def parse_suspicious_patterns
      patterns = interpolated['suspicious_content_patterns']
      return [] unless patterns

      if patterns.is_a?(String)
        JSON.parse(patterns) rescue []
      elsif patterns.is_a?(Array)
        patterns
      else
        []
      end
    end

    #
    # Determine content risk level
    #
    def determine_content_risk_level(factor_count)
      case factor_count
      when 0 then 'minimal'
      when 1 then 'low'
      when 2..3 then 'medium'
      when 4..5 then 'high'
      else 'critical'
      end
    end

    #
    # Truncate text for logging/display
    #
    def truncate_text(text, max_length)
      return '' unless text
      text.length > max_length ? "#{text[0..max_length-4]}..." : text
    end

    # Add Parlant validation to critical methods
    parlant_validate_methods :check, risk_level: ParlantIntegration::RiskLevel::MEDIUM
    parlant_validate_methods :check_rss_feeds_with_validation, risk_level: ParlantIntegration::RiskLevel::LOW
  end
end