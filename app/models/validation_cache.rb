# frozen_string_literal: true

##
# ValidationCache Model
#
# Database model for L3 persistent cache layer of Parlant validation results.
# Provides long-term storage and retrieval of validation results with optimized
# indexing and automatic cleanup of expired entries.
#
# @author Parlant Performance Team
# @since 2.0.0
class ValidationCache < ActiveRecord::Base
  # Validations
  validates :cache_key, presence: true, uniqueness: true
  validates :validation_result, presence: true
  validates :expires_at, presence: true
  validates :validation_type, presence: true

  # Indexes for performance optimization
  # These would be created via migration:
  # add_index :validation_caches, :expires_at, where: 'expires_at > NOW()'
  # add_index :validation_caches, [:validation_type, :function_signature_hash]
  # add_index :validation_caches, [:user_context_hash, :expires_at], where: 'expires_at > NOW()'
  
  # Scopes for common queries
  scope :active, -> { where('expires_at > ?', Time.current) }
  scope :expired, -> { where('expires_at <= ?', Time.current) }
  scope :by_validation_type, ->(type) { where(validation_type: type) }
  scope :by_user_context, ->(hash) { where(user_context_hash: hash) }
  scope :recent, -> { where('created_at > ?', 1.day.ago) }

  # Class methods
  class << self
    ##
    # Cleanup Expired Entries
    #
    # Removes expired cache entries to maintain database performance.
    # Should be called regularly via background job.
    #
    # @return [Integer] Number of entries cleaned up
    def cleanup_expired_entries
      deleted_count = expired.delete_all
      
      Rails.logger.info "[ValidationCache] Cleaned up expired entries", {
        deleted_count: deleted_count,
        timestamp: Time.current.iso8601
      }
      
      deleted_count
    end

    ##
    # Get Cache Statistics
    #
    # Returns comprehensive statistics about the cache state.
    #
    # @return [Hash] Cache statistics
    def cache_statistics
      {
        total_entries: count,
        active_entries: active.count,
        expired_entries: expired.count,
        entries_by_type: group(:validation_type).count,
        average_access_count: average(:access_count)&.round(2) || 0,
        most_accessed_entries: order(access_count: :desc).limit(10).pluck(:cache_key, :access_count),
        oldest_entry: minimum(:created_at),
        newest_entry: maximum(:created_at),
        database_size_estimate_mb: estimate_database_size_mb
      }
    end

    ##
    # Optimize Database Performance
    #
    # Performs database optimization tasks for better cache performance.
    def optimize_performance
      # Analyze table statistics
      connection.execute('ANALYZE validation_caches') if connection.adapter_name == 'PostgreSQL'
      
      # Log optimization
      Rails.logger.info "[ValidationCache] Database optimization completed", {
        timestamp: Time.current.iso8601,
        total_entries: count
      }
    end

    ##
    # Find Similar Validations
    #
    # Finds validations with similar context or signatures.
    #
    # @param context_hash [String] User context hash
    # @param signature_hash [String] Function signature hash
    # @return [ActiveRecord::Relation] Similar validation records
    def find_similar_validations(context_hash, signature_hash)
      active
        .where('user_context_hash = ? OR function_signature_hash = ?', context_hash, signature_hash)
        .order(:created_at)
    end

    private

    def estimate_database_size_mb
      # Rough estimate based on average record size and count
      average_record_size = 2048 # Estimated bytes per record
      total_size_bytes = count * average_record_size
      (total_size_bytes / (1024 * 1024)).round(2)
    end
  end

  # Instance methods
  
  ##
  # Increment Access Count
  #
  # Atomically increments the access count for cache hit tracking.
  def increment_access_count!
    increment!(:access_count)
    update_column(:last_accessed, Time.current)
  end

  ##
  # Check if Expired
  #
  # @return [Boolean] True if cache entry has expired
  def expired?
    expires_at <= Time.current
  end

  ##
  # Check if Recently Created
  #
  # @return [Boolean] True if created within the last hour
  def recently_created?
    created_at > 1.hour.ago
  end

  ##
  # Get Parsed Validation Result
  #
  # @return [Hash] Parsed validation result JSON
  def parsed_validation_result
    @parsed_result ||= JSON.parse(validation_result)
  rescue JSON::ParserError => e
    Rails.logger.warn "[ValidationCache] Failed to parse validation result", {
      id: id,
      cache_key: cache_key,
      error: e.message
    }
    {}
  end

  ##
  # Cache Effectiveness Score
  #
  # Calculates effectiveness score based on access patterns.
  #
  # @return [Float] Effectiveness score (0.0 to 100.0)
  def effectiveness_score
    return 0.0 if access_count == 0
    
    age_hours = (Time.current - created_at) / 1.hour
    return 100.0 if age_hours == 0
    
    # Score based on access frequency and age
    access_rate = access_count.to_f / age_hours
    score = [access_rate * 10, 100.0].min
    score.round(2)
  end

  ##
  # Generate Cache Key Hash
  #
  # Creates a consistent hash for the cache key for indexing.
  #
  # @return [String] Cache key hash
  def cache_key_hash
    Digest::SHA256.hexdigest(cache_key)[0..15]
  end

  private

  # Callbacks
  before_save :set_cache_metadata, if: :new_record?

  def set_cache_metadata
    self.created_at ||= Time.current
    self.last_accessed ||= Time.current
    self.access_count ||= 0
  end
end