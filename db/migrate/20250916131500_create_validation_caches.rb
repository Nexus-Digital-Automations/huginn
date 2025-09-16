# frozen_string_literal: true

##
# CreateValidationCaches Migration
#
# Creates the validation_caches table for L3 persistent cache layer
# with optimized indexes for high-performance cache operations.
class CreateValidationCaches < ActiveRecord::Migration[7.0]
  def up
    create_table :validation_caches, id: :uuid, default: 'gen_random_uuid()' do |t|
      # Core cache data
      t.string :cache_key, null: false, index: { unique: true }
      t.jsonb :validation_result, null: false
      t.datetime :expires_at, null: false
      t.datetime :last_accessed, null: false
      t.integer :access_count, default: 0, null: false
      
      # Classification and context
      t.string :validation_type, null: false, limit: 50
      t.string :user_context_hash, limit: 64
      t.string :function_signature_hash, limit: 64
      
      # Timestamps
      t.timestamps null: false
      
      # Performance optimization indexes
      t.index :expires_at, name: 'idx_validation_cache_expires', 
              where: 'expires_at > NOW()'
      t.index [:validation_type, :function_signature_hash], 
              name: 'idx_validation_cache_type_hash'
      t.index [:user_context_hash, :expires_at], 
              name: 'idx_validation_cache_user_context',
              where: 'expires_at > NOW()'
      t.index :access_count, name: 'idx_validation_cache_popularity'
      t.index :created_at, name: 'idx_validation_cache_created'
    end

    # Add GIN index on JSONB validation_result for fast JSON queries
    add_index :validation_caches, :validation_result, 
              using: :gin, name: 'idx_validation_cache_result_gin'

    # Add functional index for cache key hashing
    add_index :validation_caches, 'MD5(cache_key)', 
              name: 'idx_validation_cache_key_hash'

    # Create partial index for frequently accessed entries
    add_index :validation_caches, [:access_count, :expires_at],
              name: 'idx_validation_cache_hot_entries',
              where: 'access_count > 5 AND expires_at > NOW()'
  end

  def down
    drop_table :validation_caches
  end
end