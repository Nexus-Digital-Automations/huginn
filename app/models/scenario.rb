# frozen_string_literal: true

# Scenario represents a collection of related Agents grouped together for organization.
#
# Scenarios provide a way to organize agents that work together to accomplish
# specific automation tasks. They offer:
#
# * Agent grouping and logical organization
# * Bulk operations across related agents
# * Shared configuration and management
# * Export/import functionality for portability
# * User-scoped access control and ownership
#
# Each scenario maintains:
# * Descriptive name and optional description
# * Unique GUID for external references
# * Agent membership through scenario_memberships
# * User association for access control
# * Public sharing capabilities for collaboration
#
# Scenarios enable users to manage complex automations with multiple
# interconnected agents as cohesive, reusable units.
class Scenario < ActiveRecord::Base

  include HasGuid

  belongs_to :user, counter_cache: :scenario_count, inverse_of: :scenarios
  has_many :scenario_memberships, dependent: :destroy, inverse_of: :scenario
  has_many :agents, through: :scenario_memberships, inverse_of: :scenarios

  validates_presence_of :name, :user

  validates_format_of :tag_fg_color, :tag_bg_color,
                      # Regex adapted from: http://stackoverflow.com/a/1636354/3130625
                      with: /\A#(?:[0-9a-fA-F]{3}){1,2}\z/, allow_nil: true,
                      message: 'must be a valid hex color.'

  validate :agents_are_owned

  def destroy_with_mode(mode)
    case mode
    when 'all_agents'
      Agent.destroy(agents.pluck(:id))
    when 'unique_agents'
      Agent.destroy(unique_agent_ids)
    end

    destroy
  end

  def self.icons
    @icons ||= YAML.load_file(Rails.root.join('config/icons.yml'))
  end

  private

  def unique_agent_ids
    agents.joins(:scenario_memberships)
          .group('scenario_memberships.agent_id')
          .having('count(scenario_memberships.agent_id) = 1')
          .pluck('scenario_memberships.agent_id')
  end

  def agents_are_owned
    errors.add(:agents, 'must be owned by you') unless agents.all? { |s| s.user == user }
  end

end
