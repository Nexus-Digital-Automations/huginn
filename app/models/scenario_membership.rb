# frozen_string_literal: true

# ScenarioMembership represents the many-to-many relationship between Agents and Scenarios.
#
# This join model connects Agents to Scenarios, enabling agents to belong to multiple
# scenarios and scenarios to contain multiple agents. ScenarioMembership provides:
#
# * Agent-to-Scenario relationship management
# * Support for bulk operations on scenario agents
# * Proper referential integrity via dependent destroys
# * Foundation for scenario export/import functionality
#
# The membership model is essential for organizing agents into logical groupings
# and enables users to manage complex automation workflows as cohesive units.
class ScenarioMembership < ActiveRecord::Base

  belongs_to :agent, inverse_of: :scenario_memberships
  belongs_to :scenario, inverse_of: :scenario_memberships

end
