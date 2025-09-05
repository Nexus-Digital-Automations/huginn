# frozen_string_literal: true

# EventsController manages the display and interaction with Agent-generated Events.
#
# Events are the primary communication mechanism between Agents in Huginn, containing
# payloads of data that flow through the agent network. This controller provides:
#
# * Event browsing and pagination for agents
# * Individual event inspection and details
# * Event filtering and search capabilities
# * JSON API endpoints for programmatic access
#
# Events are always scoped to the current user's agents to ensure proper
# access control. The controller supports both HTML views for user interaction
# and JSON responses for API integrations.
#
# Key features include:
# * Agent-specific event listing with pagination
# * Event payload visualization and formatting
# * Time-based event browsing and filtering
# * Geographic location display for location-aware events
class EventsController < ApplicationController

  before_action :load_event, except: [:index, :show]

  def index
    if params[:agent_id]
      @agent = current_user.agents.find(params[:agent_id])
      @events = @agent.events.page(params[:page])
    else
      @events = current_user.events.preload(:agent).page(params[:page])
    end

    respond_to do |format|
      format.html
      format.json { render json: @events }
    end
  end

  def show
    respond_to do |format|
      format.html do
        load_event
      rescue ActiveRecord::RecordNotFound
        return_to = params[:return] or raise
        redirect_to return_to, allow_other_host: false
      end
      format.json { render json: @event }
    end
  end

  def reemit
    @event.reemit!
    respond_to do |format|
      format.html { redirect_back event_path(@event), notice: 'Event re-emitted.' }
    end
  end

  def destroy
    @event.destroy

    respond_to do |format|
      format.html { redirect_back events_path, notice: 'Event deleted.' }
      format.json { head :no_content }
    end
  end

  private

  def load_event
    @event = current_user.events.find(params[:id])
  end

end
