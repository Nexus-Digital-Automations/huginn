# frozen_string_literal: true

# ServicesController manages external service integrations and OAuth connections.
#
# This controller provides CRUD operations for Services that handle authentication
# and configuration for agents connecting to external APIs and services:
#
# * Listing user services with sorting and filtering
# * Creating OAuth service connections through provider callbacks
# * Managing service availability (global vs user-specific)
# * Deleting services and handling dependent agent cleanup
# * Testing service connectivity and authentication status
#
# Services are essential for agents that need to authenticate with external
# APIs like Twitter, Google, weather services, etc. The controller ensures
# proper access control so users can only manage their own services.
class ServicesController < ApplicationController

  include SortableTable

  before_action :upgrade_warning, only: :index

  def index
    set_table_sort sorts: %w[provider name global], default: { provider: :asc }

    @services = current_user.services.reorder(table_sort).page(params[:page])

    respond_to do |format|
      format.html
      format.json { render json: @services }
    end
  end

  def destroy
    @services = current_user.services.find(params[:id])
    @services.destroy

    respond_to do |format|
      format.html { redirect_to services_path }
      format.json { head :no_content }
    end
  end

  def toggle_availability
    @service = current_user.services.find(params[:id])
    @service.toggle_availability!

    respond_to do |format|
      format.html { redirect_to services_path }
      format.json { render json: @service }
    end
  end

end
