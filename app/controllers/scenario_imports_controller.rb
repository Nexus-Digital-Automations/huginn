# frozen_string_literal: true

# ScenarioImportsController handles importing scenarios from external sources.
#
# This controller manages the import process for Scenarios, allowing users to
# import pre-configured agent collections and automation workflows:
#
# * Creating new scenario imports from URLs or file uploads
# * Processing and validating imported scenario data
# * Handling import conflicts and agent dependencies
# * Providing user feedback during import process
# * Managing imported agent configuration and setup
#
# The import process includes validation of agent types, configuration
# compatibility, and user permission verification to ensure imported
# scenarios work properly in the target environment.
class ScenarioImportsController < ApplicationController

  def new
    @scenario_import = ScenarioImport.new(url: params[:url])
  end

  def create
    @scenario_import = ScenarioImport.new(scenario_import_params)
    @scenario_import.set_user(current_user)

    if @scenario_import.valid? && @scenario_import.import_confirmed? && @scenario_import.import
      redirect_to @scenario_import.scenario, notice: 'Import successful!'
    else
      render action: 'new'
    end
  end

  private

  def scenario_import_params
    params.require(:scenario_import).permit(:url, :data, :file, :do_import, merges: {})
  end

end
