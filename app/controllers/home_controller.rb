# frozen_string_literal: true

# HomeController manages the public-facing pages of the Huginn application.
#
# This controller handles pages that don't require authentication, serving as the
# entry point for visitors and providing general information about the system:
#
# * Landing page with system overview and status
# * About page with project information and documentation
# * Public system status and health information
#
# The controller skips user authentication to allow public access while still
# providing upgrade warnings and system status information for administrators.
class HomeController < ApplicationController

  skip_before_action :authenticate_user!

  before_action :upgrade_warning, only: :index

  def index; end

  def about; end

end
