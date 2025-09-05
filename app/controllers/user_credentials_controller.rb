# frozen_string_literal: true

# UserCredentialsController manages secure credential storage for Agent configurations.
#
# This controller provides CRUD operations for UserCredentials, which store
# sensitive information like API keys, passwords, and tokens that agents need
# to access external services without exposing secrets in agent configurations:
#
# * Listing user credentials with sorting and pagination
# * Creating new credentials with secure storage
# * Updating existing credential values and modes
# * Deleting credentials with dependency validation
# * Supporting both plain text and JavaScript evaluation modes
#
# All credential operations are scoped to the current user to ensure proper
# access control. Credentials are referenced in agent configurations using
# liquid templating syntax: {{ credential.name }}
class UserCredentialsController < ApplicationController

  include SortableTable

  def index
    set_table_sort sorts: %w[credential_name credential_value], default: { credential_name: :asc }

    @user_credentials = current_user.user_credentials.reorder(table_sort).page(params[:page])

    respond_to do |format|
      format.html
      format.json do
        send_data Utils.pretty_jsonify(@user_credentials.limit(nil).as_json), disposition: 'attachment'
      end
    end
  end

  def import
    if params[:file]
      file = params[:file]
      content = JSON.parse(file.read)
      new_credentials = content.map do |hash|
        current_user.user_credentials.build(hash.slice('credential_name', 'credential_value', 'mode'))
      end

      respond_to do |format|
        if new_credentials.map(&:save).all?
          format.html { redirect_to user_credentials_path, notice: 'The file was successfully uploaded.' }
        else
          format.html do
            redirect_to user_credentials_path,
                        notice: 'One or more of the uploaded credentials was not imported due to an error. Perhaps an existing credential had the same name?'
          end
        end
      end
    else
      redirect_to user_credentials_path, notice: 'No file was chosen to be uploaded.'
    end
  end

  def new
    @user_credential = current_user.user_credentials.build

    respond_to do |format|
      format.html
      format.json { render json: @user_credential }
    end
  end

  def edit
    @user_credential = current_user.user_credentials.find(params[:id])
  end

  def create
    @user_credential = current_user.user_credentials.build(user_credential_params)

    respond_to do |format|
      if @user_credential.save
        format.html { redirect_to user_credentials_path, notice: 'Your credential was successfully created.' }
        format.json { render json: @user_credential, status: :created, location: @user_credential }
      else
        format.html { render action: 'new' }
        format.json { render json: @user_credential.errors, status: :unprocessable_entity }
      end
    end
  end

  def update
    @user_credential = current_user.user_credentials.find(params[:id])

    respond_to do |format|
      if @user_credential.update(user_credential_params)
        format.html { redirect_to user_credentials_path, notice: 'Your credential was successfully updated.' }
        format.json { head :no_content }
      else
        format.html { render action: 'edit' }
        format.json { render json: @user_credential.errors, status: :unprocessable_entity }
      end
    end
  end

  def destroy
    @user_credential = current_user.user_credentials.find(params[:id])
    @user_credential.destroy

    respond_to do |format|
      format.html { redirect_to user_credentials_path }
      format.json { head :no_content }
    end
  end

  private

  def user_credential_params
    params.require(:user_credential).permit(:credential_name, :credential_value, :mode)
  end

end
