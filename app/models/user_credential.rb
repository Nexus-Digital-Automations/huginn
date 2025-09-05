# UserCredential stores user-specific credentials and secrets for Agent configurations.
#
# UserCredentials provide a secure way to store sensitive information that agents
# need to access external services without exposing secrets in agent configurations.
# Each credential includes:
#
# * Unique credential name for agent reference  
# * Encrypted credential value (passwords, API keys, tokens)
# * Processing mode (plain text or JavaScript evaluation)
# * User association for access control and isolation
#
# Credentials are referenced in agent configurations using liquid templating:
# `{{ credential.api_key }}` which gets replaced with the actual value during
# agent execution while keeping the sensitive data secure and hidden from logs.
#
# Supported modes:
# * text: Plain text credential values
# * java_script: JavaScript code that evaluates to credential value
class UserCredential < ActiveRecord::Base
  MODES = %w[text java_script]

  belongs_to :user

  validates :credential_name, presence: true, uniqueness: { case_sensitive: true, scope: :user_id }
  validates :credential_value, presence: true
  validates :mode, inclusion: { in: MODES }
  validates :user_id, presence: true

  before_validation :default_mode_to_text
  before_save :trim_fields

  protected

  def trim_fields
    credential_name.strip!
    credential_value.strip!
  end

  def default_mode_to_text
    self.mode = 'text' unless mode.present?
  end
end
