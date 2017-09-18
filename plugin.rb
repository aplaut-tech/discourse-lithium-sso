# name: lithium-sso
# about: Handles Lithium SSO easily
# version: 0.0.1
# authors: Shoppilot team

gem 'ruby-mcrypt', '0.2.0', require_name: 'mcrypt'

require 'base64'
require 'zlib'

enabled_site_setting :lithium_sso_mode
enabled_site_setting :lithium_sso_secret
enabled_site_setting :lithium_sso_client_id
enabled_site_setting :lithium_sso_login_cookie_name
enabled_site_setting :lithium_sso_logout_cookie_names


module LithiumSSO
end


after_initialize do
  [
    'lib/lithium_sso/session_controller_override.rb',
    'lib/lithium_sso/single_sign_on.rb',
    'lib/lithium_sso/cookie_reader.rb'
  ].each { |path| load Rails.root.join("plugins/lithium-sso/#{path}") }
  ::LithiumSSO::SessionControllerOverride.override!
end
