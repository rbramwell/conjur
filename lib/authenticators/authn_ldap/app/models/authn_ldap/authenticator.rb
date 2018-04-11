require 'active_support'
require 'active_support/core_ext'
require 'net/ldap'
require 'conjur/api'

module AuthnLdap

  class Authenticator

    def initialize(ldap_server:, ldap_filter: nil, conjur_api: Conjur::API)
      @ldap_server = ldap_server
      @filter = ldap_filter || '(&(objectClass=posixAccount)(uid=%s))'
      @conjur_api = conjur_api
    end

    def auth(login:, password:, account:, service_id:)
      return false if login.blank? || password.blank?

      if valid_ldap_credentials?(login, password)
        @conjur_api.authenticate_local(
          login,
          account: account, authn_type: 'ldap', service_id: service_id)
      else
        false
      end
    rescue => e
      puts "ERROR"
      puts e
      false
    end

    protected

    def valid_ldap_credentials?(login, password)
      # Prevent LDAP injection attack
      safe_login = Net::LDAP::Filter.escape(login)

      return false if blacklisted_ldap_user?(safe_login)

      puts "Before binding"

      bind_results = @ldap_server.bind_as(
        filter: @filter % safe_login,
        password: password
      )
      puts "bind results: #{bind_results}"
      bind_results ? true : false
    end

    # admin should only be able to login through plain Conjur authn
    def blacklisted_ldap_user?(login)
      login == 'admin'
    end
  end
end