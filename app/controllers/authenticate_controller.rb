# NOTE: This is needed to make the introspection use by InstalledAuthenticators
#       work.  It cannot be placed in an initializer instead.  There may be a 
#       better place for it, but this works.
#
#       It's purpose it to load all the pluggable authenticator files into 
#       memory, so we can determine which authenticators are available
#
Dir[File.join("./app/domain/authentication/**/", "*.rb")].each do |f|
  require f
end

class AuthenticateController < ApplicationController

  def authenticate
    authentication_token = ::Authentication::Strategy.new(
      authenticators: ::Authentication::InstalledAuthenticators.new(ENV),
      security: nil,
      env: ENV,
      role_class: ::Authentication::MemoizedRole,
      token_factory: TokenFactory.new
    ).conjur_token(
      ::Authentication::Strategy::Input.new(
        authenticator_name: authenticator_name,
        service_id:         params[:service_id],
        account:            params[:account],
        username:           params[:id],
        password:           request.body.read
      )
    )
    message.emit :allow
    render json: authentication_token
  rescue => e
    logger.debug("Authentication Error: #{e.message}")
    message.emit :deny
    raise Unauthorized
  ensure
    # in essence an assertion, should never happen
    message.emitted? or fail "audit message not emitted"
  end
  
  private
  
  def message
    @message ||= Audit::Event::Authn.new \
      role: target_role,
      authenticator_name: authenticator_name,
      service: service
  end

  def target_role
    @target_role ||= Role.by_login(params[:id], account: account) or raise Unauthorized
  end
  
  def authenticator_name
    @authenticator_name ||= params[:authenticator]
  end
  
  def account
    @account ||= params[:account] or raise KeyError
  end
  
  def service
    @service ||= Resource[account, 'webservice'.freeze, params[:service_id]]
  end
end

