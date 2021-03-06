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
        authenticator_name: params[:authenticator],
        service_id:         params[:service_id],
        account:            params[:account],
        username:           params[:id],
        password:           request.body.read
      )
    )
    render json: authentication_token
  rescue => e
    logger.debug("Authentication Error: #{e.message}")
    raise Unauthorized
  end

end
