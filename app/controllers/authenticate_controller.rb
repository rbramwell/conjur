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
  

# Put this in another file in an appropriate place
#
# Note this is just a wrapper over Event::Authn to clarify the naming
# and make the runtime inputs explicit instead of scattered.
#
# Some version of this could maybe replace what is now Audit::Event::Authn
#
class AuditLog

  # you can add other methods for other kinds of events Note that "username",
  # while arguably not the most appropriate name since it also includes
  # hosts, is what I'm using elsewhere, and I think consistency trumps the
  # perfect name.  Feel free to rename it everywhere though if you have
  # something better.  I think "id" is too vague.
  #
  # These arguments sure look like an object to me :)
  #
  # type (bad placeholder name) is :deny or :allow or whatever
  def self.record_authn_event(role_id:, webservice_id:, authenticator_name:,
                              type:, message: nil)
    event = ::Audit::Event::Authn.new(
      role: role_id,
      authenticator_name: authenticator_name,
      service: webservice_id
    )
    event.emit(type) # add whatever the error message logic is
  end
end

class AuthenticateController < ApplicationController

  def authenticate
    authentication_token = ::Authentication::Strategy.new(
      authenticators: ::Authentication::InstalledAuthenticators.new(ENV),
      audit_log: AuditLog,
      security: nil,            # <== Did you turn this off for testing?
      env: ENV,
      role_class: ::Role,
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
    render json: authentication_token
  rescue => e
    logger.debug("Authentication Error: #{e.message}")
    raise Unauthorized
  end

end

