require 'ostruct'

class Audit::Event::Authn < OpenStruct
  def emit_success
    self.success = true
    Audit.info message, 'authn', facility: 10, **structured_data
  end

  def emit_failure error_message
    self.error_message = error_message
    self.success = false
    Audit.warn message, 'authn', facility: 10, **structured_data
  end

  def message
    if success?
      SUCCESS_TEMPLATE % [role_id, authenticator_name, service_id]
    else
      FAILURE_TEMPLATE % [role_id, authenticator_name, service_id, error_message]
    end
  end

  SUCCESS_TEMPLATE = "%s successfully authenticated with authenticator %s service %s".freeze
  FAILURE_TEMPLATE = "%s failed to authenticate with authenticator %s service %s: %s".freeze

  def role_id
    role.id
  end

  def service_id
    service.try :id
  end

  def success?
    !!success
  end

  SDID = ::Audit::SDID

  def structured_data
    {
      SDID::SUBJECT => { role: role_id },
      SDID::AUTH => {
        authenticator: authenticator_name,
        service: service_id
      },
      SDID::ACTION => {
        operation: 'authenticate',
        result: success?? 'success' : 'failure'
      }
    }
  end
end
