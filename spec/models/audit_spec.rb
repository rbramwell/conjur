require 'spec_helper'

describe Audit::Event::Authn do
  it 'sends an info message on success' do
    expect(Audit).to receive(:info).with \
      matching(/successfully authenticated/),
      'authn',
      facility: 10,
      'subject@43868': { role: "rspec:user:alice" },
      'auth@43868': {
        authenticator: 'authn-test',
        service: 'rspec:webservice:test'
      },
      'action@43868': {
        operation: 'authenticate',
        result: 'success',
      }
    event.emit_success
  end

  it 'sends a warning message on failure' do
      expect(Audit).to receive(:warn).with \
        matching(/failed to authenticate.*: test error/),
        'authn',
        facility: 10,
        'subject@43868': { role: "rspec:user:alice" },
        'auth@43868': {
          authenticator: 'authn-test',
          service: 'rspec:webservice:test'
        },
        'action@43868': {
          operation: 'authenticate',
          result: 'failure',
        }
      event.emit_failure 'test error'
  end

  subject(:event) do
    Audit::Event::Authn.new \
      role: the_user,
      authenticator_name: 'authn-test',
      service: double(Resource, id: 'rspec:webservice:test')
  end

  include_context("create user") { let(:login) { 'alice' } }
end

describe Audit do
  describe '.info' do
    it 'sends a message with appropriate severity' do
      expect(logger).to receive(:info).with an_object_having_attributes \
        msgid: 'test-msg', structured_data: { test: 'data' }, severity: 6, to_s: 'test message'
      Audit.info 'test message', 'test-msg', test: 'data'
    end
  end

  describe '.warn' do
    it 'sends a message with appropriate severity' do
      expect(logger).to receive(:warn).with an_object_having_attributes \
        msgid: 'test-msg', structured_data: { test: 'data' }, severity: 4, to_s: 'test message'
      Audit.warn 'test message', 'test-msg', test: 'data'
    end
  end

  let(:logger) { double Logger }
  before { allow(Audit).to receive_messages logger: logger }
end

describe Audit::RFC5424Formatter do
  it "can be given facility by object attribute" do
    msg = double "message", facility: 5
    expect(formatter.call(3, Time.now, nil, msg)).to start_with '<43>'
  end

  subject(:formatter) { Audit::RFC5424Formatter.new }
end
