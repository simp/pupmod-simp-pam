require 'spec_helper'

describe 'pam::auth' do
  let(:facts){{
    :operatingsystem => 'CentOS',
    :operatingsystemrelease => '6.5',
    :operatingsystemmajrelease => '6'
  }}

  # This needs more time than we can give it right now, so it has been
  # stubbed for future fixing.
  it "should have tests - TODO"
end
