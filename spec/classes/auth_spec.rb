require 'spec_helper'

describe 'pam::auth' do
  let(:facts){{
    :operatingsystem => 'CentOS',
    :lsbdistrelease => '6.5',
    :lsbmajdistrelease => '6'
  }}

  # This needs more time than we can give it right now, so it has been
  # stubbed for future fixing.
  it "should have tests - TODO"
end
