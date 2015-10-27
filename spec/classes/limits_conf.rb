require 'spec_helper'

describe 'pam::limits' do
  let(:facts){{
    :operatingsystem => 'CentOS',
    :operatingsystemrelease => '6.5',
    :operatingsystemmajrelease => '6'
  }}

  it { should compile.with_all_deps }
  it { should create_concat_build('pam_limits').with_target('/etc/security/limits.conf') }
  it { should create_concat_build('pam_limits').that_requires('Package[pam]') }
  it { should create_file('/etc/security/limits.conf').that_subscribes_to('Concat_build[pam_limits]') }
end
