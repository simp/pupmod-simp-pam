require 'spec_helper'

describe 'pam::wheel' do
  let(:facts){{
    :operatingsystem => 'CentOS',
    :operatingsystemrelease => '6.5',
    :operatingsystemmajrelease => '6'
  }}
  let(:params){{ :wheel_group => 'administrators' }}

  before(:each) { mod_site_pp('include "pam"') }

  it { should compile.with_all_deps }

  it { should create_file('/etc/pam.d/su').with_content(/required\s+pam_wheel\.so.*group=#{params[:wheel_group]}/) }
  it { should_not create_file('/etc/pam.d/su').with_content(/root_only/) }
  it { should_not create_file('/etc/pam.d/su').with_content(/oo-trap/) }

  context 'root_only' do
    let(:params){{
      :wheel_group => 'administrators',
      :root_only => true
    }}
    it { should create_file('/etc/pam.d/su').with_content(/required\s+pam_wheel\.so.*group=#{params[:wheel_group]}/) }
    it { should create_file('/etc/pam.d/su').with_content(/root_only/) }
    it { should_not create_file('/etc/pam.d/su').with_content(/oo-trap/) }
  end

  context 'use_openshift' do
    let(:params){{
      :wheel_group => 'administrators',
      :use_openshift => true
    }}
    it { should create_file('/etc/pam.d/su').with_content(/required\s+pam_wheel\.so.*group=#{params[:wheel_group]}/) }
    it { should_not create_file('/etc/pam.d/su').with_content(/root_only/) }
    it { should create_file('/etc/pam.d/su').with_content(/oo-trap/) }
  end
end
