require 'spec_helper'

describe 'pam::access' do
  let(:facts){{
    :operatingsystem => 'CentOS',
    :lsbdistrelease => '6.5',
    :lsbmajdistrelease => '6'
  }}

  it { should compile.with_all_deps }
  it { should create_concat_build('pam_access').with({
      :target         => '/etc/security/access.conf',
      :squeeze_blank  => true,
    })
  }
  it { should create_concat_build('pam_access').that_requires('Package[pam]') }
  it { should create_file('/etc/security/access.conf').that_subscribes_to('Concat_build[pam_access]') }
  it { should create_pam__access__manage('default_deny').with({
      :permission => '-',
      :users      => 'ALL',
      :origins    => ['ALL'],
      :order      => '9999999999'
    })
  }
  it { should create_pam__access__manage('allow_local_root').with({
      :permission => '+',
      :users      => 'root',
      :origins    => ['LOCAL'],
      :order      => '0'
    })
  }
end
