require 'spec_helper'

describe 'pam' do
  let(:facts){{
    :operatingsystem => 'CentOS',
    :lsbdistrelease => '6.5',
    :lsbmajdistrelease => '6'
  }}

  it { should compile.with_all_deps }
  it { should contain_file('/etc/pam.d').with_mode('0644') }
  it { should contain_file('/etc/pam.d/other').with_content(<<-EOM.gsub(/^\s+/,'')
      auth    required    pam_warn.so
      account    required    pam_warn.so
      password    required    pam_warn.so
      session    required    pam_warn.so
      auth    required    pam_deny.so
      account    required    pam_deny.so
      password    required    pam_deny.so
      session    required    pam_deny.so
      EOM
    )
  }
  it { should contain_package('pam') }
  it { should contain_package('pam_pkcs11') }
  it { should contain_package('fprintd-pam') }
  it { should contain_pam__auth('fingerprint') }
  it { should contain_pam__auth('system') }
  it { should contain_pam__auth('password') }
  it { should contain_pam__auth('smartcard') }

  context 'no_deny_if_unknown' do
    let(:params){{ :deny_if_unknown => false }}
    it { should contain_file('/etc/pam.d/other').with_content(<<-EOM.gsub(/^\s+/,'')
        auth    required    pam_warn.so
        account    required    pam_warn.so
        password    required    pam_warn.so
        session    required    pam_warn.so
        EOM
      )
    }
  end

  context 'no_warn_if_unknown' do
    let(:params){{ :warn_if_unknown => false }}
    it { should contain_file('/etc/pam.d/other').with_content(<<-EOM.gsub(/^\s+/,'')
        auth    required    pam_deny.so
        account    required    pam_deny.so
        password    required    pam_deny.so
        session    required    pam_deny.so
        EOM
      )
    }
  end

  context 'no_warn_or_deny_if_unknown' do
    let(:params){{
      :warn_if_unknown => false,
      :deny_if_unknown => false
    }}
    it { should contain_file('/etc/pam.d/other').with_content("\n") }
  end
end
