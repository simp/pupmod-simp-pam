require 'spec_helper'

describe 'pam' do
  context 'supported operating systems' do
    on_supported_os.each do |os, facts|

      context "on #{os}" do
        let(:facts){ facts }

        context '/etc/pam.d/other with default values' do
          it { is_expected.to compile.with_all_deps }
          it { is_expected.to contain_file('/etc/pam.d').with_mode('0644') }
          it { is_expected.to contain_file('/etc/pam.d/other').with_content(<<-EOM.gsub(/^\s+/,'')
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
        end
        context '/etc/pam.d/other with use_templates => false' do
          let(:params) {{
            :use_templates => false,
            :other_content => 'this is valid pam other configuration, I promise'
          }}
          it { is_expected.to contain_file('/etc/pam.d/other').with_content('this is valid pam other configuration, I promise') }
        end

        it { is_expected.to contain_package('pam') }
        it { is_expected.to contain_package('pam_pkcs11') }
        it { is_expected.to contain_package('fprintd-pam') }
        it { is_expected.to contain_pam__auth('fingerprint') }
        it { is_expected.to contain_pam__auth('system') }
        it { is_expected.to contain_pam__auth('password') }
        it { is_expected.to contain_pam__auth('smartcard') }

        context 'no_deny_if_unknown' do
          let(:params){{ :deny_if_unknown => false }}
          it { is_expected.to contain_file('/etc/pam.d/other').with_content(<<-EOM.gsub(/^\s+/,'')
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
          it { is_expected.to contain_file('/etc/pam.d/other').with_content(<<-EOM.gsub(/^\s+/,'')
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
          it { is_expected.to contain_file('/etc/pam.d/other').with_content("\n") }
        end
      end

      context "tty_audit_enable parameter error" do
        let(:facts){ facts }
        let(:params){{ :tty_audit_enable => 'root' }}
        it { is_expected.not_to compile.with_all_deps }
      end
    end
  end
end
