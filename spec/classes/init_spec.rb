require 'spec_helper'
require 'yaml'

describe 'pam' do
  context 'supported operating systems' do
    on_supported_os.each do |os, facts|

      context "on #{os}" do
        let(:facts){ facts }

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

        context 'create pam::access::manage resources with an iterator' do
          context 'with a well-formatted data structure' do
            let(:params) {
              YAML.load(<<-EOF
pam_access_manage_hash:
  vagrant_user:
    users: vagrant
    origins:
      - ALL
    permission: '+'
  simp_group:
    users: (simp)
    origins:
      - 192.168.0.1/24
    permission: '-'
EOF
              )
            }
            it { is_expected.to create_pam__access__manage('vagrant_user').with({
             :users      => 'vagrant',
             :origins    => ['ALL'],
             :permission => '+'
            }) }
            it { is_expected.to create_pam__access__manage('simp_group').with({
             :users      => '(simp)',
             :origins    => ['192.168.0.1/24'],
             :permission => '-'
            }) }
          end

          context 'with valid yaml that fails type validation' do
            let(:params) {
              YAML.load(<<-EOF
pam_access_manage_hash:
  vagrant_user:
    users: vagrant
    origins: ALL
    permission: '+'
EOF
              )
            }
            it { is_expected.to raise_error }
          end

          context 'with invalid yaml' do
            let(:params) {
              YAML.load(<<-EOF
pam_access_manage_hash:
  vagrant_user:
  users: vagrant
    origins:
    permission: '+'
EOF
              )
            }
            it { is_expected.to raise_error }
          end

          context 'with defaults provided' do
            let(:params) {
              YAML.load(<<-EOF
pam_access_manage_hash_defaults:
  origins:
    - 10.0.2.0/24
pam_access_manage_hash:
  vagrant_user:
    users: vagrant
    permission: '+'
EOF
              )
            }
            it { is_expected.to create_pam__access__manage('vagrant_user').with({
              :users      => 'vagrant',
              :origins    => ['10.0.2.0/24'],
              :permission => '+'
            }) }
          end
        end
      end

      context 'tty_audit_enable parameter error' do
        let(:facts){ facts }
        let(:params){{ :tty_audit_enable => 'root' }}
        it { is_expected.not_to compile.with_all_deps }
      end

    end
  end
end
