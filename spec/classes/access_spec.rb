require 'spec_helper'

describe 'pam::access' do
  context 'supported operating systems' do
    on_supported_os.each do |os, facts|

      context "on #{os}" do
        let(:facts){ facts }

        it { is_expected.to compile.with_all_deps }
        it { is_expected.to create_simpcat_build('pam_access').with({
            :target         => '/etc/security/access.conf',
            :squeeze_blank  => true,
          })
        }
        it { is_expected.to create_simpcat_build('pam_access').that_requires('Package[pam]') }
        it { is_expected.to create_file('/etc/security/access.conf').that_subscribes_to('Simpcat_build[pam_access]') }
        it { is_expected.to create_pam__access__manage('default_deny').with({
            :permission => '-',
            :users      => 'ALL',
            :origins    => ['ALL'],
            :order      => '9999999999'
          })
        }
        it { is_expected.to create_pam__access__manage('allow_local_root').with({
            :permission => '+',
            :users      => 'root',
            :origins    => ['LOCAL'],
            :order      => '0'
          })
        }

        context 'create pam::access::manage resources with an iterator' do
          context 'with a well-formatted data structure' do
            let(:hieradata) { 'pam__access__user' }
            it { is_expected.to create_pam__access__manage('manage_vagrant').with({
             :users      => 'vagrant',
             :origins    => ['ALL'],
             :permission => '+'
            }) }
            it { is_expected.to create_pam__access__manage('manage_(simp)').with({
             :users      => '(simp)',
             :origins    => ['ALL'],
             :permission => '+'
            }) }
            it { is_expected.to create_pam__access__manage('manage_test').with({
              :users      => 'test',
              :origins    => ['192.168.0.1/24'],
              :permission => '+'
            }) }
            it { is_expected.to create_pam__access__manage('manage_baddude').with({
              :users      => 'baddude',
              :origins    => ['ALL'],
              :permission => '-'
            }) }
          end
        end

      end
    end
  end
end
