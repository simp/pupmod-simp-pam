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
      end
    end
  end
end
