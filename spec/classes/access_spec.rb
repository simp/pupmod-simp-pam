require 'spec_helper'

describe 'pam::access' do
  context 'supported operating systems' do
    on_supported_os.each do |os, facts|

      context "on #{os}" do
        let(:facts){ facts }

        it { is_expected.to compile.with_all_deps }
        it { is_expected.to create_concat('/etc/security/access.conf') }
        it { is_expected.to create_pam__access__rule('default_deny').with({
            :permission => '-',
            :users      => ['ALL'],
            :origins    => ['ALL'],
            :order      => 9999999999
          })
        }
        it { is_expected.to create_pam__access__rule('allow_local_root').with({
            :permission => '+',
            :users      => ['root'],
            :origins    => ['LOCAL'],
            :order      => 1
          })
        }
      end
    end
  end
end
