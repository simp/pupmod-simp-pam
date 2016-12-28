require 'spec_helper'

describe 'pam::limits' do
  context 'supported operating systems' do
    on_supported_os.each do |os, facts|

      context "on #{os}" do
        let(:facts){ facts }

        it { is_expected.to compile.with_all_deps }
        it { is_expected.to create_concat('/etc/security/limits.conf') }
      end
    end
  end
end
