require 'spec_helper'

describe 'pam::limits' do
  context 'supported operating systems' do
    on_supported_os.each do |os, facts|

      context "on #{os}" do
        let(:facts){ facts }

        it { is_expected.to compile.with_all_deps }
        it { is_expected.to create_concat_build('pam_limits').with_target('/etc/security/limits.conf') }
        it { is_expected.to create_concat_build('pam_limits').that_requires('Package[pam]') }
        it { is_expected.to create_file('/etc/security/limits.conf').that_subscribes_to('Concat_build[pam_limits]') }
      end
    end
  end
end
