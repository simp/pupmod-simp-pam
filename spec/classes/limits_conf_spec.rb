require 'spec_helper'

describe 'pam::limits' do
  context 'supported operating systems' do
    on_supported_os.each do |os, os_facts|
      context "on #{os}" do
        let(:facts) { os_facts }

        it { is_expected.to compile.with_all_deps }
        it { is_expected.to create_concat('/etc/security/limits.conf') }

        context 'when specifying hash rules' do
          let(:params) do
            {

              rules: {
                'disable_core_for_user1' => {
                  'domains' => ['user1'],
                  'type'    => 'hard',
                  'item'    => 'core',
                  'value'   => 0,
                  'order'   => 50,
                },
                'disable_core_for_all' => {
                  'domains' => ['*'],
                  'type'    => 'hard',
                  'item'    => 'core',
                  'value'   => 0,
                  'order'   => 100,
                },
              },
            }
          end

          it { is_expected.to create_pam__limits__rule('disable_core_for_user1') }
          it { is_expected.to create_pam__limits__rule('disable_core_for_all') }
        end
      end
    end
  end
end
