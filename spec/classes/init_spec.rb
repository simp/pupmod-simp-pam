require 'spec_helper'

describe 'pam' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts){ os_facts }

      context 'with default values' do
        it { is_expected.to compile.with_all_deps }
        it { is_expected.to create_class('pam') }
        it { is_expected.to create_class('pam::install').that_comes_before('Class[pam::config]') }
        it { is_expected.to contain_class('pam::config') }
        it { is_expected.to contain_package('pam').with_ensure('present') }
        it {is_expected.to contain_package('libpwquality').with_ensure('present') }
      end

      context 'with simp_options::pam=false' do
        let(:hieradata) { 'simp_options_pam_false' }

        it { is_expected.to compile.with_all_deps }
        it { is_expected.to create_class('pam') }
        it { is_expected.to_not create_class('pam::install') }
        it { is_expected.to_not contain_class('pam::config') }
      end

      context 'with enable=false' do
        let(:params) {{ :enable => false }}

        it { is_expected.to compile.with_all_deps }
        it { is_expected.to create_class('pam') }
        it { is_expected.to_not create_class('pam::install') }
        it { is_expected.to_not contain_class('pam::config') }
      end

      context 'with package_ensure=latest' do
        let(:params) {{ :package_ensure => 'latest' }}

        it { is_expected.to compile.with_all_deps }
        it { is_expected.to contain_package('pam').with_ensure('latest') }
        it { is_expected.to contain_package('libpwquality').with_ensure('latest') }
      end

      context 'with all possible faillock params set' do
        let(:params) {{ 
          :manage_faillock_conf      => false,
          :display_account_lock      => false,
          :deny                      => 6,
          :faillock_audit            => true,
          :unlock_time               => 600,
          :fail_interval             => 600,
          :faillock_log_dir          => '/var/log/faillock',
          :faillock_no_log_info      => true,
          :faillock_local_users_only => true,
          :faillock_nodelay         => true,
          :faillock_admin_group      => 'admin',
          :even_deny_root            => true
          }}

        it { is_expected.to compile.with_all_deps }
        it { is_expected.to contain_file('/etc/pam.d/password-auth').with_content(/auth     required      pam_faillock.so preauth silent deny=6 audit unlock_time=600 fail_interval=600 dir=\/var\/log\/faillock no_log_info local_users_only nodelay admin_group=admin even_deny_root/) }
        it { is_expected.to contain_file('/etc/pam.d/system-auth').with_content(/auth     required      pam_faillock.so preauth silent deny=6 audit unlock_time=600 fail_interval=600 dir=\/var\/log\/faillock no_log_info local_users_only nodelay admin_group=admin even_deny_root/) }
      end

      context 'with manage_faillock_conf=true' do
        let(:params) {{ :manage_faillock_conf => true }}

        it { is_expected.to compile.with_all_deps }
        if (os_facts[:os][:family] == 'RedHat' and os_facts[:os][:release][:major] > '7') or
           (os_facts[:os][:name] == "Amazon" and os_facts[:os][:release][:major] >= '2022')
          it { is_expected.to contain_file('/etc/security/faillock.conf') }
        else
          it { is_expected.to_not contain_file('/etc/security/faillock.conf') }
        end
      end

      context 'with all possible pwhistory params set' do
        let(:params) {{ 
          :manage_pwhistory_conf => false,
          :remember_debug        => true,
          :remember              => 18,
          :remember_for_root     => true,
          :remember_retry        => 3,
          :remember_file         => '/etc/test/opasswd'
          }}

        it { is_expected.to compile.with_all_deps }
        it { is_expected.to contain_file('/etc/pam.d/password-auth').with_content(/password     required      pam_pwhistory.so use_authtok remember=18 retry=3 file=\/etc\/test\/opasswd debug enforce_for_root/) }
        it { is_expected.to contain_file('/etc/pam.d/system-auth').with_content(/password     required      pam_pwhistory.so use_authtok remember=18 retry=3 file=\/etc\/test\/opasswd debug enforce_for_root/) }
      end

      context 'with manage_pwhistory_conf=true' do
        let(:params) {{ :manage_pwhistory_conf => true }}

        it { is_expected.to compile.with_all_deps }
        if (os_facts[:os][:family] == 'RedHat' and os_facts[:os][:release][:major] > '7') or
           (os_facts[:os][:name] == "Amazon" and os_facts[:os][:release][:major] >= '2022')
          it { is_expected.to contain_file('/etc/security/pwhistory.conf') }
        else
          it { is_expected.to_not contain_file('/etc/security/pwhistory.conf') }
        end
      end
    end
  end
end
