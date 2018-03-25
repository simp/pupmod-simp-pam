require 'spec_helper'

def el6?(facts)
  return ['CentOS', 'RedHat', 'OracleLinux'].include?(facts[:os][:name]) && facts[:os][:release][:major] == '6'
end

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
        it { is_expected.to contain_package('pam_pkcs11').with_ensure('present') }
        it { is_expected.to contain_package('fprintd-pam').with_ensure('present') }
        if el6?(os_facts)
          it { is_expected.to_not contain_package('libpwquality') }
        else
          it {is_expected.to contain_package('libpwquality').with_ensure('present') }
        end
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
        it { is_expected.to contain_package('pam_pkcs11').with_ensure('latest') }
        it { is_expected.to contain_package('fprintd-pam').with_ensure('latest') }
        if el6?(os_facts)
          it { is_expected.to_not contain_package('libpwquality') }
        else
          it { is_expected.to contain_package('libpwquality').with_ensure('latest') }
       end
      end
    end
  end
end
