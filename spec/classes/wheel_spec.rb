require 'spec_helper'

describe 'pam::wheel' do
  context 'supported operating systems' do
    on_supported_os.each do |os, facts|
      context "on #{os}" do
        let(:facts) { facts }

        let(:params) { { wheel_group: 'administrators' } }
        let(:pre_condition) do
          'include pam'
        end

        it { is_expected.to compile.with_all_deps }

        it { is_expected.to create_file('/etc/pam.d/su').with_content(%r{required\s+pam_wheel\.so.*group=#{params[:wheel_group]}}) }
        it { is_expected.not_to create_file('/etc/pam.d/su').with_content(%r{root_only}) }
        it { is_expected.not_to create_file('/etc/pam.d/su').with_content(%r{oo-trap}) }

        context 'root_only' do
          let(:params) do
            {
              wheel_group: 'administrators',
              root_only: true,
            }
          end

          it { is_expected.to create_file('/etc/pam.d/su').with_content(%r{required\s+pam_wheel\.so.*group=#{params[:wheel_group]}}) }
          it { is_expected.to create_file('/etc/pam.d/su').with_content(%r{root_only}) }
          it { is_expected.not_to create_file('/etc/pam.d/su').with_content(%r{oo-trap}) }
        end

        context 'use_openshift' do
          let(:params) do
            {
              wheel_group: 'administrators',
              use_openshift: true,
            }
          end

          it { is_expected.to create_file('/etc/pam.d/su').with_content(%r{required\s+pam_wheel\.so.*group=#{params[:wheel_group]}}) }
          it { is_expected.not_to create_file('/etc/pam.d/su').with_content(%r{root_only}) }
          it { is_expected.to create_file('/etc/pam.d/su').with_content(%r{oo-trap}) }
        end

        context 'with extra content' do
          let(:params) do
            {
              su_content_extra: ['auth sufficient pam_centrifydc.so enable_dzpamgate'],
            }
          end

          it { is_expected.to create_file('/etc/pam.d/su').with_content(%r{auth\s+sufficient\s+pam_centrifydc\.so\s+enable_dzpamgate}) }
        end

        context 'with custom content' do
          let(:params) do
            {
              content: 'this is valid pam su configuration, I promise',
            }
          end

          it { is_expected.to create_file('/etc/pam.d/su').with_content('this is valid pam su configuration, I promise') }
        end
      end
    end
  end
end
