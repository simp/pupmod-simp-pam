require 'spec_helper'

describe 'pam::wheel' do
  context 'supported operating systems' do
    on_supported_os.each do |os, facts|

      context "on #{os}" do
        let(:facts){ facts }

        let(:params){{ :wheel_group => 'administrators' }}
        let(:pre_condition){
          'include ::pam'
        }

        it { is_expected.to compile.with_all_deps }

        it { is_expected.to create_file('/etc/pam.d/su').with_content(/required\s+pam_wheel\.so.*group=#{params[:wheel_group]}/) }
        it { is_expected.not_to create_file('/etc/pam.d/su').with_content(/root_only/) }
        it { is_expected.not_to create_file('/etc/pam.d/su').with_content(/oo-trap/) }

        context 'root_only' do
          let(:params){{
            :wheel_group => 'administrators',
            :root_only => true
          }}
          it { is_expected.to create_file('/etc/pam.d/su').with_content(/required\s+pam_wheel\.so.*group=#{params[:wheel_group]}/) }
          it { is_expected.to create_file('/etc/pam.d/su').with_content(/root_only/) }
          it { is_expected.not_to create_file('/etc/pam.d/su').with_content(/oo-trap/) }
        end

        context 'use_openshift' do
          let(:params){{
            :wheel_group => 'administrators',
            :use_openshift => true
          }}
          it { is_expected.to create_file('/etc/pam.d/su').with_content(/required\s+pam_wheel\.so.*group=#{params[:wheel_group]}/) }
          it { is_expected.not_to create_file('/etc/pam.d/su').with_content(/root_only/) }
          it { is_expected.to create_file('/etc/pam.d/su').with_content(/oo-trap/) }
        end

        context 'with custom content' do
          let(:params) {{
            :content    => 'this is valid pam su configuration, I promise'
          }}
          it { is_expected.to create_file('/etc/pam.d/su').with_content('this is valid pam su configuration, I promise') }
        end
      end
    end
  end
end
