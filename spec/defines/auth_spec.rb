require 'spec_helper'

describe 'pam::auth' do
  context 'supported operating systems' do
    on_supported_os.each do |os, facts|
      context "on #{os}" do

        let(:facts){ facts }

        ['password','system'].each do |auth_type|
          context "auth type '#{auth_type}'" do
            let(:title){ auth_type }
            let(:filename){ "/etc/pam.d/#{auth_type}-auth" }
            let(:precondition){
              'include ::pam'
            }

            it { is_expected.to compile.with_all_deps }
            it { is_expected.to create_class('oddjob::mkhomedir') }
            it { is_expected.to contain_file(filename).with_mode('0644') }
            it { is_expected.to contain_file("#{filename}-ac").with_ensure('absent') }

            it { is_expected.to contain_file(filename).with_content(
              /^\s*password\s+sufficient\s+pam_unix\.so/m
              )
            }
            it { is_expected.to_not contain_file(filename).with_content(
              /^\s*password\s+sufficient\s+pam_sss\.so/m
              )
            }
            it { is_expected.to_not contain_file(filename).with_content(
              /^\s*password\s+sufficient\s+pam_ldap\.so/m
              )
            }
          end
        end

        context "using SSSD" do
          ['password','system'].each do |auth_type|
            context "auth type '#{auth_type}'" do
              let(:title){ auth_type }
              let(:filename){ "/etc/pam.d/#{auth_type}-auth" }
              let(:params){{
                :use_ldap => true,
                :use_sssd => true
              }}
              let(:precondition){
                'include ::pam'
              }

              it { is_expected.to compile.with_all_deps }
              it { is_expected.to create_class('oddjob::mkhomedir') }
              it { is_expected.to contain_file(filename).with_mode('0644') }
              it { is_expected.to contain_file("#{filename}-ac").with_ensure('absent') }

              it { is_expected.to contain_file(filename).with_content(
                /^\s*password\s+sufficient\s+pam_unix\.so/m
                )
              }
              it { is_expected.to contain_file(filename).with_content(
                /^\s*password\s+sufficient\s+pam_sss\.so.*\n\s*.+pam_unix\.so/m
                )
              }
              it { is_expected.to_not contain_file(filename).with_content(
                /^\s*password\s+sufficient\s+pam_ldap\.so/m
                )
              }
            end
          end
        end

        context "using LDAP without SSSD" do
          ['password','system'].each do |auth_type|
            context "auth type '#{auth_type}'" do
              let(:title){ auth_type }
              let(:filename){ "/etc/pam.d/#{auth_type}-auth" }
              let(:params){{
                :use_ldap => true
              }}
              let(:precondition){
                'include ::pam'
              }

              it { is_expected.to compile.with_all_deps }
              it { is_expected.to create_class('oddjob::mkhomedir') }
              it { is_expected.to contain_file(filename).with_mode('0644') }
              it { is_expected.to contain_file("#{filename}-ac").with_ensure('absent') }

              it { is_expected.to contain_file(filename).with_content(
                /^\s*password\s+sufficient\s+pam_unix\.so/m
                )
              }
              it { is_expected.to contain_file(filename).without_content(
                /^\s*password\s+sufficient\s+pam_sss\.so/m
                )
              }
              it { is_expected.to contain_file(filename).with_content(
                /^\s*.*pam_unix\.so.*\n\s*password\s+sufficient\s+pam_ldap\.so/m
                )
              }
            end
          end
        end
      end
    end
  end
end
