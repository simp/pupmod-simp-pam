require 'spec_helper'

def get_expected(filename)
  path = File.join(File.dirname(__FILE__), '..', 'expected', File.basename(__FILE__, '.rb'),
    filename)

  IO.read(path)
end

shared_examples_for "a pam.d config file generator" do
  it { is_expected.to compile.with_all_deps }
  it { is_expected.to create_class('oddjob::mkhomedir') }
  it { is_expected.to contain_file(filename).with_mode('0644') }
  it { is_expected.to contain_file("#{filename}-ac").with_ensure('absent') }
end

describe 'pam::auth' do
  context 'supported operating systems' do
    on_supported_os.each do |os, facts|
      context "on #{os}" do

        let(:facts){ facts }
        let(:pre_condition){
          'class { "::pam": auth_sections => [] }'
        }

        # The three test contexts (scenarios) allow all auth.erb code paths to be
        # exercised at least once.

        context 'Generate file using default params' do
          ['fingerprint', 'password', 'smartcard', 'system'].each do |auth_type|
            context "auth type '#{auth_type}'" do
              let(:title){ auth_type }
              let(:filename){ "/etc/pam.d/#{auth_type}-auth" }
              let(:file_content) { get_expected("#{auth_type}-auth_default_params") }

              it_should_behave_like "a pam.d config file generator"
              it { is_expected.to contain_file(filename).with_content(file_content) }
            end
          end
        end

        context 'Generate file using content params' do
          let(:params) {{
            :use_ldap                 => true,
            :use_sssd                 => false,
            :use_templates            => false,
            :fingerprint_auth_content => 'this is valid pam fingerprint_auth configuration, I promise',
            :system_auth_content      => 'this is valid pam system_auth configuration, I promise',
            :password_auth_content    => 'this is valid pam password_auth configuration, I promise',
            :smartcard_auth_content   => 'this is valid pam smartcard_auth configuration, I promise'
          }}
          ['fingerprint', 'password', 'smartcard', 'system'].each do |auth_type|
            context "auth type '#{auth_type}'" do
              let(:title){ auth_type }
              let(:filename){ "/etc/pam.d/#{auth_type}-auth" }
              let(:file_content) { get_expected("#{auth_type}-auth_custom_content").chomp! }

              it_should_behave_like "a pam.d config file generator"
              it { is_expected.to contain_file(filename).with_content(file_content) }
            end
          end
        end

        context 'Generate file with SSSD taking precedence over LDAP and no TTY auditing' do
          # In this context, we will also verify the logic to deliver config to
          # auth.erb works for all config parameters, by setting these parameters
          # to non-default values.
          let(:params){{
            :cracklib_dcredit          => 1,
            :cracklib_difok            => 2,
            :cracklib_enforce_for_root => false,
            :cracklib_gecoscheck       => false,
            :cracklib_lcredit          => 3,
            :cracklib_maxclassrepeat   => 4,
            :cracklib_maxrepeat        => 5,
            :cracklib_maxsequence      => 6,
            :cracklib_minclass         => 7,
            :cracklib_minlen           => 8,
            :cracklib_ocredit          => 9,
            :cracklib_reject_username  => false,
            :cracklib_retry            => 10,
            :cracklib_ucredit          => 11,
            :deny                      => 12,
            :display_account_lock      => true,
            :fail_interval             => 13,
            :remember                  => 14,
            :root_unlock_time          => 15,
            :rounds                    => 16,
            :uid                       => 17,
            :use_ldap                  => true,
            :unlock_time               => 18,
            :use_netgroups             => true,
            :use_openshift             => true,
            :use_sssd                  => true,
            :tty_audit_enable          => []
          }}

          ['fingerprint', 'password', 'smartcard', 'system'].each do |auth_type|
            context "auth type '#{auth_type}'" do
              let(:title){ auth_type }
              let(:filename){ "/etc/pam.d/#{auth_type}-auth" }
              let(:file_content) { get_expected("#{auth_type}-auth_sssd_no_tty_audit") }

              it_should_behave_like "a pam.d config file generator"
              it { is_expected.to contain_file(filename).with_content(file_content) }
            end
          end
        end

        context 'Generate file using SSSD, OpenShift, and TTY auditing of multiple users' do
          let(:params){{
            :use_ldap      => true,
            :use_sssd      => true,
            :use_openshift => true,
            :tty_audit_enable => ['root', 'user1', 'user2']
          }}

          ['fingerprint', 'password', 'smartcard', 'system'].each do |auth_type|
            context "auth type '#{auth_type}'" do
              let(:title){ auth_type }
              let(:filename){ "/etc/pam.d/#{auth_type}-auth" }
              let(:file_content) { get_expected("#{auth_type}-auth_sssd_openshift_multi_tty_audit") }

              it_should_behave_like "a pam.d config file generator"
              it { is_expected.to contain_file(filename).with_content(file_content) }
            end
          end
        end
      end
    end
  end
end
