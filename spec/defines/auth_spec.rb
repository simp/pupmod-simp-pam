require 'spec_helper'

def get_expected(filename)
  path = File.join(File.dirname(__FILE__), '..', 'expected', File.basename(__FILE__, '.rb'),
    filename)

  IO.read(path)
end

def el6?(facts)
  return ['CentOS', 'RedHat', 'OracleLinux'].include?(facts[:os][:name]) && facts[:os][:release][:major] == '6'
end

shared_examples_for "a pam.d config file generator" do
  it { is_expected.to compile.with_all_deps }
  it { is_expected.to create_class('oddjob::mkhomedir') }
  it { is_expected.to contain_file(filename).with_mode('0644') }
  it { is_expected.to contain_file("#{filename}-ac").with_ensure('absent') }
end

describe 'pam::auth' do
  context 'supported operating systems' do
    on_supported_os.each do |os, os_facts|
      context "on #{os}" do

        let(:facts){
          os_facts.merge(
            {
              'login_defs' => {
                'uid_min' => 1000
              }
            }
          )
        }
        let(:pre_condition){
          'class { "::pam": auth_sections => [] }'
        }

        # The three test contexts (scenarios) allow all auth.erb code paths to be
        # exercised at least once.

        context 'Generate file using default params' do
          ['fingerprint', 'password', 'smartcard', 'system'].each do |auth_type|
            context "auth type '#{auth_type}'" do
              let(:pw_backend) {
                if el6?(os_facts)
                  'cracklib'
                else
                  'pwquality'
                end
              }
              let(:title){ auth_type }
              let(:filename){ "/etc/pam.d/#{auth_type}-auth" }
              let(:file_content) { get_expected("#{pw_backend}-#{auth_type}-auth_default_params") }

              it_should_behave_like "a pam.d config file generator"
              it { is_expected.to contain_file(filename).with_content(file_content) }
            end
          end
        end

        context 'Generate file using content params' do
          let(:params) {{
            :sssd    => false,
            :content => 'this is valid pam fingerprint_auth configuration, I promise'
          }}
          ['fingerprint', 'password', 'smartcard', 'system'].each do |auth_type|
            context "auth type '#{auth_type}'" do
              let(:title){ auth_type }
              let(:filename){ "/etc/pam.d/#{auth_type}-auth" }

              it_should_behave_like "a pam.d config file generator"
              it { is_expected.to contain_file(filename).with_content(params[:content]) }
            end
          end
        end

        context 'Generate file without locale_file' do
          let(:params) {{
            :locale_file => :undef
          }}

          ['fingerprint', 'password', 'smartcard', 'system'].each do |auth_type|
            context "auth type '#{auth_type}'" do
              let(:title){ auth_type }
              let(:filename){ "/etc/pam.d/#{auth_type}-auth" }

              it_should_behave_like "a pam.d config file generator"
              it { is_expected.to contain_file(filename).without_content(%r(/envfile=.*locale/)) }
            end
          end
        end

        context 'Generate file using never param for unlock_time' do
          let(:params) {{
            :unlock_time => 'never',
          }}
          ['fingerprint', 'password', 'smartcard', 'system'].each do |auth_type|
            context "auth type '#{auth_type}'" do
              let(:pw_backend) {
                if el6?(os_facts)
                  'cracklib'
                else
                  'pwquality'
                end
              }
              let(:title){ auth_type }
              let(:filename){ "/etc/pam.d/#{auth_type}-auth" }
              let(:file_content) { get_expected("#{pw_backend}-#{auth_type}-auth_unlock_time_never") }

              it_should_behave_like "a pam.d config file generator"
              it { is_expected.to contain_file(filename).with_content(file_content) }
            end
          end
        end

        context 'Generate file with disabled root_unlock_time' do
          let(:params) {{
            :even_deny_root => false
          }}
          ['fingerprint', 'password', 'smartcard', 'system'].each do |auth_type|
            context "auth type '#{auth_type}'" do
              let(:title){ auth_type }
              let(:filename){ "/etc/pam.d/#{auth_type}-auth" }

              it_should_behave_like "a pam.d config file generator"
              it { is_expected.not_to contain_file(filename).with_content('even_deny_root') }
              it { is_expected.not_to contain_file(filename).with_content('root_unlock_time') }
            end
          end
        end

        context 'Generate file using different hash algorithm' do
          ['password', 'system'].each do |auth_type|
            let(:title){ auth_type }
            let(:filename){ "/etc/pam.d/#{auth_type}-auth" }
            let(:params) {{
              :hash_algorithm => 'blowfish',
            }}

            context "auth type '#{auth_type}'" do

              it_should_behave_like "a pam.d config file generator"
              it { is_expected.to contain_file(filename).with_content(/blowfish/) }
            end

            context 'in FIPS mode' do
              let(:facts) {
                os_facts.merge({
                  :fips_enabled => true
                })
              }

              it {
                expect {
                  should compile.with_all_deps
                }.to raise_error(/Only sha256 and sha512/)
              }
            end
          end
        end

        context 'Generate file with SSSD and no TTY auditing' do
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
            :unlock_time               => 18,
            :use_netgroups             => true,
            :use_openshift             => true,
            :sssd                      => true,
            :tty_audit_users           => []
          }}

          ['fingerprint', 'password', 'smartcard', 'system'].each do |auth_type|
            context "auth type '#{auth_type}'" do
              let(:pw_backend) {
                if el6?(os_facts)
                  'cracklib'
                else
                  'pwquality'
                end
              }
              let(:title){ auth_type }
              let(:filename){ "/etc/pam.d/#{auth_type}-auth" }
              let(:file_content) { get_expected("#{pw_backend}-#{auth_type}-auth_sssd_no_tty_audit") }

              it_should_behave_like "a pam.d config file generator"
              it { is_expected.to contain_file(filename).with_content(file_content) }
            end
          end
        end

        context 'Generate file using SSSD, OpenShift, and TTY auditing of multiple users' do
          let(:params){{
            :sssd            => true,
            :use_openshift   => true,
            :tty_audit_users => ['root', 'user1', 'user2']
          }}

          ['fingerprint', 'password', 'smartcard', 'system'].each do |auth_type|
            context "auth type '#{auth_type}'" do
              let(:pw_backend) {
                if el6?(os_facts)
                  'cracklib'
                else
                  'pwquality'
                end
              }
              let(:title){ auth_type }
              let(:filename){ "/etc/pam.d/#{auth_type}-auth" }
              let(:file_content) { get_expected("#{pw_backend}-#{auth_type}-auth_sssd_openshift_multi_tty_audit") }

              it_should_behave_like "a pam.d config file generator"
              it { is_expected.to contain_file(filename).with_content(file_content) }
            end
          end
        end
        context 'Generate file with varying list separators when list_separator == true' do
          ['!', ',', '@'].each_with_index do |separator, index|
            context "auth type separator = '#{separator}'" do
            let(:params){{
              :enable_separator => true,
              :separator => separator,
              :tty_audit_users => ['root']
            }}

              let(:pw_backend) {
                if el6?(os_facts)
                  'cracklib'
                else
                  'pwquality'
                end
              }
              let(:title){ 'password' }
              let(:filename){ "/etc/pam.d/password-auth" }
              let(:file_content) { get_expected("#{pw_backend}-password-separator-#{index}") }

              it_should_behave_like "a pam.d config file generator"
              it { is_expected.to contain_file(filename).with_content(file_content) }
            end
          end
        end
        context 'Generate file with when enable_separator == false`' do
          let(:params){{
            :enable_separator => false,
          }}
            let(:pw_backend) {
              if el6?(os_facts)
                'cracklib'
              else
                'pwquality'
              end
            }
            let(:title){ 'password' }
            let(:filename){ "/etc/pam.d/password-auth" }
            let(:file_content) { get_expected("#{pw_backend}-password-separator-false") }

            it_should_behave_like "a pam.d config file generator"
            it { is_expected.to contain_file(filename).with_content(file_content) }
        end
      end
    end
  end
end
