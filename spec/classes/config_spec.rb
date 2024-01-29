require 'spec_helper'

# We have to test pam::config via pam, because pam::config is
# private.  To take advantage of hooks built into puppet-rspec, the
# class described needs to be the class instantiated, i.e., pam.
describe 'pam' do
  let(:el7_pwquality_conf){
    <<~EOM
    # This file is generated by Puppet
    # Any changes made to it will be overwritten.
    #
    difok = 4
    minlen = 15
    dcredit = -1
    ucredit = -1
    lcredit = -1
    ocredit = -1
    minclass = 3
    maxrepeat = 2
    maxclassrepeat = 3
    maxsequence = 4
    gecoscheck = 1
    EOM
  }

  let(:el8_lt4_pwquality_conf){
    <<~EOM
    # This file is generated by Puppet
    # Any changes made to it will be overwritten.
    #
    difok = 4
    minlen = 15
    dcredit = -1
    ucredit = -1
    lcredit = -1
    ocredit = -1
    minclass = 3
    maxrepeat = 2
    maxclassrepeat = 3
    maxsequence = 4
    gecoscheck = 1
    EOM
  }


  let(:el_gt8_4_pwquality_conf){
    <<~EOM
    # This file is generated by Puppet
    # Any changes made to it will be overwritten.
    #
    difok = 4
    minlen = 15
    dcredit = -1
    ucredit = -1
    lcredit = -1
    ocredit = -1
    minclass = 3
    maxrepeat = 2
    maxclassrepeat = 3
    maxsequence = 4
    retry = 3
    dictcheck = 1
    gecoscheck = 1
    EOM
  }

  let(:default_faillock_conf){
    <<~EOM
    # This file is generated by Puppet
    # Any changes made to it will be overwritten.
    #
    audit
    silent
    deny=5
    fail_interval=900
    unlock_time=900
    even_deny_root
    root_unlock_time=60
    EOM
  }

  let(:all_params_faillock_conf){
    <<~EOM
    # This file is generated by Puppet
    # Any changes made to it will be overwritten.
    #
    dir=/var/log/faillock
    audit
    silent
    no_log_info
    local_users_only
    nodelay
    deny=4
    fail_interval=1200
    unlock_time=180
    even_deny_root
    root_unlock_time=60
    admin_group=wheel
    EOM
  }

  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts
          .merge(
            {
              :simplib__auditd => {
                'enforcing' => false
              }
            }
          )
      end

      context 'with default values' do
        it { is_expected.to compile.with_all_deps }
        it { is_expected.to contain_file('/etc/pam.d').with( {
            :ensure  => 'directory',
            :mode    => '0644',
            :recurse => true
          } )
        }

        if os_facts[:os][:name] == 'Amazon'
          if  os_facts[:os][:release][:major].to_i < 2022
            it { is_expected.to contain_file('/etc/security/pwquality.conf').with_content( el7_pwquality_conf ) }
          else
            it { is_expected.to contain_file('/etc/security/pwquality.conf').with_content( el_gt8_4_pwquality_conf ) }
          end
        elsif os_facts[:os][:release][:major] < '8'
          it { is_expected.to contain_file('/etc/security/pwquality.conf').with_content( el7_pwquality_conf ) }
        elsif os_facts[:os][:release][:minor] && os_facts[:os][:release][:major] == '8' && os_facts[:os][:release][:minor].to_i < 4
          it { is_expected.to contain_file('/etc/security/pwquality.conf').with_content( el8_lt4_pwquality_conf ) }
        else
          it { is_expected.to contain_file('/etc/security/pwquality.conf').with_content( el_gt8_4_pwquality_conf ) }
        end

        it { is_expected.to contain_file('/etc/security/pwquality.conf.d').with_ensure('absent') }
        it { is_expected.to contain_file('/etc/security/pwquality.conf.d').with_force(true) }

        # not managing content of /etc/pam.d/atd or /etc/pam.d/crond
        it { is_expected.to contain_file('/etc/pam.d/atd').with_ensure('file') }
        it { is_expected.to contain_file('/etc/pam.d/crond').with_ensure('file') }
        it { is_expected.to contain_file('/etc/pam.d/sudo').with_content(<<~EOM
            #%PAM-1.0
            # This file is generated by Puppet
            # Any changes made to it will be overwritten.
            #
            auth include system-auth
            account include system-auth
            password include system-auth
            session optional pam_keyinit.so revoke
            session required pam_limits.so
            # auditd disabled: pam_tty_audit set to optional so that all logins do not fail
            session optional pam_tty_audit.so disable=* enable=root open_only
            EOM
          )
        }

        it { is_expected.to contain_file('/etc/pam.d/sudo-i').with_content(<<~EOM
            #%PAM-1.0
            # This file is generated by Puppet
            # Any changes made to it will be overwritten.
            #
            auth include sudo
            account include sudo
            password include sudo
            session optional pam_keyinit.so force revoke
            session required pam_limits.so
            # auditd disabled: pam_tty_audit set to optional so that all logins do not fail
            session optional pam_tty_audit.so disable=* enable=root open_only
            EOM
          )
        }

        it { is_expected.to contain_file('/etc/pam.d/other').with_content(<<~EOM
            #%PAM-1.0
            # This file is generated by Puppet
            # Any changes made to it will be overwritten.
            #
            auth    required    pam_warn.so
            account    required    pam_warn.so
            password    required    pam_warn.so
            session    required    pam_warn.so
            auth    required    pam_deny.so
            account    required    pam_deny.so
            password    required    pam_deny.so
            session    required    pam_deny.so
            EOM
          )
        }

        if os_facts[:os][:family] == 'RedHat' and os_facts[:os][:release][:major] <= '7'
          it {
            project_dir = File.expand_path(File.join(File.dirname(__FILE__), '..', '..'))
            expected = IO.read(File.join(project_dir, 'files', 'simp_authconfig.sh'))
            is_expected.to contain_file('/usr/local/sbin/simp_authconfig.sh').with_content(expected)
          }

          [ '/usr/sbin/authconfig', '/usr/sbin/authconfig-tui'].each do |file|
            it { is_expected.to contain_file(file).with( {
                :ensure  => 'link',
                :target  => '/usr/local/sbin/simp_authconfig.sh',
                :require => 'File[/usr/local/sbin/simp_authconfig.sh]'
              } )
            }
          end
        else
          it { is_expected.to_not contain_file('/usr/local/sbin/simp_authconfig.sh')}
          [ '/usr/sbin/authconfig', '/usr/sbin/authconfig-tui'].each do |file|
            it { is_expected.to_not contain_file(file)}
          end
        end

        it { is_expected.to contain_pam__auth('fingerprint') }
        it { is_expected.to contain_pam__auth('system') }
        it { is_expected.to contain_pam__auth('password') }
        it { is_expected.to contain_pam__auth('smartcard') }
      end

      context 'when auditing is enabled' do
        let(:facts) do
          os_facts
            .merge(
              {
                :simplib__auditd => {
                  'enforcing' => true
                }
              }
            )
        end

        it {
          is_expected.to contain_file('/etc/pam.d/sudo-i')
            .with_content(/session\s+required\s+pam_tty_audit.so/)
        }
      end

      context 'with non-default parameters impacting /etc/security/pwquality.conf' do
        context 'with optional parameters set' do
          let(:params) {{
            :cracklib_badwords => ['bad1', 'bad2'],
            :cracklib_dictpath => '/path/to/cracklib/dict'
          }}

          it { is_expected.to contain_file('/etc/security/pwquality.conf').with_content(
            /badwords = bad1 bad2/ )
          }

          it { is_expected.to contain_file('/etc/security/pwquality.conf').with_content(
            /dictpath = \/path\/to\/cracklib\/dict/ )
          }
        end
      end

      context 'with cracklib_gecoscheck = false' do
        let(:params) {{ :cracklib_gecoscheck => false }}

        it { is_expected.to_not contain_file('/etc/security/pwquality.conf').with_content(
          /gecoscheck = 12/ )
        }
      end

      context 'with rm_pwquality_conf_d = false' do
        let(:params) {{ :rm_pwquality_conf_d => false }}

        it { is_expected.to_not contain_file('/etc/security/pwquality.conf.d') }
      end

      context 'with non-default parameters impacting /etc/pam.d/sudo*' do
        context 'with empty tty_audit_users' do
          let(:params) {{ :tty_audit_users => [] }}

          it { is_expected.to contain_file('/etc/pam.d/sudo').with_content(<<~EOM
              #%PAM-1.0
              # This file is generated by Puppet
              # Any changes made to it will be overwritten.
              #
              auth include system-auth
              account include system-auth
              password include system-auth
              session optional pam_keyinit.so revoke
              session required pam_limits.so
              EOM
            )
          }

          it { is_expected.to contain_file('/etc/pam.d/sudo-i').with_content(<<~EOM
              #%PAM-1.0
              # This file is generated by Puppet
              # Any changes made to it will be overwritten.
              #
              auth include sudo
              account include sudo
              password include sudo
              session optional pam_keyinit.so force revoke
              session required pam_limits.so
              EOM
            )
          }
        end

        context 'with multiple tty_audit_users' do
          let(:params) {{ :tty_audit_users => ['root','foo','bar'] }}

          it { is_expected.to contain_file('/etc/pam.d/sudo').with_content(<<~EOM
              #%PAM-1.0
              # This file is generated by Puppet
              # Any changes made to it will be overwritten.
              #
              auth include system-auth
              account include system-auth
              password include system-auth
              session optional pam_keyinit.so revoke
              session required pam_limits.so
              # auditd disabled: pam_tty_audit set to optional so that all logins do not fail
              session optional pam_tty_audit.so disable=* enable=root,foo,bar open_only
              EOM
            )
          }

          it { is_expected.to contain_file('/etc/pam.d/sudo-i').with_content(<<~EOM
              #%PAM-1.0
              # This file is generated by Puppet
              # Any changes made to it will be overwritten.
              #
              auth include sudo
              account include sudo
              password include sudo
              session optional pam_keyinit.so force revoke
              session required pam_limits.so
              # auditd disabled: pam_tty_audit set to optional so that all logins do not fail
              session optional pam_tty_audit.so disable=* enable=root,foo,bar open_only
              EOM
            )
          }
        end
      end

      context 'with non-default parameters impacting /etc/pam.d/other' do
        context 'with other_content set' do
          let(:params) {{ :other_content => '# some other configuration' }}

          it { is_expected.to contain_file('/etc/pam.d/other').with_content('# some other configuration') }
        end

        context 'deny_if_unknown = false' do
          let(:params){{ :deny_if_unknown => false }}
          it { is_expected.to contain_file('/etc/pam.d/other').with_content(<<~EOM
              #%PAM-1.0
              # This file is generated by Puppet
              # Any changes made to it will be overwritten.
              #
              auth    required    pam_warn.so
              account    required    pam_warn.so
              password    required    pam_warn.so
              session    required    pam_warn.so
              EOM
            )
          }
        end

        context 'no warn_if_unknown = false' do
          let(:params){{ :warn_if_unknown => false }}
          it { is_expected.to contain_file('/etc/pam.d/other').with_content(<<~EOM
              #%PAM-1.0
              # This file is generated by Puppet
              # Any changes made to it will be overwritten.
              #
              auth    required    pam_deny.so
              account    required    pam_deny.so
              password    required    pam_deny.so
              session    required    pam_deny.so
              EOM
            )
          }
        end
      end

      context 'with disable_authconfig = false' do
        let(:params){{ :disable_authconfig => false }}

        it { is_expected.to_not contain_file('/usr/local/sbin/simp_authconfig.sh') }
        it { is_expected.to_not contain_file('/usr/sbin/authconfig') }
        it { is_expected.to_not contain_file('/usr/sbin/authconfig-tui') }
      end

      context 'with empty auth_sections' do
        let(:params){{ :auth_sections => [] }}

        it { is_expected.to_not contain_pam__auth('fingerprint') }
        it { is_expected.to_not contain_pam__auth('system') }
        it { is_expected.to_not contain_pam__auth('password') }
        it { is_expected.to_not contain_pam__auth('smartcard') }
      end

      context 'with managing faillock.conf with default parameters' do
        let(:params){{ :manage_faillock_conf => true}}

        it {is_expected.to compile.with_all_deps}
        if os_facts[:os][:release][:major] <= '7'
          it {is_expected.to_not contain_file('/etc/security/faillock.conf')}
        else
          it {is_expected.to contain_file('/etc/security/faillock.conf').with_content( default_faillock_conf )}
        end
      end

      context 'with managing faillock.conf with all non-default parameters' do
        let(:params){{ 
          :manage_faillock_conf => true,
          :faillock_log_dir => '/var/log/faillock',
          :faillock_audit => true,
          :display_account_lock => false,
          :faillock_no_log_info => true,
          :faillock_local_users_only => true,
          :faillock_nodelay => true,
          :deny => 4,
          :fail_interval => 1200,
          :unlock_time => 180,
          :even_deny_root => true,
          :root_unlock_time => 60,
          :faillock_admin_group => 'wheel'
        }}

        it {is_expected.to compile.with_all_deps}
        if os_facts[:os][:release][:major] <= '7'
          it {is_expected.to_not contain_file('/etc/security/faillock.conf')}
        else
          it {is_expected.to contain_file('/etc/security/faillock.conf').with_content( all_params_faillock_conf )}
        end
      end
    end
  end
end
