require 'spec_helper'

describe 'pam::auth' do
  context 'supported operating systems' do
    on_supported_os.each do |os, facts|
      context "on #{os}" do

        let(:facts){ facts }
        let(:pre_condition){
          'class { "::pam": auth_sections => [] }'
        }
     

        # Default parameters:
        # cracklib_reject_username  = true
        # cracklib_gecoscheck       = true
        # cracklib_enforce_for_root = true
        # display_account_lock      = false
        # use_ldap                  = false
        # use_netgroups             = false
        # use_openshift             = false
        # use_sssd                  = false
        # tty_audit_enable          = ['root']
        context 'All default parameters' do
          context 'fingerprint' do
            let(:title){ 'fingerprint' }
            let(:filename){ '/etc/pam.d/fingerprint-auth' }

            it { is_expected.to compile.with_all_deps }
            it { is_expected.to create_class('oddjob::mkhomedir') }
            it { is_expected.to contain_file(filename).with_mode('0644') }
            it { is_expected.to contain_file("#{filename}-ac").with_ensure('absent') }
            it { is_expected.to contain_file(filename).with_content(<<EOM
#%PAM-1.0
# This file managed by Puppet
# User changes will be lost!
auth     optional      pam_faildelay.so
auth     required      pam_env.so
auth     required      pam_faillock.so preauth silent deny=5 even_deny_root audit unlock_time=900 root_unlock_time=60 fail_interval=900
auth     sufficient    pam_fprintd.so
auth     requisite     pam_succeed_if.so uid >= 500 quiet
auth     required      pam_deny.so

account     required      pam_unix.so broken_shadow
account     required      pam_faillock.so
account     [success=2 default=ignore] pam_succeed_if.so service = crond quiet
account     sufficient    pam_succeed_if.so uid < 500 quiet
account     requisite     pam_access.so nodefgroup
account     required      pam_permit.so

password     required      pam_deny.so

session      optional      pam_keyinit.so revoke
session      required      pam_limits.so
-session     optional      pam_systemd.so
session      sufficient    pam_succeed_if.so service = gdm-launch-environment quiet
session      sufficient    pam_succeed_if.so service in crond quiet use_uid
session      sufficient    pam_succeed_if.so user = root quiet
session      requisite     pam_access.so nodefgroup
session      required      pam_unix.so
session      required      pam_tty_audit.so disable=* enable=root
session      optional      pam_oddjob_mkhomedir.so silent
session      required      pam_lastlog.so showfailed
EOM
              )
            }
          end

          context 'password' do
            let(:title){ 'password' }
            let(:filename){ '/etc/pam.d/password-auth' }

            it { is_expected.to compile.with_all_deps }
            it { is_expected.to create_class('oddjob::mkhomedir') }
            it { is_expected.to contain_file(filename).with_mode('0644') }
            it { is_expected.to contain_file("#{filename}-ac").with_ensure('absent') }
            it { is_expected.to contain_file(filename).with_content(<<EOM
#%PAM-1.0
# This file managed by Puppet
# User changes will be lost!
auth     optional      pam_faildelay.so
auth     required      pam_env.so
auth     required      pam_faillock.so preauth silent deny=5 even_deny_root audit unlock_time=900 root_unlock_time=60 fail_interval=900
auth     sufficient    pam_unix.so try_first_pass
auth     [default=die] pam_faillock.so authfail deny=5 even_deny_root audit unlock_time=900 root_unlock_time=60
auth     requisite     pam_succeed_if.so uid >= 500 quiet
auth     required      pam_deny.so

account     required      pam_unix.so broken_shadow
account     required      pam_faillock.so
account     [success=2 default=ignore] pam_succeed_if.so service = crond quiet
account     sufficient    pam_succeed_if.so uid < 500 quiet
account     requisite     pam_access.so nodefgroup
account     required      pam_permit.so

password     requisite     pam_cracklib.so try_first_pass difok=4 retry=3 minlen=14 minclass=3 maxrepeat=2 maxclassrepeat=0 maxsequence=4 dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1 gecoscheck reject_username enforce_for_root
password     sufficient    pam_unix.so sha512 rounds=10000 shadow try_first_pass use_authtok remember=24
password     required      pam_deny.so

session      optional      pam_keyinit.so revoke
session      required      pam_limits.so
-session     optional      pam_systemd.so
session      sufficient    pam_succeed_if.so service = gdm-launch-environment quiet
session      sufficient    pam_succeed_if.so service in crond quiet use_uid
session      sufficient    pam_succeed_if.so user = root quiet
session      requisite     pam_access.so nodefgroup
session      required      pam_unix.so
session      required      pam_tty_audit.so disable=* enable=root
session      optional      pam_oddjob_mkhomedir.so silent
session      required      pam_lastlog.so showfailed
EOM
              )
            }
          end

          context 'smartcard' do
            let(:title){ 'smartcard' }
            let(:filename){ '/etc/pam.d/smartcard-auth' }

            it { is_expected.to compile.with_all_deps }
            it { is_expected.to create_class('oddjob::mkhomedir') }
            it { is_expected.to contain_file(filename).with_mode('0644') }
            it { is_expected.to contain_file("#{filename}-ac").with_ensure('absent') }
            it { is_expected.to contain_file(filename).with_content(<<EOM
#%PAM-1.0
# This file managed by Puppet
# User changes will be lost!
auth     optional      pam_faildelay.so
auth     required      pam_env.so
auth     required      pam_faillock.so preauth silent deny=5 even_deny_root audit unlock_time=900 root_unlock_time=60 fail_interval=900
auth     [success=done ignore=ignore default=die] pam_pkcs11.so wait_for_card card_only
auth     requisite     pam_succeed_if.so uid >= 500 quiet
auth     required      pam_deny.so

account     required      pam_unix.so broken_shadow
account     required      pam_faillock.so
account     [success=2 default=ignore] pam_succeed_if.so service = crond quiet
account     sufficient    pam_succeed_if.so uid < 500 quiet
account     requisite     pam_access.so nodefgroup
account     required      pam_permit.so

password     required      pam_pkcs11.so

session      optional      pam_keyinit.so revoke
session      required      pam_limits.so
-session     optional      pam_systemd.so
session      sufficient    pam_succeed_if.so service = gdm-launch-environment quiet
session      sufficient    pam_succeed_if.so service in crond quiet use_uid
session      sufficient    pam_succeed_if.so user = root quiet
session      requisite     pam_access.so nodefgroup
session      required      pam_unix.so
session      optional      pam_oddjob_mkhomedir.so silent
session      required      pam_lastlog.so showfailed
EOM
              )
            }
          end

          context 'system' do
            let(:title){ 'system' }
            let(:filename){ '/etc/pam.d/system-auth' }

            it { is_expected.to compile.with_all_deps }
            it { is_expected.to create_class('oddjob::mkhomedir') }
            it { is_expected.to contain_file(filename).with_mode('0644') }
            it { is_expected.to contain_file("#{filename}-ac").with_ensure('absent') }
            it { is_expected.to contain_file(filename).with_content(<<EOM
#%PAM-1.0
# This file managed by Puppet
# User changes will be lost!
auth     optional      pam_faildelay.so
auth     required      pam_env.so
auth     required      pam_faillock.so preauth silent deny=5 even_deny_root audit unlock_time=900 root_unlock_time=60 fail_interval=900
auth     sufficient    pam_unix.so try_first_pass
auth     requisite     pam_succeed_if.so uid >= 500 quiet
auth     required      pam_deny.so

account     required      pam_unix.so broken_shadow
account     required      pam_faillock.so
account     [success=2 default=ignore] pam_succeed_if.so service = crond quiet
account     sufficient    pam_succeed_if.so uid < 500 quiet
account     requisite     pam_access.so nodefgroup
account     required      pam_permit.so

password     requisite     pam_cracklib.so try_first_pass difok=4 retry=3 minlen=14 minclass=3 maxrepeat=2 maxclassrepeat=0 maxsequence=4 dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1 gecoscheck reject_username enforce_for_root
password     sufficient    pam_unix.so sha512 rounds=10000 shadow try_first_pass use_authtok remember=24
password     required      pam_deny.so

session      optional      pam_keyinit.so revoke
session      required      pam_limits.so
-session     optional      pam_systemd.so
session      sufficient    pam_succeed_if.so service = gdm-launch-environment quiet
session      sufficient    pam_succeed_if.so service in crond quiet use_uid
session      sufficient    pam_succeed_if.so user = root quiet
session      requisite     pam_access.so nodefgroup
session      required      pam_unix.so
session      required      pam_tty_audit.so disable=* enable=root
session      optional      pam_oddjob_mkhomedir.so silent
session      required      pam_lastlog.so showfailed
EOM
              )
            }
          end
        end
  
        context "Boolean params opposite to defaults with sssd taking precedence over ldap" do
          let(:params){{
            :cracklib_reject_username  => false,
            :cracklib_gecoscheck       => false,
            :cracklib_enforce_for_root => false,
            :display_account_lock      => true,
            :use_ldap                  => true,
            :use_netgroups             => true,
            :use_openshift             => true,
            :use_sssd                  => true
          }}

          context 'fingerprint' do
            let(:title){ 'fingerprint' }
            let(:filename){ '/etc/pam.d/fingerprint-auth' }

            it { is_expected.to compile.with_all_deps }
            it { is_expected.to create_class('oddjob::mkhomedir') }
            it { is_expected.to contain_file(filename).with_mode('0644') }
            it { is_expected.to contain_file("#{filename}-ac").with_ensure('absent') }
            it { is_expected.to contain_file(filename).with_content(<<EOM
#%PAM-1.0
# This file managed by Puppet
# User changes will be lost!
auth     optional      pam_faildelay.so
auth     required      pam_env.so
auth     required      pam_faillock.so preauth  deny=5 even_deny_root audit unlock_time=900 root_unlock_time=60 fail_interval=900
auth     sufficient    pam_fprintd.so
auth     requisite     pam_succeed_if.so uid >= 500 quiet
auth     required      pam_deny.so

account     required      pam_access.so accessfile=/etc/security/access.conf
account     required      pam_unix.so broken_shadow
account     required      pam_faillock.so
account     [success=4 default=ignore] pam_succeed_if.so quiet shell = /usr/bin/oo-trap-user
account     [success=3 default=ignore] pam_succeed_if.so service = crond quiet
account     sufficient    pam_succeed_if.so uid < 500 quiet
account     requisite     pam_access.so nodefgroup
account     [success=1 default=ignore] pam_localuser.so
account     [default=bad success=ok system_err=ignore user_unknown=ignore] pam_sss.so
account     required      pam_permit.so

password     required      pam_deny.so

session      optional      pam_keyinit.so revoke
session      required      pam_limits.so
-session     optional      pam_systemd.so
session      sufficient    pam_succeed_if.so service = gdm-launch-environment quiet
session      sufficient    pam_succeed_if.so service in crond quiet use_uid
session      sufficient    pam_succeed_if.so user = root quiet
session      [default=1 success=ignore] pam_succeed_if.so quiet shell = /usr/bin/oo-trap-user
session      required      pam_namespace.so no_unmount_on_close
session      [default=ignore success=1] pam_succeed_if.so quiet shell = /usr/bin/oo-trap-user
session      requisite     pam_access.so nodefgroup
session      optional      pam_sss.so
session      required      pam_tty_audit.so disable=* enable=root
session      optional      pam_oddjob_mkhomedir.so silent
session      required      pam_lastlog.so showfailed
EOM
              )
            }

          end

          context 'password' do
            let(:title){ 'password' }
            let(:filename){ '/etc/pam.d/password-auth' }

            it { is_expected.to compile.with_all_deps }
            it { is_expected.to create_class('oddjob::mkhomedir') }
            it { is_expected.to contain_file(filename).with_mode('0644') }
            it { is_expected.to contain_file("#{filename}-ac").with_ensure('absent') }
            it { is_expected.to contain_file(filename).with_content(<<EOM
#%PAM-1.0
# This file managed by Puppet
# User changes will be lost!
auth     optional      pam_faildelay.so
auth     required      pam_env.so
auth     required      pam_faillock.so preauth  deny=5 even_deny_root audit unlock_time=900 root_unlock_time=60 fail_interval=900
auth     sufficient    pam_sss.so forward_pass
auth     sufficient    pam_unix.so try_first_pass
auth     [default=die] pam_faillock.so authfail deny=5 even_deny_root audit unlock_time=900 root_unlock_time=60
auth     requisite     pam_succeed_if.so uid >= 500 quiet
auth     required      pam_deny.so

account     required      pam_access.so accessfile=/etc/security/access.conf
account     required      pam_unix.so broken_shadow
account     required      pam_faillock.so
account     [success=4 default=ignore] pam_succeed_if.so quiet shell = /usr/bin/oo-trap-user
account     [success=3 default=ignore] pam_succeed_if.so service = crond quiet
account     sufficient    pam_succeed_if.so uid < 500 quiet
account     requisite     pam_access.so nodefgroup
account     [success=1 default=ignore] pam_localuser.so
account     [default=bad success=ok system_err=ignore user_unknown=ignore] pam_sss.so
account     required      pam_permit.so

password     requisite     pam_cracklib.so try_first_pass difok=4 retry=3 minlen=14 minclass=3 maxrepeat=2 maxclassrepeat=0 maxsequence=4 dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1
password     sufficient    pam_sss.so use_authtok
password     sufficient    pam_unix.so sha512 rounds=10000 shadow try_first_pass use_authtok remember=24
password     required      pam_deny.so

session      optional      pam_keyinit.so revoke
session      required      pam_limits.so
-session     optional      pam_systemd.so
session      sufficient    pam_succeed_if.so service = gdm-launch-environment quiet
session      sufficient    pam_succeed_if.so service in crond quiet use_uid
session      sufficient    pam_succeed_if.so user = root quiet
session      [default=1 success=ignore] pam_succeed_if.so quiet shell = /usr/bin/oo-trap-user
session      required      pam_namespace.so no_unmount_on_close
session      [default=ignore success=1] pam_succeed_if.so quiet shell = /usr/bin/oo-trap-user
session      requisite     pam_access.so nodefgroup
session      optional      pam_sss.so
session      required      pam_tty_audit.so disable=* enable=root
session      optional      pam_oddjob_mkhomedir.so silent
session      required      pam_lastlog.so showfailed
EOM
              )
            }
          end

          context 'smartcard' do
            let(:title){ 'smartcard' }
            let(:filename){ '/etc/pam.d/smartcard-auth' }

            it { is_expected.to compile.with_all_deps }
            it { is_expected.to create_class('oddjob::mkhomedir') }
            it { is_expected.to contain_file(filename).with_mode('0644') }
            it { is_expected.to contain_file("#{filename}-ac").with_ensure('absent') }
            it { is_expected.to contain_file(filename).with_content(<<EOM
#%PAM-1.0
# This file managed by Puppet
# User changes will be lost!
auth     optional      pam_faildelay.so
auth     required      pam_env.so
auth     required      pam_faillock.so preauth  deny=5 even_deny_root audit unlock_time=900 root_unlock_time=60 fail_interval=900
auth     [success=done ignore=ignore default=die] pam_pkcs11.so wait_for_card card_only
auth     requisite     pam_succeed_if.so uid >= 500 quiet
auth     required      pam_deny.so

account     required      pam_access.so accessfile=/etc/security/access.conf
account     required      pam_unix.so broken_shadow
account     required      pam_faillock.so
account     [success=4 default=ignore] pam_succeed_if.so quiet shell = /usr/bin/oo-trap-user
account     [success=3 default=ignore] pam_succeed_if.so service = crond quiet
account     sufficient    pam_succeed_if.so uid < 500 quiet
account     requisite     pam_access.so nodefgroup
account     [success=1 default=ignore] pam_localuser.so
account     [default=bad success=ok system_err=ignore user_unknown=ignore] pam_sss.so
account     required      pam_permit.so

password     required      pam_pkcs11.so

session      optional      pam_keyinit.so revoke
session      required      pam_limits.so
-session     optional      pam_systemd.so
session      sufficient    pam_succeed_if.so service = gdm-launch-environment quiet
session      sufficient    pam_succeed_if.so service in crond quiet use_uid
session      sufficient    pam_succeed_if.so user = root quiet
session      [default=1 success=ignore] pam_succeed_if.so quiet shell = /usr/bin/oo-trap-user
session      required      pam_namespace.so no_unmount_on_close
session      [default=ignore success=1] pam_succeed_if.so quiet shell = /usr/bin/oo-trap-user
session      requisite     pam_access.so nodefgroup
session      optional      pam_sss.so
session      optional      pam_oddjob_mkhomedir.so silent
session      required      pam_lastlog.so showfailed
EOM
              )
            }
          end

          context 'system' do
            let(:title){ 'system' }
            let(:filename){ '/etc/pam.d/system-auth' }

            it { is_expected.to compile.with_all_deps }
            it { is_expected.to create_class('oddjob::mkhomedir') }
            it { is_expected.to contain_file(filename).with_mode('0644') }
            it { is_expected.to contain_file("#{filename}-ac").with_ensure('absent') }
            it { is_expected.to contain_file(filename).with_content(<<EOM
#%PAM-1.0
# This file managed by Puppet
# User changes will be lost!
auth     optional      pam_faildelay.so
auth     required      pam_env.so
auth     required      pam_faillock.so preauth  deny=5 even_deny_root audit unlock_time=900 root_unlock_time=60 fail_interval=900
auth     sufficient    pam_sss.so forward_pass
auth     sufficient    pam_unix.so try_first_pass
auth     requisite     pam_succeed_if.so uid >= 500 quiet
auth     required      pam_deny.so

account     required      pam_access.so accessfile=/etc/security/access.conf
account     required      pam_unix.so broken_shadow
account     required      pam_faillock.so
account     [success=4 default=ignore] pam_succeed_if.so quiet shell = /usr/bin/oo-trap-user
account     [success=3 default=ignore] pam_succeed_if.so service = crond quiet
account     sufficient    pam_succeed_if.so uid < 500 quiet
account     requisite     pam_access.so nodefgroup
account     [success=1 default=ignore] pam_localuser.so
account     [default=bad success=ok system_err=ignore user_unknown=ignore] pam_sss.so
account     required      pam_permit.so

password     requisite     pam_cracklib.so try_first_pass difok=4 retry=3 minlen=14 minclass=3 maxrepeat=2 maxclassrepeat=0 maxsequence=4 dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1
password     sufficient    pam_sss.so use_authtok
password     sufficient    pam_unix.so sha512 rounds=10000 shadow try_first_pass use_authtok remember=24
password     required      pam_deny.so

session      optional      pam_keyinit.so revoke
session      required      pam_limits.so
-session     optional      pam_systemd.so
session      sufficient    pam_succeed_if.so service = gdm-launch-environment quiet
session      sufficient    pam_succeed_if.so service in crond quiet use_uid
session      sufficient    pam_succeed_if.so user = root quiet
session      [default=1 success=ignore] pam_succeed_if.so quiet shell = /usr/bin/oo-trap-user
session      required      pam_namespace.so no_unmount_on_close
session      [default=ignore success=1] pam_succeed_if.so quiet shell = /usr/bin/oo-trap-user
session      requisite     pam_access.so nodefgroup
session      optional      pam_sss.so
session      required      pam_tty_audit.so disable=* enable=root
session      optional      pam_oddjob_mkhomedir.so silent
session      required      pam_lastlog.so showfailed
EOM
              )
            }
          end
        end

        context "'password' using LDAP without SSSD and use_openshift" do
          let(:title){ 'password' }
          let(:filename){ "/etc/pam.d/password-auth" }
          let(:params){{
            :use_ldap      => true,
            :use_openshift => true   # allows us to test non-SSSD paths
          }}

          it { is_expected.to compile.with_all_deps }
          it { is_expected.to create_class('oddjob::mkhomedir') }
          it { is_expected.to contain_file(filename).with_mode('0644') }
          it { is_expected.to contain_file("#{filename}-ac").with_ensure('absent') }
          it { is_expected.to contain_file(filename).with_content(<<EOM
#%PAM-1.0
# This file managed by Puppet
# User changes will be lost!
auth     optional      pam_faildelay.so
auth     required      pam_env.so
auth     required      pam_faillock.so preauth silent deny=5 even_deny_root audit unlock_time=900 root_unlock_time=60 fail_interval=900
auth     sufficient    pam_unix.so try_first_pass
auth     sufficient    pam_ldap.so use_first_pass ignore_unknown_user ignore_authinfo_unavail
auth     [default=die] pam_faillock.so authfail deny=5 even_deny_root audit unlock_time=900 root_unlock_time=60
auth     requisite     pam_succeed_if.so uid >= 500 quiet
auth     required      pam_deny.so

account     [success=1]   pam_unix.so broken_shadow
account     optional      pam_ldap.so ignore_unknown_user ignore_authinfo_unavail
account     required      pam_faillock.so
account     [success=3 default=ignore] pam_succeed_if.so quiet shell = /usr/bin/oo-trap-user
account     [success=2 default=ignore] pam_succeed_if.so service = crond quiet
account     sufficient    pam_succeed_if.so uid < 500 quiet
account     requisite     pam_access.so nodefgroup
account     required      pam_permit.so

password     requisite     pam_cracklib.so try_first_pass difok=4 retry=3 minlen=14 minclass=3 maxrepeat=2 maxclassrepeat=0 maxsequence=4 dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1 gecoscheck reject_username enforce_for_root
password     sufficient    pam_unix.so sha512 rounds=10000 shadow try_first_pass use_authtok remember=24
password     sufficient    pam_ldap.so use_authtok ignore_unknown_user ignore_authinfo_unavail
password     required      pam_deny.so

session      optional      pam_keyinit.so revoke
session      required      pam_limits.so
-session     optional      pam_systemd.so
session      sufficient    pam_succeed_if.so service = gdm-launch-environment quiet
session      sufficient    pam_succeed_if.so service in crond quiet use_uid
session      sufficient    pam_succeed_if.so user = root quiet
session      [default=1 success=ignore] pam_succeed_if.so quiet shell = /usr/bin/oo-trap-user
session      required      pam_namespace.so no_unmount_on_close
session      [default=ignore success=1] pam_succeed_if.so quiet shell = /usr/bin/oo-trap-user
session      requisite     pam_access.so nodefgroup
session      [success=1]   pam_unix.so
session      optional      pam_ldap.so ignore_unknown_user ignore_authinfo_unavail
session      required      pam_tty_audit.so disable=* enable=root
session      optional      pam_oddjob_mkhomedir.so silent
session      required      pam_lastlog.so showfailed
EOM
            )
          }
        end

        context "'system' using LDAP without SSSD and use_openshift" do
          let(:title){ 'system' }
          let(:filename){ "/etc/pam.d/system-auth" }
          let(:params){{
            :use_ldap      => true,
            :use_openshift => true   # allows us to test non-SSSD paths
          }}

          it { is_expected.to compile.with_all_deps }
          it { is_expected.to create_class('oddjob::mkhomedir') }
          it { is_expected.to contain_file(filename).with_mode('0644') }
          it { is_expected.to contain_file("#{filename}-ac").with_ensure('absent') }
          it { is_expected.to contain_file(filename).with_content(<<EOM
#%PAM-1.0
# This file managed by Puppet
# User changes will be lost!
auth     optional      pam_faildelay.so
auth     required      pam_env.so
auth     required      pam_faillock.so preauth silent deny=5 even_deny_root audit unlock_time=900 root_unlock_time=60 fail_interval=900
auth     sufficient    pam_unix.so try_first_pass
auth     sufficient    pam_ldap.so use_first_pass ignore_unknown_user ignore_authinfo_unavail
auth     requisite     pam_succeed_if.so uid >= 500 quiet
auth     required      pam_deny.so

account     [success=1]   pam_unix.so broken_shadow
account     optional      pam_ldap.so ignore_unknown_user ignore_authinfo_unavail
account     required      pam_faillock.so
account     [success=3 default=ignore] pam_succeed_if.so quiet shell = /usr/bin/oo-trap-user
account     [success=2 default=ignore] pam_succeed_if.so service = crond quiet
account     sufficient    pam_succeed_if.so uid < 500 quiet
account     requisite     pam_access.so nodefgroup
account     required      pam_permit.so

password     requisite     pam_cracklib.so try_first_pass difok=4 retry=3 minlen=14 minclass=3 maxrepeat=2 maxclassrepeat=0 maxsequence=4 dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1 gecoscheck reject_username enforce_for_root
password     sufficient    pam_unix.so sha512 rounds=10000 shadow try_first_pass use_authtok remember=24
password     sufficient    pam_ldap.so use_authtok ignore_unknown_user ignore_authinfo_unavail
password     required      pam_deny.so

session      optional      pam_keyinit.so revoke
session      required      pam_limits.so
-session     optional      pam_systemd.so
session      sufficient    pam_succeed_if.so service = gdm-launch-environment quiet
session      sufficient    pam_succeed_if.so service in crond quiet use_uid
session      sufficient    pam_succeed_if.so user = root quiet
session      [default=1 success=ignore] pam_succeed_if.so quiet shell = /usr/bin/oo-trap-user
session      required      pam_namespace.so no_unmount_on_close
session      [default=ignore success=1] pam_succeed_if.so quiet shell = /usr/bin/oo-trap-user
session      requisite     pam_access.so nodefgroup
session      [success=1]   pam_unix.so
session      optional      pam_ldap.so ignore_unknown_user ignore_authinfo_unavail
session      required      pam_tty_audit.so disable=* enable=root
session      optional      pam_oddjob_mkhomedir.so silent
session      required      pam_lastlog.so showfailed
EOM
            )
          }
        end

        context "Enabling pam_tty_audit for multiple users" do
          ['password','system','fingerprint'].each do |auth_type|
            context "auth type '#{auth_type}'" do
              let(:title){ auth_type }
              let(:filename){ "/etc/pam.d/#{auth_type}-auth" }
              let(:params){{
                :tty_audit_enable => ['root', 'user1', 'user2']
              }}

              it { is_expected.to compile.with_all_deps }
              it { is_expected.to create_class('oddjob::mkhomedir') }
              it { is_expected.to contain_file(filename).with_mode('0644') }
              it { is_expected.to contain_file("#{filename}-ac").with_ensure('absent') }
              it { is_expected.to contain_file(filename).with_content(
                /^\s*session\s+required\s+pam_tty_audit\.so\s+disable=\*\s+enable=root,user1,user2/m
                )
              }
            end
          end
        end

        context "Not using pam_tty_audit for any users" do
          ['password','system','fingerprint'].each do |auth_type|
            context "auth type '#{auth_type}'" do
              let(:title){ auth_type }
              let(:filename){ "/etc/pam.d/#{auth_type}-auth" }
              let(:params){{
                :tty_audit_enable => []
              }}

              it { is_expected.to compile.with_all_deps }
              it { is_expected.to create_class('oddjob::mkhomedir') }
              it { is_expected.to contain_file(filename).with_mode('0644') }
              it { is_expected.to contain_file("#{filename}-ac").with_ensure('absent') }
              it { is_expected.to contain_file(filename).without_content(
                /^\s*session\s+required\s+pam_tty_audit\.so/m
                )
              }
            end
          end
        end
      end
    end
  end
end
