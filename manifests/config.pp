# @summary Configuration class called from pam.
#
# @author https://github.com/simp/pupmod-simp-pam/graphs/contributors
#
class pam::config {
  assert_private()

  file { '/etc/pam.d':
    ensure                  => 'directory',
    owner                   => 'root',
    group                   => 'root',
    mode                    => '0644',
    recurse                 => true,
    # Do not manage the SELinux context of the recursively-managed files.
    # authselect regenerates the *-auth files (and their contexts) on every
    # run, so enforcing a puppet-computed seluser here flaps
    # unconfined_u <-> system_u each apply and breaks idempotency on
    # SELinux-enforcing hosts.
    selinux_ignore_defaults => true,
  }

  if ($pam::password_check_backend == 'pwquality') {
    # The 'retry' option was introduced in RHEL 8.4
    # Use the OS capability flag to determine if it should be included
    if $pam::cracklib_retry_supported {
      $_cracklib_retry = $pam::cracklib_retry
    } else {
      $_cracklib_retry = false
    }

    # The dictcheck, enforce_for_root, and reject_username options were introduced
    # to the pwquality.conf file in RHEL 8
    # Use the OS capability flags to determine if they should be included
    if $pam::pwquality_enforce_for_root_supported {
      $_cracklib_enforce_for_root = $pam::cracklib_enforce_for_root
    } else {
      $_cracklib_enforce_for_root = false
    }

    if $pam::pwquality_reject_username_supported {
      $_cracklib_reject_username = $pam::cracklib_reject_username
    } else {
      $_cracklib_reject_username = false
    }

    if $pam::pwquality_dictcheck_supported {
      $_dictcheck = $pam::dictcheck
    } else {
      $_dictcheck = false
    }

    file { '/etc/security/pwquality.conf':
      ensure  => 'file',
      owner   => 'root',
      group   => 'root',
      mode    => '0644',
      content => epp("${module_name}/etc/security/pwquality.conf.epp", {
        difok            => $pam::cracklib_difok,
        maxrepeat        => $pam::cracklib_maxrepeat,
        maxsequence      => $pam::cracklib_maxsequence,
        maxclassrepeat   => $pam::cracklib_maxclassrepeat,
        gecoscheck       => $pam::cracklib_gecoscheck,
        dcredit          => $pam::cracklib_dcredit,
        ucredit          => $pam::cracklib_ucredit,
        lcredit          => $pam::cracklib_lcredit,
        ocredit          => $pam::cracklib_ocredit,
        minclass         => $pam::cracklib_minclass,
        minlen           => $pam::cracklib_minlen,
        retry            => $_cracklib_retry,
        enforce_for_root => $_cracklib_enforce_for_root,
        reject_username  => $_cracklib_reject_username,
        badwords         => $pam::cracklib_badwords,
        dictpath         => $pam::cracklib_dictpath,
        dictcheck        => $_dictcheck
      }),
    }

    if $pam::rm_pwquality_conf_d {
      # Ensure that we can't be overridden
      file { '/etc/security/pwquality.conf.d':
        ensure => 'absent',
        force  => true,
      }
    }
  }

  if $pam::other_content {
    $_other_content = $pam::other_content
  }
  else {
    $_other_content = epp("${module_name}/etc/pam.d/other.epp", {
      warn_if_unknown => $pam::warn_if_unknown,
      deny_if_unknown => $pam::deny_if_unknown
    })
  }

  file {
    default:
      ensure => 'file',
      owner  => 'root',
      group  => 'root',
      mode   => '0644',
    ;
    ['/etc/pam.d/atd', '/etc/pam.d/crond']:
    ;
    '/etc/pam.d/sudo':
      content => epp('pam/etc/pam.d/sudo', {
        'pam_module_path'                        => 'system-auth',
        'force_revoke'                           => false,
        'tty_audit_users'                        => $pam::tty_audit_users,
        'enable_ssh_agent_auth'                  => $pam::enable_ssh_agent_auth,
        'ssh_agent_auth_authorized_keys_command' => $pam::ssh_agent_auth_authorized_keys_command,
      })
    ;
    '/etc/pam.d/sudo-i':
      content => epp('pam/etc/pam.d/sudo', {
        'pam_module_path'                        => 'sudo',
        'force_revoke'                           => true,
        'tty_audit_users'                        => $pam::tty_audit_users,
        'enable_ssh_agent_auth'                  => $pam::enable_ssh_agent_auth,
        'ssh_agent_auth_authorized_keys_command' => $pam::ssh_agent_auth_authorized_keys_command,
      })
    ;
    '/etc/pam.d/other':
      content => $_other_content,
    ;
  }

  # Transitional cleanup for the authconfig shim removed in 9.2.0.
  #
  # Earlier versions replaced /usr/sbin/authconfig and /usr/sbin/authconfig-tui
  # with symlinks to a no-op script. Deleting the code that created them does
  # not remove them, so a node that opted in keeps an unmanaged shim that a
  # later authconfig package update can silently overwrite -- ending the
  # hardening with no signal. Reap them here instead.
  #
  # Gated on the same condition that created them so that nodes which never
  # opted in are untouched and keep their real authconfig binary. Remove this
  # block, and the two parameters, in the next major release.
  #
  # Operators who still want the real tool can restore it with
  # `dnf reinstall authconfig`.
  if $pam::authconfig_present and $pam::disable_authconfig {
    file { [
        '/usr/sbin/authconfig',
        '/usr/sbin/authconfig-tui',
        '/usr/local/sbin/simp_authconfig.sh',
      ]:
        ensure => absent,
    }
  }

  if ($pam::faillock_log_dir) {
    file { $pam::faillock_log_dir:
      ensure   => 'directory',
      owner    => 'root',
      group    => 'root',
      mode     => '0750',
      seluser  => 'system_u',
      selrole  => 'object_r',
      seltype  => 'faillog_t',
      selrange => 's0',
    }
  }

  if ($pam::remember_file) {
    file { $pam::remember_file:
      ensure   => 'file',
      owner    => 'root',
      group    => 'root',
      mode     => '0600',
      seluser  => 'system_u',
      selrole  => 'object_r',
      seltype  => 'shadow_t',
      selrange => 's0',
    }
  }

  # Platforms older than EL 8 don't utilize faillock.conf and pwhistory.conf
  if $pam::faillock_conf_supported or $pam::pwhistory_conf_supported {
    if ($pam::manage_faillock_conf and $pam::faillock_conf_supported) {
      file { '/etc/security/faillock.conf':
        ensure  => 'file',
        owner   => 'root',
        group   => 'root',
        mode    => '0644',
        content => epp("${module_name}/etc/security/faillock.conf.epp", {
          dir              => $pam::faillock_log_dir,
          audit            => $pam::faillock_audit,
          silent           => !$pam::display_account_lock,
          no_log_info      => $pam::faillock_no_log_info,
          local_users_only => $pam::faillock_local_users_only,
          nodelay          => $pam::faillock_nodelay,
          deny             => $pam::deny,
          fail_interval    => $pam::fail_interval,
          unlock_time      => $pam::unlock_time,
          even_deny_root   => $pam::even_deny_root,
          root_unlock_time => $pam::root_unlock_time,
          admin_group      => $pam::faillock_admin_group
        }),
      }
    }

    if ($pam::manage_pwhistory_conf and $pam::pwhistory_conf_supported) {
      file { '/etc/security/pwhistory.conf':
        ensure  => 'file',
        owner   => 'root',
        group   => 'root',
        mode    => '0644',
        content => epp("${module_name}/etc/security/pwhistory.conf.epp", {
          debug            => $pam::remember_debug,
          enforce_for_root => $pam::remember_for_root,
          remember         => $pam::remember,
          retry            => $pam::remember_retry,
          remember_file    => $pam::remember_file,
        }),
      }
    }
  }

  if ! empty($pam::auth_sections) { ::pam::auth { $pam::auth_sections: } }

  # If $pam::use_authselect is true, select the $pam::authselect_profile_name authselect profile
  if $pam::use_authselect {
    # Created the 'simp' authselect profile skeleton with all of the non-pam bits
    # symlinked from the $pam::authselect_base_profile profile. The pam::auth class
    # will fill the content of the pam files in a later step.
    authselect::custom_profile { $pam::authselect_profile_name:
      base_profile     => $pam::authselect_base_profile,
      vendor           => true,
      symlink_meta     => true,
      symlink_nsswitch => true,
      symlink_pam      => false,
      symlink_dconf    => true,
    }

    class { 'authselect':
      profile => $pam::authselect_profile_name,
    }

    Authselect::Custom_profile[$pam::authselect_profile_name] -> Pam::Auth[$pam::auth_sections]
    Pam::Auth[$pam::auth_sections] -> Exec["authselect set profile=${pam::authselect_profile_name} features=[]"]
  }
}
