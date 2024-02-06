# @summary Configuration class called from pam.
#
# @author https://github.com/simp/pupmod-simp-pam/graphs/contributors
#
class pam::config {
  assert_private()

  file { '/etc/pam.d':
    ensure  => 'directory',
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
    recurse => true,
  }

  if $pam::use_authselect {
    file { '/etc/pam.d/simp':
      ensure  => 'directory',
      owner   => 'root',
      group   => 'root',
      mode    => '0644',
      recurse => true,
    }
  }

  if ($pam::password_check_backend == 'pwquality') {
    # The 'retry' option  was introduced in RHEL 8.4 and Amazon Linux 2022, set it to false if
    # lower than those versions so it doesn't get included
    if ($facts['os']['name'] == 'Amazon' and Integer($facts['os']['release']['major']) < 2022) or
    ($facts['os']['family'] == 'RedHat' and Integer($facts['os']['release']['major']) < 8) or
    # CentOS Streams doesn't provide a minor version number:
    (Integer($facts['os']['release']['major']) == 8 and
    $facts['os']['release']['minor'] and Integer($facts['os']['release']['minor']) < 4) {
      $_cracklib_retry = false
    } else {
      $_cracklib_retry = $pam::cracklib_retry
    }

    # The dictcheck, enforce_for_root, and reject_username options were introduced to the pwquality.conf file in RHEL 8 and Amazon 2022,
    # Set them to false if less than those versions.
    if ($facts['os']['name'] == 'Amazon' and Integer($facts['os']['release']['major']) < 2022) or
    ($facts['os']['family'] == 'RedHat' and Integer($facts['os']['release']['major']) < 8) {
      $_cracklib_enforce_for_root = false
      $_cracklib_reject_username = false
      $_dictcheck = false
    } else {
      $_cracklib_enforce_for_root = $pam::cracklib_enforce_for_root
      $_cracklib_reject_username = $pam::cracklib_reject_username
      $_dictcheck = $pam::dictcheck
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
          'pam_module_path' => 'system-auth',
          'force_revoke'    => false,
          'tty_audit_users' => $pam::tty_audit_users,
      })
      ;
    '/etc/pam.d/sudo-i':
      content => epp('pam/etc/pam.d/sudo', {
          'pam_module_path' => 'sudo',
          'force_revoke'    => true,
          'tty_audit_users' => $pam::tty_audit_users,
      })
      ;
    '/etc/pam.d/other':
      content => $_other_content,
      ;
  }

  if (($facts['os']['family'] == 'RedHat' and Integer($facts['os']['release']['major']) < 8) or
  ($facts['os']['name'] == 'Amazon' and Integer($facts['os']['release']['major']) < 2022)) and
  ($pam::disable_authconfig == true) {
    # Replace authconfig and authconfig-tui with a no-op script
    # so that those tools can't be used to modify PAM.
    file { '/usr/local/sbin/simp_authconfig.sh':
      ensure  => 'file',
      owner   => 'root',
      group   => 'root',
      mode    => '0755',
      content => file("${module_name}/simp_authconfig.sh"),
    }

    file { [
        '/usr/sbin/authconfig',
        '/usr/sbin/authconfig-tui',
      ]:
        ensure  => 'link',
        target  => '/usr/local/sbin/simp_authconfig.sh',
        require => File['/usr/local/sbin/simp_authconfig.sh'],
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

  # EL 7 and Amazon Linux 2 don't utilize faillock.conf and pwhistory.conf, it will break if used
  if ($facts['os']['family'] == 'RedHat' and Integer($facts['os']['release']['major']) > 7) or
  (($facts['os']['name'] == 'Amazon') and Integer($facts['os']['release']['major']) >= 2022) {
    if ($pam::manage_faillock_conf) {
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

    if ($pam::manage_pwhistory_conf) {
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
}
