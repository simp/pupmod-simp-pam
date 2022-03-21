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
    recurse => true
  }

  if ($pam::password_check_backend == 'pwquality') {
    file { '/etc/security/pwquality.conf':
      ensure  => 'file',
      owner   => 'root',
      group   => 'root',
      mode    => '0644',
      content => epp("${module_name}/etc/security/pwquality.conf.epp", {
        difok          => $pam::cracklib_difok,
        maxrepeat      => $pam::cracklib_maxrepeat,
        maxsequence    => $pam::cracklib_maxsequence,
        maxclassrepeat => $pam::cracklib_maxclassrepeat,
        gecoscheck     => $pam::cracklib_gecoscheck,
        dcredit        => $pam::cracklib_dcredit,
        ucredit        => $pam::cracklib_ucredit,
        lcredit        => $pam::cracklib_lcredit,
        ocredit        => $pam::cracklib_ocredit,
        minclass       => $pam::cracklib_minclass,
        minlen         => $pam::cracklib_minlen,
        badwords       => $pam::cracklib_badwords,
        dictpath       => $pam::cracklib_dictpath
      })
    }

    if $pam::rm_pwquality_conf_d {
      # Ensure that we can't be overridden
      file { '/etc/security/pwquality.conf.d':
        ensure => 'absent',
        force  => true
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
    [ '/etc/pam.d/atd', '/etc/pam.d/crond' ]:
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

  if ($facts['os']['release']['major'] <= '7') and ($pam::disable_authconfig == true) {
    # Replace authconfig and authconfig-tui with a no-op script
    # so that those tools can't be used to modify PAM.
      file { '/usr/local/sbin/simp_authconfig.sh':
        ensure  => 'file',
        owner   => 'root',
        group   => 'root',
        mode    => '0755',
        content => file("${module_name}/simp_authconfig.sh")
      }

      file { [
        '/usr/sbin/authconfig',
        '/usr/sbin/authconfig-tui'
        ]:
        ensure  => 'link',
        target  => '/usr/local/sbin/simp_authconfig.sh',
        require => File['/usr/local/sbin/simp_authconfig.sh']
      }
  }

  if ($pam::faillock_log_dir) {
    file { '$pam::faillock_log_dir':
      ensure   => 'dir',
      owner    => 'root',
      group    => 'root',
      mode     => '0750',
      seluser  => 'system_u',
      selrole  => 'object_r',
      seltype  => 'faillog_t',
      selrange => 's0'
    }
  }

  if ! empty($pam::auth_sections) { ::pam::auth { $pam::auth_sections: }}
}
