# Configuration class called from pam.
#
# @author https://github.com/simp/pupmod-simp-pam/graphs/contributors
#
class pam::config {
  assert_private()

  $_cracklib_difok          = $::pam::cracklib_difok
  $_cracklib_maxrepeat      = $::pam::cracklib_maxrepeat
  $_cracklib_maxsequence    = $::pam::cracklib_maxsequence
  $_cracklib_maxclassrepeat = $::pam::cracklib_maxclassrepeat
  $_cracklib_gecoscheck     = $::pam::cracklib_gecoscheck
  $_cracklib_dcredit        = $::pam::cracklib_dcredit
  $_cracklib_ucredit        = $::pam::cracklib_ucredit
  $_cracklib_lcredit        = $::pam::cracklib_lcredit
  $_cracklib_ocredit        = $::pam::cracklib_ocredit
  $_cracklib_minclass       = $::pam::cracklib_minclass
  $_cracklib_minlen         = $::pam::cracklib_minlen
  $_cracklib_badwords       = $::pam::cracklib_badwords
  $_cracklib_dictpath       = $::pam::cracklib_dictpath
  $_warn_if_unknown         = $::pam::warn_if_unknown
  $_deny_if_unknown         = $::pam::deny_if_unknown

  file { '/etc/pam.d':
    ensure  => 'directory',
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
    recurse => true
  }

  if $::pam::password_check_backend == 'pwquality' {
    file { '/etc/security/pwquality.conf':
      ensure  => 'file',
      owner   => 'root',
      group   => 'root',
      mode    => '0644',
      content => template("${module_name}/etc/security/pwquality.conf.erb")
    }

    if $::pam::rm_pwquality_conf_d {
      # Ensure that we can't be overridden
      file { '/etc/security/pwquality.conf.d':
        ensure => 'absent',
        force  => true
      }
    }
  }

  if $::pam::other_content {
    $_other_content = $::pam::other_content
  }
  else {
    $_other_content = template('pam/etc/pam.d/other.erb')
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
          'tty_audit_users' => $::pam::tty_audit_users,
        })
    ;
    '/etc/pam.d/sudo-i':
        content => epp('pam/etc/pam.d/sudo', {
          'pam_module_path' => 'sudo',
          'force_revoke'    => true,
          'tty_audit_users' => $::pam::tty_audit_users,
        })
    ;
    '/etc/pam.d/other':
      content => $_other_content,
    ;
  }

  if ($::pam::disable_authconfig == true) {
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

  if ! empty($::pam::auth_sections) { ::pam::auth { $::pam::auth_sections: } }
}
