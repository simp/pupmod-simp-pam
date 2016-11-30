#
# == pam::auth
#
# Set up the various -auth files in /etc/pam.d.
#
# This is only meant to be called by the main pam class. Documentation is
# identical to that in the pam class.
#
# If you want to change the umask on dynamically created home
# directories, you'll need to set oddjob::mkhomedir::umask.
#
define pam::auth (
  $cracklib_difok            = $::pam::cracklib_difok,
  $cracklib_maxrepeat        = $::pam::cracklib_maxrepeat,
  $cracklib_maxsequence      = $::pam::cracklib_maxsequence,
  $cracklib_maxclassrepeat   = $::pam::cracklib_maxclassrepeat,
  $cracklib_reject_username  = $::pam::cracklib_reject_username,
  $cracklib_gecoscheck       = $::pam::cracklib_gecoscheck,
  $cracklib_enforce_for_root = $::pam::cracklib_enforce_for_root,
  $cracklib_dcredit          = $::pam::cracklib_dcredit,
  $cracklib_ucredit          = $::pam::cracklib_ucredit,
  $cracklib_lcredit          = $::pam::cracklib_lcredit,
  $cracklib_ocredit          = $::pam::cracklib_ocredit,
  $cracklib_minclass         = $::pam::cracklib_minclass,
  $cracklib_minlen           = $::pam::cracklib_minlen,
  $cracklib_retry            = $::pam::cracklib_retry,
  $deny                      = $::pam::deny,
  $display_account_lock      = $::pam::display_account_lock,
  $fail_interval             = $::pam::fail_interval,
  $remember                  = $::pam::remember,
  $remember_retry            = $::pam::remember_retry,
  $remember_for_root         = $::pam::remember_for_root,
  $root_unlock_time          = $::pam::root_unlock_time,
  $rounds                    = $::pam::rounds,
  $uid                       = $::pam::uid,
  $unlock_time               = $::pam::unlock_time,
  $preserve_ac               = $::pam::preserve_ac,
  $use_ldap                  = $::pam::use_ldap,
  $use_netgroups             = $::pam::use_netgroups,
  $use_openshift             = $::pam::use_openshift,
  $use_sssd                  = $::pam::_use_sssd,
  $tty_audit_enable          = $::pam::tty_audit_enable,
  Boolean $use_templates     = $::pam::use_templates,
  String $fingerprint_auth_content = $::pam::fingerprint_auth_content,
  String $system_auth_content      = $::pam::system_auth_content,
  String $password_auth_content    = $::pam::password_auth_content,
  String $smartcard_auth_content   = $::pam::smartcard_auth_content
) {

  include '::oddjob::mkhomedir'

  $valid_targets = [
    'smartcard',
    'fingerprint',
    'password',
    'system'
  ]

  $l_valid_targets_join = join($valid_targets,',')
  if ! ($name in $valid_targets) {
    fail("\$name must be one of '${l_valid_targets_join}'.")
  }

  $basedir = '/etc/pam.d'
  $target = "${name}-auth"

  if $use_templates {
    $_content = template("${module_name}/etc/pam.d/auth.erb")
  }
  else {
    case $name {
      'smartcard':   { $_content = $smartcard_auth_content }
      'fingerprint': { $_content = $fingerprint_auth_content }
      'password':    { $_content = $password_auth_content }
      'system':      { $_content = $system_auth_content }
      default:       { $_content = template("${module_name}/etc/pam.d/auth.erb") }
    }
  }

  file { "${basedir}/${target}":
    ensure  => 'file',
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
    content => $_content
  }

  if ! str2bool($preserve_ac) {
    file { "${basedir}/${target}-ac":
      ensure => absent
    }
  }

}
