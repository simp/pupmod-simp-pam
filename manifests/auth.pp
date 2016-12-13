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
  Stdlib::Compat::Integer $cracklib_difok            = $::pam::cracklib_difok,
  Stdlib::Compat::Integer $cracklib_maxrepeat        = $::pam::cracklib_maxrepeat,
  Stdlib::Compat::Integer $cracklib_maxsequence      = $::pam::cracklib_maxsequence,
  Stdlib::Compat::Integer $cracklib_maxclassrepeat   = $::pam::cracklib_maxclassrepeat,
  Boolean                 $cracklib_reject_username  = $::pam::cracklib_reject_username,
  Boolean                 $cracklib_gecoscheck       = $::pam::cracklib_gecoscheck,
  Boolean                 $cracklib_enforce_for_root = $::pam::cracklib_enforce_for_root,
  Stdlib::Compat::Integer $cracklib_dcredit          = $::pam::cracklib_dcredit,
  Stdlib::Compat::Integer $cracklib_ucredit          = $::pam::cracklib_ucredit,
  Stdlib::Compat::Integer $cracklib_lcredit          = $::pam::cracklib_lcredit,
  Stdlib::Compat::Integer $cracklib_ocredit          = $::pam::cracklib_ocredit,
  Stdlib::Compat::Integer $cracklib_minclass         = $::pam::cracklib_minclass,
  Stdlib::Compat::Integer $cracklib_minlen           = $::pam::cracklib_minlen,
  Stdlib::Compat::Integer $cracklib_retry            = $::pam::cracklib_retry,
  Stdlib::Compat::Integer $deny                      = $::pam::deny,
  Boolean                 $display_account_lock      = $::pam::display_account_lock,
  Stdlib::Compat::Integer $fail_interval             = $::pam::fail_interval,
  Stdlib::Compat::Integer $remember                  = $::pam::remember,
  Stdlib::Compat::Integer $remember_retry            = $::pam::remember_retry,
  Boolean                 $remember_for_root         = $::pam::remember_for_root,
  Stdlib::Compat::Integer $root_unlock_time          = $::pam::root_unlock_time,
  Stdlib::Compat::Integer $rounds                    = $::pam::rounds,
  Stdlib::Compat::Integer $uid                       = $::pam::uid,
  Stdlib::Compat::Integer $unlock_time               = $::pam::unlock_time,
  Boolean                 $preserve_ac               = $::pam::preserve_ac,
  Boolean                 $use_ldap                  = $::pam::use_ldap,
  Boolean                 $use_netgroups             = $::pam::use_netgroups,
  Boolean                 $use_openshift             = $::pam::use_openshift,
  Boolean                 $use_sssd                  = $::pam::use_sssd,
  Array[String]           $tty_audit_enable          = $::pam::tty_audit_enable,
  Boolean                 $use_templates             = $::pam::use_templates,
  String                  $fingerprint_auth_content  = $::pam::fingerprint_auth_content,
  String                  $system_auth_content       = $::pam::system_auth_content,
  String                  $password_auth_content     = $::pam::password_auth_content,
  String                  $smartcard_auth_content    = $::pam::smartcard_auth_content,
) {
  
  include '::oddjob::mkhomedir'

  if $use_ldap and !$use_sssd {
    if $use_templates {
      fail("SIMP templates only configure unix auth or ldap using sssd.\n To use ldap without sssd you most provide your own content.")
    }
  }

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
