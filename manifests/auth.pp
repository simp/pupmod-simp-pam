# Set up the various -auth files in /etc/pam.d.
#
# This is only meant to be called by the main pam class. Documentation is
# identical to that in the pam class.
#
# If you want to change the umask on dynamically created home
# directories, you'll need to set oddjob::mkhomedir::umask.
#
# @param cracklib_difok
# @param cracklib_maxrepeat
# @param cracklib_maxsequence
# @param cracklib_maxclassrepeat
# @param cracklib_reject_username
# @param cracklib_gecoscheck
# @param cracklib_enforce_for_root
# @param cracklib_dcredit
# @param cracklib_ucredit
# @param cracklib_lcredit
# @param cracklib_ocredit
# @param cracklib_minclass
# @param cracklib_minlen
# @param cracklib_retry
# @param deny
# @param display_account_lock
# @param enable_separator
# @param fail_interval
# @param remember
# @param remember_retry
# @param remember_for_root
# @param root_unlock_time
# @param rounds
# @param uid
# @param unlock_time
# @param preserve_ac
# @param use_netgroups
# @param use_openshift
# @param separator
# @param sssd
# @param tty_audit_users
# @param content
#
define pam::auth (
  Boolean                        $cracklib_enforce_for_root = $::pam::cracklib_enforce_for_root,
  Boolean                        $cracklib_reject_username = $::pam::cracklib_reject_username,
  Integer                        $cracklib_retry            = $::pam::cracklib_retry,
  Optional[Integer]              $cracklib_difok            = undef,
  Optional[Integer]              $cracklib_maxrepeat        = undef,
  Optional[Integer]              $cracklib_maxsequence      = undef,
  Optional[Integer]              $cracklib_maxclassrepeat   = undef,
  Optional[Boolean]              $cracklib_gecoscheck       = undef,
  Optional[Integer]              $cracklib_dcredit          = undef,
  Optional[Integer]              $cracklib_ucredit          = undef,
  Optional[Integer]              $cracklib_lcredit          = undef,
  Optional[Integer]              $cracklib_ocredit          = undef,
  Optional[Integer]              $cracklib_minclass         = undef,
  Optional[Integer]              $cracklib_minlen           = undef,
  Integer                        $deny                      = $::pam::deny,
  Boolean                        $display_account_lock      = $::pam::display_account_lock,
  Integer                        $fail_interval             = $::pam::fail_interval,
  Integer                        $remember                  = $::pam::remember,
  Integer                        $remember_retry            = $::pam::remember_retry,
  Boolean                        $remember_for_root         = $::pam::remember_for_root,
  Integer                        $root_unlock_time          = $::pam::root_unlock_time,
  Integer                        $rounds                    = $::pam::rounds,
  Integer                        $uid                       = $::pam::uid,
  Integer                        $unlock_time               = $::pam::unlock_time,
  Boolean                        $preserve_ac               = $::pam::preserve_ac,
  Boolean                        $use_netgroups             = $::pam::use_netgroups,
  Boolean                        $use_openshift             = $::pam::use_openshift,
  Boolean                        $sssd                      = $::pam::sssd,
  Array[String]                  $tty_audit_users           = $::pam::tty_audit_users,
  String                         $separator                 = $::pam::separator,
  Boolean                        $enable_separator          = $::pam::enable_separator,
  Optional[String]               $content                   = undef
) {
  include '::oddjob::mkhomedir'

  $valid_targets = [
    'smartcard',
    'fingerprint',
    'password',
    'system'
  ]

  $_valid_targets_join = join($valid_targets,',')
  if ! ($name in $valid_targets) {
    fail("\$name must be one of '${_valid_targets_join}'.")
  }

  $basedir = '/etc/pam.d'
  $target = "${name}-auth"

  if $content {
    $_content = $content
  }
  else {
    $_top_var = getvar("iptables::${name}")
    if $_top_var {
      $_content = $_top_var
    }
    else {
      $_content = template("${module_name}/etc/pam.d/auth.erb")
    }
  }

  file { "${basedir}/${target}":
    ensure  => 'file',
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
    content => $_content
  }

  if ! $preserve_ac {
    file { "${basedir}/${target}-ac":
      ensure => absent
    }
  }
}
