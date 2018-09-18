# Set up the various -auth files in /etc/pam.d.
#
# This is only meant to be called via the main pam class. Documentation is
# identical to that in the pam class.
#
# If you want to change the umask on dynamically created home
# directories, you'll need to set oddjob::mkhomedir::umask.
#
# @param password_check_backend
# @param cracklib_enforce_for_root
# @param cracklib_reject_username
# @param cracklib_difok
# @param cracklib_maxrepeat
# @param cracklib_maxsequence
# @param cracklib_maxclassrepeat
# @param cracklib_gecoscheck
# @param cracklib_dcredit
# @param cracklib_ucredit
# @param cracklib_lcredit
# @param cracklib_ocredit
# @param cracklib_minclass
# @param cracklib_minlen
# @param cracklib_retry
# @param deny
# @param display_account_lock
# @param fail_interval
# @param remember
# @param remember_retry
# @param remember_for_root
# @param even_deny_root
# @param root_unlock_time
# @param hash_algorithm
# @param rounds
# @param uid
# @param unlock_time
# @param preserve_ac
# @param use_netgroups
# @param use_openshift
# @param sssd
# @param tty_audit_users
# @param separator
# @param enable_separator
# @param content
#
define pam::auth (
  Pam::PasswordBackends          $password_check_backend    = $::pam::password_check_backend,
  Optional[Stdlib::Absolutepath] $locale_file               = $::pam::locale_file,
  Boolean                        $cracklib_enforce_for_root = $::pam::cracklib_enforce_for_root,
  Boolean                        $cracklib_reject_username  = $::pam::cracklib_reject_username,
  Optional[Integer[0]]           $cracklib_difok            = $::pam::cracklib_difok,
  Optional[Integer[0]]           $cracklib_maxrepeat        = $::pam::cracklib_maxrepeat,
  Optional[Integer[0]]           $cracklib_maxsequence      = $::pam::cracklib_maxsequence,
  Optional[Integer[0]]           $cracklib_maxclassrepeat   = $::pam::cracklib_maxclassrepeat,
  Optional[Boolean]              $cracklib_gecoscheck       = $::pam::cracklib_gecoscheck,
  Optional[Integer]              $cracklib_dcredit          = $::pam::cracklib_dcredit,
  Optional[Integer]              $cracklib_ucredit          = $::pam::cracklib_ucredit,
  Optional[Integer]              $cracklib_lcredit          = $::pam::cracklib_lcredit,
  Optional[Integer]              $cracklib_ocredit          = $::pam::cracklib_ocredit,
  Optional[Integer[0]]           $cracklib_minclass         = $::pam::cracklib_minclass,
  Optional[Integer[0]]           $cracklib_minlen           = $::pam::cracklib_minlen,
  Integer[0]                     $cracklib_retry            = $::pam::cracklib_retry,
  Integer[0]                     $deny                      = $::pam::deny,
  Boolean                        $display_account_lock      = $::pam::display_account_lock,
  Integer[0]                     $fail_interval             = $::pam::fail_interval,
  Integer[0]                     $remember                  = $::pam::remember,
  Integer[0]                     $remember_retry            = $::pam::remember_retry,
  Boolean                        $remember_for_root         = $::pam::remember_for_root,
  Boolean                        $even_deny_root            = $::pam::even_deny_root,
  Integer[0]                     $root_unlock_time          = $::pam::root_unlock_time,
  Pam::HashAlgorithm             $hash_algorithm            = $::pam::hash_algorithm,
  Integer[0]                     $rounds                    = $::pam::rounds,
  Integer[0]                     $uid                       = $::pam::uid,
  Pam::AccountUnlockTime         $unlock_time               = $::pam::unlock_time,
  Boolean                        $preserve_ac               = $::pam::preserve_ac,
  Boolean                        $use_netgroups             = $::pam::use_netgroups,
  Boolean                        $use_openshift             = $::pam::use_openshift,
  Boolean                        $sssd                      = $::pam::sssd,
  Array[String[0]]               $tty_audit_users           = $::pam::tty_audit_users,
  String[0]                      $separator                 = $::pam::separator,
  Boolean                        $enable_separator          = $::pam::enable_separator,
  Optional[String]               $content                   = undef
) {
  include '::oddjob::mkhomedir'

  if fact('fips_enabled') {
    unless $hash_algorithm =~ Enum['sha256', 'sha512'] {
      fail('Only sha256 and sha512 may be used in "pam::hash_algorithm" in FIPS mode')
    }
  }

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
    $_top_var = getvar("pam::${name}_auth_content")
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
