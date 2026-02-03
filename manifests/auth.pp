# @summary Set up the various -auth files in /etc/pam.d.
#
# This is only meant to be called via the main pam class. Documentation is
# identical to that in the pam class.
#
# If you want to change the umask on dynamically created home
# directories, you'll need to set oddjob::mkhomedir::umask.
#
# @param password_check_backend
# @param locale_file
# @param auth_content_pre
# @param manage_faillock_conf
# @param faillock_audit
# @param faillock_no_log_info
# @param faillock_local_users_only
# @param faillock_nodelay
# @param faillock_admin_group
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
# @param nullok
# @param oath
# @param oath_window
# @param deny
# @param faillock
# @param faillock_log_dir
# @param display_account_lock
# @param fail_interval
# @param manage_pwhistory_conf
# @param remember_debug
# @param remember
# @param remember_retry
# @param remember_for_root
# @param remember_file
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
# @param inactive
# @param cert_auth
# @param faillock_conf_supported
# @param pwhistory_conf_supported
# @param content
#
# @author https://github.com/simp/pupmod-simp-pam/graphs/contributors
#
define pam::auth (
  Pam::PasswordBackends           $password_check_backend    = $pam::password_check_backend,
  Optional[Stdlib::Absolutepath]  $locale_file               = $pam::locale_file,
  Optional[Array[String]]         $auth_content_pre          = $pam::auth_content_pre,
  Boolean                         $cracklib_enforce_for_root = $pam::cracklib_enforce_for_root,
  Boolean                         $cracklib_reject_username  = $pam::cracklib_reject_username,
  Optional[Integer[0]]            $cracklib_difok            = $pam::cracklib_difok,
  Optional[Integer[0]]            $cracklib_maxrepeat        = $pam::cracklib_maxrepeat,
  Optional[Integer[0]]            $cracklib_maxsequence      = $pam::cracklib_maxsequence,
  Optional[Integer[0]]            $cracklib_maxclassrepeat   = $pam::cracklib_maxclassrepeat,
  Optional[Boolean]               $cracklib_gecoscheck       = $pam::cracklib_gecoscheck,
  Optional[Integer]               $cracklib_dcredit          = $pam::cracklib_dcredit,
  Optional[Integer]               $cracklib_ucredit          = $pam::cracklib_ucredit,
  Optional[Integer]               $cracklib_lcredit          = $pam::cracklib_lcredit,
  Optional[Integer]               $cracklib_ocredit          = $pam::cracklib_ocredit,
  Optional[Integer[0]]            $cracklib_minclass         = $pam::cracklib_minclass,
  Optional[Integer[0]]            $cracklib_minlen           = $pam::cracklib_minlen,
  Integer[0]                      $cracklib_retry            = $pam::cracklib_retry,
  Boolean                         $nullok                    = $pam::nullok,
  Integer[0]                      $deny                      = $pam::deny,
  Boolean                         $faillock                  = $pam::faillock,
  Boolean                         $manage_faillock_conf      = $pam::manage_faillock_conf,
  Optional[Stdlib::Absolutepath]  $faillock_log_dir          = $pam::faillock_log_dir,
  Boolean                         $faillock_audit            = $pam::faillock_audit,
  Boolean                         $faillock_no_log_info      = $pam::faillock_no_log_info,
  Boolean                         $faillock_local_users_only = $pam::faillock_local_users_only,
  Boolean                         $faillock_nodelay          = $pam::faillock_nodelay,
  Optional[String]                $faillock_admin_group      = $pam::faillock_admin_group,
  Boolean                         $display_account_lock      = $pam::display_account_lock,
  Integer[0]                      $fail_interval             = $pam::fail_interval,
  Boolean                         $manage_pwhistory_conf     = $pam::manage_pwhistory_conf,
  Boolean                         $remember_debug            = $pam::remember_debug,
  Integer[0]                      $remember                  = $pam::remember,
  Integer[0]                      $remember_retry            = $pam::remember_retry,
  Boolean                         $remember_for_root         = $pam::remember_for_root,
  Stdlib::Absolutepath            $remember_file             = $pam::remember_file,
  Boolean                         $even_deny_root            = $pam::even_deny_root,
  Integer[0]                      $root_unlock_time          = $pam::root_unlock_time,
  Pam::HashAlgorithm              $hash_algorithm            = $pam::hash_algorithm,
  Integer[0]                      $rounds                    = $pam::rounds,
  Integer[0]                      $uid                       = $pam::uid,
  Pam::AccountUnlockTime          $unlock_time               = $pam::unlock_time,
  Boolean                         $preserve_ac               = $pam::preserve_ac,
  Boolean                         $use_netgroups             = $pam::use_netgroups,
  Boolean                         $use_openshift             = $pam::use_openshift,
  Boolean                         $sssd                      = $pam::sssd,
  Array[String[0]]                $tty_audit_users           = $pam::tty_audit_users,
  String[0]                       $separator                 = $pam::separator,
  Boolean                         $enable_separator          = $pam::enable_separator,
  Boolean                         $oath                      = $pam::oath,
  Integer[0]                      $oath_window               = $pam::oath_window,
  Optional[Integer]               $inactive                  = $pam::inactive,
  Optional[Enum['try','require']] $cert_auth                 = $pam::cert_auth,
  Boolean                         $faillock_conf_supported   = $pam::faillock_conf_supported,
  Boolean                         $pwhistory_conf_supported  = $pam::pwhistory_conf_supported,
  Optional[String]                $content                   = undef
) {
  include 'oddjob::mkhomedir'

  if $oath == true {
    simplib::assert_optional_dependency($module_name, 'simp/oath')
  }

  if fact('fips_enabled') {
    unless $hash_algorithm =~ Enum['sha256', 'sha512'] {
      fail('Only sha256 and sha512 may be used in "pam::hash_algorithm" in FIPS mode')
    }
  }

  $valid_targets = [
    'smartcard',
    'fingerprint',
    'password',
    'system',
  ]

  $_valid_targets_join = join($valid_targets,',')
  if ! ($name in $valid_targets) {
    fail("\$name must be one of '${_valid_targets_join}'.")
  }

  $basedir = $pam::use_authselect ? {
    true => $pam::auth_basedir,
    default => '/etc/pam.d',
  }

  $target = "${name}-auth"

  $_pam_cert_auth = $cert_auth ? {
    undef   => undef,
    default => "${cert_auth}_cert_auth"
  }

  if $content {
    $_content = $content
  }
  else {
    $_top_var = getvar("pam::${name}_auth_content")
    if $_top_var {
      $_content = $_top_var
    }
    else {
      # Use OS capability flags to determine configuration file support
      # faillock.conf and pwhistory.conf don't exist in EL 7 and Amazon Linux 2
      $_manage_faillock_conf = $faillock_conf_supported ? {
        true    => $manage_faillock_conf,
        default => false
      }

      $_manage_pwhistory_conf = $pwhistory_conf_supported ? {
        true    => $manage_pwhistory_conf,
        default => false
      }

      # retry, enforce_for_root, and reject_username will be enforced via
      # pwquality.conf in EL8+ and Amazon Linux 2022+
      $_cracklib_retry = $faillock_conf_supported ? {
        true    => false,
        default => $cracklib_retry
      }

      $_cracklib_enforce_for_root = $faillock_conf_supported ? {
        true    => false,
        default => $cracklib_enforce_for_root
      }

      $_cracklib_reject_username = $faillock_conf_supported ? {
        true    => false,
        default => $cracklib_reject_username
      }

      $_content = epp("${module_name}/etc/pam.d/auth.epp", {
          name                      => $name,
          password_check_backend    => $password_check_backend,
          locale_file               => $locale_file,
          auth_content_pre          => $auth_content_pre,
          manage_faillock_conf      => $_manage_faillock_conf,
          cracklib_enforce_for_root => $_cracklib_enforce_for_root,
          cracklib_reject_username  => $_cracklib_reject_username,
          cracklib_difok            => $cracklib_difok,
          cracklib_maxrepeat        => $cracklib_maxrepeat,
          cracklib_maxsequence      => $cracklib_maxsequence,
          cracklib_maxclassrepeat   => $cracklib_maxclassrepeat,
          cracklib_gecoscheck       => $cracklib_gecoscheck,
          cracklib_dcredit          => $cracklib_dcredit,
          cracklib_ucredit          => $cracklib_ucredit,
          cracklib_lcredit          => $cracklib_lcredit,
          cracklib_ocredit          => $cracklib_ocredit,
          cracklib_minclass         => $cracklib_minclass,
          cracklib_minlen           => $cracklib_minlen,
          cracklib_retry            => $_cracklib_retry,
          nullok                    => $nullok,
          deny                      => $deny,
          faillock                  => $faillock,
          faillock_log_dir          => $faillock_log_dir,
          faillock_audit            => $faillock_audit,
          faillock_no_log_info      => $faillock_no_log_info,
          faillock_local_users_only => $faillock_local_users_only,
          faillock_nodelay          => $faillock_nodelay,
          faillock_admin_group      => $faillock_admin_group,
          display_account_lock      => $display_account_lock,
          fail_interval             => $fail_interval,
          manage_pwhistory_conf     => $_manage_pwhistory_conf,
          remember_debug            => $remember_debug,
          remember                  => $remember,
          remember_retry            => $remember_retry,
          remember_for_root         => $remember_for_root,
          remember_file             => $remember_file,
          even_deny_root            => $even_deny_root,
          root_unlock_time          => $root_unlock_time,
          hash_algorithm            => $hash_algorithm,
          rounds                    => $rounds,
          uid                       => $uid,
          unlock_time               => $unlock_time,
          preserve_ac               => $preserve_ac,
          use_netgroups             => $use_netgroups,
          use_openshift             => $use_openshift,
          sssd                      => $sssd,
          tty_audit_users           => $tty_audit_users,
          separator                 => $separator,
          enable_separator          => $enable_separator,
          oath                      => $oath,
          oath_window               => $oath_window,
          inactive                  => $inactive,
          pam_cert_auth             => $_pam_cert_auth
      })
    }
  }

  file { "${basedir}/${target}":
    ensure  => 'file',
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
    content => $_content,
  }

  if ! $preserve_ac {
    file { "${basedir}/${target}-ac":
      ensure => absent,
    }
  }
}
