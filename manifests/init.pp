#
# == Class: pam
#
# This class ensures that reasonable PAM security options are applied.
#
# == Global Variables
#
# $rsync_server
#
# == Parameters
#
# [*cracklib_difok*]
#   The number of character changes between the old password and the new
#   password that are enough to accept the new password. The default is 4.
#
# [*cracklib_maxrepeat*]
#   Reject passwords which contain more than N same consecutive characters.
#
# [*cracklib_maxsequence*]
#   Reject passwords which contain monotonic character sequences
#   longer than N.  The default is 0 which means that this check is
#   disabled. Examples of such sequence are '12345' or 'fedcb'. Note
#   that most such passwords will not pass the simplicity check unless
#   the sequence is only a minor part of the password.
#
# [*cracklib_maxclassrepeat*]
#   Reject passwords which contain more than N consecutive characters
#   of the same class.  The default is 0 which means that this check
#   is disabled.
#
# [*cracklib_reject_username*]
#   Check whether the name of the user in straight or reversed form is
#   contained in the new password. If it is found the new password is
#   rejected.
#
# [*cracklib_gecoscheck*]
#   Type: Boolean
#
#   Check whether the words from the GECOS field (usualy full name of
#   the user) longer than 3 characters in straight or reversed form
#   are contained in the new password. If any such word is found the
#   new password is rejected.
#
# [*cracklib_enforce_for_root*]
#   Type: Boolean
#
#   The module will return error on failed check also if the user
#   changing the password is root. This option is off by default which
#   means that just the message about the failed check is printed but
#   root can change the password anyway.
#
# [*cracklib_dcredit*]
#   Type: Positive or Negative Integer
#
#   (N >= 0) This is the maximum credit for having digits in the new
#   password.  If you have less than or N digits, each digit will
#   count +1 towards meeting the current minlen value. The default for
#   dcredit is 1 which is the recommended value for minlen less than
#   10.
#
#   (N < 0) This is the minimum number of digits that must be met for
#   a new password.
#
# [*cracklib_ucredit*]
#   Type: Positive or Negative Integer
#
#   (N >= 0) This is the maximum credit for having upper case letters
#   in the new password.  If you have less than or N digits, each
#   digit will count +1 towards meeting the current minlen value. The
#   default for dcredit is 1 which is the recommended value for minlen
#   less than 10.
#
#   (N < 0) This is the minimum number of digits that must be met for
#   a new password.
#
# [*cracklib_lcredit*]
#   Type: Positive or Negative Integer
#
#   (N >= 0) This is the maximum credit for having lower case letters
#   in the new password.  If you have less than or N digits, each
#   digit will count +1 towards meeting the current minlen value. The
#   default for dcredit is 1 which is the recommended value for minlen
#   less than 10.
#
#   (N < 0) This is the minimum number of digits that must be met for
#   a new password.
#
# [*cracklib_ocredit*]
#   Type: Positive or Negative Integer
#
#   (N >= 0) This is the maximum credit for having other characters in
#   the new password.  If you have less than or N digits, each digit
#   will count +1 towards meeting the current minlen value. The
#   default for dcredit is 1 which is the recommended value for minlen
#   less than 10.
#
#   (N < 0) This is the minimum number of digits that must be met for
#   a new password.
#
# [*cracklib_minclass*]
#   The minimum number of required classes of characters for the new
#   password. The default number is three. The four classes are digits,
#   upper and lower letters and other characters.  The difference to
#   the credit check is that a specific class if of characters is not
#   required.  Instead N out of four of the classes are required.
#
# [*cracklib_minlen*]
#   The minimum acceptable size for the new password (plus one if
#   credits are not disabled which is the default). In addition to the
#   number of characters in the new password, credit (of +1 in length)
#   is given for each different kind of character (other, upper, lower
#   and digit).  The default for this parameter is 14.
#
# [*cracklib_retry*]
#   Prompt user at most N times before returning with error.
#
# [*deny*]
#   The number of failed attempts before PAM denies a user from logging in.
#
# [*display_account_lock*]
#   Whether or not to display to the remote user that their account
#   has been locked.
#
# [*homedir_umask*]
#   Sets the file mode creation mask of the user home directories.
#
# [*remember*]
#   The last n passwords for each user are saved in /etc/security/opasswd in
#   order to force password change history and keep the user from alternating
#   between the same password too frequently.
#   Defaults to 24.
#
# [*remember_retry*]
#   Type: Integer
#   Default: 1
#     Allow this many retries for a valid password
#
# [*remember_for_root*]
#   Type: Boolean
#   Default: true
#     If set, also remember the last ``$remember`` passwords for the root user.
#
# [*root_unlock_time*]
#   Allow access after n seconds to root account after failed attempt.
#
# [*rounds*]
#   Set the optional number of rounds of the SHA256, SHA512 and blowfish password hashing algorithms to n.
#   Defaults to 10000.
#
# [*uid*]
#   Allow user logins for userse with UID higher than n. Default is 500 (system users on RedHat).
#
# [*unlock_time*]
#   Allow acesss after n seconds to user account after failed attempt.
#
# [*preserve_ac*]
#   Keep the original -ac file around for reference.
#
# [*warn_if_unknown*]
#   If you make it to the 'other' PAM configuration file, then warn
#   about this if this setting is not 'false'.
#
# [*deny_if_unknown*]
#   Type: Boolean
#   Default: true
#     If true, deny any access to an application that falls all the
#     way through the PAM stack.
#
# [*ldap*]
#   Default: true
#   Set PAM up to use LDAP connections.
#
# [*use_netgroups*]
#   Default: false
#   Set PAM up to use NIS netgroups.
#
# [*use_openshift*]
#   Default: false
#   Set PAM to work well with OpenShift.
#
# [*sssd*]
#   Default: false
#   Set PAM to work with SSSD.
#
# [*tty_audit_enable*]
#   Default: [ 'root' ]
#   The users for which TTY auditing is enabled. Set to an empty Array to not audit TTY actions for any user.
#
# [*auth_sections*]
#   Default: [ 'fingerprint', 'system', 'password', 'smartcard' ]
#   The PAM '*-auth' files to manage. Set to an empty Array to not manage any sections by default.
# [*use_templates*]
#   Default: true
#   Whether or not to use the SIMP templates to populate the pam configuration.
#   Set this to false to drop in completely custom PAM configuration files, if
#   you need to support third-party or custom modules. The following *_content
#   parameters need to be filled if this option is disabled, otherwise you may
#   leave your system in an unacessible state.
#
# [*su_content*]
#   Default: ''
#   The content that should be used to fill the /etc/pam.d/su file instead
#   of the templated content.
#
# [*other_content*]
#   Default: ''
#   The content that should be used to fill the /etc/pam.d/other file instead
#   of the templated content.
# [*auth_sections*]
#   Default: [ 'fingerprint', 'system', 'password', 'smartcard' ]
#   The PAM '*-auth' files to manage. Set to an empty Array to not manage any sections by default.
#
# [*fingerprint_content*]
#   Default: ''
#   The content that should be used to fill /etc/pam.d/fingerprint_auth_ instead
#   of the templated content.
#
# [*system_content*]
#   Default: ''
#   The content that should be used to fill /etc/pam.d/system_auth
#   instead of the templated content.
#
# [*password_content*]
#   The content that should be used to fill /etc/pam.d/password_auth
#   instead of the templated content.
#   Default: ''
#
# [*smartcard_content*]
#   The content that should be used to fill /etc/pam.d/smartcard_auth
#   instead of the templated content.
#   Default: ''
#
# [*enable*]
#   Default:  true
#   If you have included this module but want simp to stop managing your configuration files set
#   this to false.
#
# [*enable_warning*]
#   Default:  true
#   Will issue a warning if this module is included but global catalyst simp_options::pam is set to false.
#
class pam (
  Stdlib::Compat::Integer $cracklib_difok            = '4',
  Stdlib::Compat::Integer $cracklib_maxrepeat        = '2',
  Stdlib::Compat::Integer $cracklib_maxsequence      = '4',
  Stdlib::Compat::Integer $cracklib_maxclassrepeat   = '0',
  Boolean                 $cracklib_reject_username  = true,
  Boolean                 $cracklib_gecoscheck       = true,
  Boolean                 $cracklib_enforce_for_root = true,
  Stdlib::Compat::Integer $cracklib_dcredit          = '-1',
  Stdlib::Compat::Integer $cracklib_ucredit          = '-1',
  Stdlib::Compat::Integer $cracklib_lcredit          = '-1',
  Stdlib::Compat::Integer $cracklib_ocredit          = '-1',
  Stdlib::Compat::Integer $cracklib_minclass         = '3',
  Stdlib::Compat::Integer $cracklib_minlen           = '14',
  Stdlib::Compat::Integer $cracklib_retry            = '3',
  Stdlib::Compat::Integer $deny                      = '5',
  Boolean                 $display_account_lock      = false,
  String                  $homedir_umask             = '0077',
  Stdlib::Compat::Integer $remember                  = '24',
  Stdlib::Compat::Integer $remember_retry            = '1',
  Boolean                 $remember_for_root         = true,
  Stdlib::Compat::Integer $root_unlock_time          = '60',
  Stdlib::Compat::Integer $rounds                    = '10000',
  Stdlib::Compat::Integer $uid                       = '500',
  Stdlib::Compat::Integer $unlock_time               = '900',
  Stdlib::Compat::Integer $fail_interval             = '900',
  Boolean                 $preserve_ac               = false,
  Boolean                 $warn_if_unknown           = true,
  Boolean                 $deny_if_unknown           = true,
  Boolean                 $ldap                      = simplib::lookup('simp_options::ldap', { 'default_value' => false}),
  Boolean                 $use_netgroups             = false,
  Boolean                 $use_openshift             = false,
  Boolean                 $sssd                      = simplib::lookup('simp_options::sssd', { 'default_value' => false}),
  Array[String]           $tty_audit_enable          = [ 'root' ],
  Array[String]           $auth_sections             = [ 'fingerprint', 'system', 'password', 'smartcard' ],
  Boolean                 $use_templates             = true,
  String                  $su_content                = '',
  String                  $other_content             = '',
  String                  $fingerprint_auth_content  = '',
  String                  $system_auth_content       = '',
  String                  $password_auth_content     = '',
  String                  $smartcard_auth_content    = '',
  Boolean                 $enable                    = true,
  Boolean                 $enable_warning            = true,
) {

  if lookup( { 'name' => 'simp_options::pam', 'default_value' => true } )
  {
    if $enable {
      file { '/etc/pam.d':
        ensure  => 'directory',
        owner   => 'root',
        group   => 'root',
        mode    => '0644',
        recurse => true
      }

      file { [ '/etc/pam.d/atd', '/etc/pam.d/crond' ]:
        owner => 'root',
        group => 'root',
        mode  => '0640'
      }

      if $use_templates {
        $_other_content = template('pam/etc/pam.d/other.erb')
      }
      else {
        $_other_content = $other_content
      }

      file { '/etc/pam.d/other':
        ensure  => 'file',
        owner   => 'root',
        group   => 'root',
        mode    => '0644',
        content => $_other_content
      }

    # Get rid of authconfig so that the tool can't be used to modify PAM.
      case $::operatingsystem {
        'RedHat','CentOS': {
          file { [
            '/etc/pam.d/authconfig',
            '/etc/pam.d/authconfig-tui'
            ]:
              ensure => 'absent'
          }
        }
        default: {
          warning('Only RedHat and CentOS are currently supported by the pam module.')
        }
      }

      if ! empty($auth_sections) {
        ::pam::auth { $auth_sections: }
      }

      package { 'pam':        ensure => 'latest' }
      package { 'pam_pkcs11': ensure => 'latest' }
      package { 'fprintd-pam': ensure => 'latest' }
    }
  }
  else
  {
  # The global catalyst was set to false but the module was included 
    if $enable_warning {
      warning("Module pupmod-simp-pam was included but global catalyst simp_options::pam is set to false. This could have unexpected effects.")
    }
  }
}
