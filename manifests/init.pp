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
#   Changs the default of 4 for the number of character changes in the
#   new password that differentiate it from the old password.
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
#   password. The default number is zero. The four classes are digits,
#   upper and lower letters and other characters.  The difference to
#   the credit check is that a specific class if of characters is not
#   required.  Instead N out of four of the classes are required.
#
# [*cracklib_minlen*]
#   The minimum acceptable size for the new password (plus one if
#   credits are not disabled which is the default). In addition to the
#   number of characters in the new password, credit (of +1 in length)
#   is given for each different kind of character (other, upper, lower
#   and digit).  The default for this parameter is 9 which is good for
#   a old style UNIX password all of the same type of character but
#   may be too low to exploit the added security of a md5 system. Note
#   that there is a pair of length limits in Cracklib itself, a "way
#   too short" limit of 4 which is hard coded in and a defined limit
#   (6) that will be checked without reference to minlen. If you want
#   to allow passwords as short as 5 characters you should not use
#   this module.
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
#   The last n passwords for each user are saved in /etc/security/opasswd in order to force password
#   change history and keep the user from alternating between the same password too frequently.
#
# [*root_unlock_time*]
#   Allow access after n seconds to root account after failed attempt.
#
# [*rounds*]
#   Set the optional number of rounds of the SHA256, SHA512 and blowfish password hashing algorithms to n.
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
# [*use_ldap*]
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
# [*use_sssd*]
#   Default: false
#   Set PAM to work with SSSD.
#
# [*auth_sections*]
#   Default: [ 'fingerprint', 'system', 'password', 'smartcard' ]
#   The PAM '*-auth' files to manage. Set to an empty Array to not manage any sections by default.
#
class pam (
  $cracklib_difok            = '4',
  $cracklib_maxrepeat        = '2',
  $cracklib_maxsequence      = '4',
  $cracklib_maxclassrepeat   = '0',
  $cracklib_reject_username  = true,
  $cracklib_gecoscheck       = true,
  $cracklib_enforce_for_root = true,
  $cracklib_dcredit          = '-1',
  $cracklib_ucredit          = '-1',
  $cracklib_lcredit          = '-1',
  $cracklib_ocredit          = '-1',
  $cracklib_minclass         = '3',
  $cracklib_minlen           = '14',
  $cracklib_retry            = '3',
  $deny                      = '5',
  $display_account_lock      = false,
  $homedir_umask             = '0077',
  $remember                  = '24',
  $root_unlock_time          = '60',
  $rounds                    = '10000',
  $uid                       = '500',
  $unlock_time               = '900',
  $fail_interval             = '900',
  $preserve_ac               = false,
  $warn_if_unknown           = true,
  $deny_if_unknown           = true,
  $use_ldap                  = defined('$::use_ldap') ? { true => $::use_ldap, default => hiera('use_ldap',false) },
  $use_netgroups             = false,
  $use_openshift             = false,
  $use_sssd                  = false,
  $auth_sections             = [ 'fingerprint', 'system', 'password', 'smartcard' ]
) inherits ::pam::params {

  validate_integer($cracklib_difok)
  validate_integer($cracklib_maxclassrepeat)
  validate_integer($cracklib_maxrepeat)
  validate_integer($cracklib_maxsequence)
  validate_integer($cracklib_maxclassrepeat)
  validate_bool($cracklib_reject_username)
  validate_bool($cracklib_gecoscheck)
  validate_bool($cracklib_enforce_for_root)
  validate_integer($cracklib_dcredit)
  validate_integer($cracklib_ucredit)
  validate_integer($cracklib_lcredit)
  validate_integer($cracklib_ocredit)
  validate_integer($cracklib_minclass)
  validate_integer($cracklib_minlen)
  validate_integer($cracklib_retry)
  validate_integer($deny)
  validate_bool($display_account_lock)
  validate_umask($homedir_umask)
  validate_integer($remember)
  validate_integer($root_unlock_time)
  validate_integer($rounds)
  validate_integer($uid)
  validate_integer($unlock_time)
  validate_integer($fail_interval)
  validate_bool($preserve_ac)
  validate_bool($warn_if_unknown)
  validate_bool($deny_if_unknown)
  validate_bool($use_ldap)
  validate_bool($use_netgroups)
  validate_bool($use_openshift)
  validate_bool($use_sssd)
  validate_array($auth_sections)

  compliance_map()

  # We only want to use SSSD if we're using LDAP and params tells us to *or*
  # someone has explicitly set the $use_sssd variable above.

  if $use_sssd {
    $_use_sssd = $use_sssd
  }
  else {
    if $use_ldap {
      $_use_sssd = $::pam::params::use_sssd
    }
    else {
      $_use_sssd = $use_sssd
    }
  }

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

  file { '/etc/pam.d/other':
    ensure  => 'file',
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
    content => template('pam/etc/pam.d/other.erb')
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

  package { 'pam':        ensure => 'latest' }
  package { 'pam_pkcs11': ensure => 'latest' }

  if $::operatingsystem in ['RedHat','CentOS']
    and versioncmp($::operatingsystemmajrelease,'5') > 0 {
    package { 'fprintd-pam': ensure => 'latest' }
  }

  if ! empty($auth_sections) {
    ::pam::auth { $auth_sections: }
  }
}

