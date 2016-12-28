# This class ensures that reasonable PAM security options are applied.
#
# It also takes into account the global SIMP settings for LDAP and SSSD.
#
# Many options are exposed here that may affect a large number of lower-level
# PAM module settings. This is done to provide continuity across the PAM stack
# where possible.
#
# @param cracklib_difok
#   The number of character changes between the old password and the new
#   password that are enough to accept the new password
#
# @param cracklib_maxrepeat
#   Reject passwords which contain more than this many of the same consecutive
#   characters
#
# @param cracklib_maxsequence
#   Reject passwords which contain monotonic character sequences
#   longer than this
#
#   * The default is 0 which means that this check is disabled. Examples of
#     such sequence are ``12345`` or ``fedcb``
#
#   * Most such passwords will not pass the simplicity check unless the
#     sequence is only a minor part of the password
#
# @parm cracklib_maxclassrepeat
#   Reject passwords which contain more than this many consecutive characters
#   of the **same class**
#
#   * Character classes include:
#       * Upper Case
#       * Lower Case
#       * Digit
#       * Special Character
#
# @param cracklib_reject_username
#   Check whether the name of the user in straight or reversed form is
#   contained in the new password
#
# @param cracklib_gecoscheck
#   Check whether the words from the GECOS field (usualy full name of the user)
#   longer than 3 characters in straight or reversed form are contained in the
#   new password
#
# @param cracklib_enforce_for_root
#   Enforce all password check settings for the ``root`` user
#
# @param cracklib_dcredit
#   The required credit for having digits in the new password
#
#   * For Positive Integers: If you have less than or N digits, each digit will
#     count +1 towards meeting the current minlen value
#
#   * For Negative Integers: The minimum number of digits that must be met for
#     a new password
#
# @param cracklib_ucredit
#   The required credit for having upper case letters in the new password
#
#   * For Positive Integers: If you have less than or N characters , each
#     character will count +1 towards meeting the current minlen value
#
#   * For Negative Integers: The minimum number of characters that must be met
#     for a new password
#
# @param cracklib_lcredit
#   The required credit for having lower case letters in the new password
#
#   * For Positive Integers: If you have less than or N characters , each
#     character will count +1 towards meeting the current minlen value
#
#   * For Negative Integers: The minimum number of characters that must be met
#     for a new password
#
# @param cracklib_ocredit
#   The required credit for having special characters in the new password
#
#   * For Positive Integers: If you have less than or N characters , each
#     character will count +1 towards meeting the current minlen value
#
#   * For Negative Integers: The minimum number of characters that must be met
#     for a new password
#
# @param cracklib_minclass
#   The minimum number of required classes for the new password
#
#   * The four classes are digits, upper and lower letters and other characters
#
#   * The difference to the credit check is that a specific class if of
#     characters is not required.  Instead N out of four of the classes are
#     required.
#
# @param cracklib_minlen
#   The minimum acceptable size for the new password (plus one if credits are
#   not disabled)
#
# @param cracklib_retry
#   Prompt user at most N times before returning with error
#
# @param deny
#   The number of failed attempts before PAM denies a user from logging in
#
# @param display_account_lock
#   Display to the remote user that their account has been locked
#
# @param homedir_umask
#   Sets the file mode creation mask of the user home directories
#
# @param remember
#   The last N passwords for each user are saved in ``/etc/security/opasswd``
#   in order to force password change history and keep the user from
#   alternating between the same password too frequently
#
# @param remember_retry
#   Allow this many retries
#
# @param remember_for_root
#   Remember the last ``$remember`` passwords for the root user
#
# @param root_unlock_time
#   Allow access after N seconds to root account after failed attempt
#
# @param rounds
#   Set the optional number of rounds of the ``SHA256``, ``SHA512`` and
#   ``Blowfish`` password hashing algorithms to N
#
# @param uid
#   Allow user logins for userse with UID higher than N
#
# @param unlock_time
#   Allow acesss after N seconds to user account after failed attempt
#
# @param preserve_ac
#   Keep the original ``-ac`` files around for reference
#
# @param warn_if_unknown
#   If you make it to the ``other`` PAM configuration file, then provide a
#   warning that the login method was uncaught by other PAM stacks
#
# @param deny_if_unknown
#   If true, deny any access to an application that falls all the way through
#   the PAM stack to ``other``
#
# @param use_netgroups
#   Default: false
#   Set PAM up to use NIS netgroups.
#
# @param use_openshift
#   Set PAM to work with OpenShift
#
# @param sssd
#   Set PAM to work with SSSD
#
# @param tty_audit_users
#   The users for which TTY auditing is enabled
#
#   * Set to an empty Array to not audit TTY actions for any user
#
# @param su_content
#   The content that should be used to fill ``/etc/pam.d/su`` instead of the
#   templated content
#
# @param other_content
#   The content that should be used to fill ``/etc/pam.d/other`` instead of the
#   templated content
#
# @param auth_sections
#   The PAM ``*-auth`` files to manage
#
#   * Set to an empty Array to not manage any sections
#
# @param fingerprint_content
#   The content that should be used to fill ``/etc/pam.d/fingerprint_auth``
#   instead of the templated content
#
# @param system_content
#   The content that should be used to fill ``/etc/pam.d/system_auth`` instead
#   of the templated content
#
# @param password_content
#   The content that should be used to fill ``/etc/pam.d/password_auth``
#   instead of the templated content
#
# @param smartcard_content
#   The content that should be used to fill ``/etc/pam.d/smartcard_auth``
#   instead of the templated content
#
# @param enable
#   If you have included this module but want it to stop managing your
#   configuration files set this to ``false``
#
# @param enable_warning
#   Will issue a warning if this module is included but global catalyst
#   ``simp_options::pam`` is set to ``false``
#
class pam (
  Integer[0]       $cracklib_difok            = 4,
  Integer[0]       $cracklib_maxrepeat        = 2,
  Integer[0]       $cracklib_maxsequence      = 4,
  Integer[0]       $cracklib_maxclassrepeat   = 0,
  Boolean          $cracklib_reject_username  = true,
  Boolean          $cracklib_gecoscheck       = true,
  Boolean          $cracklib_enforce_for_root = true,
  Integer          $cracklib_dcredit          = -1,
  Integer          $cracklib_ucredit          = -1,
  Integer          $cracklib_lcredit          = -1,
  Integer          $cracklib_ocredit          = -1,
  Integer[0]       $cracklib_minclass         = 3,
  Integer[0]       $cracklib_minlen           = 14,
  Integer[0]       $cracklib_retry            = 3,
  Integer[0]       $deny                      = 5,
  Boolean          $display_account_lock      = false,
  Simplib::Umask   $homedir_umask             = '0077',
  Integer[0]       $remember                  = 24,
  Integer[0]       $remember_retry            = 1,
  Boolean          $remember_for_root         = true,
  Integer[0]       $root_unlock_time          = 60,
  Integer[0]       $rounds                    = 10000,
  Integer[0]       $uid                       = 500,
  Integer[0]       $unlock_time               = 900,
  Integer[0]       $fail_interval             = 900,
  Boolean          $preserve_ac               = false,
  Boolean          $warn_if_unknown           = true,
  Boolean          $deny_if_unknown           = true,
  Boolean          $use_netgroups             = false,
  Boolean          $use_openshift             = false,
  Boolean          $sssd                      = simplib::lookup('simp_options::sssd', { 'default_value' => false}),
  Array[String]    $tty_audit_users           = [ 'root' ],
  Array[Enum[
    'fingerprint',
    'system',
    'password',
    'smartcard'
  ]]               $auth_sections             = [ 'fingerprint', 'system', 'password', 'smartcard' ],
  Optional[String] $su_content                = undef,
  Optional[String] $other_content             = undef,
  Optional[String] $fingerprint_auth_content  = undef,
  Optional[String] $system_auth_content       = undef,
  Optional[String] $password_auth_content     = undef,
  Optional[String] $smartcard_auth_content    = undef,
  Boolean          $enable                    = true,
  Boolean          $enable_warning            = true
) {
  if simplib::lookup('simp_options::pam', { 'default_value' => true } ) {
    if $enable {
      include '::pam::install'

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

      if $other_content {
        $_other_content = $other_content
      }
      else {
        $_other_content = template('pam/etc/pam.d/other.erb')
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

      if ! empty($auth_sections) { ::pam::auth { $auth_sections: } }
    }
  }
  else {
  # The global catalyst was set to false but the module was included
    if $enable_warning {
      if simplib::lookup('simp_options::pam', { 'default_value' => true }) == false {
        warning('Module pupmod-simp-pam was included but global catalyst simp_options::pam is set to false. This could have unexpected effects.')
      }
    }
  }
}
