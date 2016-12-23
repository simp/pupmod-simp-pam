# Install the required PAM packages
#
class pam::install {
  assert_private()

  package { 'pam':        ensure => 'latest' }
  package { 'pam_pkcs11': ensure => 'latest' }
  package { 'fprintd-pam': ensure => 'latest' }
}
