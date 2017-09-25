# Install the required PAM packages
#
# @param ensure
#   The state in which the packages should be kept
#
class pam::install (
  $ensure = 'present'
){
  assert_private()

  package { 'pam':        ensure   => $ensure }
  package { 'pam_pkcs11': ensure   => $ensure }
  package { 'fprintd-pam': ensure  => $ensure }

  if $::pam::password_check_backend == 'pwquality' {
    package { 'libpwquality': ensure => $ensure }
  }
}
