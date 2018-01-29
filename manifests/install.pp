# Install the required PAM packages
#
# @author https://github.com/simp/pupmod-simp-pam/graphs/contributors
#
class pam::install {
  assert_private()

  package { 'pam':        ensure   => $::pam::package_ensure }
  package { 'pam_pkcs11': ensure   => $::pam::package_ensure }
  package { 'fprintd-pam': ensure  => $::pam::package_ensure }

  if $::pam::password_check_backend == 'pwquality' {
    package { 'libpwquality': ensure => $::pam::package_ensure }
  }
}
