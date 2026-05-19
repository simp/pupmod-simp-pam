# @summary Install the required PAM packages
#
# @author https://github.com/simp/pupmod-simp-pam/graphs/contributors
#
class pam::install {
  assert_private()

  package { 'pam':        ensure => $pam::package_ensure }

  if $pam::password_check_backend == 'pwquality' {
    package { 'libpwquality': ensure => $pam::package_ensure }
  }

  if $pam::enable_ssh_agent_auth {
    package { 'pam_ssh_agent_auth': ensure => $pam::package_ensure }
  }
}
