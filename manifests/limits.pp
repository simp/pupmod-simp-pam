#
# Class: pam::limits_conf
#
# Set up /etc/security/limits.conf
#
# See limits.conf(5) for additional details.
#
class pam::limits {
  include '::pam'

  simpcat_build { 'pam_limits':
    order   => ['*.limit'],
    target  => '/etc/security/limits.conf',
    require => Package['pam']
  }

  file { '/etc/security/limits.conf':
    ensure    => 'file',
    owner     => 'root',
    group     => 'root',
    mode      => '0640',
    subscribe => Simpcat_build['pam_limits'],
    audit     => content
  }
}

