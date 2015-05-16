# == Class: pam::access
#
# Set up /etc/security/access.conf with a default to allow root to
# login locally and deny everyone else from all locations.
#
# Use pam::access::manage to manage access.conf entries and
# remember that order matters!
#
# See access.conf(5) for details.
#
# == Authors
#   * Trevor Vaughan <tvaughan@onyxpoint.com>
#
class pam::access {
  include 'pam'

  concat_build { 'pam_access':
    target        => '/etc/security/access.conf',
    order         => '*.access',
    squeeze_blank => true,
    require       => Package['pam']
  }

  file { '/etc/security/access.conf':
    ensure    => 'present',
    owner     => 'root',
    group     => 'root',
    mode      => '0644',
    subscribe => Concat_build['pam_access'],
    audit     => content
  }

  # Deny everyone at the end
  pam::access::manage { 'default_deny':
    permission => '-',
    users      => 'ALL',
    origins    => ['ALL'],
    order      => '9999999999'
  }

  # Allow root locally by default.
  pam::access::manage { 'allow_local_root':
    permission => '+',
    users      => 'root',
    origins    => ['LOCAL'],
    order      => '0'
  }
}

