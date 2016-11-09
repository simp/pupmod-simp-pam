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
# == Params
#
# [*users*]
#   Default: {}
#   A hash that can be used to create several pam::access::manage resources set in Hiera.
#   Each member of the hash will be a resource (this example is from hiera):
#
#     pam::access::users:
#       defaults:
#         origins:
#           - ALL
#         permission: '+'
#       vagrant:
#       '(simp)':
#       test:
#         origins:
#           - 192.168.0.1/24
#       baddude:
#         permission: '-'
#
#
# == Authors
#   * Trevor Vaughan <tvaughan@onyxpoint.com>
#
class pam::access (
  Hash $users = {},
) {
  include '::pam'

  simpcat_build { 'pam_access':
    target        => '/etc/security/access.conf',
    order         => '*.access',
    squeeze_blank => true,
    require       => Package['pam']
  }

  file { '/etc/security/access.conf':
    ensure    => 'file',
    owner     => 'root',
    group     => 'root',
    mode      => '0644',
    subscribe => Simpcat_build['pam_access'],
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

  if ! empty($users) {
    inspect($users)
    # extract defaults and remove that hash from iteration
    $defaults  = $users['defaults']
    $raw_users = $users - 'defaults'

    $raw_users.each |$name, $options| {
      if is_hash($options) {
        $args = { 'users' => $name } + $options
      }
      else {
        $args = { 'users' => $name }
      }

      ::pam::access::manage {
        default:          * => $defaults;
        "manage_${name}": * => $args;
      }
    }
  }

}
