# Set up ``/etc/security/access.conf`` with a default to allow root to login
# locally.
#
# Use ``pam::access::rule`` to manage ``access.conf`` entries and remember
# that **order matters** (first match wins)!
#
# @param default_deny
#   Add a "default deny" rule as the last match of the rule set
#
# @param users
#   A hash that can be used to create several pam::access::rule resources set in Hiera.
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
# @see access.conf(5)
#
# @author Trevor Vaughan <tvaughan@onyxpoint.com>
#
class pam::access (
  Boolean        $default_deny = true,
  Optional[Hash] $users        = undef
){

  if $default_deny {
    include '::pam::access::default_deny'
  }

  concat { '/etc/security/access.conf':
    owner          => 'root',
    group          => 'root',
    mode           => '0644',
    ensure_newline => true,
    warn           => true
  }

  # Allow root locally by default.
  pam::access::rule { 'allow_local_root':
    permission => '+',
    users      => ['root'],
    origins    => ['LOCAL'],
    order      => 1
  }

  if $users {
    # extract defaults and remove that hash from iteration
    if $users['defaults'].is_a(Hash) {
      $defaults  = $users['defaults']
      $raw_users = $users - 'defaults'
    }
    else {
      $defaults  = {}
      $raw_users = $users
    }

    $raw_users.each |$pam_user, $options| {
      if $options.is_a(Hash) {
        $args = { 'users' => [$pam_user] } + $options
      }
      else {
        $args = { 'users' => [$pam_user] }
      }

      pam::access::rule {
        default:   * => $defaults;
        "rule_${pam_user}": * => $args;
      }
    }
  }

}

