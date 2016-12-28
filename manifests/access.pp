# Set up ``/etc/security/access.conf`` with a default to allow root to login
# locally.
#
# Use ``pam::access::rule`` to manage ``access.conf`` entries and remember
# that **order matters** (first match wins)!
#
# @param default_deny
#   Add a "default deny" rule as the last match of the rule set
#
# @see access.conf(5)
#
# @author Trevor Vaughan <tvaughan@onyxpoint.com>
#
class pam::access (
  Boolean $default_deny = true
){
  include '::pam'

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
}

