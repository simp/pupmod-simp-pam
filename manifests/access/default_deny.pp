# Add a "default deny" rule to ``pam_access``
#
# Always allow ``root`` locally for safety
#
class pam::access::default_deny {
  pam::access::rule { 'default_deny':
    permission => '-',
    users      => ['ALL'],
    origins    => ['ALL'],
    order      => 9999999999
  }
}

