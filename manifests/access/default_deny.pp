# @summary Add a "default deny" rule to ``pam_access``
#
# Always allow ``root`` locally for safety
#
# @author https://github.com/simp/pupmod-simp-pam/graphs/contributors
#
class pam::access::default_deny {
  pam::access::rule { 'default_deny':
    permission => '-',
    users      => ['ALL'],
    origins    => ['ALL'],
    order      => 9999999999,
  }
}
