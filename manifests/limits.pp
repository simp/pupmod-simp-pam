# @summary Set up ``/etc/security/limits.conf``
#
# Add entries with ``pam::limits::rule``
#
# @see limits.conf(5)
#
# @author https://github.com/simp/pupmod-simp-pam/graphs/contributors
#
class pam::limits {
  concat { '/etc/security/limits.conf':
    owner          => 'root',
    group          => 'root',
    mode           => '0640',
    order          => 'numeric',
    ensure_newline => true,
    warn           => true
  }
}
