# @summary Set up ``/etc/security/limits.conf``
#
# Add entries with ``pam::limits::rule``
#
# @param rules
#   A Hash that can be used to create pam::limits::rule resources via Hiera.
#
#   * The Hash must be formatted suitably for passing directly into `create_resource()`
#   * Remember that order matters:
#
#   @example Hiera formatted rules
#
#     pam::limits::rules:
#       disable_core_for_user1:
#         domains:
#           - 'user1'
#         type: 'hard'
#         item: 'core'
#         value: 0
#         order: 50
#       disable_core_for_all:
#         domains:
#           - '*'
#         type: 'hard'
#         item: 'core'
#         value: 0
#         order: 100
#
# @see limits.conf(5)
#
# @author https://github.com/simp/pupmod-simp-pam/graphs/contributors
#
class pam::limits (
  Optional[Hash] $rules = undef
) {
  concat { '/etc/security/limits.conf':
    owner          => 'root',
    group          => 'root',
    mode           => '0640',
    order          => 'numeric',
    ensure_newline => true,
    warn           => true,
  }

  if ($rules and !empty($rules)) { create_resources('pam::limits::rule', $rules) }
}
