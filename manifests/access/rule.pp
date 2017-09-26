# Set up entries in ``/etc/security/access.conf``
#
# These entries are the ``permission:users:origins`` sets as defined in
# ``access.conf(5)``.
#
# @see access.conf(5)
#
# @example Add administrator group access
#   pam::access::rule { 'administrators':
#     permission => '+',
#     users      => ['(administrators)'],
#     origins    => ['ALL'],
#     order      => 1000
#   }
#
# @example Add everyone except group ``bad_guys``
#   pam::access::rule { 'bad_guys':
#     permission => '+',
#     users      => ['ALL EXCEPT (bad_guys)'],
#     origins    => ['ALL'],
#     order      => 1000
#   }
#
# @example Add everyone except the hippopotamus
#   pam::access::rule { 'but_not_the_hippopotamus':
#     permission => '+',
#     users      => ['ALL EXCEPT hippopotamus'],
#     origins    => ['ALL'],
#     order      => 1000
#   }
#
# @example Allow group auditors from two specific hosts
#   pam::access::rule { 'auditors_from_trusted_nodes':
#     permission => '+',
#     users      => ['(auditors)'],
#     origins    => ['1.2.3.4','5.6.7.8'],
#     order      => 1000
#   }
#
# @param name [String]
#   A unique name for the resource
#
# @param comment
#   A comment to include with this entry
#
# @param permission
#   If +, grant access. If -, revoke access
#
# @param users
#   The users, groups, or netgroups to allow access to the system.
#
#   Syntax:
#       ```
#       user     => username
#       group    => (groupname)
#       netgroup => @netgroup
#       ```
#
#   * Entries are **not** validated so complex expressions are allowed such as
#   ``ALL EXCEPT (bad_guys)``
#
# @param origins
#   The locations from which users are allowed to login to the system
#
#   * See ``access.conf(5)`` for the full list
#
# @param order
#   The order in which you want this rule to appear
#
#   * If you do not specify a order, the rules will be listed in alphanumeric
#   order by name
#
# @author Trevor Vaughan <tvaughan@onyxpoint.com>
#
define pam::access::rule (
  Array[String]         $users,
  Array[String]         $origins,
  Enum['+','-']         $permission = '+',
  Optional[String]      $comment    = undef,
  Integer[1,9999999999] $order      = 1000
) {
  include '::pam::access'
  if (simplib::lookup('pam::enable_separator', { 'default_value'    => true }) == true) {
    $_separator = simplib::lookup('pam::separator', { 'default_value' => ','})
  } else {
    $_separator = ' '
  }
  $_name = regsubst($name,'/','_')
  $_origins = join($origins, $_separator)
  $_users = join($users,$_separator)

  if $comment {
    if $comment =~ /^\s*#/ {
      $_comment = regsubst($comment,"\n","\n# ",'G')
    }
    else {
      $_comment = regsubst("# ${comment}","\n","\n# ",'G')
    }

    $_content = "${_comment}\n${permission}:${_users}:${_origins}\n"
  }
  else {
    $_content = "${permission}:${_users}:${_origins}\n"
  }

  concat::fragment { "pam_access_rule_${_name}":
    order   => $order,
    target  => '/etc/security/access.conf',
    content => $_content
  }
}
