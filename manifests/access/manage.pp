# == Define: pam::access::manage
#
# Set up entries in /etc/security/access.conf
#
# These entries are the 'permission:users:origins' sets as defined in
# access.conf(5).
#
# == Examples
#
# [*Add administrator group access*]
#
#   pam::access::manage { 'administrators':
#     permission => '+',
#     users => '(administrators)',
#     origins => ['ALL'],
#     order => '1000'
#   }
#
# [*Add everyone except group bad guys*]
#
#   pam::access::manage { 'bad_guys':
#     permission => '+',
#     users => 'ALL EXCEPT (bad_guys)',
#     origins => ['ALL'],
#     order => '1000'
#   }
#
# [*Add everyone except the hippopotamus*]
#
#   pam::access::manage { 'but_not_the_hippopotamus':
#     permission => '+',
#     users => 'ALL EXCEPT hippopotamus',
#     origins => ['ALL'],
#     order => '1000'
#   }
#
# [*Allow group auditors from two specific hosts*]
#
#   pam::access::manage { 'auditors_from_trusted_nodes':
#     permission => '+',
#     users => '(auditors)',
#     origins => ['1.2.3.4','5.6.7.8'],
#     order => '1000'
#   }
#
# == Parameters
#
# [*name*]
# Type: String
#   A unique name for the resource. Slashes will be replaced with
#   underscores.
#
# [*comment*]
# Type: String
#   A comment to include with this entry. Do not include the leading
#   '#' marks.
#
# [*permission*]
# Type: '+' or '-'
# Default: '+'
#   If +, grant access. If -, revoke access.
#   The default is '+' because we're making the assumption that you're
#   denying all by default.
#
# [*users*]
# Type: String
#   The users, groups, or netgroups to allow access to the system.
#   Syntax:
#     user     => username
#     group    => (groupname)
#     netgroup => @netgroup
#   This field is not validated so complex expressions are allowed
#   such as: ALL EXCEPT (bad_guys)
#
# [*origins*]
# Type: Array of Strings
#   The locations from which users are allowed to login to the system.
#   See access.conf(5) for the full list.
#
# [*order*]
# Type: Integer
#   The order where you want this rule to appear.  1000 is the
#   default.  If you don't specify a order, the rules will be listed
#   in alphabetical order by name.
#
#   Items ARE order dependent, don't set order below 1 or above
#   9999999999.
#
# == Authors
#   * Trevor Vaughan <tvaughan@onyxpoint.com>
#
define pam::access::manage (
  String $users,
  Array[String] $origins,
  Enum['+','-'] $permission = '+',
  String $comment = '',
  Stdlib::Compat::Integer $order = '1000'
) {
  if $order > '9999999999' {
    fail('$order must be less than 9999999999.')
  }

  $l_name = regsubst($name,'/','_')
  $l_origins = join($origins,' ')

  if empty($comment) {
    $content = "${permission} : ${users} : ${l_origins}\n"
  }
  else {
    $l_comment = regsubst($comment,"\n","\n# ",'G')
    $content = "# ${l_comment}\n${permission} : ${users} : ${l_origins}\n"
  }

  simpcat_fragment { "pam_access+${order}.${l_name}.access": content => $content }
}
