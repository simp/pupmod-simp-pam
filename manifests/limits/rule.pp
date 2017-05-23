# These entries are the ``domain type item value`` resource limiting sets as
# defined in ``limits.conf(5)``.
#
# Be aware that order matters and the **LAST** item that matches in the
# ``limits.conf`` file will take effect.
#
# @see limits.conf(5)
#
# @example Enforce hard and soft disable on core dumps
#   pam::limits::rule { 'limit_core':
#     domains => ['*'],
#     type    => '-',
#     item    => 'core',
#     value   => 0,
#     order   => 1
#   }
#
# @example Only allow 2 administrators to login at once
#   pam::limits::rule { 'limit_admins':
#     domains => ['%administrators', '%wheel'],
#     type    => 'hard',
#     item    => 'maxlogins',
#     value   => 2,
#     order   => 1
#   }
#
# @param name [String]
#   A descriptive name for your resource
#
# @param domains
#   The domains to which these limits should apply
#
#   * One entry will be created per domain, in listed order
#   * See the ``<domain>`` section of ``limits.conf(5)`` for details
#
# @param item
#   The ``item`` to which these limits should apply
#
#   * See the ``<item>`` section of ``limits.conf(5)`` for details
#
# @param value
#   The ``value`` to apply to the ``item`` and ``domains``
#
#   * See the ``<item>`` section of ``limits.conf(5)`` for details
#
# @param type
#   The ``type`` to apply to the ``item`` and ``domains``
#
#   * See the ``<type>`` section of ``limits.conf(5)`` for details
#
# @param order
#   The order in which this rule should appear
#
#   * If you don't specify a order, the rules will be listed in alphanumeric
#     order by name
#
define pam::limits::rule (
  Array[String]             $domains,
  Pam::Limits::Item         $item,
  Pam::Limits::Value        $value,
  Enum['hard','soft','-']   $type   = '-',
  Integer[0]                $order  = 1000
) {
  include '::pam::limits'

  if $item in ['priority','nice'] {
    if $value in ['unlimited','infinity'] {
      fail("'${value}' is not valid for '${item}'; expected Integer")
    }
  }

  $_name = regsubst($name,'/','_')

  $_content = map($domains) |$domain| {
    "${domain}\t${type}\t${item}\t${value}\n"
  }

  concat::fragment { "pam_limits_rule_${_name}":
    order   => $order,
    target  => '/etc/security/limits.conf',
    content => join($_content,"\n")
  }
}
