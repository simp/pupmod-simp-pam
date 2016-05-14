# _Description_
#
# These entries are the 'domain type item value' sets as defined in
# limits.conf(5).
#
# _Example_
#
#  pam::limits::add { 'limit1':
#    domain => '*',
#    type => '-',
#    item => 'core',
#    value => '0',
#    order => '1'
#  }
define pam::limits::add (
# _Variables_
#
# $name
#     This becomes part of the temp file name.
#     Do not use '/' as part of the name!
    $domain,
    $item,
    $value,
    $type = '-',
# $order
#     The order where you want this rule to appear.  1000 is the default.  If
#     you don't specify a order, the rules will be listed in alphabetical order
#     by name.
    $order = '1000'
  ) {
  include '::pam::limits'

  validate_array_member($item,[
    'core',
    'data',
    'fsize',
    'memlock',
    'nofile',
    'rss',
    'stack',
    'cpu',
    'nproc',
    'as',
    'maxlogins',
    'maxsyslogins',
    'priority',
    'locks',
    'sigpending',
    'msgqueue',
    'nice',
    'rtprio'
  ])
  if $item in ['priority','nice'] {
    validate_integer($value)
  }
  else {
    validate_re($value,'^(\d+|unlimited|infinity)$')
  }
  validate_array_member($type,['hard','soft','-'])
  validate_integer($order)

  $l_name = regsubst($name,'/','_')

  concat_fragment { "pam_limits+${order}.${l_name}.limit":
    content => "${domain}\t${type}\t${item}\t${value}\n"
  }
}
