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
# _Variables_
#
# $name
#     This becomes part of the temp file name.
#     Do not use '/' as part of the name!
# $order
#     The order where you want this rule to appear.  1000 is the default.  If
#     you don't specify a order, the rules will be listed in alphabetical order
#     by name.
define pam::limits::add (
  String                  $domain,
  Pam::Limits::Item         $item,
  Pam::Limits::Value        $value,
  Enum['hard','soft','-'] $type = '-',
  Stdlib::Compat::Integer $order = '1000'
  ) {
  include '::pam::limits'

  if $item in ['priority','nice'] {
    if $value in ['unlimited','infinity'] {
      err("The value ${value} is not an appropriate value for ${item} in pam::limits::add.  It must be an integer")
    }
  }

  $l_name = regsubst($name,'/','_')

  simpcat_fragment { "pam_limits+${order}.${l_name}.limit":
    content => "${domain}\t${type}\t${item}\t${value}\n"
  }
}
