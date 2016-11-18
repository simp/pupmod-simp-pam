# _Description_
#
# Enable wheel restrictions for su access.
#
class pam::wheel (
# _Variables_
#
# $wheel_group
#     What group should be the 'wheel' equivalent. Set to the traditional
#     'wheel' by default.
    $wheel_group = 'wheel',
# $root_only
#     Set this if you only want to make this effective when su'ing to root.
    $root_only = false,
# $use_openshift
#    Whether or not to configure things in such a way that the
#    openshift_origin puppet code is compatible.
    $use_openshift = pick($::pam::use_openshift,false)
) inherits ::pam {
  validate_string($wheel_group)
  validate_bool($root_only)
  validate_bool($use_openshift)


  file { '/etc/pam.d/su':
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
    content => template('pam/etc/pam.d/su.erb')
  }
}
