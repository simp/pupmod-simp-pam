# Enable wheel restrictions for su access
#
# @see pam_wheel(8)
#
# @param wheel_group
#   What group should be the ``wheel`` equivalent
#
# @param root_only
#   Only enforce ``wheel`` restrictions when changing to the ``root`` user
#
# @param use_openshift
#    Whether or not to configure things in such a way that the ``openshift``
#    puppet code is compatible
#
# @param content
#   Optional custom content for file
#
class pam::wheel (
  String           $wheel_group   = 'wheel',
  Boolean          $root_only     = false,
  Boolean          $use_openshift = $::pam::use_openshift,
  Optional[String] $content       = $::pam::su_content
) inherits ::pam {
  if $content {
    $_content = $content
  }
  else {
    $_content = template("${module_name}/etc/pam.d/su.erb")
  }

  file { '/etc/pam.d/su':
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
    content => $_content
  }
}
