#!/bin/sh
# This file is managed by Puppet. DO NOT EDIT.

# authconfig cannot be used to generate equivalent,
# security-compliant, PAM configuration as that created by
# SIMP.  To prevent an administrator from inadvertently
# corrupting PAM configuration by using /usr/sbin/authconfig,
# /usr/sbin/authconfig-tui or tools that call them, SIMP has
# replaced the original authconfig and authconfig-tui links
# with links to this no-op script.

/bin/true
