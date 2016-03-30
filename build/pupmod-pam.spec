Summary: PAM Puppet Module
Name: pupmod-pam
Version: 4.2.1
Release: 0
License: Apache License, Version 2.0
Group: Applications/System
Source: %{name}-%{version}-%{release}.tar.gz
Buildroot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
Requires: pupmod-simpcat >= 2.0.0-0
Requires: pupmod-oddjob >= 1.0.0-0
Requires: pupmod-rsync >= 2.0.0-0
Requires: pupmod-sssd >= 2.0.0-0
Requires: puppet >= 3.3.0
Requires: simp_rsync_filestore >= 2.0.0-2
Buildarch: noarch
Requires: simp-bootstrap >= 4.2.0
Obsoletes: pupmod-pam-test
Requires: pupmod-onyxpoint-compliance_markup

Prefix: %{_sysconfdir}/puppet/environments/simp/modules

%description
This Puppet module provides the capability to configure various PAM settings on
the system.

Included are capabilities to manage:
  * system-auth
  * Group-based access to the system
  * access.conf

The system-auth settings are a bit draconian, but simple enough to work within.

%prep
%setup -q

%build

%install
[ "%{buildroot}" != "/" ] && rm -rf %{buildroot}

mkdir -p %{buildroot}/%{prefix}/pam

dirs='files lib manifests templates'
for dir in $dirs; do
  test -d $dir && cp -r $dir %{buildroot}/%{prefix}/pam
done

%clean
[ "%{buildroot}" != "/" ] && rm -rf %{buildroot}

mkdir -p %{buildroot}/%{prefix}/pam

%files
%defattr(0640,root,puppet,0750)
%{prefix}/pam

%post
#!/bin/sh

%postun
# Post uninstall stuff

%changelog
* Wed Mar 30 2016 Trevor Vaughan <tvaughan@onyxpoint.com> - 4.2.1-0
- Move pam_oddjob_mkhomedir below pam_sssd in the stack due to a odd
  SELinux-related bug which prevented users from logging into systems via SSH.

* Mon Mar 14 2016 Nick Markowski <nmarkowski@keywcorp.com> - 4.2.0-0
- Ensure that EL6.7+ uses SSSD over NSCD

* Tue Feb 23 2016 Ralph Wright <ralph.wright@onyxpoint.com> - 4.1.0-14
- Added compliance function support

* Wed Nov 18 2015 Trevor Vaughan <tvaughan@onyxpoint.com> - 4.1.0-13
- Updated to enable SSSD properly now that most of the major items have been
  resolved upstream.

* Mon Nov 09 2015 Chris Tessmer <chris.tessmer@onypoint.com> - 4.1.0-13
- Migration to simplib and simpcat (lib/ only)

* Tue Oct 27 2015 Trevor Vaughan <tvaughan@onyxpoint.com> - 4.1.0-12
- Removed all calls to the lsb* facts and replaced them with 'operatingsystem*'
  facts

* Fri Sep 18 2015 Trevor Vaughan <tvaughan@onyxpoint.com> - 4.1.0-11
- Moved pam_mkhomedir to before pam_systemd to fix issues with systemd
  subsystem failures occuring due to a lack of a home directory.

* Sat May 16 2015 Trevor Vaughan <tvaughan@onyxpoint.com> - 4.1.0-10
- Slight update to more closely align with the STIG.

* Fri Jan 16 2015 Trevor Vaughan <tvaughan@onyxpoint.com> - 4.1.0-9
- Changed puppet-server requirement to puppet

* Thu Oct 02 2014 Trevor Vaughan <tvaughan@onyxpoint.com> - 4.1.0-8
- Updated the mode on limits.conf and access.conf to be
  non-executable.
- Changed the mode on access.conf to be world readable so that the
  RHEL7 screensaver can unlock properly.

* Wed Oct 01 2014 Trevor Vaughan <tvaughan@onxypoint.com> - 4.1.0-7
- Added options to the auth configs in PAM to ensure that GDM works
  properly in RHEL7.

* Thu Sep 04 2014 Adam Yohrling <adam.yohrling@onyxpoint.com> - 4.1.0-6
- Added optional pam_systemd module to access template. This will
  only work if present on the system and is required for CentOS/RHEL 7

* Fri Jul 25 2014 Trevor Vaughan <tvaughan@onyxpoint.com> - 4.1.0-5
- Added oddjob support for creating home directories for setting
  correct SELinux contexts on created home directories.
  See: https://bugzilla.redhat.com/show_bug.cgi?id=447096#c3

* Sun Jun 22 2014 Kendall Moore <kmoore@keywcorp.com> - 4.1.0-4
- Removed MD5 file checksums for FIPS compliance.

* Thu Apr 10 2014 Trevor Vaughan <tvaughan@onyxpoint.com> - 4.1.0-3
- Added full support for access.conf and removed groupaccess.conf
  since it is no longer required. pam::access::manage should now be
  used instead of pam::groupaccess::modify.
- Renamed pam::access_conf and pam::limits_conf to pam::access and
  pam::limits respectively.
- Moved pam::limits::add_limit to pam::limits::add

* Mon Feb 10 2014 Trevor Vaughan <tvaughan@onyxpoint.com> - 4.1.0-2
- Updates to fully support OpenShift.
- Added OpenSCAP support.

* Tue Jan 28 2014 Trevor Vaughan <tvaughan@onyxpoint.com> - 4.1.0-1
- Added proper support to the wheel class for OpenShift support so that
  it does not conflict with the base classes from openshift_origin.

* Tue Oct 22 2013 Trevor Vaughan <tvaughan@onyxpoint.com> - 4.1.0-0
- Converted groupaccess over to using simp_file_line instead of
  concat.
- Cleaned up the PAM settings quite a bit and now using a single
  template for all -auth files in /etc/pam.d.
- pam_faillock no longer causes spurious failed logins with sudo.

* Mon Oct 07 2013 Kendall Moore <kmoore@keywcorp.com> - 4.0.0-7
- Updated all erb templates to properly scope variables.
- Added variables to init.pp to make templates more configurable.

* Wed Oct 02 2013 Trevor Vaughan <tvaughan@onyxpoint.com> - 4.0.0-6
- Use 'versioncmp' for all version comparisons.

* Mon Feb 25 2013 Maintenance
4.0-5
- Added a call to $::rsync_timeout to the rsync call since it is now required.

* Tue Jul 24 2012 Maintenance
4.0.0-4
- Added maxclassrepeat=3 and gecoscheck to the cracklib line.
- Removed the *credit items from the cracklib line. We have minclass=3 which is
  good enough and having the rest in there was confusing.

* Wed Jun 13 2012 Maintenance
4.0.0-3
- Fixed a bug where the other *-auth files in pam.d were not updated to handle
  faillock properly.

* Wed May 16 2012 Maintenance
4.0.0-2
- Moved mit-tests to /usr/share/simp...
- Updated pp files to better meet Puppet's recommended style guide.

* Fri Mar 02 2012 Maintenance
4.0.0-1
- Improved test stubs.

* Fri Feb 10 2012 Maintenance
4.0.0-0
- Updated the PAM template to handle faillog as the new default in
  RHEL6.
- Added tests for verifying that a user account lockout happens after 5 tries,
  can be unlocked, and functions properly after that.

* Tue Dec 20 2011 Maintenance
2.0.0-5
- Updated the spec file to not require a separate file list.
- Added a line to allow the local 'wheel' group to get to su and bypass
  checking the alternately set group. This allows the alternate group to be in
  LDAP and the local group to be able to su when LDAP is down or an emergency
  user is local.

* Thu Oct 27 2011 Maintenance
2.0.0-4
- Added the new 'auth' portions of pam.d and removed everything except for
  'other' from the rsync segment of pam.d.

* Mon Oct 10 2011 Maintenance
2.0.0-3
- Updated to put quotes around everything that need it in a comparison
  statement so that puppet > 2.5 doesn't explode with an undef error.
- Updated to work around the issue where SSSD can't update shadow fields in
  LDAP.

* Tue Jun 07 2011 Maintenance - 2.0.0-2
- Rearranged items in system-auth so that fewer erroneous errors would be
  thrown on login. You'll still get them if logging in as a local user. Red Hat
  is aware of the issue.
- Fixed this module for the case where $use_sssd does not exist.
- Default password length is now 14
- Removed nullok to prevent all blank password usage
- Added support for wheel in 'su' via pam::wheel
- Set pam_lastlog

* Tue Apr 05 2011 Maintenance - 2.0.0-1
- Added support to system-auth for SSSD.
- Updated to use rsync native type
- Updated system-auth to enforce a stronger default password set.
- This needs to be templated but not for 2.0.0-Beta.
- Updated to use concat_build and concat_fragment types

* Tue Jan 11 2011 Maintenance - 2.0.0-0
- Refactored for SIMP-2.0.0-alpha release

* Mon Jan 10 2011 Maintenance - 1.0-4
- Updated the PAM configuration to fix an issue where pam_unix.so was set to
  default=ignore. This is definitely not what you want.

* Thu Nov 04 2010 Maintenance - 1.0-3
- pam_tally2 still wasn't properly taking  effect. Should be corrected.
- This update adds the ability to modify the delay after a failed login via
  PAM.  FAIL_DELAY by itself doesn't do anything without the addition of
  pam_faildelay.so this item was added to the default PAM config.

* Tue Oct 26 2010 Maintenance - 1.0-2
- Converting all spec files to check for directories prior to copy.

* Tue Aug 10 2010 Maintenance
1.0-1
- Rearranged the pam_tally2 items in system-auth.erb to ensure that account
  lockouts are taking effect properly.

* Fri Jun 04 2010 Maintenance
1.0-0
- Modified the system-auth.erb file to:
  - Get rid of session messages in /var/log/secure when cron runs.
  - Ensure that cron can run without having a user in the groupaccess.conf file.
  - Skip pam_ldap if pam_unix succeeds.
- Code refactor and update
- Added 'Tidy' statements to match the rest of the multi-build patterns.
- Fixed a problem with pam_succeed_if.so uid=0 causing auid to be set to -1. Changed to user = root.
- Changed the pam_mkhomedir call to be 'optional' instead of 'required'. This
  allows users to login even if their home directory can't be created.

* Fri Feb 05 2010 Maintenance
0.1-10
- Fixed some incorrect settings with pam_cracklib.so and added in some new
  checking functionality for repeated characters and username matching.
- Removed the necessity of the rootaccess file. This does mean that root can su
  to any user but completely prevents root lockouts.
