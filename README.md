[![License](https://img.shields.io/:license-apache-blue.svg)](http://www.apache.org/licenses/LICENSE-2.0.html)
[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/73/badge)](https://bestpractices.coreinfrastructure.org/projects/73)
[![Puppet Forge](https://img.shields.io/puppetforge/v/simp/pam.svg)](https://forge.puppetlabs.com/simp/pam)
[![Puppet Forge Downloads](https://img.shields.io/puppetforge/dt/simp/pam.svg)](https://forge.puppetlabs.com/simp/pam)
[![Build Status](https://travis-ci.org/simp/pupmod-simp-pam.svg)](https://travis-ci.org/simp/pupmod-simp-pam)

#### Table of Contents

<!-- vim-markdown-toc GFM -->

* [Overview](#overview)
* [This is a SIMP module](#this-is-a-simp-module)
* [Module Description](#module-description)
* [Setup](#setup)
  * [Setup Requirements](#setup-requirements)
  * [What ``pam`` Affects](#what-pam-affects)
* [Usage](#usage)
  * [Basic Usage](#basic-usage)
  * [Restricting System Logins (pam_access)](#restricting-system-logins-pam_access)
    * [Managing System Access](#managing-system-access)
  * [Restricting Resource Usage (pam_limits)](#restricting-resource-usage-pam_limits)
  * [Restricting ``su`` to the ``wheel`` Group](#restricting-su-to-the-wheel-group)
  * [Managing /etc/security/faillock.conf](#managing-etcsecurityfaillockconf)
    * [/etc/security_faillock.conf Example With All Parameters](#etcsecurityfaillockconf-hieradata-example-with-all-parameters)
* [Development](#development)
  * [Acceptance tests](#acceptance-tests)

<!-- vim-markdown-toc -->

## Overview

This module configures PAM in an authoritative, but flexible, manner.

See [REFERENCE.md](./REFERENCE.md) for API details.

## This is a SIMP module

This module is a component of the [System Integrity Management Platform](https://simp-project.com),
a compliance-management framework built on Puppet.

If you find any issues, they can be submitted to our [JIRA](https://simp-project.atlassian.net/).

This module is optimally designed for use within a larger SIMP ecosystem, but it can be used independently:
* When included within the SIMP ecosystem, security compliance settings will be
  managed from the Puppet server.
* If used independently, all SIMP-managed security subsystems will be disabled by
  default and must be explicitly opted into by administrators.  Please review
  [simp_options](https://github.com/simp/pupmod-simp-simp_options) for details.

## Module Description

This module provides a reasonably safe configuration of the main PAM stack
focused on common security and compliance settings. Care has been taken to
provide a significant set of switches and override mechanisms in order to
provide for user flexibility.

## Setup

### Setup Requirements

No special dependencies are required for core functionality of this module.

You will need to download the
[simp/oath](https://github.com/simp/pupmod-simp-simp_oath) if you want to use
the **EXPERIMENTAL** OATH (TOTP/HOTP) support.

### What ``pam`` Affects

The ``pam`` module modifies various settings in the ``/etc/pam.d/`` and
``/etc/security`` directories related to user logins via various authentication
methods.

## Usage

### Basic Usage

To set up PAM using a sane set of defaults, you can simply ``include`` the
class as follows:

```puppet
include 'pam'
```

This will set up PAM with the following capabilities:

* ``pwquality`` settings
* ``faillock`` support with auto-unlocking
* Password hash algorithm strengthening
* Password history management
* Automatic home directory creation
* User TTY auditing (only ``root`` by default)
* Overall default deny

### Restricting System Logins (pam_access)

To set up a 'default deny' policy for your system (local ``root`` logins are
always allowed):

```puppet
include 'pam::access'
```

#### Managing System Access

There are two methods for allowing users/groups into the system. The first is
to use the ``pam::access::rule`` defined type.

The parameters are named after their counterparts as defined in
``access.conf(5)``.

```puppet
pam::access::rule { 'Allow Security Group from Anywhere':
  users   => ['(security)'],
  origins => ['ALL']
}

pam::access::rule { 'Allow Alice from Home':
  users   => ['alice'],
  origins => ['alice.home.net']
}

pam::access::rule { 'Allow Bob from Local':
  users   => ['bob'],
  origins => ['LOCAL'],
  order   => 2000
}

pam::access::rule { 'Deny Bob from Remote':
  users      => ['bob'],
  origins    => ['ALL'],
  permission => '-',
  order      => 2001
}
```

The second method is to define the access list as a ``Hash`` directly in Hiera:

```yaml
---
pam::access::users:
  defaults:
    origins:
      - ALL
    permission: "+"
    "(security)":
    alice:
      origins:
        - 'alice.home.net'
    # Note, the hiera method is not as flexible so we needed to use the 'bob'
    # group so that we could properly restrict the 'bob' user.
    "(bob)":
      origins:
        - 'LOCAL'
      order: 2000
    'bob':
      permission: "-"
      order: 2001
```

### Restricting Resource Usage (pam_limits)

To activate management of various PAM resource limits via
``/etc/security/limits.conf``:

```puppet
include 'pam::limits'
```

You can then use the module to restrict resource limits for logged in
accordance with the ``pam_limits(8)`` documentation.

```puppet
pam::limits::rule { 'Limit Number of Processes for all Users':
  domains => ['*'],
  type    => 'soft',
  item    => 'nproc',
  value   => 50
}
```

The second method is to define the rule list as a ``Hash`` directly in Hiera:

```yaml
---
pam::limits::rules:
  disable_core_for_all:
    domains:
      - '*'
    type: 'hard'
    item: 'core'
    value: 0
    order: 100
```

### Restricting ``su`` to the ``wheel`` Group

To restrict the use of ``su`` to the ``wheel`` group:

```puppet
include 'pam::wheel'
```

You can change the target group by updating the value of
``pam::wheel::wheel_group`` via Hiera.

### Managing /etc/security/faillock.conf

To manage faillock with ``/etc/security/faillock.conf`` instead of inline parameters in the auth files set the following in hieradata:

```yaml
pam::manage_faillock_conf: true
```

A couple of things to note here are:

- ``pam::faillock`` must still be true for faillock to work appropriately
- By default, /etc/security/faillock.conf will be empty except for a comment saying the file is managed by puppet. To set content in the file, the following parameters are available:

  - ``pam::faillock_dir``
  - ``pam::faillock_audit``
  - ``pam::faillock_silent``
  - ``pam::faillock_no_log_info``
  - ``pam::faillock_local_users_only``
  - ``pam::faillock_nodelay``
  - ``pam::faillock_deny``
  - ``pam::faillock_fail_interval``
  - ``pam::faillock_unlock_time``
  - ``pam::faillock_even_deny_root``
  - ``pam::faillock_root_unlock_time``
  - ``pam::faillock_admin_group``

#### /etc/security/faillock.conf Hieradata Example With All Parameters

```yaml
pam::faillock: true
pam::manage_faillock_conf: true
pam::faillock_dir: '/var/log/faillock'
pam::faillock_audit: true
pam::faillock_silent: true
pam::faillock_no_log_info: false
pam::faillock_local_users_only: false
pam::faillock_nodelay: false
pam::faillock_deny: 5
pam::faillock_fail_interval: 900
pam::faillock_unlock_time: 900
pam::faillock_even_deny_root: true
pam::faillock_root_unlock_time: 60
pam::faillock_admin_group: 'wheel'
```

## Development

Please read our [Contribution Guide](https://simp.readthedocs.io/en/stable/contributors_guide/Contribution_Procedure.html)

### Acceptance tests

This module includes [Beaker](https://github.com/puppetlabs/beaker) acceptance
tests using the SIMP [Beaker Helpers](https://github.com/simp/rubygem-simp-beaker-helpers).
By default the tests use [Vagrant](https://www.vagrantup.com/) with
[VirtualBox](https://www.virtualbox.org) as a back-end; Vagrant and VirtualBox
must both be installed to run these tests without modification. To execute the
tests run the following:

```shell
bundle exec rake beaker:suites
```

Some environment variables may be useful:

```shell
BEAKER_debug=true
BEAKER_provision=no
BEAKER_destroy=no
BEAKER_use_fixtures_dir_for_modules=yes
BEAKER_fips=yes
```

* `BEAKER_debug`: show the commands being run on the STU and their output.
* `BEAKER_destroy=no`: prevent the machine destruction after the tests finish so you can inspect the state.
* `BEAKER_provision=no`: prevent the machine from being recreated. This can save a lot of time while you're writing the tests.
* `BEAKER_use_fixtures_dir_for_modules=yes`: cause all module dependencies to be loaded from the `spec/fixtures/modules` directory, based on the contents of `.fixtures.yml`.  The contents of this directory are usually populated by `bundle exec rake spec_prep`.  This can be used to run acceptance tests to run on isolated networks.
* `BEAKER_fips=yes`: enable FIPS-mode on the virtual instances. This can
  take a very long time, because it must enable FIPS in the kernel
  command-line, rebuild the initramfs, then reboot.

Please refer to the [SIMP Beaker Helpers documentation](https://github.com/simp/rubygem-simp-beaker-helpers/blob/master/README.md)
for more information.
