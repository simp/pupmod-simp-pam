# AGENTS.md

This file provides guidance to AI agents when working with code in this repository.

## What this module does

`simp-pam` is a SIMP Puppet module that manages **PAM (Pluggable Authentication
Modules)** configuration on Enterprise Linux systems. It manages the `/etc/pam.d`
`*-auth` stacks, password-quality policy (`pwquality`/`cracklib`), account
lockout (`faillock`), password history (`pwhistory`), `/etc/security/access.conf`
(`pam_access`), `/etc/security/limits.conf` (`pam_limits`), `su`/`wheel`
restrictions, and optional integrations with `authselect`, `oath` (TOTP), and
SSH-agent authentication for `sudo`.

The module is gated on the global `simp_options::pam` catalyst and its own
`$enable` flag: it only manages anything when **both** are true
(`manifests/init.pp`). If the module is included while
`simp_options::pam` is `false`, it emits a warning instead of managing state
(`init.pp`).

Much of the module's real complexity is **OS-version-conditional**: newer
`pwquality.conf` options, `faillock.conf`, and `pwhistory.conf` only exist on
EL8+ / Amazon 2022+, so capability flags in Hiera (`data/os/*.yaml`) drive
whether those settings are written to config files or inlined into the auth
stacks.

### Business logic

Public API (consumers `include`/declare these; none call `assert_private()`):

- **`pam` (`manifests/init.pp`)** — main entry class. Huge parameter
  list (`init.pp`); the only parameter with **no default** is
  `$password_check_backend` (`Pam::PasswordBackends`, from module data —
  `cracklib` in `data/common.yaml`, `pwquality` on RedHat via
  `data/os/RedHat.yaml`). It is a pure orchestrator: under the
  `simp_options::pam` + `$enable` gate it calls
  `simplib::assert_metadata($module_name)` (`init.pp`), then
  `include 'pam::install'` and `include 'pam::config'` ordered
  `Class['pam::install'] -> Class['pam::config']` (`init.pp`). All
  resources live in the private classes / the `pam::auth` define.
- **`pam::auth` (`manifests/auth.pp`)** — define that renders each
  `*-auth` file. **Not `assert_private()`'d**, but its docstring says it is
  "only meant to be called via the main pam class" (`auth.pp`). Titles must be
  one of `smartcard`/`fingerprint`/`password`/`system` or it `fail()`s
  (`auth.pp`). Most parameters default by reading `$pam::*`
  (`auth.pp`). Key logic:
  - If `$oath` is true, asserts the optional `simp/oath` dependency
    (`auth.pp`).
  - **FIPS guard**: when the `fips_enabled` fact is set, only `sha256`/`sha512`
    are allowed for `$hash_algorithm`, else `fail()` (`auth.pp`).
  - `smartcard` defaults `$cert_auth` to `'require'` (preserving the old
    `pam_pkcs11.so card_only` behavior now that the stack uses `pam_sss.so`)
    (`auth.pp`).
  - OS capability flags (`$faillock_conf_supported`, `$pwhistory_conf_supported`)
    decide whether `faillock`/`pwhistory`/`retry`/`enforce_for_root`/
    `reject_username` are written into `faillock.conf`/`pwhistory.conf` vs.
    inlined into the auth EPP (`auth.pp`).
  - Writes `${basedir}/${name}-auth` where `$basedir` is the authselect vendor
    dir when `$pam::use_authselect`, else `/etc/pam.d` (`auth.pp`,
    `269-275`); removes the `-ac` companion file unless `$preserve_ac`
    (`auth.pp`).
- **`pam::wheel` (`manifests/wheel.pp`)** — `inherits pam`; manages
  `/etc/pam.d/su` from the `su.epp` template (or custom `$content`).
- **`pam::access` (`manifests/access.pp`)** — manages
  `/etc/security/access.conf` as a `concat`. Always adds an
  `allow_local_root` rule at order 1 (`access.pp`); optionally includes
  `pam::access::default_deny`; can build rules from a `$users` hash (with an
  optional `defaults` sub-hash) (`access.pp`).
- **`pam::access::rule` (`manifests/access/rule.pp`)** — a
  `concat::fragment` for one `permission:users:origins` line. Reads
  `pam::enable_separator` / `pam::separator` via `simplib::lookup` to pick the
  list separator (`rule.pp`).
- **`pam::access::default_deny` (`manifests/access/default_deny.pp`)** —
  a single `-:ALL:ALL` rule at the max order (`9999999999`).
- **`pam::limits` (`manifests/limits.pp`)** — manages
  `/etc/security/limits.conf` as a `concat`; can build rules from a `$rules`
  hash via `create_resources` (`limits.pp`).
- **`pam::limits::rule` (`manifests/limits/rule.pp`)** — a
  `concat::fragment` per limits entry; `fail()`s if `priority`/`nice` is given a
  non-integer `unlimited`/`infinity` value (`limits/rule.pp`).

Private classes (call `assert_private()`):

- **`pam::install` (`manifests/install.pp`)** — installs `pam`,
  conditionally `libpwquality` (when backend is `pwquality`) and
  `pam_ssh_agent_auth` (when `$enable_ssh_agent_auth`).
- **`pam::config` (`manifests/config.pp`)** — the bulk of file
  management: `pwquality.conf` (gated on OS capability flags,
  `config.pp`), `/etc/pam.d/{sudo,sudo-i,other,atd,crond}`, the
  `simp_authconfig.sh` no-op shim replacing `authconfig`/`authconfig-tui` on
  systems where `$authconfig_present` (`config.pp`), `faillock.conf` /
  `pwhistory.conf` (gated, `config.pp`), declares
  `::pam::auth { $pam::auth_sections }` (`config.pp`), and drives
  `authselect::custom_profile` + `class { 'authselect' }` when
  `$pam::use_authselect` (`config.pp`).

### Gotchas / non-obvious details

- **Two gates, both must be true.** Nothing is managed unless
  `simp_options::pam` (default `true`) **and** `$enable` (default `true`) are
  both true (`init.pp`). Included with the catalyst off, the module only
  warns (`init.pp`).
- **OS capability flags are the real control plane.** `data/os/RedHat-8.yaml`,
  `RedHat-9.yaml`, `RedHat-10.yaml`, `Amazon-2.yaml` set
  `pam::*_supported` / `pam::authconfig_present`. EL8+ turns on
  `faillock_conf_supported`, `pwhistory_conf_supported`, and the newer
  `pwquality` options; Amazon 2 turns them **off** and sets
  `authconfig_present: true`. These flags decide whether settings go into
  dedicated `.conf` files or inline into the auth stacks (`config.pp`,
  `171-210`; `auth.pp`). The docstrings note EL7/Amazon-2 fall back to
  inline management.
- **`retry` needs RHEL 8.4+.** `data/os/RedHat-8.yaml` warns that
  `cracklib_retry_supported` should be overridden to `false` on RHEL 8.0-8.3.
- **FIPS restricts the hash algorithm.** With `fips_enabled` set, only
  `sha256`/`sha512` pass; anything else `fail()`s in `pam::auth`
  (`auth.pp`).
- **`simp/oath` and `puppet-authselect` are OPTIONAL dependencies**
  (`metadata.json` `simp.optional_dependencies`), not hard deps. `oath` is
  guarded at runtime with `simplib::assert_optional_dependency` only when
  `$oath` is true (`auth.pp`). `authselect` is declared directly in
  `pam::config` when `$use_authselect` is true (`config.pp`) — there is
  **no** `assert_optional_dependency` guarding the authselect path, so enabling
  `use_authselect` without the module present will fail to compile.
- **`simp/simp_options` is NOT a declared dependency** in `metadata.json`, yet
  the manifests consume the `simp_options::*` seam via `simplib::lookup`
  (provided by `simp/simplib`). `simp_options` appears only as a fixture
  (`.fixtures.yml`).
- **Access rules: order matters, first match wins.** `pam::access` hard-codes
  `allow_local_root` at order 1 (`access.pp`) and `default_deny` at order
  `9999999999` (`default_deny.pp`). Limits rules are the opposite — **last**
  match wins (`limits/rule.pp`).
- **`pam::access::rule` and `pam::limits::rule` each `include` their parent
  class** (`access/rule.pp`, `limits/rule.pp`), so declaring a rule pulls
  in the `concat` target automatically.
- **`pam::wheel` is not wired into `pam::config`** — it is a standalone class
  (`inherits pam`) that a consumer must `include` explicitly; the default
  `/etc/pam.d/su` templating for wheel is not applied just by including `pam`.

## The `simp_options` / `simplib::lookup` seam

The module's SIMP-catalyst seam. Calls (with `file:line`):

| File | Key | `default_value` |
|------|-----|-----------------|
| `init.pp` | `simp_options::oath` | `false` |
| `init.pp` | `simp_options::uid::min` | `pick(fact('login_defs.uid_min'), 1000)` |
| `init.pp` | `simp_options::sssd` | `false` |
| `init.pp` | `simp_options::authselect` | `false` |
| `init.pp` | `simp_options::package_ensure` | `'present'` |
| `init.pp` | `simp_options::pam` | `true` |
| `init.pp` | `simp_options::pam` | `true` |
| `access/rule.pp` | `pam::enable_separator` (module-local) | `true` |
| `access/rule.pp` | `pam::separator` (module-local) | `','` |

Keep routing SIMP feature toggles through `simplib::lookup('simp_options::*', {
'default_value' => ... })` with an explicit default rather than assuming
`simp_options` is included.

## Dependencies

Module dependencies (from `metadata.json`):

- `puppetlabs/concat` `>= 6.4.0 < 10.0.0` (provides `concat` / `concat::fragment`
  for `access.conf` and `limits.conf`)
- `puppetlabs/stdlib` `>= 8.0.0 < 10.0.0`
- `simp/oddjob` `>= 2.0.0 < 4.0.0` (`pam::auth` includes `oddjob::mkhomedir`,
  `auth.pp`)
- `simp/simplib` `>= 4.9.0 < 6.0.0` (provides `simplib::lookup`,
  `simplib::assert_metadata`, `simplib::assert_optional_dependency`, the
  `Simplib::*` types, and the `login_defs` / `fips_enabled` facts)
- `simp/useradd` `>= 0.2.2 < 3.0.0`

Optional dependencies (from `metadata.json` `simp.optional_dependencies`):

- `simp/oath` `>= 0.1.0 < 2.0.0` — TOTP; asserted at runtime only when `$oath`.
- `puppet-authselect` `>= 1.1.2 < 2.0.0` — used when `$use_authselect`
  (declared directly, not `assert_optional_dependency`-guarded).

Fixture-only repositories (from `.fixtures.yml`, for test compilation, not
runtime deps): `auditd`, `augeasproviders_core`, `augeasproviders_ssh`,
`haveged`, `iptables`, `logrotate`, `pki`, `rsyslog`, `ssh`, `sssd`, `systemd`,
`simp_options` (plus the runtime and optional deps above).

Runtime requirement (from `metadata.json` `requirements`): `openvox
>= 8.0.0 < 9.0.0`.

Supported OS matrix (from `metadata.json`): CentOS 9/10; RedHat 8/9/10;
OracleLinux 8/9/10; Rocky 8/9/10; AlmaLinux 8/9/10.

## Repository layout

- `manifests/init.pp` — the `pam` orchestrator class (gate + include of the
  private classes).
- `manifests/install.pp`, `manifests/config.pp` — private (`assert_private()`)
  install/config classes.
- `manifests/auth.pp` — `pam::auth` define (renders the `*-auth` files).
- `manifests/wheel.pp` — `pam::wheel` (`su`/wheel restrictions).
- `manifests/access.pp`, `manifests/access/rule.pp`,
  `manifests/access/default_deny.pp` — `pam_access` (`access.conf`) management.
- `manifests/limits.pp`, `manifests/limits/rule.pp` — `pam_limits`
  (`limits.conf`) management.
- `types/` — `Pam::PasswordBackends`, `Pam::HashAlgorithm`,
  `Pam::AccountUnlockTime`, `Pam::AuthSections`, `Pam::Limits::Item`,
  `Pam::Limits::Value`.
- `templates/etc/pam.d/{auth,other,sudo,su}.epp` and
  `templates/etc/security/{faillock,pwhistory,pwquality}.conf.epp` — the EPP
  templates.
- `files/simp_authconfig.sh` — the no-op shim that replaces
  `authconfig`/`authconfig-tui` on Amazon-2 (`config.pp`).
- `data/common.yaml` — defaults (`password_check_backend: cracklib`, plus
  `lookup_options` deep-merge for `pam::access::users` / `pam::limits::rules`).
  `data/os/*.yaml` — OS capability flags and per-OS backend/locale overrides.
- `hiera.yaml` — module data hierarchy (v5): OS family+major → OS name+major →
  OS family → kernel → common.
- `metadata.json` — deps, optional deps, OS matrix, openvox requirement.
- `spec/classes/`, `spec/defines/` — rspec-puppet unit tests;
  `spec/acceptance/suites/{default,security_modules}/` — beaker suites with
  docker/vagrant nodesets under `spec/acceptance/nodesets/`.
- No `lib/` — this module ships no custom Ruby types/providers/functions/facts;
  every custom type, fact, and function it uses comes from the dependencies
  above.
- **Acceptance runs in CI:** `.github/workflows/pr_tests.yml` has an
  `acceptance` job (`pr_tests.yml`) whose matrix nodes are
  `almalinux8`, `almalinux9`, and `almalinux10`. Its final step runs
  `bundle exec rake beaker:suites[default,<node>]` under
  `BEAKER_HYPERVISOR=vagrant_libvirt` (`pr_tests.yml`). Both `docker_*` and
  vagrant nodesets ship under `spec/acceptance/nodesets/`, but CI drives only
  the AlmaLinux vagrant nodes.

## Common commands

```sh
# Install dependencies
bundle install

# Run all unit tests
bundle exec rake spec

# Run unit tests in parallel (as CI does)
bundle exec rake parallel_spec

# Puppet syntax + lint
bundle exec rake syntax
bundle exec rake lint
bundle exec rake metadata_lint

# Ruby lint
bundle exec rake rubocop

# Regenerate REFERENCE.md from puppet-strings docstrings
puppet strings generate --format markdown --out REFERENCE.md

# Run a beaker acceptance suite against an AlmaLinux node (as CI does)
bundle exec rake beaker:suites[default,almalinux8]
```

Relevant gem pins (from `Gemfile`): `simp-rake-helpers ~> 6.0`,
`simp-rspec-puppet-facts ~> 4.0.0`, `simp-beaker-helpers ~> 3.1`,
`rubocop ~> 1.85`. There is **no** `puppetlabs_spec_helper` pin — this module
has moved to the **voxpupuli-test** harness, so `spec/spec_helper.rb` requires
`voxpupuli/test/spec_helper` (`spec_helper.rb`). The test group installs
**both** `openvox` and `puppet` gems (`Gemfile`) with the tested version
range `>= 8 < 9`.

## Conventions

- Preserve the `@summary` / `@param` puppet-strings docstrings — they drive
  `REFERENCE.md`. Regenerate `REFERENCE.md` after changing docs or parameters.
- Keep OS-version differences in `data/os/*.yaml` capability flags, not
  hard-coded in manifests; read them as `$pam::*_supported` and branch on them
  as `config.pp` / `auth.pp` do.
- Continue routing SIMP feature toggles through
  `simplib::lookup('simp_options::*', { 'default_value' => ... })` rather than
  assuming `simp_options` is included.
- Guard optional integrations with `simplib::assert_optional_dependency` and a
  runtime check, as the `oath` path does (`auth.pp`).
- `Gemfile`, `spec/spec_helper.rb`, and `.github/workflows/pr_tests.yml` carry a
  **puppetsync** notice — they are baseline-managed and the next sync overwrites
  local edits. Push changes to those files upstream to the baseline, not here.
- Match the existing 2-space Puppet indentation and aligned-arrow parameter
  style used across `manifests/`.
