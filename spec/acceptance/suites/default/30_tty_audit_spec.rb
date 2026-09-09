require 'spec_helper_acceptance'

test_name 'pam_tty_audit'

# Regression coverage for the pam_tty_audit rendering, which nothing else in
# this suite asserts on. This module owns the templates that emit the line
# (templates/etc/pam.d/sudo.epp and templates/etc/pam.d/auth.epp), so a change
# in how it is rendered has to fail here rather than in a downstream suite.
#
# The control flag is gated on the live `simplib__auditd` fact, which reports
# `enforcing` only when the kernel audit subsystem is enabled *and* the auditd
# daemon is running. That makes the rendered content a function of node state
# rather than of the catalog, so both branches are driven here explicitly.
describe 'pam_tty_audit' do
  # The files pam renders a pam_tty_audit line into: sudo/sudo-i come from
  # sudo.epp, and auth.epp emits the line only for the system, password, and
  # fingerprint sections -- not smartcard.
  tty_audit_files = [
    '/etc/pam.d/sudo',
    '/etc/pam.d/sudo-i',
    '/etc/pam.d/system-auth',
    '/etc/pam.d/password-auth',
    '/etc/pam.d/fingerprint-auth',
  ]

  let(:manifest) do
    <<~EOS
      include 'pam'
    EOS
  end

  hosts.each do |host|
    context "on #{host}" do
      before(:context) do
        install_package(host, 'audit-rules') unless host.check_for_command('auditctl')
      end

      # `auditctl -e` is the only lever available: auditd.service sets
      # RefuseManualStop, so the daemon cannot be stopped to clear the fact.
      #
      # Leave kernel auditing on rather than off, so a failure part way through
      # does not hand a node with auditing disabled to anything that reuses it
      # (BEAKER_destroy=no). EL8/EL9 boot this way; EL10 boots with `enabled 0`,
      # so this is the safe direction rather than a strict restore.
      after(:context) do
        on(host, 'auditctl -e 1')
      end

      context 'with auditd not enforcing' do
        before(:context) do
          on(host, 'auditctl -e 0')
        end

        # Precondition rather than an assertion about pam: if the fact does not
        # report the state we just set, the rest of this context is vacuous.
        it 'reports simplib__auditd.enforcing as false' do
          expect(pfact_on(host, 'simplib__auditd.enforcing')).to be false
        end

        it 'works with no errors' do
          apply_manifest_on(host, manifest, catch_failures: true)
        end

        it 'is idempotent' do
          apply_manifest_on(host, manifest, { catch_changes: true })
        end

        tty_audit_files.each do |tty_audit_file|
          it "sets pam_tty_audit to optional in #{tty_audit_file}" do
            expect(file_contents_on(host, tty_audit_file)).to match(%r{^session\s+optional\s+pam_tty_audit\.so})
          end
        end
      end

      context 'when auditd starts enforcing' do
        before(:context) do
          on(host, 'auditctl -e 1')
        end

        it 'reports simplib__auditd.enforcing as true' do
          expect(pfact_on(host, 'simplib__auditd.enforcing')).to be true
        end

        # The fact is read at catalog compile time, so this apply is where the
        # files flip from optional to required. That one rewrite is the
        # module's current, intended behaviour; what must not happen is the
        # rewrite repeating on every run afterwards.
        it 'works with no errors' do
          apply_manifest_on(host, manifest, catch_failures: true)
        end

        it 'is idempotent' do
          apply_manifest_on(host, manifest, { catch_changes: true })
        end

        tty_audit_files.each do |tty_audit_file|
          it "sets pam_tty_audit to required in #{tty_audit_file}" do
            expect(file_contents_on(host, tty_audit_file)).to match(%r{^session\s+required\s+pam_tty_audit\.so})
          end
        end
      end
    end
  end
end
