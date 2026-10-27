require 'spec_helper_acceptance'

test_name 'pam class'

describe 'pam class' do
  let(:manifest) do
    <<~EOS
      include 'pam'
    EOS
  end

  hosts.each do |host|
    # Exercise noop from a clean (uninstalled) state: on a fresh node the Sicura
    # console previews the module with `puppet apply --noop`, which must not error
    # even though nothing pam manages exists yet. Real idempotence is covered
    # by the applies below. A post-convergence noop check is deliberately omitted:
    # `puppet apply --noop --detailed-exitcodes` always exits 0, so it could never
    # fail and would test nothing.
    context 'in noop mode from a clean state' do
      # Setup, not an assertion: as before(:context) a failure errors this context
      # rather than aborting the whole suite under .rspec's --fail-fast. `puppet
      # resource` exits 0 whether it removes the package or finds it already absent
      # (no --detailed-exitcodes), so no acceptable_exit_codes override is needed.
      before(:context) do
        on(host, 'puppet resource package pam ensure=absent')
      end

      it 'applies without errors in noop mode' do
        apply_manifest_on(host, manifest, catch_failures: true, noop: true)
      end
    end

    context "on #{host}" do
      context 'default parameters' do
        def os_major(host)
          on(host, 'facter -p os.release.major').stdout.strip.to_i
        end

        it 'works with no errors' do
          apply_manifest_on(host, manifest, catch_failures: true)
        end

        it 'is idempotent' do
          apply_manifest_on(host, manifest, { catch_changes: true })
        end

        it 'does not replace authconfig and authselect should do nothing if not forced' do
          skip('authselect works differently on el10+ and does not require --force') unless os_major(host) < 10
          # Images installed with an authselect profile selected (e.g. Oracle
          # Linux) keep authselect in charge, so there is nothing for it to
          # refuse; see 'with an authselect profile already selected'.
          if on(host, 'test -L /etc/pam.d/system-auth', accept_all_exit_codes: true).exit_code.zero?
            skip('authselect manages the auth files on this host, so the module leaves them alone')
          end
          # Install the authconfig package if it doesn't exist
          on(host, 'dnf install -y authconfig')

          # OEL symlinks this internally
          result = on(host, 'ls -l /usr/sbin/authconfig', accept_all_exit_codes: true)
          expect(result.stdout).not_to include('simp_auth')

          result = on(host, '/usr/bin/authselect select sssd', accept_all_exit_codes: true)
          expect(result.stderr).to include('Refusing to activate profile')
          apply_manifest_on(host, manifest, { catch_changes: true })
        end
      end
      context 'with use_authselect set to true' do
        let(:manifest) do
          <<~EOS
            class { 'pam':
              use_authselect => true,
            }
          EOS
        end

        it 'applies the manifest without error' do
          apply_manifest_on(host, manifest, catch_failures: true)
        end

        it 'is idempotent' do
          apply_manifest_on(host, manifest, { catch_changes: true })
        end

        it 'activates the simp authselect profile' do
          result = on(host, '/usr/bin/authselect current')
          expect(result.stdout).to match(%r{Profile ID:\s+simp})
        end

        it 'matches content of /etc/authselect/password-auth to /usr/share/authselect/vendor/simp/password-auth' do
          on(host, 'dnf install -y diffutils') unless host.check_for_command('diff')
          # Compare the two files ignoring comments and newlines, authselect adds some comments and blank lines when selecting a profile
          result = on(host, 'diff <(grep -v "^\s*#" /etc/authselect/password-auth | tr -d "\n") <(grep -v "^\s*#" /usr/share/authselect/vendor/simp/password-auth | tr -d "\n")',
accept_all_exit_codes: true)
          expect(result.exit_code).to eq(0)
        end
      end

      # Hosts installed with an authselect profile already selected (e.g. the
      # Oracle Linux 8/9 images) must keep a valid authselect configuration.
      context 'with an authselect profile already selected' do
        before(:context) do
          # 'minimal' was renamed 'local' in authselect 1.5 (EL10)
          profile = on(host, 'test -d /usr/share/authselect/default/local', accept_all_exit_codes: true).exit_code.zero? ? 'local' : 'minimal'
          on(host, "authselect select #{profile} with-faillock --force")
        end

        # Later spec files expect the module's stacks, so hand the files back.
        after(:context) do
          on(host, 'rm -f /etc/pam.d/{fingerprint,password,smartcard,system}-auth')
          apply_manifest_on(host, "include 'pam'", catch_failures: true)
        end

        it 'applies without errors' do
          apply_manifest_on(host, manifest, catch_failures: true)
        end

        it 'is idempotent' do
          apply_manifest_on(host, manifest, catch_changes: true)
        end

        it 'leaves the authselect symlinks in place' do
          ['fingerprint', 'password', 'smartcard', 'system'].each do |f|
            on(host, "test -L /etc/pam.d/#{f}-auth")
          end
        end

        it 'leaves a valid authselect configuration' do
          on(host, 'authselect check')
        end
      end
    end
  end
end
