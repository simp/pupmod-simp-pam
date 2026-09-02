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
          expect(result.stdout).to match(%r{Profile ID:\s+custom/simp})
        end

        it 'matches content of /etc/authselect/password-auth to /etc/authselect/custom/simp/password-auth' do
          on(host, 'dnf install -y diffutils') unless host.check_for_command('diff')
          # Compare the two files ignoring comments and newlines, authselect adds some comments and blank lines when selecting a profile
          result = on(host, 'diff <(grep -v "^\s*#" /etc/authselect/password-auth | tr -d "\n") <(grep -v "^\s*#" /etc/authselect/custom/simp/password-auth | tr -d "\n")',
accept_all_exit_codes: true)
          expect(result.exit_code).to eq(0)
        end

        # The CIS rule "Ensure active authselect profile includes pam modules"
        # resolves the active profile's template directory to
        # /etc/authselect/<profile> for a 'custom/'-prefixed name and to
        # /usr/share/authselect/default/<profile> otherwise. A custom profile
        # is the only one of the two layouts it can reach.
        it 'puts the profile where the CIS authselect audit looks for it' do
          profile = on(host, 'head -1 /etc/authselect/authselect.conf').stdout.strip
          expect(profile).to start_with('custom/')

          on(host, "test -d /etc/authselect/#{profile}")
          on(host, "grep -P -- '\\bpam_unix\\.so\\b' /etc/authselect/#{profile}/{password,system}-auth")
        end
      end
    end
  end
end
