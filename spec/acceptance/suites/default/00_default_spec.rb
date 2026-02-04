require 'spec_helper_acceptance'

test_name 'pam class'

describe 'pam class' do
  let(:manifest) do
    <<~EOS
      include 'pam'
    EOS
  end

  hosts.each do |host|
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

        os_major = fact_on(host, 'os.release.major')

        # Total hack to support Amazon without a bunch of logic
        if ['2'].include?(os_major)
          it 'replaces authconfig and authconfi-tui links' do
            result = on(host, 'ls -l /usr/sbin/authconfig')
            expect(result.stdout).to match(%r{authconfig -> /usr/local/sbin/simp_authconfig.sh})

            result = on(host, 'ls -l /usr/sbin/authconfig-tui')
            expect(result.stdout).to match(%r{authconfig-tui -> /usr/local/sbin/simp_authconfig.sh})
          end

          it 'authconfig and authconfig-tui should have no affect on PAM configuration' do
            on(host, '/usr/sbin/authconfig --update')
            # verify Puppet detects no changes to PAM configuration after authconfig is run
            apply_manifest_on(host, manifest, { catch_changes: true })

            # verify Puppet detects no changes to PAM configuration after authconfig-tui is run
            on(host, '/usr/sbin/authconfig-tui --update')
            apply_manifest_on(host, manifest, { catch_changes: true })
          end
        else
          it 'does not replace authconfig and authselect should do nothing if not forced' do
            skip('authselect works differently on el10+ and does not require --force') unless os_major(host) < 10
            # Install the authconfig package if it doesn't exist
            on(host, 'dnf install -y authconfig')

            # OEL symlinks this internally
            result = on(host, 'ls -l /usr/sbin/authconfig', accept_all_exit_codes: true)
            expect(result.stdout).not_to match(%r{simp_auth})

            result = on(host, '/usr/bin/authselect select sssd', accept_all_exit_codes: true)
            expect(result.stderr).to match(%r{Refusing to activate profile})
            apply_manifest_on(host, manifest, { catch_changes: true })
          end
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
    end
  end
end
