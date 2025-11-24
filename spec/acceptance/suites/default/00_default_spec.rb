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
        it 'works with no errors' do
          apply_manifest_on(host, manifest, catch_failures: true)
        end

        it 'is idempotent' do
          apply_manifest_on(host, manifest, { catch_changes: true })
        end

        os_major = fact_on(host, 'os.release.major')

        # Total hack to support Amazon without a bunch of logic
        if ['7', '2'].include?(os_major)
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
            # OEL symlinks this internally
            result = on(host, 'ls -l /usr/sbin/authconfig', accept_all_exit_codes: true)
            expect(result.stdout).not_to match(%r{simp_auth})

            result = on(host, '/usr/bin/authselect select sssd', accept_all_exit_codes: true)
            expect(result.stderr).to match(%r{Refusing to activate profile})
            apply_manifest_on(host, manifest, { catch_changes: true })
          end
        end
      end
    end
  end
end
