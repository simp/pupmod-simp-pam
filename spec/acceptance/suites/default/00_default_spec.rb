require 'spec_helper_acceptance'

test_name 'pam class'

describe 'pam class' do
  let(:manifest) {
    <<-EOS
      include '::pam'
    EOS
  }

  hosts.each do |host|
    context "on #{host}" do
      context 'default parameters' do
        it 'should work with no errors' do
           apply_manifest_on(host, manifest, :catch_failures => true)
        end

        it 'should be idempotent' do
          apply_manifest_on(host, manifest, {:catch_changes => true})
        end

        case  host[:platform]
        when /el-[67]-x86_64/
          it 'should replace authconfig and authconfi-tui links' do
            result = on(host, 'ls -l /usr/sbin/authconfig')
            expect(result.stdout).to match(/authconfig -> \/usr\/local\/sbin\/simp_authconfig.sh/)

            result = on(host, 'ls -l /usr/sbin/authconfig-tui')
            expect(result.stdout).to match(/authconfig-tui -> \/usr\/local\/sbin\/simp_authconfig.sh/)
          end

          it 'authconfig and authconfig-tui should have no affect on PAM configuration' do
            on(host, '/usr/sbin/authconfig --update')
            # verify Puppet detects no changes to PAM configuration after authconfig is run
            apply_manifest_on(host, manifest, {:catch_changes => true})

            # verify Puppet detects no changes to PAM configuration after authconfig-tui is run
            on(host, '/usr/sbin/authconfig-tui --update')
            apply_manifest_on(host, manifest, {:catch_changes => true})
          end
        else
          it 'should not replace authconfig and authselect should do nothing if not forced' do
            on(host, 'ls -l /usr/sbin/authconfig', :acceptable_exit_codes => [2] )
            result = on(host,'/usr/bin/authselect select sssd', :accept_all_exit_codes => true)
            expect(result.stderr).to match(/Refusing to activate profile/)
            apply_manifest_on(host, manifest, {:catch_changes => true})
          end
        end
      end
    end
  end
end
