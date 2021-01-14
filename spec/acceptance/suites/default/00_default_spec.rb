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

        it 'should not replace authconfig and authselect should do nothing if not forced' do
          # OEL symlinks this internally
          result = on(host, 'ls -l /usr/sbin/authconfig', :accept_all_exit_codes => true)
          expect(result.stdout).not_to match(/simp_auth/)

          result = on(host,'/usr/bin/authselect select sssd', :accept_all_exit_codes => true)
          expect(result.stderr).to match(/Refusing to activate profile/)
          apply_manifest_on(host, manifest, {:catch_changes => true})
        end
      end
    end
  end
end
