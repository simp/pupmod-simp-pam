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
        # Using puppet_apply as a helper
        it 'should work with no errors' do
           apply_manifest_on(host, manifest, :catch_failures => true)
        end

        it 'should be idempotent' do
          apply_manifest_on(host, manifest, {:catch_changes => true})
        end
      end
    end
  end
end
