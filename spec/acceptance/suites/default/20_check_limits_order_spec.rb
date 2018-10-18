require 'spec_helper_acceptance'

test_name 'pam class'

describe 'pam class' do
  let(:manifest) {
    <<-EOS
      include '::pam'
      include '::pam::limits'

      pam::limits::rule { 'limit_wild_nproc_soft':
        domains => ['*'],
        type    => 'soft',
        item    => 'nproc',
        value   => 50,
        order   => 1,
      }

      pam::limits::rule { 'limit_test_nproc_soft':
        domains => ['test'],
        type    => 'soft',
        item    => 'nproc',
        value   => 20,
        order   => 9,
      }

      pam::limits::rule { 'limit_test_nproc_hard':
        domains => ['test'],
        type    => 'hard',
        item    => 'nproc',
        value   => 50,
        order   => 10,
      }
    EOS
  }

  let(:limits_content) { File.read('spec/expected/limits_acceptance/limits_conf_numeric') }

  hosts.each do |host|
    context "on #{host}" do
      context 'default parameters' do
        it 'should work with no errors' do
           apply_manifest_on(host, manifest, :catch_failures => true)
        end

        it 'should be idempotent' do
          apply_manifest_on(host, manifest, {:catch_changes => true})
        end

        describe file('/etc/security/limits.conf') do
          it { should be_file }
          its(:content) { should eq(limits_content) }
        end
      end
    end
  end
end
