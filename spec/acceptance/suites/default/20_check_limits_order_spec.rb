require 'spec_helper_acceptance'

test_name 'pam class'

describe 'pam class' do
  let(:hieradata) do
    {
      'pam::limits::rules' => {
        'disable_core_for_all' => {
          'domains' => ['*'],
          'type'    => 'hard',
          'item'    => 'core',
          'value'   => 0,
          'order'   => 100,
        },
      },
    }
  end

  let(:manifest) do
    <<~EOS
      include 'pam'
      include 'pam::limits'

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
  end

  let(:limits_content) { File.read('spec/expected/limits_acceptance/limits_conf_numeric').strip }

  context 'default parameters' do
    hosts.each do |host|
      context "on #{host}" do
        it 'works with no errors' do
          set_hieradata_on(host, hieradata)
          apply_manifest_on(host, manifest, catch_failures: true)
        end

        it 'is idempotent' do
          apply_manifest_on(host, manifest, { catch_changes: true })
        end

        it 'creates /etc/security/limits.conf with correct content' do
          expect(file_exists_on(host, '/etc/security/limits.conf')).to be true
          expect(file_contents_on(host, '/etc/security/limits.conf')).to eq(limits_content)
        end
      end
    end
  end
end
