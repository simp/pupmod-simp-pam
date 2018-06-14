require 'spec_helper_acceptance'

test_name 'pam STIG enforcement'

describe 'pam STIG enforcement' do

  let(:manifest) {
    <<-EOS
      include 'pam'
    EOS
  }

  let(:hieradata) { <<-EOF
---
compliance_markup::enforcement:
  - disa_stig
  EOF
  }

  hosts.each do |host|
    context 'when enforcing the STIG' do
      let(:hiera_yaml) { <<-EOM
---
version: 5
hierarchy:
  - name: Common
    path: default.yaml
  - name: Compliance
    lookup_key: compliance_markup::enforcement
defaults:
  data_hash: yaml_data
  datadir: "#{hiera_datadir(host)}"
  EOM
      }

      # Using puppet_apply as a helper
      it 'should work with no errors' do
        create_remote_file(host, host.puppet['hiera_config'], hiera_yaml)
        write_hieradata_to(host, hieradata)

        apply_manifest_on(host, manifest, :catch_failures => true)
      end

      it 'should be idempotent' do
        apply_manifest_on(host, manifest, :catch_changes => true)
      end
    end
  end
end
