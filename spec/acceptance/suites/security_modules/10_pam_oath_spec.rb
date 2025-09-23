require 'spec_helper_acceptance'
require 'json'

test_name 'pam check oath'

describe 'pam check oath' do
  let(:server_hieradata) do
    {
      'simp_options::trusted_nets'                => ['ALL'],
      'ssh::server::conf::banner'                 => '/dev/null',
      'ssh::server::conf::permitrootlogin'        => true,
      'ssh::server::conf::passwordauthentication' => true,
      'ssh::server::conf::authorizedkeysfile'     => '.ssh/authorized_keys',
      'simp_options::oath'                        => true,
      'oath::oath_users'                          => JSON.parse(%({"tst0_usr": {"token_type": "HOTP/T30/6", "pin": "-", "secret_key": "000001"}})),
    }
  end

  #
  # NOTE: by default, include 'ssh' will automatically include the ssh_server
  let(:client_manifest) { "include 'ssh::client'" }

  let(:server_manifest) do
    <<~SERVER_CONFIG
      include 'ssh::server'
      include 'pam'
      include 'oath'
    SERVER_CONFIG
  end
  let(:password) { 'suP3rF00B@rB@11bx23' }

  let(:files_dir) { File.join(File.dirname(__FILE__), 'files') }

  hosts_as('server').each do |sut_server|
    os = sut_server.hostname.split('-').first
    context "on #{os}:" do
      let(:server) { sut_server }

      let(:client) do
        os = server.hostname.split('-').first
        hosts_as('client').find { |x| x.hostname =~ %r{^#{os}-.+} }
      end

      context 'with default parameters' do
        it 'configures server with no errors' do
          install_package(server, 'epel-release')
          install_package(server, 'oathtool')
          install_package(server, 'expect')
          set_hieradata_on(server, server_hieradata)
          apply_manifest_on(server, server_manifest, expect_changes: true)
        end

        it "configures #{os}-server idempotently" do
          set_hieradata_on(server, server_hieradata)
          apply_manifest_on(server, server_manifest, catch_changes: true)
        end

        it "configures #{os}-client idempotently" do
          apply_manifest_on(client, client_manifest, catch_changes: true)
        end
      end

      context 'Test /etc/pam.d/system-auth oath through su' do
        let(:test_user) { 'tst0_usr' }
        let(:vagrant_user) { 'vagrant' }
        let(:oath_key) { '000001' }

        it 'Copy test scripts to server' do
          scp_to(server, File.join(files_dir, 'expect_su_test'), '/usr/local/bin/expect_su_test')
          on(server, "chown #{vagrant_user}:#{vagrant_user} /usr/local/bin/expect_su_test")
          on(server, 'chmod u+x /usr/local/bin/expect_su_test')
        end

        it 'check that the test user can su' do
          on(server, %(runuser -l #{vagrant_user} -c "/usr/local/bin/expect_su_test #{test_user} #{oath_key} #{password}"))
        end

        it 'fail auth with bad TOTP' do
          on(server, %(runuser -l #{vagrant_user} -c "/usr/local/bin/expect_su_test #{test_user} 000000 #{password}"), acceptable_exit_codes: [1])
        end

        it 'fail auth with good TOTP and bad pass' do
          on(server, %(runuser -l #{vagrant_user} -c "/usr/local/bin/expect_su_test #{test_user} #{oath_key} bad_password"), acceptable_exit_codes: [1])
        end
        it 'test group exclusion' do
          on(server, "echo '#{test_user}' >> /etc/liboath/exclude_groups.oath")
          on(server, "su -l #{vagrant_user} -c '/usr/local/bin/su_test_script.rb -u #{test_user} -p #{password}'")
          on(server, "sed -i.old -r '/#{test_user}/d' /etc/liboath/exclude_groups.oath")
        end
        it 'test user exclusion' do
          on(server, "echo '#{test_user}' >> /etc/liboath/exclude_users.oath")
          on(server, "su -l #{vagrant_user} -c '/usr/local/bin/su_test_script.rb -u #{test_user} -p #{password}'")
          on(server, "sed -i.old -r '/#{test_user}/d' /etc/liboath/exclude_users.oath")
        end
      end
    end
  end
end
