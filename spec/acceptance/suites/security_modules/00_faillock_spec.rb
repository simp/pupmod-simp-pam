require 'spec_helper_acceptance'

test_name 'pam check faillock'

describe 'pam check faillock' do
  let(:server_hieradata) do
    {
      'simp_options::trusted_nets'                => ['ALL'],
      'ssh::server::conf::banner'                 => '/dev/null',
      'ssh::server::conf::permitrootlogin'        => true,
      'ssh::server::conf::passwordauthentication' => true,
      'ssh::server::conf::authorizedkeysfile'     => '.ssh/authorized_keys',
    }
  end

  # NOTE: by default, include 'ssh' will automatically include the ssh_server
  let(:client_manifest) { "include 'ssh::client'" }

  let(:server_manifest) do
    <<~SERVER_CONFIG
      include 'ssh::server'
      include 'pam'
    SERVER_CONFIG
  end
  let(:test_user) { 'tst0_usr' }
  let(:vagrant_user) { 'vagrant' }
  let(:password) { 'suP3rF00B@rB@11bx23' }

  let(:files_dir) { File.join(File.dirname(__FILE__), 'files') }

  # Number of failures pam_faillock currently has recorded for a user. Each
  # entry in `faillock --user` output starts with the date of the failure.
  def recorded_failures(host, user)
    on(host, "faillock --user #{user}").stdout.lines.grep(%r{^\d{4}-\d{2}-\d{2}\s}).size
  end

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
          set_hieradata_on(server, server_hieradata)
          apply_manifest_on(server, server_manifest, expect_changes: true)
        end

        it "configures #{os}-server idempotently" do
          set_hieradata_on(server, server_hieradata)
          apply_manifest_on(server, server_manifest, catch_changes: true)
        end

        it "configures #{os}-client with no errors" do
          install_package(client, 'epel-release')
          apply_manifest_on(client, client_manifest, expect_changes: true)
        end
        it "configures #{os}-client idempotently" do
          apply_manifest_on(client, client_manifest, catch_changes: true)
        end
      end

      context 'create and test the test user' do
        it 'has a test user' do
          on(server, "puppet resource user #{test_user} ensure=present comment='Tst0 User'")
        end

        it 'test user should accept a valid password change' do
          stdin = "#{password}\n" * 2
          on(server, "passwd #{test_user} ", stdin: stdin)
        end

        it 'has files and packages necessary for testing' do
          scp_to(server, File.join(files_dir, 'su_test_script.rb'), '/usr/local/bin/su_test_script.rb')
          on(server, "chown #{vagrant_user}:#{vagrant_user} /usr/local/bin/su_test_script.rb")
          on(server, 'chmod u+x /usr/local/bin/su_test_script.rb')
          on(client, 'yum install -y sshpass')
        end

        it 'is able to log in with correct password' do
          on(client, "sshpass -p '#{password}' ssh -o StrictHostKeyChecking=no -o NumberOfPasswordPrompts=1 #{test_user}@#{os}-server 'hostname;'")
        end
      end

      context 'Test /etc/pam.d/password-auth faillock through ssh' do
        it 'activate faillock for test user over ssh' do
          5.times do
            on(client, "sshpass -p 'badPassword' ssh -o StrictHostKeyChecking=no -o NumberOfPasswordPrompts=1 #{test_user}@#{os}-server 'hostname;'", acceptable_exit_codes: [255])
          end
        end

        it 'still fails with correct password' do
          on(client, "sshpass -p '#{password}' ssh -o StrictHostKeyChecking=no -o NumberOfPasswordPrompts=1 #{test_user}@#{os}-server 'hostname;'", acceptable_exit_codes: [255])
        end

        it 'clear faillock' do
          on(server, "faillock --user #{test_user} --reset")
        end
      end

      # The pam_unix auth line has to keep a plain control for the CIS rule
      # "Ensure pam_unix module is enabled" (EL8/EL9 5.3.2.5, EL10 5.3.1.5).
      # This is the benchmark's own OVAL pattern.
      context 'CIS pam_unix control' do
        ['/etc/pam.d/system-auth', '/etc/pam.d/password-auth'].each do |pam_file|
          it "emits an accepted pam_unix control in #{pam_file}" do
            on(server, "grep -P -- '^\\h*auth\\h+(required|requisite|sufficient)\\h+pam_unix\\.so\\b' #{pam_file}")
          end
        end
      end

      # A plain 'sufficient' control on pam_unix makes the 'authsucc' call
      # unreachable, so the tally is reset by 'account required
      # pam_faillock.so' instead. If that reset ever stops happening, failures
      # accumulate across successful logins and eventually lock the user out.
      context 'A successful login clears the faillock tally' do
        it 'starts from a clean tally' do
          on(server, "faillock --user #{test_user} --reset")
          expect(recorded_failures(server, test_user)).to eq(0)
        end

        it 'records failures below the deny threshold' do
          3.times do
            on(client, "sshpass -p 'badPassword' ssh -o StrictHostKeyChecking=no -o NumberOfPasswordPrompts=1 #{test_user}@#{os}-server 'hostname;'", acceptable_exit_codes: [255])
          end

          expect(recorded_failures(server, test_user)).to eq(3)
        end

        it 'still allows a login with the correct password' do
          on(client, "sshpass -p '#{password}' ssh -o StrictHostKeyChecking=no -o NumberOfPasswordPrompts=1 #{test_user}@#{os}-server 'hostname;'")
        end

        it 'clears the recorded failures' do
          expect(recorded_failures(server, test_user)).to eq(0)
        end
      end

      context 'Test /etc/pam.d/system-auth faillock through su' do
        it 'check that the test user can su' do
          on(server, "su -l #{vagrant_user} -c '/usr/local/bin/su_test_script.rb -u #{test_user} -p #{password}'")
        end

        it 'activate faillock through su on server vagrant -> test user' do
          5.times do
            on(server, %(su -l #{vagrant_user} -c "/usr/local/bin/su_test_script.rb -u #{test_user} -p badPassword"), acceptable_exit_codes: [1])
          end
        end

        it 'check that vagrant user can not su to tst0_usr' do
          on(server, %(su -l #{vagrant_user} -c "/usr/local/bin/su_test_script.rb -u #{test_user} -p #{password}"), acceptable_exit_codes: [1])
        end

        it 'clear faillock' do
          on(server, "faillock --user #{test_user} --reset")
        end
      end

      context 'With faillock disabled' do
        it 'disables faillock' do
          set_hieradata_on(server, server_hieradata.merge({ 'pam::faillock' => false }))
          apply_manifest_on(server, server_manifest, expect_changes: true)
        end

        it 'is idempotent' do
          apply_manifest_on(server, server_manifest, catch_changes: true)
        end

        it 'fails login 5 times' do
          5.times do
            output = on(server, %(su -l #{vagrant_user} -c "/usr/local/bin/su_test_script.rb -u #{test_user} -p badPassword"), accept_all_exit_codes: true)

            expect(output.exit_code).not_to eq(0)
          end
        end

        it 'does not lock out the user' do
          on(client, "sshpass -p '#{password}' ssh -o StrictHostKeyChecking=no -o NumberOfPasswordPrompts=1 #{test_user}@#{os}-server 'hostname;'")
        end
      end
    end
  end
end
