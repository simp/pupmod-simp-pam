require 'spec_helper_acceptance'

test_name 'pam check faillock'

describe 'pam check faillock' do


  let(:server_hieradata) do
    {
      'simp_options::trusted_nets'                => ['ALL'],
      'ssh::server::conf::banner'                 => '/dev/null',
      'ssh::server::conf::permitrootlogin'        => true,
      'ssh::server::conf::passwordauthentication' => true,
      'ssh::server::conf::authorizedkeysfile'     => '.ssh/authorized_keys'
    }
  end
  #
  # NOTE: by default, include 'ssh' will automatically include the ssh_server
  let(:client_manifest) { "include 'ssh::client'" }

  let(:server_manifest) {
     <<-SERVER_CONFIG
         include 'ssh::server'
         include 'pam'
     SERVER_CONFIG
  }
  let(:password) {"suP3rF00B@rB@11bx23"}

  let(:files_dir) { File.join(File.dirname(__FILE__), 'files') }
  hosts_as('server').each do |_server|
    os = _server.hostname.split('-').first
    context "on #{os}:" do

      let(:server) { _server }

      let(:client) do
        os = server.hostname.split('-').first
        hosts_as('client').select { |x| x.hostname =~ /^#{os}-.+/ }.first
      end


      context 'with default parameters' do
        it 'should configure server with no errors' do
          install_package(server, 'epel-release')
          set_hieradata_on(server, server_hieradata)
          apply_manifest_on(server, server_manifest, expect_changes: true)
        end

        it "should configure #{os}-server idempotently" do
          set_hieradata_on(server, server_hieradata)
          apply_manifest_on(server, server_manifest, catch_changes: true)
        end

        it "should configure #{os}-client with no errors" do
          install_package(client, 'epel-release')
          apply_manifest_on(client, client_manifest, expect_changes: true)
        end
        it "should configure #{os}-client idempotently" do
          apply_manifest_on(client, client_manifest, catch_changes: true)
        end
      end


      context 'create and test the test user' do

        let(:test_user) { 'tst0_usr' }
        let(:vagrant_user) { 'vagrant' }


        it 'should have a test user' do
          on(server, "puppet resource user #{test_user} ensure=present comment='Tst0 User'")
        end

        it 'test user should accept a valid password change' do
          stdin = "#{password}\n" * 2
          on(server, "passwd #{test_user} ", :stdin => stdin)
        end

        it 'should have files and packages necessary for testing' do
          scp_to(server, File.join(files_dir, 'su_test_script.rb'), '/usr/local/bin/su_test_script.rb')
          on(server, "chown #{vagrant_user}:#{vagrant_user} /usr/local/bin/su_test_script.rb")
          on(server, "chmod u+x /usr/local/bin/su_test_script.rb")
          on(client, 'yum install -y sshpass')
        end

        it 'should be able to log in with correct password' do
          on(client, "sshpass -p '#{password}' ssh -o StrictHostKeyChecking=no -o NumberOfPasswordPrompts=1 #{test_user}@#{os}-server 'hostname;'")
        end

      end
      
      context "Test /etc/pam.d/password-auth faillock through ssh" do

        let(:test_user) { 'tst0_usr' }
        let(:vagrant_user) { 'vagrant' }
        
        it 'activate faillock for test user over ssh' do
          5.times do
          on(client, "sshpass -p 'badPassword' ssh -o StrictHostKeyChecking=no -o NumberOfPasswordPrompts=1 #{test_user}@#{os}-server 'hostname;'", :acceptable_exit_codes => [255])
          end
        end

        it 'should still fail with correct password' do
          on(client, "sshpass -p '#{password}' ssh -o StrictHostKeyChecking=no -o NumberOfPasswordPrompts=1 #{test_user}@#{os}-server 'hostname;'", :acceptable_exit_codes => [255])
        end

        it 'clear faillock' do
          on(server, "faillock --user #{test_user} --reset")
        end
      end

      context "Test /etc/pam.d/system-auth faillock through su" do

        let(:test_user) { 'tst0_usr' }
        let(:vagrant_user) { 'vagrant' }

        it 'check that the test user can su' do  
          on(server, "su -l #{vagrant_user} -c '/usr/local/bin/su_test_script.rb -u #{test_user} -p #{password}'")
        end

        it 'activate faillock through su on server vagrant -> test user' do
          5.times do
            on(server, %Q[su -l #{vagrant_user} -c "/usr/local/bin/su_test_script.rb -u #{test_user} -p badPassword"], :acceptable_exit_codes => [1])
          end
        end

        it 'check that vagrant user cant su to tst0_usr' do  
          on(server, %Q[su -l #{vagrant_user} -c "/usr/local/bin/su_test_script.rb -u #{test_user} -p #{password}"], :acceptable_exit_codes => [1])
        end

        it 'clear faillock' do
          on(server, "faillock --user #{test_user} --reset")
        end
      end
    end
  end
end
