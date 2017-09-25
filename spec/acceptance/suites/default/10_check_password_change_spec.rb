require 'spec_helper_acceptance'

test_name 'pam check password change'

describe 'pam check password change' do
  hosts.each do |host|
    context "on #{host}" do
      context 'changing a user password' do
        let(:test_user) { 'test_user' }

        it 'should have a test user' do
          on(host, "puppet resource user #{test_user} ensure=present comment='Test User'")
        end

        it 'should accept a valid password change' do
          on(host, "echo 'suP3rF00B@rB@11b$x23' | passwd --stdin #{test_user}")
        end

        it 'should reject passwords that are too short' do
          on(host, "echo 'suP3rF00B' | passwd --stdin #{test_user}", :acceptable_exit_codes => [1])
        end

        it 'should reject passwords that do not contain numbers' do
          on(host, "echo 'suPerFooB@rB@z%xAB' | passwd --stdin #{test_user}", :acceptable_exit_codes => [1])
        end

        it 'should reject passwords that do not contain lower case letters' do
          on(host, "echo 'E723X00^@3Z8@67X23' | passwd --stdin #{test_user}", :acceptable_exit_codes => [1])
        end

        it 'should reject passwords that do not contain upper case letters' do
          on(host, "echo 'su2er3oo5@r2@z%x23' | passwd --stdin #{test_user}", :acceptable_exit_codes => [1])
        end

        it 'should reject passwords that do not contain symbols' do
          on(host, "echo 'su2er3oo52r2Xz2x23' | passwd --stdin #{test_user}", :acceptable_exit_codes => [1])
        end

        it 'should reject passwords that have too many repeating characters' do
          on(host, "echo 'suPerFoooB@rB@z%x23' | passwd --stdin #{test_user}", :acceptable_exit_codes => [1])
        end

        it 'should reject passwords that have a monotonic character sequence that is too long' do
          on(host, "echo 'suPerFoo23456B@rB@z%x' | passwd --stdin #{test_user}", :acceptable_exit_codes => [1])
        end

        it 'should reject passwords containing the username' do
          on(host, "echo 'suPerFooB@rB@z%test_user' | passwd --stdin #{test_user}", :acceptable_exit_codes => [1])
        end

        it 'should reject passwords containing part of the GECOS' do
          on(host, "echo 'Test$uPerFooB@rB@z%' | passwd --stdin #{test_user}", :acceptable_exit_codes => [1])
        end
      end
    end
  end
end
