require 'spec_helper_acceptance'

test_name 'pam check password change'

describe 'pam check password change' do
  hosts.each do |host|
    context "on #{host}" do
      context 'changing a user password' do
        # The test user name can't have any more than 3 characters
        # from same character set in a row for us to test some of the
        # password restrictions.
        let(:test_user) { 'tst0_usr' }

        # number of times to repeat the input of a valid password for passwd success
        let(:repeat_when_success) { 2 }

        # number of times to repeat the input of an invalid password for passwd failure
        let(:repeat_when_failure) { 3 }

        it 'should have a test user' do
          # The test user GECOS entry can't have any more than 3 characters from the
          # same character set in a row for us to test the GECOS password restriction.
          on(host, "puppet resource user #{test_user} ensure=present comment='Tst0 User'")
        end

        it 'should accept a valid password change' do
          stdin = "suP3rF00B@rB@11b$x23\n"*repeat_when_success
          on(host, "passwd #{test_user}", :stdin => stdin)
        end

        it 'should reject passwords that are too short' do
          stdin = "suP3rF!0B\n"*repeat_when_failure
          result = on(host, "passwd #{test_user}", {:stdin => stdin, :acceptable_exit_codes => [1]})
          if host.name =~ /el6/
            expect(result.stderr).to match(/is too simple/)
          else
            expect(result.stderr).to match(/password is shorter than 15 characters/)
          end
        end

        it 'should reject passwords that do not contain numbers' do
          stdin = "suPerFooB@rB@z%xAB\n"*repeat_when_failure
          result = on(host, "passwd #{test_user}", {:stdin => stdin, :acceptable_exit_codes => [1]})
          if host.name =~ /el6/
            expect(result.stderr).to match(/is too simple/)
          else
            expect(result.stderr).to match(/password contains less than 1 digit/)
          end
        end

        it 'should reject passwords that do not contain lower case letters' do
          stdin = "E723X00^@3Z8@67X23\n"*repeat_when_failure
          result = on(host, "passwd #{test_user}", {:stdin => stdin, :acceptable_exit_codes => [1]})
          if host.name =~ /el6/
            expect(result.stderr).to match (/is too simple/)
          else
            expect(result.stderr).to match (/password contains less than 1 lowercase letter/)
          end
        end

        it 'should reject passwords that do not contain upper case letters' do
          stdin = "su2er3oo5@r2@z%x23\n"*repeat_when_failure
          result = on(host, "passwd #{test_user}", {:stdin => stdin, :acceptable_exit_codes => [1]})
          if host.name =~ /el6/
            expect(result.stderr).to match(/is too simple/)
          else
            expect(result.stderr).to match(/password contains less than 1 uppercase letter/)
          end
        end

        it 'should reject passwords that do not contain symbols' do
          stdin = "su2er3oo52r2Xz2x23\n"*repeat_when_failure
          result = on(host, "passwd #{test_user}", {:stdin => stdin, :acceptable_exit_codes => [1]})
          if host.name =~ /el6/
            expect(result.stderr).to match(/is too simple/)
          else
            expect(result.stderr).to match(/password contains less than 1 non-alphanumeric character/)
          end
        end

        it 'should reject passwords that have too many characters from the same character class' do
          stdin = "supeRFooB@rB@z%x23\n"*repeat_when_failure
          result = on(host, "passwd #{test_user}", {:stdin => stdin, :acceptable_exit_codes => [1]})
          if host.name =~ /el6/
            expect(result.stderr).to match(/is too simple/)
          else
            expect(result.stderr).to match(/password contains more than 3 characters of the same class consecutively/)
          end
        end

        it 'should reject passwords that have too many repeating characters' do
          stdin = "suPerFoooB@rB@z%x23\n"*repeat_when_failure
          result = on(host, "passwd #{test_user}", {:stdin => stdin, :acceptable_exit_codes => [1]})
          if host.name =~ /el6/
            expect(result.stderr).to match(/contains too many same characters consecutively/)
          else
            expect(result.stderr).to match(/password contains more than 2 same characters consecutively/)
          end
        end

        it 'should reject passwords that have a monotonic character sequence that is too long' do
          if host.name =~ /el7/
            skip 'unable to cause failure on el7 without first hitting other password restrictions'
          end

          stdin = "123=456=789=0Qw\n"*repeat_when_failure       # el6: 'too simplistic/systematic'
          result = on(host, "passwd #{test_user}", {:stdin => stdin, :acceptable_exit_codes => [1]})
          expect(result.stderr).to match(/is too simplistic\/systematic/)
        end

        it 'should reject passwords containing the username' do
          stdin = "suPerFo0B@rB@z%#{test_user}\n"*repeat_when_failure
          result = on(host, "passwd #{test_user}", {:stdin => stdin, :acceptable_exit_codes => [1]})
          if host.name =~ /el6/
            expect(result.stderr).to match(/contains the user name in some form/)
          else
            expect(result.stderr).to match(/password contains the user name in some form/)
          end
        end

        it 'should reject passwords containing part of the GECOS' do
          stdin = "Tst0$uPerFo0B@rB@z%\n"*repeat_when_failure
          result = on(host, "passwd #{test_user}", {:stdin => stdin, :acceptable_exit_codes => [1]})
          if host.name =~ /el6/
            expect(result.stderr).to match(/contains the user name in some form/)
          else
            expect(result.stderr).to match(/password contains words from the real name of the user in some form/)
          end
        end
      end
    end
  end
end
