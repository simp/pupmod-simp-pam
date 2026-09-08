#!/opt/puppetlabs/puppet/bin/ruby

require 'English'
require 'pty'
require 'expect'
require 'optparse'
require 'timeout'

# Echoed by the su'd command on success. See run_interactive for why the su is
# non-interactive rather than a login shell we type 'exit' at.
SUCCESS_MARKER = 'SU_TEST_LOGIN_OK'.freeze

# parses out provided command line arguments.
# No command line args are required as sane defaults are set
# Returns:
# +array+:: Array with default then any command line args that override those
# defaults
def parse_opts
  options = { user: 'root', output: nil, pass: '',
             prompt: '.assword:\s*' }

  optparse = OptionParser.new do |opts|
    opts.banner = 'Usage: su_test_script.rb [-p password] [-u user]'\
                  '[-e expected prompt] [-o expected output]'

    opts.on('-p', '--password pass', 'Password to authenticate with,'\
            ' defaults to empty string') do |pass|
      options[:pass] = pass
    end
    opts.on('-u', '--user user', 'User to su to, defaults to root') do |user|
      options[:user] = user
    end
    opts.on('-e' + '--expected-prompt prompt', 'Regex for prompt to look for'\
            ' during command execution. Defaults to ".assword:\\s*"') do |prompt|
      options[:prompt] = prompt
    end
    opts.on('-o' + '--output output', 'Escaped regex for expected output of a'\
            ' successful su attempt.'\
            "\nDefaults to the #{SUCCESS_MARKER} echoed by the su'd command.") do |output|
      options[:output] = output
    end
  end

  optparse.parse!
  options[:output] = SUCCESS_MARKER if options[:output].nil?

  options
end

# Performs the ruby equivalent of bash expect command
# Parmas:
# +command+:: su command to run in the new pty
# +password+:: password to fill when prompted by pty
# +prompt+:: regex for target prompt to fill password when seen
# Return:
# +outputs+:: Concatenated output of su command for regex determination of
# success or failure
def run_interactive(command, password, prompt, timeout = 60)
  outputs = ''
  pid = nil

  begin
    # Every step below can block indefinitely: IO#expect has no timeout of its
    # own, reading the pty waits on the child, and Process.wait waits on it
    # again. A pam stack that never reaches the password prompt -- one of the
    # states this suite deliberately provokes -- would hang the acceptance run
    # rather than failing it, so bound the whole interaction.
    Timeout.timeout(timeout) do
      r, w, pid = PTY.spawn(command)
      r.expect(prompt)
      sleep(1)
      w.puts("#{password}\r")
      begin
        r.each { |l| outputs += l }
      rescue Errno::EIO
        # Ignoring EIO errors
      end
      Process.wait(pid)
    end
  rescue Timeout::Error
    warn "Timed out after #{timeout}s running #{command.inspect}"
    warn "Output so far: #{outputs.inspect}"

    begin
      Process.kill('TERM', pid) if pid
      Process.wait(pid) if pid
    rescue Errno::ESRCH, Errno::ECHILD
      # Child is already gone
    end
  rescue PTY::ChildExited => e
    $stderr.puts "Child process exited with error #{e}! #{$ERROR_INFO.status.exitstatus}"
  end

  outputs
end

# Calls necessary functions and parses output to determine success or failure
# Aborts if login output does not match regex (exit code: 1)
# returns normally if output does match regex (exit code: 0)
def main
  options = parse_opts

  # 'su -l <user> -c <cmd>' rather than a login shell: the command exits on its
  # own, so nothing has to be typed at the shell afterwards. Writing 'exit'
  # into the pty right after the password is a race -- the input is discarded
  # while the login shell sets the terminal up, and on EL10 it loses every
  # time, leaving the reader blocked on a shell that never exits. EL8 and EL9
  # happen to win that race, which is why this only ever hung on EL10.
  outputs = run_interactive("su -l #{options[:user]} -c 'echo #{SUCCESS_MARKER}'",
                            options[:pass], %r{#{options[:prompt]}})
  if outputs.match?(%r{#{options[:output]}}m)
    warn 'Login successful'
  else
    abort 'Login failed'
  end
end

main
