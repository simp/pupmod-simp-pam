#!/opt/puppetlabs/puppet/bin/ruby

require 'English'
require 'pty'
require 'expect'
require 'optparse'
require 'timeout'

# Echoed by the su'd command on success. See run_interactive for why the su is
# non-interactive rather than a login shell we type 'exit' at.
SUCCESS_MARKER = 'SU_TEST_LOGIN_OK'.freeze

# Exit codes. The caller has to be able to tell an authentication denial (which
# several tests assert with acceptable_exit_codes: [1]) from the script itself
# falling over, otherwise a broken harness looks exactly like a correct denial.
EXIT_AUTHENTICATED = 0
EXIT_DENIED        = 1
EXIT_HARNESS_ERROR = 2

# Outcome of one su attempt.
# +status+:: :authenticated, :denied or :harness_error
# +output+:: whatever was read back from the pty
# +detail+:: human readable reason, for the :denied and :harness_error cases
Result = Struct.new(:status, :output, :detail)

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
    opts.on('-e', '--expected-prompt prompt', 'Regex for prompt to look for'\
            ' during command execution. Defaults to ".assword:\\s*"') do |prompt|
      options[:prompt] = prompt
    end
    opts.on('-o', '--output output', 'Escaped regex for expected output of a'\
            ' successful su attempt.'\
            "\nDefaults to the #{SUCCESS_MARKER} echoed by the su'd command.") do |output|
      options[:output] = output
    end
  end

  optparse.parse!
  options[:output] = SUCCESS_MARKER if options[:output].nil?

  options
end

# Shuts down a pty interaction that did not finish on its own.
#
# Closing the master first so that a child blocked writing to the pty sees the
# hangup, then signalling the process group rather than the single pid --
# PTY.spawn calls setsid, so the child is a group leader and anything it forked
# is only reachable through -pid. Every wait here is bounded; an unbounded one
# would re-hang at exactly the point the caller's timeout exists to prevent.
# Params:
# +pid+:: pid returned by PTY.spawn, or nil if the spawn never happened
# +ios+:: pty master/slave IO objects to close
def reap(pid, *ios)
  ios.each do |io|
    io.close if io && !io.closed?
  rescue IOError, Errno::EIO
    # Already gone
  end

  return if pid.nil?

  ['TERM', 'KILL'].each do |signal|
    begin
      Process.kill(signal, -pid)
    rescue Errno::ESRCH, Errno::EPERM
      # Group is already gone
    end

    begin
      return Timeout.timeout(5) { Process.wait(pid) }
    rescue Timeout::Error
      next
    rescue Errno::ECHILD
      return nil
    end
  end

  nil
end

# Performs the ruby equivalent of bash expect command
# Parmas:
# +command+:: su command to run in the new pty
# +password+:: password to fill when prompted by pty
# +prompt+:: regex for target prompt to fill password when seen
# +timeout+:: seconds to allow the whole interaction
# Return:
# +Result+:: status of the attempt plus the pty output backing it
def run_interactive(command, password, prompt, timeout = 60)
  outputs = ''
  pid = nil
  r = nil
  w = nil

  begin
    # Bound the whole interaction. IO#expect has no timeout of its own, reading
    # the pty waits on the child, and Process.wait waits on it again, so any of
    # the three can block forever.
    Timeout.timeout(timeout) do
      r, w, pid = PTY.spawn(command)

      # A pam stack that denies before prompting -- the pam_faillock lockout
      # this suite deliberately provokes -- makes su exit without writing a
      # prompt. IO#expect calls IO#eof? on the master, which raises Errno::EIO
      # once the child is gone. That is a denial, not a crash, so catch it here
      # rather than letting it escape as a traceback that happens to exit 1.
      begin
        matched = r.expect(prompt)
      rescue Errno::EIO
        matched = nil
      end

      if matched.nil?
        reap(pid, r, w)
        return Result.new(:denied, outputs, 'su exited without prompting for a password')
      end

      sleep(1)

      begin
        w.puts("#{password}\r")
      rescue Errno::EIO, Errno::EPIPE
        reap(pid, r, w)
        return Result.new(:denied, outputs, 'su closed the pty before the password could be sent')
      end

      begin
        r.each { |l| outputs += l }
      rescue Errno::EIO
        # Expected: the master reports EIO once the child has exited
      end

      Process.wait(pid)
    end
  rescue Timeout::Error
    reap(pid, r, w)
    return Result.new(:harness_error, outputs,
                      "timed out after #{timeout}s running #{command.inspect}")
  rescue PTY::ChildExited => e
    reap(nil, r, w)
    return Result.new(:denied, outputs,
                      "child process exited: #{e} (#{$ERROR_INFO.status&.exitstatus})")
  end

  Result.new(:authenticated, outputs, nil)
end

# Calls necessary functions and parses output to determine success or failure
# Exits EXIT_AUTHENTICATED when the su'd command ran, EXIT_DENIED when
# authentication was refused, and EXIT_HARNESS_ERROR when this script could not
# carry the attempt out -- the last of which must never be mistaken for a
# denial by a caller asserting acceptable_exit_codes.
def main
  options = parse_opts

  # 'su -l <user> -c <cmd>' rather than a login shell: the command exits on its
  # own, so nothing has to be typed at the shell afterwards. Writing 'exit'
  # into the pty right after the password is a race -- the input is discarded
  # while the login shell sets the terminal up, and on EL10 it loses every
  # time, leaving the reader blocked on a shell that never exits. EL8 and EL9
  # happen to win that race, which is why this only ever hung on EL10.
  result = run_interactive("su -l #{options[:user]} -c 'echo #{SUCCESS_MARKER}'",
                           options[:pass], %r{#{options[:prompt]}})

  case result.status
  when :harness_error
    warn "Harness error: #{result.detail}"
    warn "Output so far: #{result.output.inspect}"
    exit EXIT_HARNESS_ERROR
  when :denied
    warn "Login failed: #{result.detail}"
    exit EXIT_DENIED
  end

  # Only reachable once the interaction completed cleanly, so a match here
  # cannot be the partial output of a timed-out run.
  if result.output.match?(%r{#{options[:output]}}m)
    warn 'Login successful'
    exit EXIT_AUTHENTICATED
  end

  warn "Login failed: expected output #{options[:output].inspect} not seen"
  exit EXIT_DENIED
end

main
