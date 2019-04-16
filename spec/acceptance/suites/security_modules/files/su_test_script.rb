#!/opt/puppetlabs/puppet/bin/ruby

require 'pty'
require 'expect'
require 'optparse'


# parses out provided command line arguments. 
# No command line args are required as sane defaults are set
# Returns:
# +array+:: Array with default then any command line args that override those
# defaults
def parse_opts
  options = {:user => 'root', :output => nil, :pass => '', 
             :prompt => '.assword:\s*'}
  
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
    opts.on('-e' '--expected-prompt prompt', 'Regex for prompt to look for'\
            ' during command execution. Defaults to ".assword:\\s*"') do |prompt|
      options[:prompt] = prompt
    end
    opts.on('-o' '--output output', 'Escaped regex for expected output of a'\
            ' successful su attempt.'\
            '\nDefaults to looking for the prompt of the new user.'\
            '\nEx: "#{options[:user]}@.+[$#]"'
           ) do |output|
      options[:output] = output
    end
  end
  
  optparse.parse!
  if options[:output].nil?
    options[:output] = "#{options[:user]}@.+[$#]"
  end

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
def run_interactive command, password, prompt
  outputs = ''
  begin 
    r, w, pid = PTY.spawn(command)
    r.expect(prompt)
    sleep(1)
    w.puts("#{password}\r")
    w.puts("exit")
    begin
      r.each { |l| outputs += l }
    rescue Errno::EIO
    end
    Process.wait(pid)
  rescue PTY::ChildExited => e
    $stderr.puts "Child process exited with error #{e}! #{$!.status.exitstatus}"
  end
  return outputs
end


# Calls necessary functions and parses output to determine success or failure
# Aborts if login output does not match regex (exit code: 1)
# returns normally if output does match regex (exit code: 0)
def main
  options = parse_opts()
  outputs = run_interactive("su -l #{options[:user]}", options[:pass],
                            %r{#{options[:prompt]}})
  if outputs.match(/#{options[:output]}/m)
    puts "Login successful"
  else
    abort "Login failed"
  end
end

main()
