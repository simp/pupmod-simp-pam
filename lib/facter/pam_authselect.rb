# frozen_string_literal: true

# @summary Provides the authselect configuration that is active on the host
#
# Reads `/etc/authselect/authselect.conf`, whose first line is the selected
# profile and whose remaining lines are the enabled features, and lists the
# files in `/etc/pam.d` that are symlinks into `/etc/authselect`, i.e. the
# files authselect currently owns.
#
# @see authselect(8)
#
# @return [Hash, nil] nil when no profile is selected and no `/etc/pam.d`
#   file is an authselect symlink
#
# @example Output Hash
#
#   {
#     'profile'   => 'minimal',
#     'features'  => ['with-faillock', 'with-silent-lastlog'],
#     'symlinked' => ['fingerprint-auth', 'password-auth', 'postlogin', 'smartcard-auth', 'system-auth'],
#   }
#
Facter.add('pam_authselect') do
  confine kernel: :linux
  confine { File.directory?('/etc/authselect') }

  setcode do
    conf_file = '/etc/authselect/authselect.conf'

    entries = []
    if File.exist?(conf_file)
      entries = File.readlines(conf_file).map(&:strip).reject { |line| line.empty? || line.start_with?('#') }
    end

    authselect_links = Dir.glob('/etc/pam.d/*').select do |path|
      File.symlink?(path) &&
        File.expand_path(File.readlink(path), File.dirname(path)).start_with?('/etc/authselect/')
    end
    symlinked = authselect_links.map { |path| File.basename(path) }.sort

    if entries.empty? && symlinked.empty?
      nil
    else
      {
        'profile'   => entries.first,
        'features'  => entries.drop(1),
        'symlinked' => symlinked,
      }
    end
  rescue => e
    Facter.warn("Failed to retrieve the authselect configuration: #{e.message}")
    nil
  end
end
