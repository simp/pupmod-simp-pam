skips = {
  'V-71965' => 'N/A',
  'V-71943' => 'Check needs to be fixed',
  'V-71945' => 'Check needs to be fixed',
  'V-72275' => 'Check needs to be fixed'
}
overrides = []
subsystems = [ 'pam' ]

require_controls 'disa_stig-el7-baseline' do
  skips.each_pair do |ctrl, reason|
    control ctrl do
      describe "Skip #{ctrl}" do
        skip "Reason: #{skips[ctrl]}" do
        end
      end
    end
  end

  @conf['profile'].info[:controls].each do |ctrl|
    next if (overrides + skips.keys).include?(ctrl[:id])

    tags = ctrl[:tags]
    if tags && tags[:subsystems]
      subsystems.each do |subsystem|
        if tags[:subsystems].include?(subsystem)
          control ctrl[:id]
        end
      end
    end
  end
end
