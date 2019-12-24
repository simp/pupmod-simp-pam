# Valid PAM limits
type Pam::Limits::Item = Enum[
  'core',
  'data',
  'fsize',
  'memlock',
  'nofile',
  'rss',
  'stack',
  'cpu',
  'nproc',
  'as',
  'maxlogins',
  'maxsyslogins',
  'priority',
  'locks',
  'sigpending',
  'msgqueue',
  'nice',
  'rtprio'
]
