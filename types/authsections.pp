# Valid PAM `auth` sections
type Pam::AuthSections = Array[Enum[
  'fingerprint',
  'system',
  'password',
  'smartcard'
]]
