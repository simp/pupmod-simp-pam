# Valid PAM password validation backends
type Pam::PasswordBackends = Enum[
  'cracklib',
  'pwquality'
]
