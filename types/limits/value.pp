# Valid PAM limit values
type Pam::Limits::Value =  Variant[
  Enum['unlimited','infinity'],
  Integer
]
