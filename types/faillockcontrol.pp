# Valid PAM control values for the ``pam_faillock.so authfail`` line
#
# ``[default=die]`` aborts the auth stack immediately on a failed
# authentication and is the arrangement documented in ``pam_faillock(8)``.
# ``required`` and ``requisite`` are the plain controls that the CIS Benchmark
# audit of the auth stack will accept; with either of them a failed
# authentication falls through to ``pam_deny.so`` instead of dying on the spot,
# which reaches the same outcome.
type Pam::FaillockControl = Enum[
  '[default=die]',
  'required',
  'requisite'
]
