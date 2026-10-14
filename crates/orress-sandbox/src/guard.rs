//! The execution guard. Running a flagged sample is gated: by default it is refused on a
//! bare-metal host and requires an explicit confirmation even inside a VM. The caller enforces
//! the [`Decision`] — this module only decides.

/// What running a sample requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    /// Refuse to run unless we appear to be inside a VM.
    pub require_vm: bool,
    /// Require an explicit user confirmation for each run.
    pub require_confirmation: bool,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            require_vm: true,
            require_confirmation: true,
        }
    }
}

/// The guard's decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allowed,
    /// Allowed in principle, but the user has not confirmed yet.
    NeedsConfirmation,
    /// Refused: policy requires a VM and we are on bare metal.
    RefusedNotInVm,
}

impl Decision {
    pub fn is_allowed(self) -> bool {
        self == Decision::Allowed
    }

    pub fn explain(self) -> &'static str {
        match self {
            Decision::Allowed => "ready to run (in a VM, confirmed)",
            Decision::NeedsConfirmation => "confirm you want to run this sample",
            Decision::RefusedNotInVm => {
                "refused: not running inside a VM — enable a VM or disable the VM requirement"
            }
        }
    }
}

/// Decides whether a sample may run under `policy`, given whether we are in a VM and whether the
/// user has confirmed.
pub fn guard(policy: &Policy, in_vm: bool, confirmed: bool) -> Decision {
    if policy.require_vm && !in_vm {
        return Decision::RefusedNotInVm;
    }
    if policy.require_confirmation && !confirmed {
        return Decision::NeedsConfirmation;
    }
    Decision::Allowed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_on_bare_metal_by_default() {
        let p = Policy::default();
        assert_eq!(guard(&p, false, true), Decision::RefusedNotInVm);
    }

    #[test]
    fn needs_confirmation_in_vm() {
        let p = Policy::default();
        assert_eq!(guard(&p, true, false), Decision::NeedsConfirmation);
        assert_eq!(guard(&p, true, true), Decision::Allowed);
    }

    #[test]
    fn can_relax_vm_requirement() {
        let p = Policy {
            require_vm: false,
            require_confirmation: false,
        };
        assert!(guard(&p, false, false).is_allowed());
    }
}
