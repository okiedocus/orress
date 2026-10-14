//! x86 condition codes shared by the Jcc / SETcc families.

use iced_x86::Mnemonic;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cc {
    O,
    No,
    B,
    Ae,
    E,
    Ne,
    Be,
    A,
    S,
    Ns,
    P,
    Np,
    L,
    Ge,
    Le,
    G,
}

pub fn jcc(m: Mnemonic) -> Option<Cc> {
    use Mnemonic as M;
    Some(match m {
        M::Jo => Cc::O,
        M::Jno => Cc::No,
        M::Jb => Cc::B,
        M::Jae => Cc::Ae,
        M::Je => Cc::E,
        M::Jne => Cc::Ne,
        M::Jbe => Cc::Be,
        M::Ja => Cc::A,
        M::Js => Cc::S,
        M::Jns => Cc::Ns,
        M::Jp => Cc::P,
        M::Jnp => Cc::Np,
        M::Jl => Cc::L,
        M::Jge => Cc::Ge,
        M::Jle => Cc::Le,
        M::Jg => Cc::G,
        _ => return None,
    })
}

pub fn setcc(m: Mnemonic) -> Option<Cc> {
    use Mnemonic as M;
    Some(match m {
        M::Seto => Cc::O,
        M::Setno => Cc::No,
        M::Setb => Cc::B,
        M::Setae => Cc::Ae,
        M::Sete => Cc::E,
        M::Setne => Cc::Ne,
        M::Setbe => Cc::Be,
        M::Seta => Cc::A,
        M::Sets => Cc::S,
        M::Setns => Cc::Ns,
        M::Setp => Cc::P,
        M::Setnp => Cc::Np,
        M::Setl => Cc::L,
        M::Setge => Cc::Ge,
        M::Setle => Cc::Le,
        M::Setg => Cc::G,
        _ => return None,
    })
}
