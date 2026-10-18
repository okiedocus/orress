//! The ORRESS exploit-development toolkit: the pwntools-style primitives for writing exploits —
//! integer [`pack`]ing, [`cyclic`] (de Bruijn) patterns, [`rop`] gadget search, and [`tube`]s that
//! talk to a local process or a remote service. Pure logic with no UI; the Exploit console and the
//! Gadgets panel in `orress-views` drive it, and `orress-script` exposes it to Rhai scripts.

pub mod cyclic;
pub mod pack;
pub mod rop;
pub mod tube;

pub use cyclic::{cyclic, cyclic_find};
pub use pack::{Endian, pack, unpack};
pub use rop::{Gadget, find_gadgets};
pub use tube::Tube;
