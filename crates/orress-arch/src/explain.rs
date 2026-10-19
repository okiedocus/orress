//! Plain-language explanations of instructions and registers, for Explain Mode.

use crate::Isa;

/// Explains a mnemonic, e.g. `"jnz"`. Prefixes such as `rep` are explained separately.
pub fn mnemonic(isa: Isa, mnemonic: &str) -> Option<&'static str> {
    let m = mnemonic.rsplit(' ').next().unwrap_or(mnemonic);
    match isa {
        Isa::X86 | Isa::X64 => x86(m),
        Isa::Arm64 => arm64(m),
        Isa::Riscv64 => None,
        Isa::Mips32 | Isa::Mips32El => None,
    }
}

fn x86(m: &str) -> Option<&'static str> {
    Some(match m {
        "mov" => "Copy a value: mov dst, src puts src into dst. The most common instruction.",
        "movzx" => {
            "Copy a small value into a bigger register, filling the rest with zeros (zero-extend). Typical for reading one byte or character."
        }
        "movsx" | "movsxd" => {
            "Copy a small value into a bigger register, keeping its sign (sign-extend)."
        }
        "lea" => {
            "Load Effective Address: computes an address (or any a+b*c+d arithmetic) without reading memory. Often loads a pointer to a string."
        }
        "push" => {
            "Put a value on top of the stack (rsp/esp goes down). Also used to pass arguments in 32-bit code."
        }
        "pop" => "Take the value from the top of the stack into a register (rsp/esp goes up).",
        "call" => {
            "Call a function: push the return address, then jump to it. When the function returns, execution continues after this call."
        }
        "ret" | "retn" => {
            "Return from the function: pop the return address from the stack and jump back to the caller. The return value is in rax/eax."
        }
        "jmp" => "Jump: continue execution at another address, always.",
        "cmp" => {
            "Compare: computes a - b to set the flags, without storing the result. A conditional jump right after decides what happens."
        }
        "test" => {
            "Bitwise AND to set the flags, without storing the result. `test eax, eax` checks whether eax is zero."
        }
        "je" | "jz" => {
            "Jump if equal / zero (ZF=1): taken when the previous cmp found both values equal, or the result was zero."
        }
        "jne" | "jnz" => {
            "Jump if not equal / not zero (ZF=0). In a crackme this is often the jump to \"Wrong password\"."
        }
        "jg" | "jnle" => "Jump if greater (signed comparison).",
        "jge" | "jnl" => "Jump if greater or equal (signed).",
        "jl" | "jnge" => "Jump if less (signed).",
        "jle" | "jng" => "Jump if less or equal (signed).",
        "ja" | "jnbe" => "Jump if above (unsigned comparison).",
        "jae" | "jnb" | "jnc" => "Jump if above or equal (unsigned); also: jump if no carry.",
        "jb" | "jnae" | "jc" => "Jump if below (unsigned); also: jump if carry.",
        "jbe" | "jna" => "Jump if below or equal (unsigned).",
        "js" => "Jump if the result was negative (sign flag set).",
        "jns" => "Jump if the result was not negative.",
        "jo" | "jno" => "Jump on (no) signed overflow.",
        "jp" | "jpe" | "jnp" | "jpo" => {
            "Jump on parity flag; rare in normal code, often from floating-point compares."
        }
        "jcxz" | "jecxz" | "jrcxz" => "Jump if the counter register is zero.",
        "loop" => "Decrement rcx/ecx and jump if it is not zero yet.",
        "xor" => {
            "Exclusive OR. `xor eax, eax` sets eax to 0. XOR with a key is the most common simple encryption in CTFs."
        }
        "and" => "Bitwise AND: keeps only the bits set in both values. Used for masking.",
        "or" => "Bitwise OR: sets bits.",
        "not" => "Flips every bit.",
        "neg" => "Negates a number (two's complement): x becomes -x.",
        "add" => "Addition: dst = dst + src.",
        "sub" => {
            "Subtraction: dst = dst - src. `sub rsp, N` reserves N bytes of stack for local variables."
        }
        "inc" => "Add 1.",
        "dec" => "Subtract 1.",
        "imul" => "Signed multiplication.",
        "mul" => "Unsigned multiplication (result in rdx:rax).",
        "idiv" => "Signed division: rdx:rax / operand; quotient in rax, remainder in rdx.",
        "div" => "Unsigned division: quotient in rax, remainder (modulo) in rdx.",
        "shl" | "sal" => "Shift bits left: multiplies by a power of two.",
        "shr" => "Shift bits right (unsigned): divides by a power of two.",
        "sar" => "Shift bits right keeping the sign (signed division by a power of two).",
        "rol" => {
            "Rotate bits left: bits pushed out on the left come back on the right. Common in hash and crypto code."
        }
        "ror" => "Rotate bits right. ror 13 is the classic shellcode API-hash.",
        "nop" => {
            "No operation: does nothing. Used as padding; patching a check with NOPs removes it."
        }
        "int3" => {
            "Breakpoint trap. Debuggers place this byte (0xCC) to stop the program. Padding between functions also uses it."
        }
        "int" => "Software interrupt. `int 0x80` is a Linux system call in 32-bit code.",
        "syscall" => {
            "Ask the operating system kernel to do something (read, write, exit ...). The call number is in rax."
        }
        "sysenter" => "Fast system call (32-bit).",
        "hlt" => "Halt the processor. Crashes a normal program; marks unreachable code.",
        "ud2" => {
            "Undefined instruction: always crashes. Compilers put it after code that must never be reached."
        }
        "leave" => {
            "Function epilogue: restores the stack pointer and rbp/ebp (mov rsp, rbp; pop rbp)."
        }
        "enter" => "Function prologue that sets up a stack frame (rarely used).",
        "cdq" | "cdqe" | "cqo" | "cwde" | "cbw" | "cwd" => {
            "Sign-extend a value in rax/eax, usually right before a division."
        }
        "sete" | "setz" | "setne" | "setnz" | "setg" | "setl" | "setge" | "setle" | "seta"
        | "setb" | "setae" | "setbe" => {
            "Set a byte register to 1 if the condition holds, otherwise 0. Turns a comparison into a boolean."
        }
        "cmove" | "cmovz" | "cmovne" | "cmovnz" | "cmovg" | "cmovl" | "cmovge" | "cmovle"
        | "cmova" | "cmovb" | "cmovae" | "cmovbe" | "cmovs" | "cmovns" => {
            "Conditional move: copy only if the condition holds. A branch-free if/else."
        }
        "xchg" => "Swap two values.",
        "bswap" => "Reverse the byte order of a register (endianness swap).",
        "movs" | "movsb" | "movsw" | "movsd" | "movsq" => {
            "Copy memory from [rsi] to [rdi]. With `rep` it copies rcx elements: an inlined memcpy."
        }
        "stos" | "stosb" | "stosw" | "stosd" | "stosq" => {
            "Store al/ax/eax/rax at [rdi]. With `rep` it fills memory: an inlined memset."
        }
        "cmps" | "cmpsb" | "cmpsw" | "cmpsd" | "cmpsq" => {
            "Compare memory at [rsi] and [rdi]. With `repe` it compares buffers: an inlined memcmp, a classic password check."
        }
        "scas" | "scasb" | "scasw" | "scasd" | "scasq" => {
            "Compare al/eax with [rdi]. `repne scasb` finds a byte: an inlined strlen."
        }
        "lods" | "lodsb" | "lodsw" | "lodsd" | "lodsq" => {
            "Load from [rsi] into al/ax/eax/rax and advance rsi."
        }
        "rdtsc" => {
            "Read the CPU's time-stamp counter. Two reads around code detect slow single-stepping: an anti-debug trick."
        }
        "cpuid" => "Ask the CPU about itself. Malware uses it to detect virtual machines.",
        "endbr64" | "endbr32" => {
            "Marks a valid target for indirect jumps (Intel CET). Harmless; found at the start of most functions in modern Linux binaries."
        }
        "pxor" | "xorps" | "xorpd" | "vpxor" => {
            "XOR on 128/256-bit vector registers. `pxor xmm0, xmm0` zeroes a register."
        }
        "movdqa" | "movdqu" | "movaps" | "movups" | "vmovdqu" | "vmovdqa" => {
            "Copy 16/32 bytes at once with vector registers. Compilers use it to copy or zero buffers and strings."
        }
        "movd" | "movq" => "Move between general registers and vector (xmm) registers.",
        _ => return None,
    })
}

fn arm64(m: &str) -> Option<&'static str> {
    let m = m.split('.').next().unwrap_or(m);
    Some(match m {
        "mov" => "Copy a value into a register.",
        "movz" | "movk" | "movn" => {
            "Build a constant 16 bits at a time (move wide). Several in a row form one large number."
        }
        "ldr" | "ldur" | "ldrb" | "ldrh" | "ldrsw" | "ldrsb" | "ldrsh" => {
            "Load from memory into a register. ARM only touches memory with load and store instructions."
        }
        "str" | "stur" | "strb" | "strh" => "Store a register to memory.",
        "ldp" => {
            "Load two registers from memory at once. At the end of a function it restores saved registers."
        }
        "stp" => {
            "Store two registers at once. `stp x29, x30, [sp, #-16]!` at the start of a function saves the frame pointer and return address."
        }
        "adrp" => {
            "Address of a 4 KiB page, relative to the current instruction. Followed by add or ldr to reach a specific address, often a string."
        }
        "adr" => "Address relative to the current instruction.",
        "add" | "adds" => "Addition (adds also sets the flags).",
        "sub" | "subs" => "Subtraction (subs also sets the flags).",
        "cmp" => "Compare: subtract to set the flags without storing the result.",
        "cmn" => "Compare with the negated value (add to set flags).",
        "tst" => "Bitwise AND to set the flags.",
        "b" => {
            "Branch: jump to an address. With a condition (b.eq, b.ne ...) only when the condition holds."
        }
        "bl" => "Branch with link: call a function. The return address goes in x30 (lr).",
        "br" => "Jump to the address in a register.",
        "blr" => "Call the function whose address is in a register.",
        "ret" => "Return to the caller (jump to x30). The return value is in x0.",
        "cbz" => "Compare and branch if zero: jump when the register is 0.",
        "cbnz" => "Compare and branch if not zero.",
        "tbz" | "tbnz" => "Test one bit and branch if it is zero / not zero.",
        "eor" => "Exclusive OR (XOR). Common in simple CTF encryption.",
        "and" | "ands" => "Bitwise AND.",
        "orr" => "Bitwise OR. `orr x0, xzr, x1` is a mov.",
        "lsl" | "lsr" | "asr" | "ror" => "Shift or rotate bits.",
        "mul" | "madd" | "msub" | "smull" | "umull" => {
            "Multiplication (madd/msub also add or subtract)."
        }
        "sdiv" | "udiv" => {
            "Division. ARM has no remainder instruction; msub after the division computes it."
        }
        "csel" | "csinc" | "csinv" | "csneg" | "cset" | "csetm" | "cinc" => {
            "Conditional select: pick a value based on the flags, a branch-free if/else."
        }
        "svc" => "Supervisor call: a system call. The number is in x8 on Linux.",
        "nop" => "No operation.",
        "brk" => "Breakpoint trap.",
        "paciasp" | "autiasp" | "bti" => {
            "Pointer authentication / branch target marker: security features, safe to ignore while reversing."
        }
        _ => return None,
    })
}

/// Explains a register name.
pub fn register(isa: Isa, reg: &str) -> Option<&'static str> {
    match isa {
        Isa::X86 | Isa::X64 => x86_register(reg),
        Isa::Arm64 => arm64_register(reg),
        Isa::Riscv64 => None,
        Isa::Mips32 | Isa::Mips32El => None,
    }
}

fn x86_register(r: &str) -> Option<&'static str> {
    Some(match r {
        "rax" | "eax" | "ax" | "al" | "ah" => {
            "Accumulator. Holds a function's return value. eax is its lower 32 bits, al the lowest byte."
        }
        "rbx" | "ebx" | "bx" | "bl" | "bh" => "General purpose register, preserved across calls.",
        "rcx" | "ecx" | "cx" | "cl" | "ch" => {
            "Counter register. 1st argument in Windows x64 calls; counts for rep and shifts."
        }
        "rdx" | "edx" | "dx" | "dl" | "dh" => {
            "Data register. 2nd argument in Windows x64; 3rd in Linux x64. Also the high half of multiplications and the remainder of divisions."
        }
        "rsi" | "esi" | "si" | "sil" => {
            "Source index. 2nd argument in Linux x64 calls; source for string instructions."
        }
        "rdi" | "edi" | "di" | "dil" => {
            "Destination index. 1st argument in Linux x64 calls; destination for string instructions."
        }
        "rsp" | "esp" | "sp" | "spl" => {
            "Stack pointer: address of the top of the stack. Grows downward."
        }
        "rbp" | "ebp" | "bp" | "bpl" => {
            "Base (frame) pointer. Local variables are often at [rbp-N], arguments in 32-bit code at [ebp+N]."
        }
        "r8" | "r8d" | "r8w" | "r8b" => "3rd argument in Windows x64; 5th in Linux x64.",
        "r9" | "r9d" | "r9w" | "r9b" => "4th argument in Windows x64; 6th in Linux x64.",
        "r10" | "r10d" | "r11" | "r11d" => {
            "Scratch registers. On Linux, syscall arguments use r10 instead of rcx."
        }
        "r12" | "r13" | "r14" | "r15" | "r12d" | "r13d" | "r14d" | "r15d" => {
            "General purpose registers, preserved across calls."
        }
        "rip" | "eip" => "Instruction pointer: address of the next instruction to execute.",
        "xmm0" | "xmm1" | "xmm2" | "xmm3" => {
            "128-bit vector register. Holds floating-point arguments and results, or copies 16 bytes at once."
        }
        _ => return None,
    })
}

fn arm64_register(r: &str) -> Option<&'static str> {
    Some(match r {
        "x0" | "w0" => "1st argument and the return value. w0 is its lower 32 bits.",
        "x1" | "w1" => "2nd argument.",
        "x2" | "w2" => "3rd argument.",
        "x3" | "w3" => "4th argument.",
        "x8" | "w8" => "Indirect result register; holds the system call number on Linux.",
        "x29" | "fp" => "Frame pointer.",
        "x30" | "lr" => "Link register: the return address set by bl.",
        "sp" | "wsp" => "Stack pointer.",
        "xzr" | "wzr" => "Zero register: always reads as 0, writes are discarded.",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explains_common_things() {
        assert!(mnemonic(Isa::X64, "jnz").unwrap().contains("not zero"));
        assert!(mnemonic(Isa::X64, "rep stosb").is_some());
        assert!(mnemonic(Isa::Arm64, "b.eq").is_some());
        assert!(register(Isa::X64, "rdi").unwrap().contains("1st argument"));
        assert!(mnemonic(Isa::X64, "vfmadd231ps").is_none());
    }
}
