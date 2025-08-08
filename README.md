# CTF Writeups

[![English](https://img.shields.io/badge/README-English-blue)](README.md)
[![한국어](https://img.shields.io/badge/README-한국어-red)](README_ko.md)

A collection of Capture The Flag (CTF) challenge solutions and writeups.
Primarily focusing on pwnable challenges.

## Repository Structure

```
ctf-writeup/
├── [Competition Name]/
│   ├── [Year]/
│   │   ├── [Category]/
│   │   │   ├── [Challenge Name]/
│   │   │   │   ├── README.md          # Challenge writeup
│   │   │   │   ├── exploit.py         # Exploit code
│   │   │   │   └── files/             # Challenge files
│   │   │   └── ...
│   │   └── ...
│   └── ...
└── README.md
```

## Categories

- **Pwn** - Binary exploitation challenges
- **Web** - Web application security challenges  
- **Crypto** - Cryptography challenges
- **Rev** - Reverse engineering challenges
- **Forensics** - Digital forensics challenges
- **Misc** - Miscellaneous challenges

## Writeup Format

Each challenge writeup should include:

1. **Challenge Description** - Problem statement and provided files
2. **Analysis** - Initial reconnaissance and vulnerability identification
3. **Exploitation** - Step-by-step solution process
4. **Solution** - Final exploit code and flag
5. **Lessons Learned** - Key takeaways and techniques used

## Development Setup

### Prerequisites
- Python 3.x
- pwntools (`pip install pwntools`)
- GDB with pwndbg (for pwn challenges)
- Common CTF tools as needed

### Running Solutions
```bash
# Navigate to challenge directory
cd [Competition]/[Year]/[Category]/[Challenge]

# For interactive challenges
python3 exploit.py
```

## Contributing

When adding new writeups:
1. Follow the established directory structure
2. Include all relevant files and documentation
3. Test solutions before committing
4. Use clear, educational explanations in writeups
