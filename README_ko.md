# CTF Writeups

[![English](https://img.shields.io/badge/README-English-blue)](README.md)
[![한국어](https://img.shields.io/badge/README-한국어-red)](README_ko.md)

CTF(Capture The Flag) 챌린지 솔루션과 writeup 모음집입니다.
주로 pwnable 영역의 문제를 풀고 있습니다.

## 레포지토리 구조

```
ctf-writeup/
├── [대회명]/
│   ├── [연도]/
│   │   ├── [카테고리]/
│   │   │   ├── [문제명]/
│   │   │   │   ├── README.md          # 문제 writeup
│   │   │   │   ├── exploit.py         # 익스플로잇 코드
│   │   │   │   └── files/             # 문제 파일들
│   │   │   └── ...
│   │   └── ...
│   └── ...
└── README.md
```

## 카테고리

- **Pwn** - 바이너리 익스플로잇 문제
- **Web** - 웹 애플리케이션 보안 문제  
- **Crypto** - 암호학 문제
- **Rev** - 리버스 엔지니어링 문제
- **Forensics** - 디지털 포렌식 문제
- **Misc** - 기타 문제

## Writeup 형식

각 문제의 writeup은 다음 내용을 포함해야 합니다:

1. **문제 설명** - 문제 내용과 제공된 파일들
2. **분석** - 초기 조사 및 취약점 식별
3. **익스플로잇** - 단계별 해결 과정
4. **솔루션** - 최종 익스플로잇 코드와 플래그
5. **배운 점** - 핵심 내용과 사용된 기법들

## 개발 환경 설정

### 필수 도구
- Python 3.x
- pwntools (`pip install pwntools`)
- pwndbg가 설치된 GDB (pwn 문제용)
- 기타 필요한 CTF 도구들

### 솔루션 실행
```bash
# 문제 디렉토리로 이동
cd [대회명]/[연도]/[카테고리]/[문제명]

# 대화형 문제의 경우
python3 exploit.py
```

## 기여하기

새로운 writeup을 추가할 때:
1. 정해진 디렉토리 구조를 따라주세요
2. 관련 파일과 문서를 모두 포함해주세요
3. 커밋하기 전에 솔루션을 테스트해주세요
4. writeup에서 명확하고 교육적인 설명을 사용해주세요