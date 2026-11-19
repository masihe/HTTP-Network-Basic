# HTTP-Network-Basic

HTTP와 네트워크 통신의 기초를 **실제 패킷을 보면서** 배우는 학습용 레포입니다.

책에서 "TCP는 3-way handshake로 연결을 맺는다", "HTTP는 요청과 응답으로 이루어진다", "HTTPS는 암호화된다"라고 읽은 내용을, 직접 만든 작은 서버와 클라이언트로 통신을 일으키고 Wireshark로 잡아서 눈으로 확인합니다.

## 무엇을 보게 되나

브라우저에 `https://example.com`을 입력하면, 아래 층이 위에서부터 차례로 쌓여서 전송됩니다. 실습은 이 그림을 **아래층부터** 하나씩 올라가며 봅니다.

```
┌──────────────────────────────────────────┐
│ HTTP   GET / HTTP/1.1 ...  쿠키, 세션    │  02, 04
├──────────────────────────────────────────┤
│ TLS    암호화 (HTTPS일 때만)             │  05
├──────────────────────────────────────────┤
│ TCP    연결, 순서 보장, handshake         │  01
├──────────────────────────────────────────┤
│ IP     주소 ← 이름을 주소로 바꾸는 DNS    │  03
└──────────────────────────────────────────┘
```

## 학습 순서

| 폴더 | 주제 | 직접 보게 되는 것 | 캡처 어댑터 |
|---|---|---|---|
| [00-setup](00-setup/README.md) | 준비 | Wireshark·Npcap 설치, 첫 캡처 | loopback |
| [01-tcp-connection](01-tcp-connection/README.md) | TCP | SYN / SYN-ACK / ACK, 데이터, FIN, Seq·Ack 번호 | loopback |
| [02-http-raw](02-http-raw/README.md) | HTTP 메시지 | 요청 줄·헤더·빈 줄·본문이 `\r\n`으로 이어진 텍스트, 상태 코드 200/400/404/405 | loopback |
| [03-dns](03-dns/README.md) | DNS | 이름 → 주소 → TCP 연결 → HTTP로 이어지는 실제 인터넷 요청 | Wi-Fi / 이더넷 |
| [04-keepalive-cookie-session](04-keepalive-cookie-session/README.md) | 연결 재사용, 상태 유지 | keep-alive로 연결 하나를 재사용하는 모습, Set-Cookie와 Cookie, 세션 | loopback |
| [05-https-tls](05-https-tls/README.md) | HTTPS | 암호화로 가려지는 것과 남는 것(SNI), 키로 복호화한 HTTP | Wi-Fi / 이더넷 |

각 폴더의 README는 같은 순서로 되어 있습니다.
1. 이 실습에서 무엇을 보는지
2. 실행 명령
3. Wireshark에서 찾을 것(관찰 포인트)
4. **관찰 기록**: 직접 보고 채우는 빈칸

관찰 기록을 채우는 것이 이 레포의 핵심입니다. 실습을 마치면 각 README가 내 실험 노트가 됩니다.

## 사용한 프로그램

### 관찰 도구

| 프로그램 | 무엇인가 | 이 레포에서 쓰는 곳 |
|---|---|---|
| **Wireshark** | 네트워크를 지나가는 패킷을 잡아서 계층별로 해석해 보여주는 프로그램입니다. 필터로 원하는 패킷만 골라 보고, Follow Stream으로 연결 하나의 대화를 모아 봅니다. | 모든 실습 |
| **Npcap** | Windows용 패킷 캡처 드라이버입니다. 운영체제 안쪽에서 패킷을 복사해 Wireshark에 넘겨줍니다. Wireshark는 화면이고, Npcap은 실제로 패킷을 잡는 손입니다. 127.0.0.1 통신을 잡는 loopback 어댑터도 Npcap이 만듭니다. | 모든 캡처 |
| **tshark** | Wireshark의 명령줄 버전입니다. Wireshark를 설치하면 함께 들어옵니다(`C:\Program Files\Wireshark\tshark.exe`). `-D`는 어댑터 목록을 보여주고, `-i`로 어댑터를 골라 캡처합니다. | 설치 확인, 캡처 결과 검증 |
| **브라우저 개발자도구** (F12) | 브라우저가 보낸 요청과 받은 응답을 보여줍니다. **Network** 탭에서 헤더를, **Application** 탭에서 저장된 쿠키를 봅니다. 패킷이 아니라 브라우저가 이해한 HTTP 수준의 정보입니다. | 02, 04 |

### 요청을 보내는 도구

| 프로그램 | 무엇인가 | 이 레포에서 쓰는 곳 |
|---|---|---|
| **curl** (`curl.exe`) | 명령줄에서 HTTP 요청을 보내는 프로그램입니다. `-v`를 붙이면 보낸 줄(`>`)과 받은 줄(`<`)을 모두 출력합니다. `-d`는 본문을 보내고, `-H`는 헤더를 추가하고, `-c`/`-b`는 쿠키를 저장하고 보냅니다. Windows 10 이후에는 기본으로 들어 있습니다. | 02, 03, 04 |
| **nslookup** | DNS 서버에 "이 이름의 주소가 뭐냐"고 직접 물어보는 Windows 기본 명령입니다. | 03 |
| **ipconfig /flushdns** | Windows가 기억해 둔 DNS 결과(캐시)를 지웁니다. 이 PC에서는 관리자 권한이 필요했습니다. | 03 |

### 서버와 클라이언트를 만든 재료 (Python 3.11 표준 라이브러리)

추가 설치 없이 Python에 기본으로 들어 있는 모듈만 썼습니다.

| 모듈 | 무엇인가 | 쓰는 곳 |
|---|---|---|
| `socket` | TCP 연결을 직접 열고, 바이트를 보내고 받는 가장 낮은 수준의 도구입니다. HTTP가 무엇인지 모르고 바이트만 다룹니다. | 01, 02 |
| `http.server` | HTTP 요청 파싱과 응답 형식을 대신 처리해 주는 간단한 웹 서버 틀입니다. | 04, 00의 첫 캡처 |
| `http.client`, `ssl` | HTTPS 요청을 보내는 클라이언트입니다. `ssl`이 OpenSSL로 TLS를 처리하고, Wireshark 복호화용 키 파일을 남길 수 있습니다. | 05 |
| `http.cookies`, `secrets` | 쿠키 헤더 파싱, 추측할 수 없는 세션 ID 생성 | 04 |

02는 일부러 `socket`만으로 HTTP를 손으로 파싱하고, 04는 `http.server`에 맡겼습니다. 둘을 비교하면 웹 프레임워크가 무엇을 대신해 주는지 볼 수 있습니다.

### 설치를 도운 도구

| 프로그램 | 무엇인가 |
|---|---|
| **winget** | Windows 기본 패키지 설치 도구입니다. Wireshark를 설치할 때 썼습니다. Npcap은 winget에 없어서 공식 사이트에서 받았습니다. |

## 준비물

- Windows 10/11
- Python 3.11 이상
- Wireshark + Npcap: [00-setup](00-setup/README.md)을 따라 설치합니다.
- 인터넷 연결(03, 05)

## 자주 걸리는 것

- **PowerShell에서 `curl`이 이상하게 동작한다**: Windows PowerShell 5.1에서 `curl`은 `Invoke-WebRequest`의 별칭입니다. 항상 `curl.exe`라고 씁니다.
- **localhost 통신이 Wireshark에 안 보인다**: Wi-Fi가 아니라 **Adapter for loopback traffic capture**에서 캡처해야 합니다.
- **포트가 이미 사용 중이다**: 서버마다 `--port` 인자로 다른 포트를 쓸 수 있습니다. 클라이언트에도 같은 포트를 넘깁니다.
- **파일이 git에 올라가면 안 된다**: 04의 `cookies.txt`와 05의 TLS 키 파일(`sslkeys*.txt`, `*.keylog`)은 `.gitignore`에 들어 있습니다. 특히 TLS 키 파일이 있으면 캡처한 HTTPS를 누구나 풀 수 있습니다.

## 폴더 구조

```
HTTP-Network-Basic/
├─ README.md                        ← 지금 이 문서
├─ 00-setup/README.md               Wireshark·Npcap 설치와 첫 캡처
├─ 01-tcp-connection/
│  ├─ server.py                     받은 바이트를 출력하고 그대로 돌려주는 TCP 서버
│  └─ client.py                     문자열 하나를 보내고 닫는 TCP 클라이언트
├─ 02-http-raw/
│  ├─ server.py                     socket만으로 만든 HTTP 서버 (원본 바이트 출력)
│  ├─ request.txt                   손으로 쓴 HTTP 요청
│  └─ send_raw.py                   request.txt를 그대로 보내는 도구
├─ 03-dns/README.md                 코드 없이 nslookup·curl·Wireshark로 관찰
├─ 04-keepalive-cookie-session/
│  └─ server.py                     로그인 쿠키와 세션, 연결 재사용을 보여주는 서버
└─ 05-https-tls/
   └─ client.py                     TLS 정보 출력, 키 파일 기록 HTTPS 클라이언트
```
