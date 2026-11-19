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
│ TCP    연결, 순서 보장, handshake         │  01, 08
├──────────────────────────────────────────┤
│ IP     주소, TTL, 분할 ← 이름→주소는 DNS  │  03, 07
├──────────────────────────────────────────┤
│ 링크   MAC 주소, ARP                      │  06
└──────────────────────────────────────────┘
          ↑ 이 겹겹의 포장을 바이트로 직접 벗겨 보기: 09
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

### TCP/IP 심화 (아래 계층부터)

00~05를 마친 뒤, 각 계층이 어떻게 동작하는지 한 층씩 더 깊이 봅니다.

| 폴더 | 계층 | 직접 보게 되는 것 | 캡처 어댑터 |
|---|---|---|---|
| [06-link-layer-arp](06-link-layer-arp/README.md) | 링크 | 도착 MAC은 게이트웨이, 도착 IP는 최종 목적지. ARP 브로드캐스트. loopback에는 MAC이 없음 | Wi-Fi / 이더넷 |
| [07-ip-icmp](07-ip-icmp/README.md) | 네트워크 | TTL과 라우터의 TTL 초과 알림(tracert), ICMP, 3000바이트 ping이 3조각으로 쪼개지는 IP 분할 | Wi-Fi / 이더넷 |
| [08-tcp-deep](08-tcp-deep/README.md) | 전송 | RST, SYN 재전송(1→2→4초), window가 0이 되는 흐름 제어, TCP와 UDP 비교 | loopback (+ Wi-Fi) |
| [09-encapsulation](09-encapsulation/README.md) | 전체 | 패킷 하나를 Python으로 바이트 단위로 잘라 계층별 헤더 해석, IP 체크섬 직접 계산 | 앞 실습의 캡처 재사용 |

각 폴더의 README는 같은 순서로 되어 있습니다.
1. 이 실습에서 무엇을 보는지
2. 실행 명령
3. Wireshark에서 찾을 것(관찰 포인트)
4. **관찰 기록**: 직접 보고 채우는 빈칸

관찰 기록을 채우는 것이 이 레포의 핵심입니다. 실습을 마치면 각 README가 내 실험 노트가 됩니다.

## 웹 화면으로 테스트하기 (web-lab)

각 챕터를 순서대로 눌러 가며 **실제로 실행하고 결과를 보는** 화면입니다. 버튼을 누르면 이 PC에서 다음 순서로 진행됩니다.
1. 그 챕터의 실습 서버와 클라이언트를 실행합니다.
2. 동시에 dumpcap으로 패킷을 캡처합니다.
3. tshark로 해석한 패킷 표와 자동 확인 결과(✓ / ✗ / !)를 보여 줍니다.

Python 표준 라이브러리만 쓰므로 따로 설치할 것은 없습니다. Wireshark와 Npcap은 [00-setup](00-setup/README.md)대로 설치되어 있어야 합니다.

### 시작

레포 폴더에서 실행합니다.

```powershell
python web-lab\server.py
```

브라우저로 **http://127.0.0.1:8765/** 를 엽니다. 왼쪽에서 챕터를 고르고, 각 테스트의 **실행** 버튼을 누릅니다.

- 테스트는 한 번에 하나씩만 돕니다. 실습 포트(8000, 8001, 9000 등)를 함께 쓰기 때문입니다.
- 테스트가 띄운 실습 서버와 캡처 프로그램은 **그 테스트가 끝나면 바로 꺼집니다**.
- 터미널에서 실습 서버를 따로 켜 두었다면 포트가 겹쳐서 테스트가 "이미 다른 프로그램이 쓰고 있습니다"로 멈춥니다. 그 서버를 끄고 다시 누르세요.
- 이 서버는 내 PC 안(127.0.0.1)에서만 접속을 받고, 미리 정해 둔 테스트만 실행합니다.
- 관리자 권한이 필요한 단계, Wireshark 화면에서 직접 클릭하는 단계, 브라우저 개발자도구는 자동으로 할 수 없습니다. 그런 단계는 각 챕터의 "직접 해 볼 것"에 따로 적었습니다.

### 종료

둘 중 하나로 끕니다.
- 서버를 실행한 터미널에서 **Ctrl+C**
- 화면 오른쪽 위의 **서버 종료** 버튼

어느 쪽이든 서버는 다음 일을 하고 끝납니다.
1. 실행 중이던 테스트 프로그램이 있으면 자식 프로세스까지 끝냅니다.
2. 임시 폴더(캡처 파일, 05의 TLS 키 파일)를 지웁니다.
3. 터미널에 `[web-lab] 종료했습니다. 테스트가 띄운 프로그램은 모두 끝났습니다.`를 찍습니다.

터미널에 프롬프트가 다시 나오면 끝난 것입니다.

**남은 프로그램이 없는지 확인하기.** 아래 두 명령이 모두 아무것도 출력하지 않으면 정상입니다.

```powershell
Get-Process tshark, dumpcap, Udpdump -ErrorAction SilentlyContinue
```

```powershell
Get-NetTCPConnection -State Listen -LocalPort 8765, 8000, 8001, 8080, 9000, 9100 -ErrorAction SilentlyContinue
```

무언가 남아 있으면 다음을 확인하세요.
- **Udpdump나 tshark가 남아 있다:** 보안 프로그램(V3) 알림 창이 열려 있는지 봅니다. 창에서 차단 후 확인을 누르면 풀립니다. [00-setup의 V3 안내](00-setup/README.md#보안-프로그램v3-알림이-뜨면)를 참고하세요. 창이 없는데도 남아 있으면 PC를 재시작합니다.
- **8765 포트가 남아 있다:** 서버 터미널을 닫지 않은 것입니다. 그 터미널에서 Ctrl+C를 누릅니다.
- 서버가 끝날 때 프로그램을 끝내지 못하면 터미널에 `경고: 끝나지 않은 프로그램이 있습니다 (PID ...)`가 찍힙니다.

## 사용한 프로그램

### 관찰 도구

| 프로그램 | 무엇인가 | 이 레포에서 쓰는 곳 |
|---|---|---|
| **Wireshark** | 네트워크를 지나가는 패킷을 잡아서 계층별로 해석해 보여주는 프로그램입니다. 필터로 원하는 패킷만 골라 보고, Follow Stream으로 연결 하나의 대화를 모아 봅니다. | 모든 실습 |
| **Npcap** | Windows용 패킷 캡처 드라이버입니다. 운영체제 안쪽에서 패킷을 복사해 Wireshark에 넘겨줍니다. Wireshark는 화면이고, Npcap은 실제로 패킷을 잡는 손입니다. 127.0.0.1 통신을 잡는 loopback 어댑터도 Npcap이 만듭니다. | 모든 캡처 |
| **tshark** | Wireshark의 명령줄 버전입니다. Wireshark를 설치하면 함께 들어옵니다(`C:\Program Files\Wireshark\tshark.exe`). `-r`로 캡처 파일을 읽고, `-Y`로 필터를 걸고, `-T fields -e`로 원하는 필드만 뽑습니다. | 웹 테스트의 캡처 해석 |
| **dumpcap** | Wireshark에 들어 있는 캡처 전용 프로그램입니다(`C:\Program Files\Wireshark\dumpcap.exe`). `-D`는 어댑터 목록, `-i`는 캡처할 어댑터, `-w`는 저장할 파일입니다. tshark와 달리 시작할 때 extcap 보조 도구(Udpdump 등)를 실행하지 않습니다. | 설치 확인, 웹 테스트의 캡처 |
| **브라우저 개발자도구** (F12) | 브라우저가 보낸 요청과 받은 응답을 보여줍니다. **Network** 탭에서 헤더를, **Application** 탭에서 저장된 쿠키를 봅니다. 패킷이 아니라 브라우저가 이해한 HTTP 수준의 정보입니다. | 02, 04 |

### 요청을 보내는 도구

| 프로그램 | 무엇인가 | 이 레포에서 쓰는 곳 |
|---|---|---|
| **curl** (`curl.exe`) | 명령줄에서 HTTP 요청을 보내는 프로그램입니다. `-v`를 붙이면 보낸 줄(`>`)과 받은 줄(`<`)을 모두 출력합니다. `-d`는 본문을 보내고, `-H`는 헤더를 추가하고, `-c`/`-b`는 쿠키를 저장하고 보냅니다. Windows 10 이후에는 기본으로 들어 있습니다. | 02, 03, 04 |
| **nslookup** | DNS 서버에 "이 이름의 주소가 뭐냐"고 직접 물어보는 Windows 기본 명령입니다. | 03 |
| **ipconfig /flushdns** | Windows가 기억해 둔 DNS 결과(캐시)를 지웁니다. 이 PC에서는 관리자 권한이 필요했습니다. | 03 |
| **ipconfig**, **arp -a** | 내 IP, 서브넷, 기본 게이트웨이를 보여 주고(`ipconfig`), Windows가 기억하는 IP → MAC 표를 보여 줍니다(`arp -a`). | 06 |
| **ping** | ICMP Echo 요청을 보내고 응답을 기다립니다. `-i`는 TTL 시작값, `-l`은 데이터 크기, `-n`은 보낼 횟수입니다. | 06, 07 |
| **tracert** | TTL을 1부터 늘려 가며 보내서, 목적지까지 거치는 라우터를 한 단계씩 찾아냅니다. `-d`는 주소를 이름으로 바꾸지 않게 합니다. | 07 |

### 서버와 클라이언트를 만든 재료 (Python 3.11 표준 라이브러리)

추가 설치 없이 Python에 기본으로 들어 있는 모듈만 썼습니다.

| 모듈 | 무엇인가 | 쓰는 곳 |
|---|---|---|
| `socket` | TCP 연결을 직접 열고, 바이트를 보내고 받는 가장 낮은 수준의 도구입니다. HTTP가 무엇인지 모르고 바이트만 다룹니다. UDP 소켓도 만듭니다. | 01, 02, 08 |
| `subprocess`, `threading` | 다른 프로그램(실습 서버, dumpcap, tshark, curl)을 실행하고 그 출력을 읽습니다. | web-lab |
| `struct`, `ipaddress` | 바이트 묶음을 정해진 자리에서 숫자로 읽고(`struct`), 4바이트를 IP 주소로 바꿉니다(`ipaddress`). | 09 |
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
├─ 05-https-tls/
│  └─ client.py                     TLS 정보 출력, 키 파일 기록 HTTPS 클라이언트
├─ 06-link-layer-arp/README.md      코드 없이 ipconfig·arp·ping·Wireshark로 관찰
├─ 07-ip-icmp/README.md             코드 없이 ping·tracert·Wireshark로 관찰
├─ 08-tcp-deep/
│  ├─ connect_probe.py              접속 한 번 시도: 성공 / RST / 시간 초과
│  ├─ flow_server.py                읽지 않고 버티는 서버 (window 0 만들기)
│  ├─ flow_client.py                계속 보내다 막히는 순간을 출력하는 클라이언트
│  └─ udp_echo.py                   UDP 에코 서버·클라이언트
├─ 09-encapsulation/
│  └─ dissect.py                    Hex Stream 패킷을 계층별로 해부
└─ web-lab/                         챕터별 자동 테스트 웹 화면
   ├─ server.py                     127.0.0.1:8765 서버. 종료할 때 테스트 프로그램과 임시 파일 정리
   ├─ chapters.py                   챕터 설명과 테스트 20개 정의
   ├─ runner.py                     명령 실행, 실습 서버 띄우기, dumpcap 캡처, tshark 해석
   └─ index.html                    화면
```
