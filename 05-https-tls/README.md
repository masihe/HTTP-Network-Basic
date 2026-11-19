# 05. HTTPS: TLS가 무엇을 가리고 무엇을 남기나

04에서 쿠키의 sid가 Wireshark에 평문으로 그대로 보였습니다. **HTTPS**는 HTTP를 그대로 둔 채, TCP와 HTTP 사이에 **TLS**(데이터를 암호화하고 상대 서버가 진짜인지 인증서로 확인하는 규약) 층을 하나 끼운 것입니다.

```
HTTP     GET / HTTP/1.1 ...      ← 02~04에서 본 텍스트 그대로
TLS      (암호화)                ← 이번에 새로 끼는 층
TCP      SYN / SYN-ACK / ACK     ← 01에서 본 것
IP
```

이 실습은 두 번 캡처합니다.
1. **키 없이** 보기: 암호화된 덩어리만 보입니다. 그래도 보이는 정보가 무엇인지 확인합니다.
2. **키를 넣고** 보기: Wireshark가 암호를 풀면 02에서 본 HTTP 텍스트가 다시 나타납니다.

## 왜 curl이 아니라 client.py인가

Wireshark가 TLS를 풀려면, 클라이언트가 대화에 쓴 키를 파일로 남겨 줘야 합니다(`SSLKEYLOGFILE` 형식).
이 PC에서 직접 시험해 본 결과는 다음과 같습니다.

| 클라이언트 | TLS 라이브러리 | 키 파일 |
|---|---|---|
| `C:\Windows\System32\curl.exe` | Schannel(Windows 내장) | 지원하지 않음 |
| Git에 들어 있는 curl | Schannel | 지원하지 않음 |
| curl.se 공식 Windows 빌드 8.23.0 | LibreSSL | 파일은 생기지만 **0바이트** |
| Python 3.11 `ssl` | OpenSSL 3.0 | TLS 1.3 키 5종이 기록됨 |

그래서 Python 표준 라이브러리로 만든 `client.py`를 씁니다.
`client.py`는 `example.com`에 HTTPS GET을 보내고, TLS 버전, 암호 방식, 인증서 정보, HTTP 응답 헤더를 출력합니다. `--keylog`를 주면 TLS 키를 그 파일에 기록합니다.

## 실행

이번에도 인터넷으로 나가는 통신이므로, Wireshark에서 03과 같은 **Wi-Fi 또는 이더넷** 어댑터로 캡처합니다.

### 1) 키 없이 캡처

필터에 `tls && ip.addr == 104.20.23.154`를 입력하고 캡처를 시작합니다. 주소는 03에서 `nslookup`으로 확인한 값을 넣으세요. 잘 안 잡히면 `tcp.port == 443`으로 넓힙니다.

```powershell
python client.py
```

관찰 포인트:
- 첫 TLS 패킷은 **Client Hello**입니다. 펼쳐서 `Extension: server_name`을 찾으면 `example.com`이 **평문으로** 보입니다. 이것을 **SNI**(클라이언트가 어느 사이트에 접속하려는지 서버에 알려주는 값)라고 합니다. 접속하는 사이트 이름은 HTTPS로도 가려지지 않는다는 뜻입니다.
- Server Hello 다음부터는 `Application Data`만 이어집니다. 경로(`/`), 헤더, 쿠키, 본문 중 어느 것도 보이지 않습니다.
- 필터를 `http`로 바꾸면 아무것도 남지 않습니다.

### 2) 키를 넣고 캡처

```powershell
python client.py --keylog sslkeys.txt
```

1. Wireshark에서 **Edit → Preferences → Protocols → TLS**를 엽니다. 버전에 따라 Protocols 목록에서 TLS를 찾아야 합니다.
2. **(Pre)-Master-Secret log filename**에 방금 생긴 `sslkeys.txt`의 전체 경로를 넣고 OK를 누릅니다.
3. 필터를 `http`로 바꿉니다. 아까 안 보이던 `GET / HTTP/1.1`과 `HTTP/1.1 200 OK`가 나타납니다.
4. 패킷 하나를 우클릭하고 **Follow → TLS Stream**을 누르면, 02에서 본 것과 같은 모양의 HTTP 텍스트가 보입니다.

`sslkeys.txt`가 있으면 이 캡처를 누구나 풀 수 있습니다. 실습이 끝나면 지우세요. 레포의 `.gitignore`에도 들어 있어서 git에는 올라가지 않습니다.

## 관찰 포인트 (공통)

- **handshake가 두 번**입니다. TCP handshake(SYN…)가 끝난 뒤에 TLS handshake(Client Hello, Server Hello…)가 또 일어납니다. HTTP 요청은 그 뒤에야 나갑니다. Time 열로 HTTP보다 얼마나 늦어지는지 확인해 보세요.
- `client.py` 출력의 `TLSv1.3`, 암호 방식은 Server Hello 패킷에서도 확인할 수 있습니다.
- 응답 헤더에 `Content-Length` 대신 `Transfer-Encoding: chunked`가 있습니다. 서버가 전체 길이를 미리 알리지 않고 조각으로 나눠 보내는 방식입니다. 02의 서버가 `Content-Length`로 본문 끝을 알린 것과 비교해 보세요.

## 처음 실행할 때 인증서 오류가 나면

`CERTIFICATE_VERIFY_FAILED: unable to get local issuer certificate`가 나올 수 있습니다. 이 PC에서도 처음에 이 오류가 났습니다.

Windows는 루트 인증서(인증서 신뢰 사슬의 맨 꼭대기)를 처음 필요할 때 인터넷에서 받아 저장합니다. 하지만 Python(OpenSSL)은 이미 저장된 것만 읽고, 이 자동 다운로드를 하지 않습니다. Windows 기본 curl로 한 번 접속하면 Windows가 루트 인증서를 받아 두므로, 그다음부터는 Python도 성공합니다.

```powershell
curl.exe -sI https://example.com/
```

## 관찰 기록

- Client Hello에서 보인 SNI 값:
- 키 없이 볼 때 알 수 있었던 것 / 알 수 없었던 것:
- 키를 넣은 뒤 보인 요청 줄과 응답 상태 줄:
- TCP SYN부터 HTTP 요청이 나가기까지 걸린 시간 (02의 HTTP와 비교):
- 04의 sid 쿠키를 HTTPS로 보냈다면 Wireshark에서 어떻게 보였을까?
- 그 밖에 예상과 달랐던 점:
