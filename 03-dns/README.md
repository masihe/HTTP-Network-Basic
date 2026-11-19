# 03. DNS: 이름을 주소로 바꾸고 나서야 연결이 시작된다

01과 02에서는 `127.0.0.1`이라는 주소를 직접 썼습니다. 하지만 브라우저에는 보통 `example.com` 같은 **이름**을 입력합니다.
TCP 연결은 IP 주소로만 맺을 수 있어서, 연결 전에 이름을 주소로 바꾸는 단계가 필요합니다. 그 일을 하는 것이 **DNS**(도메인 이름을 IP 주소로 바꿔 주는 전화번호부 같은 서비스)입니다.

이 실습에는 코드가 없습니다. 실제 인터넷에 있는 `example.com`에 요청하고, 그 흐름을 Wireshark로 봅니다.

```
① DNS 질의:   내 PC → DNS 서버 (UDP 53번)   "example.com의 주소는?"
② DNS 응답:   DNS 서버 → 내 PC              "104.20.23.154 등이다"
③ TCP 연결:   내 PC → 104.20.23.154:80      SYN / SYN-ACK / ACK   (01에서 본 것)
④ HTTP:       GET / HTTP/1.1 ... → 200 OK                          (02에서 본 것)
```

## 준비: 캡처할 어댑터 고르기

이번에는 loopback이 아니라 **실제로 인터넷에 연결된 어댑터**에서 캡처합니다.
Wireshark 첫 화면의 어댑터 목록에서, 이름 옆의 그래프가 움직이고 있는 **Wi-Fi** 또는 **이더넷**을 고르면 됩니다.

## 실행

1. Wireshark에서 그 어댑터로 캡처를 시작하고, 필터에 다음을 입력합니다.

   ```
   dns.qry.name contains "example" || (tcp.port == 80 && ip.addr == 104.20.23.154)
   ```

   필터의 IP는 이 문서를 쓸 때 `nslookup`으로 확인한 값입니다. 바뀌었을 수 있으니, 패킷이 안 보이면 `dns || tcp.port == 80`으로 넓혀서 보세요.

2. **관리자 권한 PowerShell**을 열고 DNS 캐시를 비웁니다. Windows는 한 번 알아낸 주소를 잠시 기억해 둡니다. 캐시가 남아 있으면 ①②가 생략되어 캡처에 나오지 않습니다. 이 PC에서는 이 명령에 관리자 권한이 필요했습니다.

   ```powershell
   ipconfig /flushdns
   ```

3. 일반 PowerShell에서 요청합니다. Windows PowerShell에서 그냥 `curl`이라고 치면 PowerShell 내장 명령(`Invoke-WebRequest`)이 실행되므로 반드시 `curl.exe`로 씁니다.

   ```powershell
   curl.exe -v http://example.com/
   ```

4. 따로 DNS만 물어볼 수도 있습니다.

   ```powershell
   nslookup example.com
   ```

## 관찰 포인트

- **순서**: DNS 질의 → 응답 → SYN → … → HTTP 순으로 찍히는지 확인합니다. DNS 응답이 오기 전에는 SYN이 나가지 않습니다.
- **DNS는 UDP**(연결을 맺지 않고 패킷 하나를 던지는 규약)를 씁니다. DNS 패킷 앞뒤에는 handshake가 없습니다. 01의 TCP와 비교해 보세요.
- DNS 질의는 보통 두 개가 나갑니다. **A**는 IPv4 주소를, **AAAA**는 IPv6 주소를 묻습니다. 응답 패킷을 펼치면 Answers 아래에 주소들이 보입니다.
- DNS 질의 패킷의 **Transaction ID**와 응답의 ID가 같습니다. UDP에는 연결이 없어서, 이 번호로 어떤 질문에 대한 답인지 짝을 맞춥니다.
- `curl.exe -v` 출력의 `Trying 104.20.23.154:80...` 줄이 DNS 응답에서 받은 주소 중 하나인지 확인합니다.
- `nslookup`을 실행하면 출력 첫 줄의 "서버" 주소로 질의가 나갑니다. 이 주소가 내 PC가 쓰는 DNS 서버입니다.

## 잘 안 보일 때

- **DNS 패킷이 하나도 없다**: 캐시가 남아 있을 수 있습니다. 관리자 PowerShell에서 `ipconfig /flushdns`를 다시 실행합니다. 또는 Windows나 브라우저가 DNS over HTTPS(DNS 질의를 HTTPS로 암호화해 보내는 기능)를 쓰고 있을 수 있습니다. 그러면 DNS가 443 포트 안에 숨어서 `dns` 필터로는 보이지 않습니다.
- **HTTP 대신 TLS만 보인다**: `http://`가 아니라 `https://`로 요청한 것입니다. HTTPS는 05에서 봅니다.

## 관찰 기록

- 내 PC가 쓰는 DNS 서버 주소:
- DNS 질의 패킷의 출발 포트와 도착 포트:
- A 응답과 AAAA 응답에서 받은 주소들:
- curl이 실제로 연결한 주소:
- DNS 응답이 도착하고 SYN이 나가기까지 걸린 시간(Time 열의 차이):
- 그 밖에 예상과 달랐던 점:
