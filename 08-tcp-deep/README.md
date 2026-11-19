# 08. 전송 계층 심화: TCP는 실패와 속도 차이를 어떻게 다루나

01에서는 모든 것이 잘 될 때의 TCP를 봤습니다. 이번에는 일이 꼬일 때를 봅니다.

| 상황 | 스크립트 | 보게 되는 것 |
|---|---|---|
| 아무도 안 기다리는 포트에 접속 | `connect_probe.py` | **RST**(연결을 즉시 거절하는 신호) |
| 응답이 아예 없는 주소에 접속 | `connect_probe.py` | **SYN 재전송**, 간격이 두 배씩 늘어남 |
| 받는 쪽이 읽지 않고 버팀 | `flow_server.py` + `flow_client.py` | **window**가 줄어 0이 됨, 보내는 쪽이 멈춤(**흐름 제어**) |
| TCP 대신 UDP로 보냄 | `udp_echo.py` | handshake도 Seq/Ack도 FIN도 없음 |

Wireshark 필터는 실습마다 아래에 적었습니다. 응답 없는 주소 실습만 Wi-Fi 어댑터에서 캡처하고, 나머지는 **Adapter for loopback traffic capture**에서 캡처합니다.

---

## 1) RST: 문은 있는데 아무도 없다

```powershell
python connect_probe.py --port 9
```

필터: `tcp.port == 9`

- 내 SYN에 상대 운영체제가 곧바로 `[RST, ACK]`로 답합니다. "그 포트에서 기다리는 프로그램이 없다"는 뜻입니다. Python에서는 `ConnectionRefusedError`가 됩니다.
- **이 PC에서 본 Windows의 특이한 동작**: RST를 받고도 바로 포기하지 않습니다. 0.5초 간격으로 SYN을 4번 더 보낸 뒤에 포기합니다. 그래서 스크립트 출력이 약 2초입니다. Wireshark에는 `[TCP Port numbers reused]`라는 표시와 함께 SYN/RST 쌍이 5번 찍힙니다.

## 2) SYN 재전송: 아무 답도 없다

`10.255.255.1`은 이 네트워크에 없는 주소입니다. RST조차 오지 않습니다.

```powershell
python connect_probe.py --host 10.255.255.1 --port 80 --timeout 10
```

필터: `ip.addr == 10.255.255.1` (Wi-Fi 어댑터)

- 같은 SYN이 `[TCP Retransmission]` 표시를 달고 다시 나갑니다.
- **Time 열**을 보면 이 PC에서는 1초 → 2초 → 4초 간격이었습니다. 답이 없으면 기다리는 시간을 두 배씩 늘립니다. 네트워크가 막혔을 때 재전송으로 더 막지 않으려는 장치입니다.
- RST와 비교하세요. "거절당함"은 즉시 알 수 있지만, "답이 없음"은 기다려 보는 수밖에 없습니다.

## 3) 흐름 제어: 받는 쪽이 못 따라올 때

TCP 헤더의 **Window** 값은 "나는 지금 이만큼 더 받을 수 있다"는 뜻입니다. 받는 쪽이 매 ACK마다 이 값을 알려 주고, 보내는 쪽은 그보다 많이 보내지 않습니다.

```powershell
python flow_server.py
```

```powershell
python flow_client.py
```

- 서버는 받는 버퍼를 8192바이트로 작게 잡고, 접속을 받은 뒤 5초 동안 `recv()`를 하지 않습니다.
- 클라이언트는 1024바이트씩 계속 보냅니다. 출력에 `send()가 5.00초 동안 막혔다가 풀림`이 찍힙니다.

필터: `tcp.port == 9100`

이 PC에서 본 순서는 다음과 같습니다.
1. 서버 ACK의 `Win=` 값이 8192에서 1024씩 줄어듭니다.
2. `[TCP Window Full]`: 클라이언트가 window를 꽉 채웠습니다.
3. `[TCP ZeroWindow]`: 서버가 `Win=0`을 알립니다. 더 받을 수 없다는 뜻입니다.
4. `[TCP ZeroWindowProbe]`: 클라이언트가 1바이트짜리 탐색 패킷으로 "이제 열렸어?"라고 묻습니다. 간격이 0.3 → 0.6 → 1.2 → 2.4초로 늘어납니다.
5. 5초 뒤 서버가 읽기 시작하면 `[TCP Window Update]`로 window가 다시 열리고, 데이터가 몰려서 나갑니다.

`--chunk 1000`으로 바꿔서 해 보세요. 8192는 1000으로 나눠떨어지지 않습니다. window가 192에서 멈추고, 클라이언트는 1000바이트 조각을 보낼 수 없어서 기다립니다. 정확히 0이 되지는 않지만 흐름 제어는 똑같이 일어납니다.

메뉴 **Statistics → TCP Stream Graphs → Window Scaling**을 열면 window 변화를 그래프로 볼 수 있습니다.

## 4) UDP: 연결 없이 던지기

```powershell
python udp_echo.py server
```

```powershell
python udp_echo.py client
```

필터: `udp.port == 9300`

- 패킷이 **딱 2개**입니다. 보낸 것 하나, 돌려받은 것 하나입니다. SYN도 ACK도 FIN도 없습니다.
- 패킷을 펼쳐 보면 UDP 헤더에는 출발 포트, 도착 포트, 길이, 체크섬 4개뿐입니다. 8바이트입니다. TCP 헤더(최소 20바이트)의 Seq, Ack, Window, Flags가 없습니다. 그래서 순서 보장, 재전송, 흐름 제어도 없습니다.
- 서버를 끄고 클라이언트만 실행해 보세요. Windows는 상대 운영체제가 보낸 ICMP "Port Unreachable"을 `ConnectionResetError`로 알려 줍니다. 이 PC의 **loopback 캡처에는 ICMP 패킷이 나타나지 않았습니다**. Windows가 내부에서 처리하는 것으로 보입니다.
- 03의 DNS가 UDP를 쓰는 이유를 생각해 보세요. 짧은 질문 하나에 답 하나면 끝나는 일에 handshake까지 하면 느리기 때문입니다.

## 관찰 기록

- RST 실습에서 SYN/RST 쌍은 몇 번 찍혔나? 마지막 시도까지 걸린 시간:
- SYN 재전송 간격(Time 열의 차이):
- 흐름 제어에서 `Win=` 값이 줄어든 순서와, ZeroWindow가 처음 나온 시각:
- ZeroWindowProbe 간격:
- `--chunk 1000`일 때 마지막 window 값:
- UDP 헤더 4개 필드의 값:
- 그 밖에 예상과 달랐던 점:
