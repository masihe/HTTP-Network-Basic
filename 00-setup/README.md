# 00. 준비: Wireshark와 Npcap 설치

## 무엇을 설치하나

| 프로그램 | 하는 일 |
|---|---|
| **Npcap** | Windows 안쪽에 설치되는 드라이버입니다. 네트워크를 지나가는 패킷을 복사해서 프로그램에 넘겨주는 "손" 역할을 합니다. 관리자 권한이 필요합니다. |
| **Wireshark** | Npcap이 넘겨준 패킷을 해석해서 보여주는 "화면" 역할을 합니다. `tshark`(명령줄판 Wireshark)도 함께 설치됩니다. |

Wireshark만 설치하고 Npcap이 없으면, 프로그램은 열리지만 캡처할 어댑터가 하나도 나오지 않습니다.

이 PC에는 Python 3.11과 curl이 이미 있어서 따로 설치하지 않았습니다. curl은 Windows에 기본으로 들어 있는 `curl.exe`를 씁니다.

## 설치 순서

### 1. Wireshark

둘 중 하나를 고릅니다.

- winget(Windows 기본 패키지 설치 도구)으로 설치하기. `--interactive`를 붙여야 설치 화면이 뜹니다.

  ```powershell
  winget install --id WiresharkFoundation.Wireshark --exact --interactive
  ```

- 또는 https://www.wireshark.org/download.html 에서 Windows x64 Installer를 받아 실행하기.

설치 화면에서 Npcap을 함께 설치하는 항목이 보이면 켜 둡니다. 이 PC에서는 Wireshark 4.6.10을 winget으로 설치했는데 Npcap이 설치되지 않았습니다. 그래서 다음 단계에서 Npcap을 따로 설치했습니다.

### 2. Npcap

Npcap은 라이선스 때문에 winget에 없습니다. 공식 사이트에서만 받을 수 있습니다.

1. https://npcap.com/#download 에서 **Npcap installer**를 받습니다. 이 문서를 쓸 때의 최신 버전은 `npcap-1.90.exe`, 약 1.3MB였습니다.
2. 실행하고, UAC 창에서 **예**를 누른 뒤 라이선스 화면에서 **I Agree**를 누릅니다.
3. 옵션 화면은 다음과 같이 둡니다.
   - **Support loopback traffic capture** 항목이 보이면 **체크**합니다. 127.0.0.1끼리의 통신(실습 01, 02, 04)을 잡으려면 꼭 필요합니다.
   - **Restrict Npcap driver's access to Administrators only**는 **체크하지 않습니다**. 체크하면 Wireshark를 매번 관리자 권한으로 실행해야 합니다.
   - **Support raw 802.11 traffic**은 체크하지 않습니다.
   - 나머지는 기본값으로 둡니다.
4. **Install**을 누르고 끝나면 **Finish**를 누릅니다.
5. **PC를 재시작**합니다.

## 설치 확인

### 어댑터 목록

```powershell
& "C:\Program Files\Wireshark\tshark.exe" -D
```

목록에 다음 두 종류가 보이면 성공입니다.
- `Adapter for loopback traffic capture`: 01, 02, 04 실습용입니다.
- `Wi-Fi` 또는 `이더넷`: 03, 05 실습용입니다.

`Unable to load Npcap`이 나오면 Npcap이 설치되지 않았거나 재시작이 필요한 상태입니다.

### 첫 캡처

1. Wireshark를 열고 **Adapter for loopback traffic capture**를 더블클릭합니다.
2. 필터 칸에 `tcp.port == 8080`을 입력합니다.
3. 터미널 하나에서 Python 내장 웹 서버를 켭니다.

   ```powershell
   python -m http.server 8080 --bind 127.0.0.1
   ```

4. 다른 터미널에서 요청합니다. Windows PowerShell에서 `curl`이라고만 치면 PowerShell 내장 명령(`Invoke-WebRequest`)이 실행되므로 `curl.exe`라고 씁니다.

   ```powershell
   curl.exe http://127.0.0.1:8080/
   ```

5. Wireshark에 `[SYN]`, `GET / HTTP/1.1`, `HTTP/1.1 200 OK` 같은 줄이 찍히면 준비가 끝난 것입니다. 웹 서버는 Ctrl+C로 끕니다.

## Wireshark 화면 읽는 법 (최소한)

| 영역 | 내용 |
|---|---|
| 위: 패킷 목록 | 한 줄이 패킷 하나입니다. **Time**(캡처 시작 후 초), **Source → Destination**, **Protocol**, **Info**(요약) |
| 가운데: 상세 | 고른 패킷을 계층별로 펼쳐 봅니다. Frame → Ethernet/Null → IP → TCP → HTTP 순서로 쌓여 있습니다. |
| 아래: 바이트 | 실제로 전송된 바이트입니다. 왼쪽은 16진수, 오른쪽은 글자입니다. |

- 필터 칸에 조건을 입력하고 Enter를 누르면 맞는 패킷만 남습니다. 칸이 초록색이면 문법이 맞고, 빨간색이면 틀린 것입니다.
- 빨간 네모 버튼은 캡처 중지, 상어 지느러미 버튼은 캡처 시작입니다.
