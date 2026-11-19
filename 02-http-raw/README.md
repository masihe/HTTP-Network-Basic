# 02. HTTP는 TCP 위에 실린 텍스트다

01에서는 TCP 연결 위로 `hello tcp`를 보냈습니다. 그 자리에 정해진 형식의 텍스트를 보내면 그게 **HTTP**입니다.

`server.py`는 웹 프레임워크 없이 소켓만으로 만든 HTTP 서버입니다. 요청 바이트를 직접 읽고 쪼개고, 응답도 문자열을 이어 붙여 만듭니다. 그리고 받은 것과 보낸 것을 원본 바이트 그대로 출력합니다.

| 요청 | 응답 |
|---|---|
| `GET /` | 200 OK, HTML 한 줄 |
| `POST /echo` | 200 OK, 받은 본문을 그대로 돌려줌 |
| `POST /` 처럼 경로는 있는데 메서드가 틀림 | 405 Method Not Allowed + `Allow` 헤더 |
| 없는 경로 | 404 Not Found |
| 형식이 틀린 요청 (요청 줄이 세 부분이 아님, `Content-Length: abc` 등) | 400 Bad Request |

## HTTP 메시지의 모양

```
GET / HTTP/1.1\r\n            ← 요청 줄: 메서드, 경로, 버전
Host: 127.0.0.1:8000\r\n      ← 헤더: "이름: 값" 한 줄씩
Accept: */*\r\n
\r\n                          ← 빈 줄: 헤더가 끝났다는 신호
(본문)                        ← 본문 길이는 Content-Length 헤더로 알려준다
```

응답도 같은 모양입니다. 첫 줄만 `HTTP/1.1 200 OK`(버전, 상태 코드, 설명)로 바뀝니다.
줄바꿈은 반드시 `\r\n`(CR LF, 바이트로는 `0d 0a`)입니다. 서버가 "헤더가 어디서 끝나는지"를 `\r\n\r\n`으로 찾기 때문입니다. `server.py`의 `read_head()`가 바로 이 일을 합니다.

## 실행

```powershell
python server.py
```

다른 터미널에서 다음 세 가지 방법으로 같은 서버에 요청해 봅니다.

**1) 손으로 쓴 요청 보내기**: `request.txt`의 내용을 그대로 보냅니다.

```powershell
python send_raw.py
```

`request.txt`를 고쳐서 다시 보내 보세요. 예를 들어 첫 줄을 `GET /nope HTTP/1.1`로 바꾸거나, `HTTP/1.1`을 지워 보세요.

**2) curl로 보내기**: `-v`를 붙이면 `>`는 보낸 줄, `<`는 받은 줄로 표시됩니다.

```powershell
curl.exe -v http://127.0.0.1:8000/
```

```powershell
curl.exe -v -d "hello body" http://127.0.0.1:8000/echo
```

```powershell
curl.exe -v -X DELETE http://127.0.0.1:8000/echo
```

**3) 브라우저로 보내기**: `http://127.0.0.1:8000/`을 엽니다. F12로 개발자도구를 열고 **Network** 탭에서 새로고침한 뒤 요청을 클릭하면 Headers 탭이 보입니다.

## Wireshark로 보기

1. **Adapter for loopback traffic capture**에서 캡처하고, 필터에 `tcp.port == 8000`을 입력합니다.
2. `curl.exe -v http://127.0.0.1:8000/`을 실행합니다.
3. 필터를 `http`로 바꾸면 Wireshark가 HTTP로 해석한 패킷만 남습니다.
4. 아무 패킷이나 우클릭하고 **Follow → HTTP Stream**(또는 TCP Stream)을 누릅니다.

### 관찰 포인트

- HTTP 패킷 앞뒤로 01에서 본 SYN / SYN-ACK / ACK와 FIN이 그대로 있습니다. HTTP는 TCP 연결 **안에서** 오가는 데이터일 뿐입니다.
- 요청 패킷을 클릭해서 아래쪽 바이트 창을 보면 줄 끝마다 `0d 0a`가 있고, 헤더 끝에는 `0d 0a 0d 0a`가 있습니다.
- curl, 브라우저, `send_raw.py`가 보내는 헤더가 서로 다릅니다. 브라우저는 `User-Agent`, `Accept-Language` 같은 헤더를 훨씬 많이 붙입니다. 서버 터미널 출력과 비교해 보세요.
- 브라우저는 `/` 말고 `/favicon.ico`도 요청합니다. 우리 서버는 404로 답합니다.
- 이 서버는 `Connection: close`를 보내고 응답마다 연결을 닫습니다. 그래서 요청마다 handshake가 새로 일어납니다. 연결을 재사용하는 방식은 04에서 봅니다.

## 관찰 기록

- `curl.exe -v`의 `>` 줄과 서버가 출력한 원본 바이트를 비교했을 때 같은가?
- 브라우저가 보낸 헤더 중 curl에는 없던 것:
- `request.txt`에서 무엇을 바꿨을 때 400이 나왔나? 서버는 어떤 이유를 출력했나?
- `POST /echo` 요청에서 Content-Length 값과 실제 본문 길이:
- 그 밖에 예상과 달랐던 점:
