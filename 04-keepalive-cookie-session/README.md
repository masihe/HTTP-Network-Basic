# 04. keep-alive와 쿠키·세션

이 실습에서는 두 가지를 봅니다.

1. **keep-alive**: 02의 서버는 응답할 때마다 연결을 닫아서, 요청마다 handshake를 새로 했습니다. HTTP/1.1은 기본적으로 한 TCP 연결로 요청을 여러 개 주고받습니다.
2. **쿠키와 세션**: HTTP는 요청끼리 서로를 기억하지 않습니다. 그런데 로그인 상태는 어떻게 유지될까요? 서버가 **쿠키**(서버가 "다음부터 이 값을 같이 보내라"고 브라우저에 맡겨 두는 작은 문자열)를 내려 주고, 클라이언트가 그 쿠키를 매 요청에 붙여 보내기 때문입니다.

`server.py`는 Python 표준 라이브러리의 `http.server`로 만들었습니다. 02처럼 바이트를 직접 쪼개는 일은 라이브러리에 맡기고, 대신 다음 동작에 집중합니다.

| 요청 | 동작 |
|---|---|
| `GET /` | 로그인 폼 HTML |
| `POST /login` (본문 `name=kim`) | 세션을 만들고 `Set-Cookie: sid=<무작위 32자>` 응답 |
| `GET /me` | `Cookie: sid=...`를 보고 누군지 알아보면 200, 모르면 401 |

세션은 서버 메모리의 dict(`sid → 이름`)에 들어 있습니다. 그래서 **서버를 껐다 켜면 모든 로그인이 풀립니다**. 쿠키에는 이름이 아니라 무작위 sid만 들어 있다는 점에 주목하세요.

서버 터미널의 각 줄 앞에 `[127.0.0.1:64421]`처럼 **클라이언트 포트**가 찍힙니다. 포트가 같으면 같은 TCP 연결이라는 뜻입니다.

## 실행

```powershell
python server.py
```

### 1) keep-alive 보기

URL 두 개를 한 번에 요청합니다.

```powershell
curl.exe -v http://127.0.0.1:8001/ http://127.0.0.1:8001/me
```

curl 출력에 `Reusing existing http: connection`이 보이고, 서버 로그에는 같은 포트가 두 번 찍힙니다.

이번에는 연결을 닫아 달라고 요청합니다.

```powershell
curl.exe -v -H "Connection: close" http://127.0.0.1:8001/ http://127.0.0.1:8001/me
```

서버 로그의 포트가 요청마다 달라집니다.

### 2) 쿠키·세션 보기 (curl)

`-c`는 받은 쿠키를 파일에 저장하고, `-b`는 그 파일의 쿠키를 붙여서 보냅니다. 브라우저가 하는 일을 손으로 하는 것입니다.

```powershell
curl.exe -v http://127.0.0.1:8001/me
```

```powershell
curl.exe -v -c cookies.txt -d "name=kim" http://127.0.0.1:8001/login
```

```powershell
curl.exe -v -b cookies.txt http://127.0.0.1:8001/me
```

```powershell
curl.exe -v -H "Cookie: sid=deadbeef" http://127.0.0.1:8001/me
```

- 첫 번째 `/me`는 쿠키가 없어서 401입니다.
- 로그인 응답의 `< Set-Cookie:` 줄을 확인합니다.
- 세 번째 요청의 `> Cookie:` 줄에 같은 sid가 실려 갑니다. 그래서 200이 나옵니다.
- 마지막은 sid를 지어내서 보낸 경우입니다. 서버의 dict에 없으므로 401입니다.

`cookies.txt`는 실습용 임시 파일이니 다 보고 지워도 됩니다.

### 3) 쿠키·세션 보기 (브라우저)

`http://127.0.0.1:8001/`을 열고 이름을 넣어 로그인한 뒤, `/me` 링크를 누릅니다.
- **개발자도구 → Network**: `/login` 응답 헤더의 `Set-Cookie`, `/me` 요청 헤더의 `Cookie`를 확인합니다.
- **개발자도구 → Application → Cookies → http://127.0.0.1:8001**: 브라우저가 저장한 sid가 보입니다. 여기서 쿠키를 지우고 `/me`를 새로고침하면 401이 됩니다.
- 쿠키에 붙은 `HttpOnly`는 페이지의 JavaScript(`document.cookie`)가 이 쿠키를 읽지 못하게 막는 표시입니다. 콘솔에 `document.cookie`를 입력해서 확인해 보세요.

## Wireshark로 보기

**Adapter for loopback traffic capture**에서 캡처하고, 필터에 `tcp.port == 8001`을 입력합니다.

- keep-alive 명령을 실행하면 **SYN이 한 번**만 나오고 그 뒤로 HTTP 요청이 두 개 이어집니다. `Connection: close` 명령에서는 SYN이 두 번 나옵니다.
- 필터를 `tcp.flags.syn == 1 && tcp.flags.ack == 0 && tcp.port == 8001`로 바꾸면 "새 연결 시작"만 남습니다. 두 명령의 줄 수를 비교해 보세요.
- `http.cookie || http.set_cookie` 필터를 쓰면 쿠키가 오가는 패킷만 볼 수 있습니다. sid 값이 **평문**으로 보입니다. HTTPS가 아니면 같은 네트워크의 누군가가 이 값을 훔쳐 내 행세를 할 수 있다는 뜻입니다. 05에서 HTTPS로 이 값이 가려지는 것을 봅니다.

## 관찰 기록

- keep-alive 명령에서 SYN 개수 / `Connection: close` 명령에서 SYN 개수:
- 서버 로그에 찍힌 포트 번호(두 경우):
- 로그인 응답의 Set-Cookie 전체 줄:
- 서버를 재시작한 뒤 같은 cookies.txt로 `/me`를 요청하면 어떻게 되나? 왜 그런가?
- 브라우저 Application 탭에서 본 쿠키의 속성(Path, HttpOnly, SameSite 등):
- 그 밖에 예상과 달랐던 점:
