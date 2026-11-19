"""TCP 클라이언트: 서버에 접속해 문자열 하나를 보내고, 돌아온 응답을 출력한 뒤 연결을 닫는다."""

import argparse
import socket


def send_once(host: str, port: int, message: str) -> bytes:
    """host:port에 접속해 message를 UTF-8로 보내고 서버가 돌려준 바이트를 반환한다."""
    payload = message.encode("utf-8")
    # create_connection() 안에서 SYN → SYN-ACK → ACK가 오간다.
    with socket.create_connection((host, port), timeout=5) as sock:
        print(f"[client] 연결됨: {sock.getsockname()} -> {sock.getpeername()}")
        sock.sendall(payload)
        print(f"[client] 보낸 바이트 {len(payload)}개: {payload!r}")

        received = b""
        while len(received) < len(payload):
            chunk = sock.recv(1024)
            if not chunk:
                break
            received += chunk
        print(f"[client] 받은 바이트 {len(received)}개: {received!r}")
    # with 블록을 벗어나면 close() → FIN이 나간다.
    print("[client] 연결 닫음")
    return received


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--message", default="hello tcp")
    args = parser.parse_args()
    send_once(args.host, args.port, args.message)


if __name__ == "__main__":
    main()
