"""TCP 에코 서버: 접속을 받아 받은 바이트를 그대로 출력하고 돌려준다. HTTP는 쓰지 않는다."""

import argparse
import socket


def serve(host: str, port: int) -> None:
    """host:port에서 접속을 하나씩 받아, 받은 바이트를 출력하고 그대로 돌려준다."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((host, port))
        listener.listen()
        print(f"[server] {host}:{port} 에서 대기 중 (Ctrl+C로 종료)")

        while True:
            # accept()가 돌아오는 시점에는 이미 3-way handshake가 끝나 있다.
            conn, addr = listener.accept()
            with conn:
                print(f"[server] 연결됨: {addr}")
                while True:
                    data = conn.recv(1024)
                    if not data:
                        # 빈 바이트 = 상대가 FIN을 보내 연결을 닫았다는 뜻
                        print(f"[server] 상대가 연결을 닫음: {addr}")
                        break
                    print(f"[server] 받은 바이트 {len(data)}개: {data!r}")
                    conn.sendall(data)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    args = parser.parse_args()
    try:
        serve(args.host, args.port)
    except KeyboardInterrupt:
        print("\n[server] 종료")


if __name__ == "__main__":
    main()
