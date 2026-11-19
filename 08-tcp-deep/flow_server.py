"""흐름 제어 관찰용 서버: 접속을 받은 뒤 한동안 데이터를 읽지 않고 버텨서, 받는 쪽 window가 0이 되게 만든다."""

import argparse
import socket
import time


def serve_once(host: str, port: int, rcvbuf: int, hold: float) -> int:
    """접속 하나를 받아 hold초 동안 읽지 않다가 끝까지 읽고, 받은 총 바이트 수를 반환한다."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # 받는 버퍼를 작게 잡아야 window가 금방 바닥난다. listen 전에 정해야 accept한 소켓에도 적용된다.
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
        listener.bind((host, port))
        listener.listen()
        print(f"[server] {host}:{port} 대기 중 (받는 버퍼 {rcvbuf}바이트)")

        conn, addr = listener.accept()
        with conn:
            actual = conn.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
            print(f"[server] 연결됨: {addr}, 실제 받는 버퍼 {actual}바이트")
            print(f"[server] {hold}초 동안 recv()를 하지 않습니다 → 버퍼가 차면 window가 0이 됩니다")
            time.sleep(hold)

            print("[server] 이제 읽기 시작합니다 → window가 다시 열립니다")
            total = 0
            while chunk := conn.recv(65536):
                total += len(chunk)
            print(f"[server] 상대가 연결을 닫음. 받은 총 바이트: {total}")
            return total


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9100)
    parser.add_argument("--rcvbuf", type=int, default=8192, help="받는 버퍼 크기(바이트)")
    parser.add_argument("--hold", type=float, default=5.0, help="읽지 않고 버틸 시간(초)")
    args = parser.parse_args()
    serve_once(args.host, args.port, args.rcvbuf, args.hold)


if __name__ == "__main__":
    main()
