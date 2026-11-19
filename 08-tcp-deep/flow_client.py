"""흐름 제어 관찰용 클라이언트: 데이터를 조각으로 계속 보내며, 상대가 읽지 않아 send가 멈추는 순간을 시간과 함께 출력한다."""

import argparse
import socket
import time


def flood(host: str, port: int, total: int, chunk: int, sndbuf: int) -> None:
    """host:port에 total바이트를 chunk 단위로 보내고, 0.5초 넘게 막힌 send를 표시한다."""
    payload = b"x" * chunk
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        # 보내는 쪽 버퍼도 작게 잡아야, 상대 window가 0일 때 send()가 금방 멈춘다.
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, sndbuf)
        sock.connect((host, port))
        print(f"[client] 연결됨. {total}바이트를 {chunk}바이트씩 보냅니다")

        start = time.perf_counter()
        sent = 0
        while sent < total:
            before = time.perf_counter()
            sock.sendall(payload)
            sent += chunk
            waited = time.perf_counter() - before
            if waited > 0.5:
                print(f"[client] {before - start:5.2f}초: send()가 {waited:.2f}초 동안 막혔다가 풀림 (누적 {sent}바이트)")
        print(f"[client] {time.perf_counter() - start:5.2f}초: 모두 보냄 ({sent}바이트). 연결을 닫습니다")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9100)
    parser.add_argument("--total", type=int, default=204_800, help="보낼 총 바이트")
    # 1024는 받는 버퍼 8192를 딱 나눠떨어지게 채워서 window가 정확히 0이 된다. 1000이면 192가 남아 0까지 가지 않는다.
    parser.add_argument("--chunk", type=int, default=1024, help="한 번에 send할 바이트")
    parser.add_argument("--sndbuf", type=int, default=8192, help="보내는 버퍼 크기(바이트)")
    args = parser.parse_args()
    flood(args.host, args.port, args.total, args.chunk, args.sndbuf)


if __name__ == "__main__":
    main()
