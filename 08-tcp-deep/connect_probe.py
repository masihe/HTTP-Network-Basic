"""TCP 접속을 한 번 시도하고, 성공·거부(RST)·시간 초과 중 무엇이 일어났는지와 걸린 시간을 출력한다."""

import argparse
import socket
import time


def probe(host: str, port: int, timeout: float) -> str:
    """host:port에 접속을 시도하고 결과를 한 줄 문자열로 반환한다. 연결되면 바로 닫는다."""
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            outcome = "연결 성공 (SYN-ACK를 받음)"
    except ConnectionRefusedError:
        outcome = "연결 거부 (상대가 RST로 답함: 그 포트에서 기다리는 프로그램이 없다)"
    except TimeoutError:
        outcome = f"시간 초과 ({timeout}초 동안 아무 답도 없음: SYN을 재전송하다 포기)"
    elapsed = time.perf_counter() - start
    return f"{host}:{port} → {outcome}, {elapsed:.2f}초 걸림"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9)
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args()
    print(probe(args.host, args.port, args.timeout))


if __name__ == "__main__":
    main()
