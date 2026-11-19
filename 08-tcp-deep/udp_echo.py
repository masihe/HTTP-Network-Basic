"""UDP 에코: server는 받은 데이터그램을 그대로 돌려주고, client는 하나를 보내고 답을 기다린다. 연결 과정이 없다."""

import argparse
import socket


def run_server(host: str, port: int) -> None:
    """host:port에서 데이터그램을 받을 때마다 출력하고 보낸 쪽에 그대로 돌려준다."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((host, port))
        print(f"[udp server] {host}:{port} 대기 중 (Ctrl+C로 종료). listen()도 accept()도 없습니다")
        while True:
            data, addr = sock.recvfrom(65535)
            print(f"[udp server] {addr} 에게서 {len(data)}바이트: {data!r}")
            sock.sendto(data, addr)


def run_client(host: str, port: int, message: str, timeout: float) -> bytes | None:
    """message를 데이터그램 하나로 보내고, timeout초 안에 온 답을 반환한다. 답이 없으면 None."""
    payload = message.encode("utf-8")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(payload, (host, port))  # connect 없이 바로 보낸다
        print(f"[udp client] 보낸 바이트 {len(payload)}개: {payload!r}")
        try:
            data, _ = sock.recvfrom(65535)
        except TimeoutError:
            print(f"[udp client] {timeout}초 안에 답이 없음. UDP는 재전송하지 않으므로 그대로 끝")
            return None
        except ConnectionResetError:
            # Windows는 상대가 'ICMP 포트 도달 불가'로 답하면 이 예외로 알려준다.
            print("[udp client] 상대가 ICMP Port Unreachable로 답함 (그 포트에서 기다리는 프로그램이 없다)")
            return None
        print(f"[udp client] 받은 바이트 {len(data)}개: {data!r}")
        return data


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["server", "client"])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9300)
    parser.add_argument("--message", default="hello udp")
    parser.add_argument("--timeout", type=float, default=3.0)
    args = parser.parse_args()
    if args.mode == "server":
        try:
            run_server(args.host, args.port)
        except KeyboardInterrupt:
            print("\n[udp server] 종료")
    else:
        run_client(args.host, args.port, args.message, args.timeout)


if __name__ == "__main__":
    main()
