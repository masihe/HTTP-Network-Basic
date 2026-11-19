"""텍스트 파일에 손으로 쓴 HTTP 요청을 그대로 TCP로 보내고, 돌아온 응답 바이트를 출력한다."""

import argparse
import socket
from pathlib import Path


def load_request(path: Path) -> bytes:
    """파일을 읽어 줄바꿈을 HTTP 규칙인 \\r\\n으로 맞춘 요청 바이트를 반환한다."""
    text = path.read_text(encoding="utf-8")
    head, sep, body = text.partition("\n\n")
    if not sep:
        raise ValueError(f"{path}: 헤더 끝을 알리는 빈 줄이 없습니다")
    # 메모장이나 git이 줄바꿈을 \n이나 \r\n으로 바꿔 저장할 수 있으므로, 헤더 줄바꿈을 \r\n으로 통일한다.
    lines = head.replace("\r\n", "\n").split("\n")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("utf-8") + body.encode("utf-8")


def send(host: str, port: int, request: bytes) -> bytes:
    """request를 보내고, 서버가 연결을 닫을 때까지 받은 응답 바이트를 반환한다."""
    with socket.create_connection((host, port), timeout=5) as sock:
        sock.sendall(request)
        response = b""
        while chunk := sock.recv(4096):
            response += chunk
    return response


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", type=Path, nargs="?", default=Path(__file__).with_name("request.txt"))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()

    request = load_request(args.file)
    print("----- 보낸 요청 (원본 바이트) -----")
    print(repr(request))
    response = send(args.host, args.port, request)
    print("----- 받은 응답 (원본 바이트) -----")
    print(repr(response))


if __name__ == "__main__":
    main()
