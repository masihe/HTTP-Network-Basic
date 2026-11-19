"""HTTPS 클라이언트: TLS 연결 정보와 HTTP 응답을 출력하고, 원하면 TLS 키를 파일로 남긴다(Wireshark 복호화용)."""

import argparse
import http.client
import ssl
from pathlib import Path
from urllib.parse import urlsplit


def fetch(url: str, keylog: Path | None) -> None:
    """url에 HTTPS GET을 보내고, TLS 정보와 응답 상태·헤더를 출력한다. keylog가 있으면 TLS 키를 그 파일에 덧붙여 쓴다."""
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        raise ValueError(f"https:// 로 시작하는 URL이어야 합니다: {url!r}")

    context = ssl.create_default_context()  # 인증서 검증을 켠 기본 설정
    if keylog is not None:
        context.keylog_filename = str(keylog)

    conn = http.client.HTTPSConnection(parts.hostname, parts.port or 443, context=context, timeout=10)
    try:
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        conn.request("GET", path, headers={"User-Agent": "05-https-tls-client"})
        response = conn.getresponse()

        tls = conn.sock
        cert = tls.getpeercert()
        subject = dict(item[0] for item in cert["subject"])
        issuer = dict(item[0] for item in cert["issuer"])
        print("----- TLS 연결 -----")
        print(f"버전: {tls.version()}")
        print(f"암호 방식: {tls.cipher()[0]}")
        print(f"서버 인증서 주인: {subject.get('commonName')}")
        print(f"인증서 발급자: {issuer.get('organizationName')} / {issuer.get('commonName')}")

        body = response.read()
        print("----- HTTP 응답 (TLS로 풀린 뒤의 내용) -----")
        print(f"HTTP/{response.version / 10:.1f} {response.status} {response.reason}")
        for name, value in response.getheaders():
            print(f"{name}: {value}")
        print(f"(본문 {len(body)}바이트)")
    finally:
        conn.close()

    if keylog is not None:
        print(f"----- TLS 키를 {keylog} 에 기록함 -----")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url", nargs="?", default="https://example.com/")
    parser.add_argument("--keylog", type=Path, help="TLS 키를 남길 파일 경로 (Wireshark 복호화용)")
    args = parser.parse_args()
    fetch(args.url, args.keylog)


if __name__ == "__main__":
    main()
