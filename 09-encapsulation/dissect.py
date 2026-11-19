"""Wireshark의 'Copy as Hex Stream' 문자열을 받아 링크 → IP → TCP/UDP/ICMP → 데이터 순서로 헤더를 직접 잘라 출력한다."""

import argparse
import ipaddress
import struct
import sys

ETHERTYPES = {0x0800: "IPv4", 0x0806: "ARP", 0x86DD: "IPv6"}
IP_PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP"}
TCP_FLAGS = ["FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"]


class Truncated(Exception):
    """패킷이 헤더를 다 담기에 짧을 때 쓰는 예외."""


def take(data: bytes, offset: int, size: int, what: str) -> bytes:
    """data[offset:offset+size]를 반환한다. 모자라면 어느 부분에서 끊겼는지 알리는 Truncated를 던진다."""
    if offset + size > len(data):
        raise Truncated(f"{what}에 {size}바이트가 필요한데 {len(data) - offset}바이트만 남음 (오프셋 {offset})")
    return data[offset : offset + size]


def field(offset: int, size: int, name: str, value: object) -> None:
    """'[오프셋..끝] 이름: 값' 형식으로 필드 한 줄을 출력한다."""
    print(f"  [{offset:4d}..{offset + size - 1:4d}] {name:<22} {value}")


def mac(raw: bytes) -> str:
    """6바이트를 aa:bb:cc:dd:ee:ff 형식으로 바꾼다."""
    return ":".join(f"{b:02x}" for b in raw)


def checksum16(data: bytes) -> int:
    """16비트 1의 보수 합 체크섬(IP 헤더 체크섬 방식)을 계산한다."""
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def parse_hex(text: str) -> bytes:
    """Hex Stream 문자열에서 공백과 콜론을 빼고 바이트로 바꾼다. 16진수가 아니면 ValueError."""
    cleaned = "".join(text.split()).replace(":", "")
    if not cleaned:
        raise ValueError("입력이 비어 있습니다")
    if len(cleaned) % 2:
        raise ValueError(f"16진수 글자 수가 홀수입니다 ({len(cleaned)}글자). 복사가 잘렸을 수 있습니다")
    try:
        return bytes.fromhex(cleaned)
    except ValueError as e:
        raise ValueError(f"16진수가 아닌 글자가 있습니다: {e}") from e


def dissect_ethernet(data: bytes) -> tuple[str, int]:
    """Ethernet II 헤더(14바이트, VLAN 태그가 있으면 18바이트)를 출력하고 (다음 계층 이름, 다음 계층 시작 오프셋)을 반환한다."""
    head = take(data, 0, 14, "Ethernet 헤더")
    ethertype = struct.unpack("!H", head[12:14])[0]
    print("■ 링크 계층: Ethernet II (14바이트" + (" + VLAN 태그 4바이트)" if ethertype == 0x8100 else ")"))
    field(0, 6, "도착 MAC", mac(head[0:6]))
    field(6, 6, "출발 MAC", mac(head[6:12]))
    offset = 14
    if ethertype == 0x8100:
        # 802.1Q VLAN 태그: 4바이트가 끼어들고, 진짜 EtherType은 그 뒤에 온다.
        tag = take(data, 14, 4, "VLAN 태그")
        tci, ethertype = struct.unpack("!HH", tag)
        field(12, 2, "TPID", "0x8100 (802.1Q VLAN 태그가 끼어 있음)")
        field(14, 2, "VLAN ID", f"{tci & 0x0FFF} (하나의 망을 나눈 논리 네트워크 번호)")
        field(16, 2, "EtherType", f"0x{ethertype:04x} ({ETHERTYPES.get(ethertype, '모름')})")
        offset = 18
    else:
        field(12, 2, "EtherType", f"0x{ethertype:04x} ({ETHERTYPES.get(ethertype, '모름')})")
    return ETHERTYPES.get(ethertype, f"0x{ethertype:04x}"), offset


def dissect_null(data: bytes) -> tuple[str, int]:
    """loopback 캡처의 Null/Loopback 헤더(4바이트)를 출력하고 (다음 계층 이름, 4)를 반환한다."""
    head = take(data, 0, 4, "Null 헤더")
    family = struct.unpack("<I", head)[0]  # 이 값만 리틀엔디언(캡처한 PC의 바이트 순서)이다
    print("■ 링크 계층: Null/Loopback (4바이트, MAC 주소 없음)")
    field(0, 4, "주소 체계", f"{family} ({'IPv4' if family == 2 else 'IPv4가 아님'})")
    return ("IPv4" if family == 2 else f"family {family}"), 4


def dissect_arp(data: bytes, start: int) -> None:
    """IPv4용 ARP 본문(28바이트)을 출력한다."""
    body = take(data, start, 28, "ARP")
    op = struct.unpack("!H", body[6:8])[0]
    print("■ ARP (28바이트): IP 주소로 MAC 주소를 묻고 답한다")
    field(start + 6, 2, "동작", f"{op} ({'요청: 이 IP 누구야?' if op == 1 else '응답: 나야' if op == 2 else '모름'})")
    field(start + 8, 6, "보낸 쪽 MAC", mac(body[8:14]))
    field(start + 14, 4, "보낸 쪽 IP", ipaddress.IPv4Address(body[14:18]))
    field(start + 18, 6, "찾는 쪽 MAC", f"{mac(body[18:24])} (요청이면 아직 모르므로 0)")
    field(start + 24, 4, "찾는 쪽 IP", ipaddress.IPv4Address(body[24:28]))


def dissect_ipv4(data: bytes, start: int) -> tuple[int, int, int, bool]:
    """IPv4 헤더를 출력하고 (프로토콜 번호, 다음 계층 시작, IP 패킷 끝, 첫 조각 여부)를 반환한다."""
    first = take(data, start, 20, "IPv4 헤더")
    version, ihl = first[0] >> 4, (first[0] & 0x0F) * 4
    if version != 4:
        raise ValueError(f"IPv4가 아닙니다 (version={version})")
    if ihl < 20:
        raise ValueError(f"IPv4 헤더 길이가 비정상입니다 (IHL={ihl}바이트)")
    head = take(data, start, ihl, "IPv4 헤더(옵션 포함)")
    total_len, ident, flags_frag = struct.unpack("!HHH", head[2:8])
    ttl, proto, stored_sum = head[8], head[9], struct.unpack("!H", head[10:12])[0]
    df, mf, frag_offset = bool(flags_frag & 0x4000), bool(flags_frag & 0x2000), (flags_frag & 0x1FFF) * 8
    computed = checksum16(head[:10] + b"\x00\x00" + head[12:])

    print(f"■ 네트워크 계층: IPv4 ({ihl}바이트)")
    field(start, 1, "버전 / 헤더 길이", f"{version} / {ihl}바이트")
    field(start + 2, 2, "전체 길이", f"{total_len}바이트 (IP 헤더 + 그 위 전부)")
    field(start + 4, 2, "식별자(ID)", f"0x{ident:04x} (조각들이 같은 ID를 가짐)")
    field(start + 6, 2, "플래그 / 조각 위치", f"DF={int(df)} MF={int(mf)} / {frag_offset}바이트")
    field(start + 8, 1, "TTL", f"{ttl} (라우터를 지날 때마다 1씩 줄어듦)")
    field(start + 9, 1, "프로토콜", f"{proto} ({IP_PROTOCOLS.get(proto, '모름')})")
    verdict = "일치" if computed == stored_sum else f"불일치 (계산값 0x{computed:04x})"
    if stored_sum == 0 and computed != 0:
        verdict += " ← 0이면 네트워크 카드가 나중에 채우는 경우(checksum offload)일 수 있음"
    field(start + 10, 2, "헤더 체크섬", f"0x{stored_sum:04x} → 직접 계산해 보니 {verdict}")
    field(start + 12, 4, "출발 IP", ipaddress.IPv4Address(head[12:16]))
    field(start + 16, 4, "도착 IP", ipaddress.IPv4Address(head[16:20]))
    return proto, start + ihl, start + total_len, frag_offset == 0


def dissect_tcp(data: bytes, start: int, end: int) -> int:
    """TCP 헤더를 출력하고 데이터 시작 오프셋을 반환한다."""
    first = take(data, start, 20, "TCP 헤더")
    src, dst, seq, ack, off_flags, window = struct.unpack("!HHIIHH", first[:16])
    hlen = (off_flags >> 12) * 4
    if hlen < 20:
        raise ValueError(f"TCP 헤더 길이가 비정상입니다 ({hlen}바이트)")
    take(data, start, hlen, "TCP 헤더(옵션 포함)")
    flags = [name for bit, name in enumerate(TCP_FLAGS) if off_flags & (1 << bit)]

    print(f"■ 전송 계층: TCP ({hlen}바이트, 그중 옵션 {hlen - 20}바이트)")
    field(start, 2, "출발 포트", src)
    field(start + 2, 2, "도착 포트", dst)
    field(start + 4, 4, "Seq (절대값)", f"{seq} (Wireshark는 0부터 세는 상대값으로 보여줌)")
    field(start + 8, 4, "Ack (절대값)", ack)
    field(start + 12, 2, "헤더 길이 / 플래그", f"{hlen}바이트 / {', '.join(flags) or '없음'}")
    field(start + 14, 2, "Window", f"{window} (window scale 옵션이 있으면 곱해서 해석)")
    return start + hlen


def dissect_udp(data: bytes, start: int) -> int:
    """UDP 헤더(8바이트)를 출력하고 데이터 시작 오프셋을 반환한다."""
    head = take(data, start, 8, "UDP 헤더")
    src, dst, length, csum = struct.unpack("!HHHH", head)
    print("■ 전송 계층: UDP (8바이트: 필드가 4개뿐)")
    field(start, 2, "출발 포트", src)
    field(start + 2, 2, "도착 포트", dst)
    field(start + 4, 2, "길이", f"{length}바이트 (UDP 헤더 + 데이터)")
    field(start + 6, 2, "체크섬", f"0x{csum:04x}")
    return start + 8


def dissect_icmp(data: bytes, start: int) -> int:
    """ICMP 헤더 앞부분(4바이트)을 출력하고 그 뒤 오프셋을 반환한다."""
    head = take(data, start, 4, "ICMP 헤더")
    kinds = {0: "Echo Reply (ping 응답)", 3: "Destination Unreachable", 8: "Echo Request (ping 요청)", 11: "Time Exceeded (TTL 초과)"}
    print("■ ICMP (IP 위에서 오류와 상태를 알림)")
    field(start, 1, "타입", f"{head[0]} ({kinds.get(head[0], '기타')})")
    field(start + 1, 1, "코드", head[1])
    return start + 4


def show_payload(data: bytes, start: int, end: int) -> None:
    """남은 데이터 길이와 앞부분을 출력한다."""
    payload = data[start:end]
    print(f"■ 데이터 ({len(payload)}바이트)")
    if payload:
        preview = payload[:120]
        print(f"  [{start:4d}..{end - 1:4d}] {preview!r}{' ...' if len(payload) > 120 else ''}")
    if end < len(data):
        print(f"  (IP 패킷이 끝난 뒤 {len(data) - end}바이트는 Ethernet 최소 길이를 맞추는 채움 바이트)")


def dissect(data: bytes, link: str) -> None:
    """바이트 전체를 링크 계층부터 차례로 해부해 출력한다."""
    print(f"전체 {len(data)}바이트\n")
    upper, offset = dissect_ethernet(data) if link == "ethernet" else dissect_null(data)
    print()
    if upper == "ARP":
        dissect_arp(data, offset)
        return
    if upper != "IPv4":
        print(f"이 스크립트는 IPv4와 ARP만 해부합니다 (다음 계층: {upper})")
        return

    proto, offset, end, first_fragment = dissect_ipv4(data, offset)
    end = min(end, len(data))
    print()
    if not first_fragment:
        print("이 패킷은 쪼개진 IP 조각의 뒷부분입니다. 전송 계층 헤더는 첫 조각에만 있습니다.")
        show_payload(data, offset, end)
        return
    if proto == 6:
        offset = dissect_tcp(data, offset, end)
    elif proto == 17:
        offset = dissect_udp(data, offset)
    elif proto == 1:
        offset = dissect_icmp(data, offset)
    print()
    show_payload(data, offset, end)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("hex", nargs="?", help="Hex Stream 문자열. 생략하면 표준 입력에서 읽음")
    parser.add_argument("--link", choices=["ethernet", "null"], default="ethernet",
                        help="Wi-Fi/이더넷 캡처는 ethernet, loopback 캡처는 null")
    args = parser.parse_args()

    text = args.hex if args.hex is not None else sys.stdin.read()
    try:
        dissect(parse_hex(text), args.link)
    except (ValueError, Truncated) as e:
        print(f"\n해부 중단: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
