import pydivert
import socket
import struct

DISCORD_YOUTUBE_DOMAINS = [
    "discord.com", "discord.gg", "discordapp.com", "discordcdn.com", "discordapp.net",
    "youtube.com", "youtu.be", "ytimg.com", "googlevideo.com", "youtubei.googleapis.com",
    "youtubekids.com", "youtube-nocookie.com", "youtube-ui.l.google.com", "ggpht.com"
]

CLOUDFLARE_IP = "104.16.0.1"  # Пример, можно заменить

def domain_in_sni(packet_payload):
    try:
        if packet_payload[0] == 0x16 and packet_payload[5] == 0x01:
            length = struct.unpack(">H", packet_payload[3:5])[0]
            sni_start = packet_payload.find(b"\x00\x00")
            if sni_start != -1:
                sni_len = packet_payload[sni_start+2]
                sni = packet_payload[sni_start+3:sni_start+3+sni_len].decode()
                for domain in DISCORD_YOUTUBE_DOMAINS:
                    if domain in sni:
                        return True
    except:
        pass
    return False

print("[*] Starting packet interception...")

with pydivert.WinDivert("outbound and tcp.DstPort == 443") as w:
    w.sniffed_packets = []
    for packet in w:
        if packet.is_outbound and packet.tcp and packet.tcp.dst_port == 443:
            if domain_in_sni(packet.payload):
                print(f"[!] Intercepted TLS SNI to Discord/YouTube: Redirecting to {CLOUDFLARE_IP}")
                packet.ip.dst_addr = CLOUDFLARE_IP
                packet.tcp.dst_port = 443  # не меняем порт
                packet.recalculate_checksum()
        w.send(packet)
