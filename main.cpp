#include "headers.h"

void usage();
char *my_strnstr(const char *big, const char *little, size_t len); 
void get_mymac(char *dev);
bool sendFowardPacket(pcap_t *handle, const u_char *Packet, Ip_Tcp *org_packet, int packet_size, int data_size);
bool sendBackwardPacket(pcap_t *handle, const u_char *Packet, Ip_Tcp *org_packet, int packet_size, bool RST_FIN, int data_size); //RST가 TRUE
Mac mymac;

int main(int argc, char *argv[])
{
    if(argc != 3)
    {
        usage();
        return -1;
    }

    char *dev = argv[1];
    char *pattern = argv[2];
    get_mymac(dev);
    printf("My Mac: %s\n", std::string(mymac).data());

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr)
    {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }
    struct pcap_pkthdr *header;
    const u_char *Packet;

    while(true)
    {
        int res = pcap_next_ex(handle, &header, &Packet);
        if (res == 0)
            continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
        {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        struct EthHdr* eth_packet;
        eth_packet = (struct EthHdr*)Packet;
        if(eth_packet->type() != EthHdr::Ip4)
            continue;

        //Tcp 확인
		EthIpPacket *eth_ip_packet = (struct EthIpPacket *)Packet;
		if (eth_ip_packet->ip_.p() != IpHdr::Tcp)
			continue;

		Ip_Tcp *ip_tcp = (struct Ip_Tcp *)Packet;

		int data_size;
		data_size = ip_tcp->ip_.len() - ip_tcp->ip_.hl() * 4 - ip_tcp->tcp_.off() * 4;
        if (data_size > 0)
		{
			//pattern이 존재하는지 데이터 길이만큼 확인
			if(my_strnstr(ip_tcp->data, pattern, data_size))
            {
                //패턴을 패킷에서 찾았을 때
                //HTTP, HTTPS 구분
                //HTTP packet에 대해서는 Forward RST, Backward FIN을, HTTPS packet에 대해서는 Forward RST, Backward RST를 보내고 있다
                if(ip_tcp->tcp_.sport() == 80 || ip_tcp->tcp_.dport() == 80)
                {
                    printf("HTTP임\n");
                    if(sendFowardPacket(handle, Packet, ip_tcp, header->caplen, data_size))
                        printf("HTTP Foward success\n");
                    else
                        {
                            printf("HTTP Foward fail\n");
                             return -1;
                        }

                    if(sendBackwardPacket(handle, Packet, ip_tcp, header->caplen, false, data_size))
                        printf("HTTP Backward success\n");
                    else
                        {
                            printf("HTTP Backward fail\n");
                             return -1;
                        }
                }

                else if(ip_tcp->tcp_.sport() == 443 || ip_tcp->tcp_.dport() == 443)
                {
                    printf("HTTPS임\n");
                    if(sendFowardPacket(handle, Packet, ip_tcp, header->caplen, data_size))
                        printf("HTTPS Foward success\n");
                    else
                        {
                            printf("HTTPS Foward fail\n");
                             return -1;
                        }

                    if(sendBackwardPacket(handle, Packet, ip_tcp, header->caplen, true, data_size))
                        printf("HTTPS Backward success\n");
                    else
                        {
                            printf("HTTPS Backward fail\n");
                             return -1;
                        }
                }

            }
		}

    }
    pcap_close(handle);
    return 0;

    
}

bool sendFowardPacket(pcap_t *handle, const u_char *Packet, Ip_Tcp *org_packet, int packet_size, int data_size)
{
    u_char *temp = (u_char*)malloc(packet_size); 
    memcpy(&temp, Packet, packet_size);
    Forward_Packet *fwdpacket = (Forward_Packet *)temp;

    fwdpacket->eth_.smac_ = mymac;
    fwdpacket->eth_.dmac_ = org_packet->eth_.dmac();

    fwdpacket->ip_.len_ = htons(sizeof(struct IpHdr) + sizeof(struct TcpHdr));
    fwdpacket->ip_.ttl_ = org_packet->ip_.ttl();
    fwdpacket->ip_.sum_ = htons(IpHdr::calcChecksum(&(fwdpacket->ip_)));

    fwdpacket->tcp_.seq_ = htonl(org_packet->tcp_.seq_ + data_size);
    fwdpacket->tcp_.ack_ = org_packet->tcp_.ack_;
    fwdpacket->tcp_.off_rsvd_ = (sizeof(struct TcpHdr) / 4) << 4;
    fwdpacket->tcp_.flags_ = 0;
    fwdpacket->tcp_.flags_ = TcpHdr::Rst | TcpHdr::Ack;
    fwdpacket->tcp_.sum_ = htons(TcpHdr::calcChecksum(&(fwdpacket->ip_), &(fwdpacket->tcp_)));
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(fwdpacket), sizeof(fwdpacket));
    free(temp);
	if (res != 0)
    {
        printf("sendFowardPacket Error");
		return false;
    }

    return true;
}

bool sendBackwardPacket(pcap_t *handle, const u_char *Packet, Ip_Tcp *org_packet, int packet_size, bool RST_FIN, int data_size) //RST가 TRUE
{
    u_char *temp = (u_char*)malloc(packet_size); 
    memcpy(&temp, Packet, packet_size);
    Backward_Packet *bwdpacket = (Backward_Packet *)temp;

    bwdpacket->eth_.type_ = EthHdr::Ip4;
    bwdpacket->eth_.smac_ = mymac;
    bwdpacket->eth_.dmac_ = org_packet->eth_.smac();

    if(RST_FIN)
        bwdpacket->ip_.len_ = htons(sizeof(struct IpHdr) + sizeof(struct TcpHdr));
    else
        bwdpacket->ip_.len_ = htons(sizeof(struct IpHdr) + sizeof(struct TcpHdr) + 58);
    bwdpacket->ip_.ttl_ = 128;
    bwdpacket->ip_.sip_ = org_packet->ip_.dip_;
    bwdpacket->ip_.dip_ = org_packet->ip_.sip_;
    bwdpacket->ip_.sum_ = htons(IpHdr::calcChecksum(&(bwdpacket->ip_)));

    bwdpacket->tcp_.sport_ = org_packet->tcp_.dport_;
    bwdpacket->tcp_.dport_ = org_packet->tcp_.sport_;
    bwdpacket->tcp_.seq_ = org_packet->tcp_.seq_;
    bwdpacket->tcp_.ack_ = htonl(org_packet->tcp_.seq() + data_size);
    bwdpacket->tcp_.off_rsvd_ = (sizeof(struct TcpHdr) / 4) << 4;
    bwdpacket->tcp_.flags_ = 0;
    if(RST_FIN)
        bwdpacket->tcp_.flags_ = TcpHdr::Rst | TcpHdr::Ack;
    else
        bwdpacket->tcp_.flags_ = TcpHdr::Fin | TcpHdr::Ack;

    bwdpacket->tcp_.sum_ = htons(TcpHdr::calcChecksum(&(bwdpacket->ip_), &(bwdpacket->tcp_)));
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(bwdpacket), sizeof(bwdpacket));
    free(temp);
	if (res != 0)
    {
        printf("sendFowardPacket Error");
		return false;
    }

    return true;

}


void usage()
{
    printf("syntax : tcp-block <interface> <pattern>\n");
    printf("sample : tcp-block wlan0 \"Host: test.gilgil.net\"\n");
}

char *my_strnstr(const char *big, const char *little, size_t len)
{
	size_t llen;
	size_t blen;
	size_t i;

	if (!*little)
		return ((char *)big);
	llen = strlen(little);
	blen = strlen(big);
	i = 0;
	if (blen < llen || len < llen)
		return (0);
	while (i + llen <= len)
	{
		if (big[i] == *little && !strncmp(big + i, little, llen))
			return ((char *)big + i);
		i++;
	}
	return (0);
}

void get_mymac(char *dev)
{
    int fd;
    struct ifreq ifr;
    const char *iface = dev;
    memset(&ifr, 0, sizeof(ifr));

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);

    if (0 == ioctl(fd, SIOCGIFHWADDR, &ifr))
    {
        mymac = Mac((uint8_t *)ifr.ifr_hwaddr.sa_data);
    }


    close(fd);
    return;
}