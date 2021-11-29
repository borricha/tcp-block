#include "headers.h"

#pragma pack(push, 1)
struct EthIpPacket  final
{
    EthHdr eth_;
    IpHdr ip_;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct Ip_Tcp final
{
    EthHdr eth_;
	IpHdr ip_;
	TcpHdr tcp_;
	char data[256];
};
#pragma pack(pop)



void usage();
char *my_strnstr(const char *big, const char *little, size_t len); 
void get_mymac(char *dev, Mac *mymac);

int main(int argc, char *argv[])
{
    if(argc != 3)
    {
        usage();
        return -1;
    }

    char *dev = argv[1];
    char *pattern = argv[2];
    Mac mymac;
    get_mymac(dev, &mymac);
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
                }

                else if(ip_tcp->tcp_.sport() == 443 || ip_tcp->tcp_.dport() == 443)
                {
                    printf("HTTPS임\n");
                }

            }
		}

    }

    
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

void get_mymac(char *dev, Mac *mymac)
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
        *mymac = Mac((uint8_t *)ifr.ifr_hwaddr.sa_data);
    }


    close(fd);
    return;
}
