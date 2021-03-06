#pragma once
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

#pragma pack(push, 1)
struct Forward_Packet final
{
    EthHdr eth_;
	IpHdr ip_;
	TcpHdr tcp_;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct Backward_Packet final
{
    EthHdr eth_;
	IpHdr ip_;
	TcpHdr tcp_;
    char msg[100];
};
#pragma pack(pop)