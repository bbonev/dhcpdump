//
// $Id: dhcp_options.h,v 1.4 2004/10/31 11:22:58 mavetju Exp $
//

//
// this list was stolen from The DHCP Handbook by Droms and Lemon, Appendix D
//

// The first comment is the number, the last parameter is if it's verbosed
const char *dhcp_options[] = {
/*   0 */	"pad",
/*   1 */	"Subnet mask",						/**/
/*   2 */	"Time offset",						/**/
/*   3 */	"Routers",						/**/
/*   4 */	"Time server",						/**/
/*   5 */	"Name server",						/**/
/*   6 */	"DNS server",						/**/
/*   7 */	"Log server",						/**/
/*   8 */	"Cookie server",					/**/
/*   9 */	"LPR server",						/**/
/*  10 */	"Impress server",					/**/
/*  11 */	"Resource location server",				/**/
/*  12 */	"Host name",						/**/
/*  13 */	"Boot file size",					/**/
/*  14 */	"Merit dump file",					/**/
/*  15 */	"Domainname",						/**/
/*  16 */	"Swap server",						/**/
/*  17 */	"Root path",						/**/
/*  18 */	"Extensions path",					/**/
/*  19 */	"IP forwarding",					/**/
/*  20 */	"Non-local source routing",				/**/
/*  21 */	"Policy filter",					/**/
/*  22 */	"Maximum datagram reassembly size",			/**/
/*  23 */	"Default IP TTL",					/**/
/*  24 */	"Path MTU aging timeout",				/**/
/*  25 */	"Path MTU plateau table",				/**/
/*  26 */	"Interface MTU",					/**/
/*  27 */	"All subnets local",					/**/
/*  28 */	"Broadcast address",					/**/
/*  29 */	"Perform mask discovery",				/**/
/*  30 */	"Mask supplier",					/**/
/*  31 */	"Perform router discovery",				/**/
/*  32 */	"Router solicitation",					/**/
/*  33 */	"Static route",						/**/
/*  34 */	"Trailer encapsulation",				/**/
/*  35 */	"ARP cache timeout",					/**/
/*  36 */	"Ethernet encapsulation",				/**/
/*  37 */	"TCP default TTL",					/**/
/*  38 */	"TCP keepalive interval",				/**/
/*  39 */	"TCP keepalive garbage",				/**/
/*  40 */	"NIS domain",						/**/
/*  41 */	"NIS servers",						/**/
/*  42 */	"NTP servers",						/**/
/*  43 */	"Vendor specific info",					/**/
/*  44 */	"NetBIOS name server",					/**/
/*  45 */	"NetBIOS datagram distribution server",			/**/
/*  46 */	"NetBIOS node type",					/**/
/*  47 */	"NetBIOS scope",					/**/
/*  48 */	"X Window System font server",				/**/
/*  49 */	"X Window System display server",			/**/
/*  50 */	"Request IP address",					/**/
/*  51 */	"IP address leasetime",					/**/
/*  52 */	"Option overload",					/**/
/*  53 */	"DHCP message type",					/**/
/*  54 */	"Server identifier",					/**/
/*  55 */	"Parameter Request List",				/**/
/*  56 */	"Message",						/**/
/*  57 */	"Maximum DHCP message size",				/**/
/*  58 */	"T1",							/**/
/*  59 */	"T2",							/**/
/*  60 */	"Vendor class identifier",				/**/
/*  61 */	"Client-identifier",					/**/
/*  62 */	"Netware/IP domain name",				/**/
/*  63 */	"Netware/IP domain information",			/**/
/*  64 */	"NIS+ domain",						/**/
/*  65 */	"NIS+ servers",						/**/
/*  66 */	"TFTP server name",					/**/
/*  67 */	"Bootfile name",					/**/
/*  68 */	"Mobile IP home agent",					/**/
/*  69 */	"SMTP server",						/**/
/*  70 */	"POP3 server",						/**/
/*  71 */	"NNTP server",						/**/
/*  72 */	"WWW server",						/**/
/*  73 */	"Finger server",					/**/
/*  74 */	"IRC server",						/**/
/*  75 */	"StreetTalk server",					/**/
/*  76 */	"StreetTalk directory assistance server",		/**/
/*  77 */	"User-class Identification",
/*  78 */	"SLP-directory-agent",
/*  79 */	"SLP-service-scope",
/*  80 */	"Naming Authority",
/*  81 */	"Client FQDN",						/**/
/*  82 */	"Relay Agent Information",
/*  83 */	"Agent Remote ID",
/*  84 */	"Agent Subnet Mask",
/*  85 */	"NDS server",						/**/
/*  86 */	"NDS tree name",					/**/
/*  87 */	"NDS context",						/**/
/*  88 */	"IEEE 1003.1 POSIX",
/*  89 */	"FQDN",
/*  90 */	"Authentication",
/*  91 */	"Vines TCP/IP",
/*  92 */	"Server Selection",
/*  93 */	"Client System",
/*  94 */	"Client NDI",
/*  95 */	"LDAP",
/*  96 */	"IPv6 Transitions",
/*  97 */	"UUID/GUID",
/*  98 */	"UPA servers",
/*  99 */	"???",
/* 100 */	"Printer Name",
/* 101 */	"MDHCP",
/* 102 */	"???",
/* 103 */	"???",
/* 104 */	"???",
/* 105 */	"???",
/* 106 */	"???",
/* 107 */	"???",
/* 108 */	"Swap Path",
/* 109 */	"???",
/* 110 */	"IPX Compatability",
/* 111 */	"???",
/* 112 */	"Netinfo Address",
/* 113 */	"Netinfo Tag",
/* 114 */	"URL",
/* 115 */	"DHCP Failover",
/* 116 */	"DHCP Autoconfiguration",
/* 117 */	"Name Service Search",
/* 118 */	"Subnet selection",
/* 119 */	"Domain Search",
/* 120 */	"SIP Servers DHCP Option",
/* 121 */	"Classless Static Route",
/* 122 */	"???",
/* 123 */	"???",
/* 124 */	"???",
/* 125 */	"???",
/* 126 */	"Extension",
/* 127 */	"Extension",
/* 128 */	"???",
/* 129 */	"???",
/* 130 */	"???",
/* 131 */	"???",
/* 132 */	"???",
/* 133 */	"???",
/* 134 */	"???",
/* 135 */	"???",
/* 136 */	"???",
/* 137 */	"???",
/* 138 */	"???",
/* 139 */	"???",
/* 140 */	"???",
/* 141 */	"???",
/* 142 */	"???",
/* 143 */	"???",
/* 144 */	"HP - TFTP file",
/* 145 */	"???",
/* 146 */	"???",
/* 147 */	"???",
/* 148 */	"???",
/* 149 */	"???",
/* 150 */	"???",
/* 151 */	"???",
/* 152 */	"???",
/* 153 */	"???",
/* 154 */	"???",
/* 155 */	"???",
/* 156 */	"???",
/* 157 */	"???",
/* 158 */	"???",
/* 159 */	"???",
/* 160 */	"???",
/* 161 */	"???",
/* 162 */	"???",
/* 163 */	"???",
/* 164 */	"???",
/* 165 */	"???",
/* 166 */	"???",
/* 167 */	"???",
/* 168 */	"???",
/* 169 */	"???",
/* 170 */	"???",
/* 171 */	"???",
/* 172 */	"???",
/* 173 */	"???",
/* 174 */	"???",
/* 175 */	"???",
/* 176 */	"???",
/* 177 */	"???",
/* 178 */	"???",
/* 179 */	"???",
/* 180 */	"???",
/* 181 */	"???",
/* 182 */	"???",
/* 183 */	"???",
/* 184 */	"???",
/* 185 */	"???",
/* 186 */	"???",
/* 187 */	"???",
/* 188 */	"???",
/* 189 */	"???",
/* 190 */	"???",
/* 191 */	"???",
/* 192 */	"???",
/* 193 */	"???",
/* 194 */	"???",
/* 195 */	"???",
/* 196 */	"???",
/* 197 */	"???",
/* 198 */	"???",
/* 199 */	"???",
/* 200 */	"???",
/* 201 */	"???",
/* 202 */	"???",
/* 203 */	"???",
/* 204 */	"???",
/* 205 */	"???",
/* 206 */	"???",
/* 207 */	"???",
/* 208 */	"???",
/* 209 */	"???",
/* 210 */	"Authenticate",
/* 211 */	"???",
/* 212 */	"???",
/* 213 */	"???",
/* 214 */	"???",
/* 215 */	"???",
/* 216 */	"???",
/* 217 */	"???",
/* 218 */	"???",
/* 219 */	"???",
/* 220 */	"???",
/* 221 */	"???",
/* 222 */	"???",
/* 223 */	"???",
/* 224 */	"???",
/* 225 */	"???",
/* 226 */	"???",
/* 227 */	"???",
/* 228 */	"???",
/* 229 */	"???",
/* 230 */	"???",
/* 231 */	"???",
/* 232 */	"???",
/* 233 */	"???",
/* 234 */	"???",
/* 235 */	"???",
/* 236 */	"???",
/* 237 */	"???",
/* 238 */	"???",
/* 239 */	"???",
/* 240 */	"???",
/* 241 */	"???",
/* 242 */	"???",
/* 243 */	"???",
/* 244 */	"???",
/* 245 */	"???",
/* 246 */	"???",
/* 247 */	"???",
/* 248 */	"???",
/* 249 */	"MSFT - Classless route",
/* 250 */	"???",
/* 251 */	"???",
/* 252 */	"MSFT - WinSock Proxy Auto Detect",
/* 253 */	"???",
/* 254 */	"???",
/* 255 */	"End"};


const char *dhcp_message_types[] = {
		"wrong specified",
/*   1 */	"DHCPDISCOVER",
/*   2 */	"DHCPOFFER",
/*   3 */	"DHCPREQUEST",
/*   4 */	"DHCPDECLINE",
/*   5 */	"DHCPACK",
/*   6 */	"DHCPNAK",
/*   7 */	"DHCPRELEASE",
/*   8 */	"DHCPINFORM"
};

const char *netbios_node_type[] = {
/* 0 */		"none",
/* 1 */		"B-node",
/* 2 */		"P-node",
/* 3 */		"",
/* 4 */		"M-node",
/* 5 */		"",
/* 6 */		"",
/* 7 */		"",
/* 8 */		"H-node"
};

const char *option_overload[] = {
/* 0 **/	"unspecified",
/* 1 */		"file field holds options",
/* 2 */		"sname field holds options",
/* 3 */		"file and sname field holds options"
};

const char *enabledisable[] = {
/* 0 */		"disabled",
/* 1 */		"enabled"
};

const char *ethernet_encapsulation[] = {
/* 0 */		"Ethernet version 2",
/* 1 */		"IEEE 802.3"
};

const char *operands[] = {
/* 0 */		"wrong specified",
/* 1 */		"BOOTPREQUEST",
/* 2 */		"BOOTPREPLY"
};

/*
 * From RFC 3046
 */
const char *relayagent_suboptions[] = {
/* 0 */		"<unknown-0>",
/* 1 */		"Circuit-ID",
/* 2 */		"Remote-ID"
};

/*
 * Copied from RFC1700
 */
const char *htypes[] = {
/*  0 */		"wrong specified",
/*  1 */		"Ethernet",
/*  2 */		"Experimental Ethernet",
/*  3 */		"Amateur Radio AX.25",
/*  4 */		"Proteon ProNET Token Ring",
/*  5 */		"Chaos",
/*  6 */		"IEEE 802 Networks",
/*  7 */		"ARCNET",
/*  8 */		"Hyperchannel",
/*  9 */		"Lanstar",
/* 10 */		"Autonet Short Address",
/* 11 */		"LocalTalk",
/* 12 */		"LocalNet",
/* 13 */		"Ultra link",
/* 14 */		"SMDS",
/* 15 */		"Frame Relay",
/* 16 */		"ATM",
/* 17 */		"HDLC",
/* 18 */		"Fibre Channel",
/* 19 */		"ATM",
/* 20 */		"Serial Line",
/* 21 */		"ATM"
};
