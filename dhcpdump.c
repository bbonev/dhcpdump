// DHCPDUMP
//
// Usage: tcpdump -s 1518 -lenx port bootps or port bootpc | dhcpdump
//
// note 1: how does this work for FDDI / PPP links?
// note 2: what is this number 14?
//
// $Id: dhcpdump.c,v 1.11 2003/11/20 06:12:27 mavetju Exp $
//

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <regex.h>
#include "config.h"
#include "dhcp_options.h"

#ifndef HAVE_STRSEP
#include "strsep.c"
#endif

#define bool int
#define TRUE (1)
#define FALSE (0)

#define LARGESTRING 1024

#define uchar unsigned char

// header variables
uchar	timestamp[40];			// timestamp on header
uchar	mac_origin[40];			// mac address of origin
uchar	mac_destination[40];		// mac address of destination
uchar	ip_origin[40];			// ip address of origin
uchar	ip_destination[40];		// ip address of destination
int	max_data_len;			// maximum size of a packet

int	tcpdump_style=-1;

int check_ch(uchar *data,int data_len,regex_t *preg);
int readheader(uchar *buf);
int readdata(uchar *buf,uchar *data,int *data_len);
int printdata(uchar *data,int data_len);

void printIPaddress(uchar *data);
void printIPaddressAddress(uchar *data);
void printIPaddressMask(uchar *data);
void print8bits(uchar *data);
void print16bits(uchar *data);
void print32bits(uchar *data);
void printTime8(uchar *data);
void printTime32(uchar *data);
void printReqParmList(uchar *data,int len);
void printHexColon(uchar *data,int len);
void printHex(uchar *data,int len);
void printHexString(uchar *data,int len);

int main(int argc,char **argv) {
    char *hmask=NULL;
    regex_t preg;
    int i;

    // data variables
    uchar	data[LARGESTRING];		// data of the udp packet
    int		data_len=0;			// length of the packet

    uchar	buf[LARGESTRING];		// buffer from input line

    for (i=1;i<argc;i++) {
	if (argv[i]==NULL || argv[i][0]!='-') break;
	switch (argv[i][1]) {
	case 'h':
	    hmask=argv[++i];
	    break;
	default:
	    fprintf(stderr,"%s: %c: uknown option\n",argv[0],argv[i][1]);
	    exit(2);
	}
    }

    if (hmask) regcomp(&preg,hmask,REG_EXTENDED | REG_ICASE | REG_NOSUB);

    while (!feof(stdin)) {
	if (fgets(buf,LARGESTRING,stdin)==NULL)
	    return 1;

	if (isdigit(buf[0])) {
	    //
	    // this is a header, salvage the information needed and go on:
	    // - time
	    // - mac origin
	    // - mac destination
	    // - ip origin
	    // - ip destination
	    //
	    readheader(buf);
	    data_len=0;
	} else if (buf[0]=='\t') {
	    if (readdata(buf,data,&data_len)==1
	    &&  ( !hmask || !check_ch(data,data_len,&preg)))
		printdata(data,data_len);
	}
    }
    return 0;
}

// check for matching CHADDR (Peter Apian-Bennewitz <apian@ise.fhg.de>)
int check_ch(uchar *data,int data_len,regex_t *preg) {
    char ch_ip[50];

    if (data_len<43) return(0);
    sprintf(ch_ip,
	"%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n",
           data[28],data[29],data[30],data[31],
           data[32],data[33],data[34],data[35],
           data[36],data[37],data[38],data[39],
           data[40],data[41],data[42],data[43]);
   return (regexec(preg,ch_ip,0,NULL,0));
}


// print the data as an IP address
void printIPaddress(uchar *data) {
    printf("%d.%d.%d.%d",
	data[0],data[1],data[2],data[3]);
}

// print the data as an IP address and an IP address
void printIPaddressAddress(uchar *data) {
    printf("%d.%d.%d.%d %d.%d.%d.%d",
	data[0],data[1],data[2],data[3],
	data[4],data[5],data[6],data[7]);
}

// print the data as an IP address and mask
void printIPaddressMask(uchar *data) {
    printf("%d.%d.%d.%d/%d.%d.%d.%d",
	data[0],data[1],data[2],data[3],
	data[4],data[5],data[6],data[7]);
}

// prints a value of 8 bits (1 byte)
void print8bits(uchar *data) {
    printf("%d",data[0]);
}

// prints a value of 16 bits (2 bytes)
void print16bits(uchar *data) {
    printf("%d",(data[0]<<8)+data[1]);
}

// prints a value of 32 bits (4 bytes)
void print32bits(uchar *data) {
    printf("%d",(data[0]<<24)+(data[1]<<16)+(data[2]<<8)+data[3]);
}

// print the data as a 8bits time-value
void printTime8(uchar *data) {
    int t=data[0];
    printf("%d (",t);
    if (t>7*24*3600) { printf("%dw",t/(7*24*3600));t%=7*24*3600; }
    if (t>24*3600) { printf("%dd",t/(24*3600));t%=24*3600; }
    if (t>3600) { printf("%dh",t/3600);t%=3600; }
    if (t>60) { printf("%dm",t/60);t%=60; }
    if (t>0) printf("%ds",t);
    printf(")");
}

// print the data as a 32bits time-value
void printTime32(uchar *data) {
    int t=(data[0]<<24)+(data[1]<<16)+(data[2]<<8)+data[3];
    printf("%d (",t);
    if (t>7*24*3600) { printf("%dw",t/(7*24*3600));t%=7*24*3600; }
    if (t>24*3600) { printf("%dd",t/(24*3600));t%=24*3600; }
    if (t>3600) { printf("%dh",t/3600);t%=3600; }
    if (t>60) { printf("%dm",t/60);t%=60; }
    if (t>0) printf("%ds",t);
    printf(")");
}

// print the data as a hex-list, with the translation into ascii behind it
void printHexString(uchar *data,int len) {
    int i,j,k;

    for (i=0;i<=len/8;i++) {
	for (j=0;j<8;j++) {
	    if (i*8+j>=len) break;
	    printf("%02x",data[i*8+j]);
	}
	for (k=j;k<8;k++)
	    printf("  ");
	printf(" ");
	for (j=0;j<8;j++) {
	    char c=data[i*8+j];
	    if (i*8+j>=len) break;
	    printf("%c",isprint(c)?c:'.');
	}
	if (i*8+j<len) printf("\n\t\t\t\t\t    ");
    }
}

// print the data as a hex-list, without the translation into ascii behind it
void printHex(uchar *data,int len) {
    int i,j;

    for (i=0;i<=len/8;i++) {
	for (j=0;j<8;j++) {
	    if (i*8+j>=len) break;
	    printf("%02x",data[i*8+j]);
	}
	if (i*8+j<len) printf("\n\t\t\t\t\t    ");
    }
}

// print the data as a hex-list seperated by colons
void printHexColon(uchar *data,int len) {
    int i;

    for (i=0;i<len;i++) {
	if (i!=0) printf(":");
	printf("%02x",data[i]);
    }
}

// print the list of requested parameters
void printReqParmList(uchar *data,int len) {
    int i;

    for (i=0;i<len;i++) {
	printf("%3d (%s)\n",data[i],dhcp_options[data[i]]);
	printf("\t\t\t\t\t    ");
    }
}

// print the header and the options.
int printdata(uchar *data,int data_len) {
    int j,i;
    uchar buf[LARGESTRING];

    if (data_len==0)
	return 0;

    // Skip the ethernet header. Is there a way to do this better?
    data+=28;	// note 1

    printf(  "  TIME: %s\n",timestamp);
    printf(  "    IP: %s (%s) > %s (%s)\n",
	ip_origin,mac_origin,ip_destination,mac_destination);
    printf(  "    OP: %d (%s)\n",data[0],operands[data[0]]);
    printf(  " HTYPE: %d (%s)\n",data[1],htypes[data[1]]);
    printf(  "  HLEN: %d\n",data[2]);
    printf(  "  HOPS: %d\n",data[3]);
    printf(  "   XID: %02x%02x%02x%02x\n",
	data[4],data[5],data[6],data[7]);
    printf(  "  SECS: ");print16bits(data+8);//,255*data[8]+data[9]);
    printf("\n FLAGS: %x\n",255*data[10]+data[11]);

    printf(  "CIADDR: ");printIPaddress(data+12);
    printf("\nYIADDR: ");printIPaddress(data+16);
    printf("\nSIADDR: ");printIPaddress(data+20);
    printf("\nGIADDR: ");printIPaddress(data+24);
    printf("\nCHADDR: ");printHexColon(data+28,16);
    printf("\n SNAME: %s.\n",data+44);
    printf(  " FNAME: %s.\n",data+108);

    j=236;
    j+=4;	/* cookie */
    while (j<data_len && data[j]!=255) {
	printf("OPTION: %3d (%3d) %-26s",data[j],data[j+1],dhcp_options[data[j]]);

	switch (data[j]) {
	default:
	    printHexString(data+j+2,data[j+1]);
	    break;

	case 0:		// pad
	    break;

	case  1:	// Subnetmask
	case  3:	// Routers
	case 16:	// Swap server
	case 28:	// Broadcast address
	case 32:	// Router solicitation
	case 50:	// Requested IP address
	case 54:	// Server identifier
	    printIPaddress(data+j+2);
	    break;

	case 12:	// Hostname
	case 14:	// Merit dump file
	case 15:	// Domain name
	case 17:	// Root Path
	case 18:	// Extensions path
	case 40:	// NIS domain
	case 56:	// Message
	case 62:	// Netware/IP domain name
	case 64:	// NIS+ domain
	case 66:	// TFTP server name
	case 67:	// bootfile name
	case 60:	// Domain name
	case 86:	// NDS Tree name
	case 87:	// NDS context
	    strncpy(buf,&data[j+2],data[j+1]);
	    buf[data[j+1]]=0;
	    printf("%s",buf);
	    break;

	case  4:	// Time servers
	case  5:	// Name servers
	case  6:	// DNS server
	case  7:	// Log server
	case  8:	// Cookie server
	case  9:	// LPR server
	case 10:	// Impress server
	case 11:	// Resource location server
	case 41:	// NIS servers
	case 42:	// NTP servers
	case 44:	// NetBIOS name server
	case 45:	// NetBIOS datagram distribution server
	case 48:	// X Window System font server
	case 49:	// X Window System display server
	case 65:	// NIS+ servers
	case 68:	// Mobile IP home agent
	case 69:	// SMTP server
	case 70:	// POP3 server
	case 71:	// NNTP server
	case 72:	// WWW server
	case 73:	// Finger server
	case 74:	// IRC server
	case 75:	// StreetTalk server
	case 76:	// StreetTalk directory assistance server
	case 85:	// NDS server
	    for (i=0;i<data[j+1]/4;i++) {
		if (i!=0) printf(",");
		printIPaddress(data+j+2+i*4);
	    }
	    break;

	case 21:	// Policy filter
	    for (i=0;i<data[j+1]/8;i++) {
		if (i!=0) printf(",");
		printIPaddressMask(data+j+2+i*8);
	    }
	    break;

	case 33:	// Static route
	    for (i=0;i<data[j+1]/8;i++) {
		if (i!=0) printf(",");
		printIPaddressAddress(data+j+2+i*8);
	    }
	    break;

	case 25:	// Path MTU plateau table
	    for (i=0;i<data[j+1]/2;i++) {
		if (i!=0) printf(",");
		print16bits(data+j+2+i*2);
	    }
	    break;

	case 13:	// bootfile size
	case 22:	// Maximum datagram reassembly size
	case 26:	// Interface MTU
	case 57:	// Maximum DHCP message size
	    print16bits(data+j+2);
	    break;

	case 19:	// IP forwarding enabled/disable
	case 20:	// Non-local source routing
	case 27:	// All subnets local
	case 29:	// Perform mask discovery
	case 30:	// Mask supplier
	case 31:	// Perform router discovery
	case 34:	// Trailer encapsulation
	case 39:	// TCP keepalive garbage
	    printf("%d (%s)",data[j+2],enabledisable[data[j+2]]);
	    break;

	case 23:	// Default IP TTL
	    printTime8(data+j+2);
	    break;

	case 37:	// TCP default TTL
	    print8bits(data+j+2);
	    break;

	case 43:	// Vendor specific info
	case 47:	// NetBIOS scope (no idea how it looks like)
	    printHexString(data+j+2,data[j+1]);
	    break;

	case 46:	// NetBIOS over TCP/IP node type
	    printf("%d (%s)",
		data[j+2],netbios_node_type[data[j+2]]);
	    break;
	    
	case  2:	// Time offset
	case 24:	// Path MTU aging timeout
	case 35:	// ARP cache timeout
	case 38:	// TCP keepalive interval
	case 51:	// IP address leasetime
	case 58:	// T1
	case 59:	// T2
	    printTime32(data+j+2);
	    break;

	case 36:	// Ethernet encapsulation
	    printf("%d (%s)",
		data[j+2],
		data[j+2]>sizeof(ethernet_encapsulation)?
		    "*wrong value*":
		    ethernet_encapsulation[data[j+2]]);
	    break;

	case 52:	// Option overload
	    printf("%d (%s)",
		data[j+2],
		data[j+2]>sizeof(option_overload)?
		    "*wrong value*":
		    option_overload[data[j+2]]);
	    break;

	case 53:	// DHCP message type
	    printf("%d (%s)",
		data[j+2],
		data[j+2]>sizeof(dhcp_message_types)?
		    "*wrong value*":
		    dhcp_message_types[data[j+2]]);
	    break;

	case 55:	// Parameter Request List
	    printReqParmList(data+j+2,data[j+1]);
	    break;

	case 63:	// Netware/IP domain information
	    printHex(data+j+2,data[j+1]);
	    break;

	case 61:	// Client identifier
	    printHexColon(data+j+2,data[j+1]);
	    break;

	case 81:	// Client FQDN
	    print8bits(data+j+2);
	    printf("-");
	    print8bits(data+j+3);
	    printf("-");
	    print8bits(data+j+4);
	    printf(" ");
	    strncpy(buf,&data[j+5],data[j+1]-3);
	    buf[data[j+1-3]]=0;
	    printf("%s",buf);
	    break;

	case 82:	// Relay Agent Information
	    printf("\n");
	    for (i=j+2;i<j+data[j+1];) {
		printf("%-17s %-13s ", " ",
		    data[i]>sizeof(relayagent_suboptions)?
		    "*wrong value*":
		    relayagent_suboptions[data[i]]);
		if (i+data[i+1]>j+data[j+1]) {
		    printf("*MALFORMED -- TOO LARGE*\n");
		    break;
		}
		printHexColon(data+i+2,data[i+1]);
		i+=data[i+1];
	    }
	    break;

	}
	printf("\n");

	/*
	// This might go wrong if a mallformed packet is received.
	// Maybe from a bogus server which is instructed to reply
	// with invalid data and thus causing an exploit.
	// My head hurts... but I think it's solved by the checking
	// for j<data_len at the begin of the while-loop.
	*/
	if (data[j]==0)		// padding
	    j++;
	else
	    j+=data[j+1]+2;
    }

    printf("---------------------------------------------------------------------------\n");
    fflush(stdout);

    return 0;
}

//
// read the data of the packet, which is a bunch of hexdigits like:
// ffff ffff 0043 0044 013f 2432 0201 0600.
//
// For tcpdump 3.8.3, it is:
// 0x0110:  04c0 a801 0133 0400 0002 5801 04ff ffff  .....3....X.....
//
int readdata(uchar *buf,uchar *data,int *data_len) {
    int i,length;
    bool first=TRUE;
    int prev=0;

    if (tcpdump_style==0) {
	length=strlen(buf);
	for (i=0;i<length;i++) {
	    if (buf[i]==' ') continue;
	    if (buf[i]=='\t') continue;
	    if (buf[i]=='\r') continue;
	    if (buf[i]=='\n') continue;

	    if (isxdigit(buf[i])) {
		if (buf[i]<='9') {
		    if (first) {
			prev=buf[i]-'0'; first=FALSE;
		    } else {
			data[(*data_len)++]=prev*16+buf[i]-'0'; first=TRUE;
		    }
		} else {
		    buf[i]=tolower(buf[i]);
		    if (first) {
			prev=buf[i]-'a'+10; first=FALSE;
		    } else {
			data[(*data_len)++]=prev*16+buf[i]-'a'+10; first=TRUE;
		    }
		}
		continue;
	    }
	    fprintf(stderr,"Error in packet: offset: %d, character %c\n",i,buf[i]);
	}

	if (*data_len>=max_data_len)
	    return 1;
    }

    if (tcpdump_style==1) {
	bool foundcolon=FALSE;
	bool founddata=FALSE;
	bool foundspace=FALSE;
	int count=0;

	length=strlen(buf);
	for (i=0;i<length;i++) {
	    if (buf[i]==' ') {
		if (founddata && foundspace)
		    foundcolon=FALSE;
		else
		    foundspace=TRUE;
		continue;
	    }
	    foundspace=FALSE;
	    if (buf[i]=='\t') continue;
	    if (buf[i]=='\r') { count=0; continue; }
	    if (buf[i]=='\n') { count=0; continue; }

	    if (buf[i]==':') { foundcolon=TRUE; continue; }
	    if (!foundcolon) continue;

	    if (count==32) continue;

	    if (isxdigit(buf[i])) {
		if (buf[i]<='9') {
		    if (first) {
			prev=buf[i]-'0'; first=FALSE;
		    } else {
			data[(*data_len)++]=prev*16+buf[i]-'0'; first=TRUE;
		    }
		} else {
		    buf[i]=tolower(buf[i]);
		    if (first) {
			prev=buf[i]-'a'+10; first=FALSE;
		    } else {
			data[(*data_len)++]=prev*16+buf[i]-'a'+10; first=TRUE;
		    }
		}
		count++;
		founddata++;
		continue;
	    }
	    fprintf(stderr,"Error in packet: offset: %d, character %c\n",i,buf[i]);
	}

	if (*data_len>=max_data_len)
	    return 1;
    }

    return 0;
}

// read the header of the packet, which should look like this:
// 14:06:20.149959 0:80:5f:c1:71:f ff:ff:ff:ff:ff:ff 0800 353:
// 130.139.64.101.67 > 255.255.255.255.68:  
// field 1: timestamp
// field 2: mac address origin
// field 3: mac address destination
// field 5: length of IP packets + 14
// field 6: ip address origin
// field 8: ip address destination
//
// tcpdump 3.8.3 has this as header:
// 18:19:30.618569 00:0b:82:01:b5:e3 > ff:ff:ff:ff:ff:ff, ethertype IPv4 
// (0x0800), length 342: IP 0.0.0.0.68 > 255.255.255.255.67: BOOTP/DHCP,
// Request from 00:0b:82:01:b5:e3, length: 300
// field 1: timestamp
// field 2: mac address origin
// field 4: mac address destination
// field 9: length of IP packets + 14
// field 11: ip address origin
// field 13: ip address destination
//
//
int readheader(uchar *lbuf) {
    int n;
    char **ap;
    char *argv[16];
    char max_data_str[20];

    char *buf=(char *)lbuf;

    if (tcpdump_style==-1) {
	char *b=(char *)malloc(LARGESTRING);
	strcpy(b,buf);
	tcpdump_style=0;
	for (ap=argv,n=0;(*ap=strsep(&b," \t"))!=NULL;n++) {
	    if (n==2) {
		if (ap[0][0]=='>') tcpdump_style=1;
		break;
	    }
	}
	if (tcpdump_style==0)
	    fprintf(stderr,"Old-style tcpdump output\n");
	if (tcpdump_style==1)
	    fprintf(stderr,"TCPdump 3.8.x output\n");
	// XXX yeah yeah *b is a memory leak.
    }

    if (tcpdump_style==0) {
	buf=(char *)lbuf;
	for (ap=argv,n=0;(*ap=strsep(&buf," \t"))!=NULL;n++)
	    if (**ap!='\0') {
		if (++ap>=&argv[8])
		    break;
		switch(n) {
		    default:
			break;
		    case 0: 	// timestamp
			strcpy(timestamp,argv[0]);
			break;
		    case 1:	// mac origin
			strcpy(mac_origin,argv[1]);
			break;
		    case 2:	// mac destination
			strcpy(mac_destination,argv[2]);
			break;
		    case 4: // size of packet
			strcpy(max_data_str,argv[4]);
			max_data_str[strlen(max_data_str)-1]=0;
			max_data_len=atoi(max_data_str)-14; // note 2 *************
			break;
		    case 5:	// ip origin
			strcpy(ip_origin,argv[5]);
			break;
		    case 7:	// ip destination
			strcpy(ip_destination,argv[7]);
			ip_destination[strlen(ip_destination)-1]=0;
			break;
		}
	    }
	return 0;
    }

    if (tcpdump_style==1) {
// tcpdump 3.8.3 has this as header:
// 18:19:30.618569 00:0b:82:01:b5:e3 > ff:ff:ff:ff:ff:ff, ethertype IPv4 
// (0x0800), length 342: IP 0.0.0.0.68 > 255.255.255.255.67: BOOTP/DHCP,
// Request from 00:0b:82:01:b5:e3, length: 300
// field 1: timestamp
// field 2: mac address origin
// field 4: mac address destination
// field 9: length of IP packets + 14
// field 11: ip address origin
// field 13: ip address destination
	buf=(char *)lbuf;
	for (ap=argv,n=0;(*ap=strsep(&buf," \t"))!=NULL;n++) {
//fprintf(stderr,"n: %d\n",n);
	    if (**ap!='\0') {
		if (++ap>=&argv[13])
		    break;
		switch(n) {
		    default:
			break;
		    case 0: 	// timestamp
			strcpy(timestamp,argv[0]);
//fprintf(stderr,"timestamp: %s\n",timestamp);
			break;
		    case 1:	// mac origin
			strcpy(mac_origin,argv[1]);
//fprintf(stderr,"mac origin: %s\n",mac_origin);
			break;
		    case 3:	// mac destination
			strcpy(mac_destination,argv[3]);
			mac_destination[strlen(mac_destination)-1]=0;
//fprintf(stderr,"mac destination: %s\n",mac_destination);
			break;
		    case 8: // size of packet
			strcpy(max_data_str,argv[8]);
			max_data_str[strlen(max_data_str)-1]=0;
			max_data_len=atoi(max_data_str)-14; // note 2 *************
//fprintf(stderr,"maxdatalen: %d\n",max_data_len);
			break;
		    case 10:	// ip origin
			strcpy(ip_origin,argv[10]);
//fprintf(stderr,"ip origin: %s\n",ip_origin);
			break;
		    case 12:	// ip destination
			strcpy(ip_destination,argv[12]);
			ip_destination[strlen(ip_destination)-1]=0;
//fprintf(stderr,"ip destination: %s\n",ip_destination);
			break;
		}
	    }
	}
//fprintf(stderr,"%d\n",n);
	return 0;
    }

    return 1;

}
