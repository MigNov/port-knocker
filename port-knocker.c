/*
 * Copyright (c) 1999 - 2005 NetGroup, Politecnico di Torino (Italy)
 * Copyright (c) 2005 - 2006 CACE Technologies, Davis (California)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Politecnico di Torino, CACE Technologies 
 * nor the names of its contributors may be used to endorse or promote 
 * products derived from this software without specific prior written 
 * permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifdef _MSC_VER
/*
 * we do not want the warnings about the old deprecated and unsecure CRT functions
 * since these examples can be compiled under *nix as well
 */
#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable : 4996)
#endif

#ifdef __linux__
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>
#include <unistd.h>
#define _strdup strdup
#endif

#include <pcap.h>
#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <time.h>
#include <string.h>

#define OS_WINDOWS	0
#define OS_LINUX	1
#define OS_UNKNOWN	2

#define OPT_ERROR	0x01
#define OPT_DEBUG	0x10
#define OPT_VERBOSE	0x20

char os_type_str[16];
int interface_number = -1;
int opts = 0;
char *output_file = NULL;

void out_printf(const char* fmt, ...) {
	va_list arglist;
	unsigned char str[8192];

	memset(str, 0, sizeof(str));

	va_start(arglist, fmt);
	vsnprintf(str, sizeof(str), fmt, arglist);
	va_end(arglist);

	if (output_file != NULL) {
		FILE* fp = fopen(output_file, "a");
		if (fp != NULL) {
			fprintf(fp, "%s", str);
			fclose(fp);
		}
	}
	else {
		fprintf(stderr, "%s", str);
	}
}

#if defined(_WIN32) || defined(_WIN64)
#include <tchar.h>
BOOL LoadNpcapDlls()
{
	_TCHAR npcap_dir[512];
	UINT len;
	len = GetSystemDirectory(npcap_dir, 480);
	if (!len) {
		fprintf(stderr, "Error in GetSystemDirectory: %x", GetLastError());
		return FALSE;
	}
	_tcscat_s(npcap_dir, 512, _T("\\Npcap"));
	if (SetDllDirectory(npcap_dir) == 0) {
		fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
		return FALSE;
	}
	return TRUE;
}
#endif

/* 4 bytes IP address */
typedef struct ip_address
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

/* IPv4 header */
typedef struct ip_header
{
	u_char	ver_ihl;		// Version (4 bits) + Internet header length (4 bits)
	u_char	tos;			// Type of service 
	u_short tlen;			// Total length 
	u_short identification; // Identification
	u_short flags_fo;		// Flags (3 bits) + Fragment offset (13 bits)
	u_char	ttl;			// Time to live
	u_char	proto;			// Protocol
	u_short crc;			// Header checksum
	ip_address	saddr;		// Source address
	ip_address	daddr;		// Destination address
	u_int	op_pad;			// Option + Padding
}ip_header;

/* TCP header */
typedef struct tcp_header
{
	uint16_t sport;
	uint16_t dport;
	uint32_t seq;
	uint32_t ack;
	uint8_t  data_offset;  // 4 bits
	uint8_t  flags;
	uint16_t window_size;
	uint16_t checksum;
	uint16_t urgent_p;
} tcp_header;

/* UDP header*/
typedef struct udp_header
{
	u_short sport;			// Source port
	u_short dport;			// Destination port
	u_short len;			// Datagram length
	u_short crc;			// Checksum
} udp_header;

/* Global configuration file variable */
char* config_file = NULL;
char *current_distro = NULL;
int current_major = 0;
int current_minor = 0;

/* prototype of the packet handler */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

char *xpath_get(const char* filename, const xmlChar* xpathExpr)
{
    int num;
    xmlDocPtr doc;
    xmlXPathContextPtr xpathCtx;
    xmlXPathObjectPtr xpathObj;
    xmlNodeSetPtr nodeset;
    char* ret = NULL;

    if (filename == NULL) {
        return ret;
    }
    if (xpathExpr == NULL) {
        return ret;
    }

    /* Load XML document */
    doc = xmlParseFile(filename);
    if (doc == NULL) {
        return ret;
    }

    /* Create xpath evaluation context */
    xpathCtx = xmlXPathNewContext(doc);
    if (xpathCtx == NULL) {
        xmlFreeDoc(doc);
        return ret;
    }

    /* Evaluate xpath expression */
    xpathObj = xmlXPathEvalExpression(xpathExpr, xpathCtx);
    if (xpathObj == NULL) {
        xmlXPathFreeContext(xpathCtx);
        xmlFreeDoc(doc);
        return ret;
    }

    /* Process results */
    nodeset = xpathObj->nodesetval;
    if (nodeset == NULL) {
        return ret;
    }
    num = nodeset->nodeNr;

    for (int i = 0; i < nodeset->nodeNr; i++) {
        xmlChar* keyword;
        keyword = xmlNodeListGetString(doc, nodeset->nodeTab[i]->xmlChildrenNode, 1);
        if (keyword != NULL) {
            ret = _strdup( (char *)keyword );
            break;
        }
        xmlFree(keyword);
    }

    /* Cleanup */
    xmlXPathFreeObject(xpathObj);
    xmlXPathFreeContext(xpathCtx);
    xmlFreeDoc(doc);

    return ret;
}

#ifdef __linux__
int FileExists(char *szPath)
{
    return (access(szPath, F_OK) == 0);
}
#else
BOOL FileExists(LPCTSTR szPath)
{
    DWORD dwAttrib = GetFileAttributes(szPath);

    return (dwAttrib != INVALID_FILE_ATTRIBUTES && !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}
#endif

/*
* Detect OS and OS version
*
* @param out_distro output of distribution
* @param out_major major version of OS
* @param out_minor minor version of OS
* @returns
*   OS_WINDOWS for Windows OS
*   OS_LINUX   for Linux OS
*   OS_UNKNOWN for unknown OS
*/
int GetOSVersion(char **out_distro, int *out_major, int *out_minor)
{
    char distro[1024];
	int ret = OS_UNKNOWN;
    int major = 0, minor = 0;

#if defined(_WIN32) || defined(_WIN64)
	OSVERSIONINFOEX osvi;

	ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	if (!GetVersionEx((LPOSVERSIONINFO)&osvi))
		return FALSE;

	major = osvi.dwMajorVersion;
	minor = osvi.dwMinorVersion;

    strcpy(distro, "windows");
	ret = OS_WINDOWS;
#elif __linux__
	// write detection of version (possibly kernel version, but may be also the /etc/os-release version)
	FILE *fp = fopen("/etc/os-release", "r");
    if (fp != NULL) {
        while (!feof(fp)) {
            char str[1024];
            fgets(str, sizeof(str), fp);
            if (strncmp(str, "ID=", 3) == 0) {
                strcpy(distro, str + 3);
                if (distro[strlen(distro) - 1] == '\n')
                    distro[strlen(distro) - 1] = 0;
            }
            if (strncmp(str, "VERSION_ID=", 11) == 0) {
                major = atoi(str + 11);
            }
        }
        fclose(fp);
    }
	ret = OS_LINUX;
#endif
    if (out_major != NULL) {
        *out_major = major;
    }
    if (out_minor != NULL) {
        *out_minor = minor;
    }
    if (out_distro != NULL) {
        *out_distro = strdup(distro);
    }
	return ret;
}

/*
* Function to detect whether "value" is a number
* 
* @param value string value to be checked for valid number
* @returns
*   1 if value is a valid number
*   0 if value is not a valid number
*/
int is_number(char* value)
{
	int ret = 0;
	if (value == NULL) {
		return 1;
	}
	for (unsigned int i = 0; i < strlen(value); i++) {
		if (isdigit(value[i]))
			ret++;
	}
	return (ret == strlen(value));
}

/**
 * Replaces all found instances of the passed substring in the passed string.
 *
 * @param subject The string in which to look
 * @param search The substring to look for
 * @param replace The substring with which to replace the found substrings
 *
 * @return A new string with the search/replacement performed
 **/
char* str_replace(const char* subject, const char* search, const char* replace) {
	int i, j, k;

	int searchSize = strlen(search);
	int replaceSize = strlen(replace);
	int size = strlen(subject);

	char* ret;

	if (!searchSize) {
		ret = malloc(size + 1);
		for (i = 0; i <= size; i++) {
			ret[i] = subject[i];
		}
		return ret;
	}

	int retAllocSize = (strlen(subject) + 1) * 2; // Allocation size of the return string.
	// let the allocation size be twice as that of the subject initially
	ret = malloc(retAllocSize);

	int bufferSize = 0; // Found characters buffer counter
	char* foundBuffer = malloc(searchSize); // Found character bugger

	for (i = 0, j = 0; i <= size; i++) {
		/**
		 * Double the size of the allocated space if it's possible for us to surpass it
		 **/
		if (retAllocSize <= j + replaceSize) {
			retAllocSize *= 2;
			ret = (char*)realloc(ret, retAllocSize);
		}
		/**
		 * If there is a hit in characters of the substring, let's add it to the
		 * character buffer
		 **/
		else if (subject[i] == search[bufferSize]) {
			foundBuffer[bufferSize] = subject[i];
			bufferSize++;

			/**
			 * If the found character's bugger's counter has reached the searched substring's
			 * length, then there's a hit. Let's copy the replace substring's characters
			 * onto the return string.
			 **/
			if (bufferSize == searchSize) {
				bufferSize = 0;
				for (k = 0; k < replaceSize; k++) {
					ret[j++] = replace[k];
				}
			}
		}
		/**
		 * If the character is a miss, let's put everything back from the buffer
		 * to the return string, and set the found character buffer counter to 0.
		 **/
		else {
			for (k = 0; k < bufferSize; k++) {
				ret[j++] = foundBuffer[k];
			}
			bufferSize = 0;
			/**
			 * Add the current character in the subject string to the return string.
			 **/
			ret[j++] = subject[i];
		}
	}

	/**
	 * Free memory
	 **/
	free(foundBuffer);

	return ret;
}

void show_usage(char* progname)
{
	printf("Port Knocker Utility\n\n");
	printf("Syntax: %s [-c <config_file>] [-i <interface_number>] [-o <output_file>] [-d] [-v]\n", progname);
	printf("where:\n");
	printf(" -c <config_file> - utility configuration file\n");
	printf(" -i <interface_number> - number of interface to listen on\n");
	printf(" -o <output_file> - name of the output file\n");
	printf(" -d - debug\n");
	printf(" -v - verbose\n");
}
/*
* Function to parse options, getopt() not available on MSVC for Windows
* 
* @param argc argument count
* @param argv argument list
* 
* @returns
*   OPT_* flags bit array
*
* Options supported:
* -c <config-file>
* -i <interface>
* -d debug
* -v verbose
*/
int parse_options(unsigned int argc, char* argv[])
{
	int ret = 0;
	if (argc == 1) {
		return 0;
	}

	// Implement our version of "limited" getopt() as getopt() is not available on MSVC for Windows
	for (unsigned int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-c") == 0) {
			if (argc < i + 2) { // this will check for argument
				fprintf(stderr, "Error: Invalid config file argument\n");
				return OPT_ERROR;
			}
			else {
				config_file = _strdup(argv[i + 1]);
			}
		}
		else
		if (strcmp(argv[i], "-i") == 0) {
			if (argc < i + 2) { // this will check for argument
				fprintf(stderr, "Error: Invalid interface input\n");
				return OPT_ERROR;
			}
			else {
				if (is_number(argv[i + 1]) == 0) {
					fprintf(stderr, "Error: Invalid interface number\n");
					return OPT_ERROR;
				}
				interface_number = atoi(argv[i + 1]);
			}
		}
		else
		if (strcmp(argv[i], "-o") == 0) {
			if (argc < i + 2) { // this will check for argument
				fprintf(stderr, "Error: Output file is missing\n");
				return OPT_ERROR;
			}
			else {
				output_file = _strdup(argv[i + 1]);
			}
		}
		else
		if (strcmp(argv[i], "-h") == 0) {
			show_usage(argv[0]);
			return OPT_ERROR;
		}
		else
		if (strcmp(argv[i], "-d") == 0) {
			ret |= OPT_DEBUG;
		}
		else
		if (strcmp(argv[i], "-v") == 0) {
			ret |= OPT_VERBOSE;
		}
	}

	return ret;
}

#ifdef __linux__
char *getConfigFile(void)
{
        FILE *fp = NULL;
        char fn[1024], buf[4096];
        snprintf(fn, sizeof(fn), "/proc/%d/cmdline", getpid());
        fp = fopen(fn, "r");
        if (fp == NULL) {
            return NULL;
        }
        fgets(buf, sizeof(buf), fp);
        fclose(fp);
        strcat(buf, ".xml");
        return strdup(buf);
}
#else
char *getConfigFile(void)
{
        TCHAR me[MAX_PATH];
        GetModuleFileName(NULL, me, sizeof(me));
        if ((me != NULL) && (strlen(me) > 3)) {
                me[strlen(me) - 1] = 'l';
                me[strlen(me) - 2] = 'm';
                me[strlen(me) - 3] = 'x';

                return _strdup(me);
        }
        
        return NULL;
}
#endif

/*
* Main function entry point
* 
* @param argc argument count
* @param argv argument list
*/
int main(unsigned int argc, char *argv[])
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i=0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;
	struct bpf_program fcode;
	char* packet_filter = NULL;
	
#if defined(_WIN32) || defined(_WIN64)
	/* Load Npcap and its functions. */
	if (!LoadNpcapDlls())
	{
		out_printf("Couldn't load Npcap\n");
		exit(1);
	}
#endif

	opts = parse_options(argc, argv);
	if (opts & OPT_ERROR) {
		return 1;
	}

    if (config_file == NULL) {
        config_file = getConfigFile();
		
        if (config_file == NULL) {
            out_printf("Error: Configuration file cannot be autodetected\n");
            return 1;
        }
    }

	if (!FileExists(config_file)) {
        out_printf("Error: Configuration file does not exist\n");
        return 2;
    }

    int osver = GetOSVersion(&current_distro, &current_major, &current_minor);
    if (osver == OS_WINDOWS) {
        snprintf(os_type_str, sizeof(os_type_str), "windows");
    }
	else
    if (osver == OS_LINUX) {
        snprintf(os_type_str, sizeof(os_type_str), "linux");
	}
	else {
		fprintf(stderr, "Error: Unsupported operating system\n");
		return 1;
	}

	packet_filter = xpath_get(config_file, "//port-knocker-configuration/@filter");

	if (opts & OPT_DEBUG) {
        out_printf("[DEBUG] Operating system detected: %s %d.%d\n", current_distro, current_major, current_minor);
		out_printf("[DEBUG] Packet filter: '%s'\n", packet_filter);
	}

	/* Retrieve the device list */
	if(pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		out_printf("Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
	
	if (interface_number == -1) {
		/* Print the list */
		for (d = alldevs; d; d = d->next)
		{
			printf("%d. %s", ++i, d->name);
			if (d->description)
				printf(" (%s)\n", d->description);
			else
				printf(" (No description available)\n");
		}

		if (i == 0)
		{
			printf("\nNo interfaces found! Make sure Npcap is installed.\n");
			return -1;
		}

		printf("Enter the interface number (1-%d): ", i);
		scanf("%d", &inum);
	}
	else {
		inum = interface_number;

		for (d = alldevs; d; d = d->next)
		{
			i++;
		}

		if (i == 0)
		{
			out_printf("\nNo interfaces found! Make sure libpcap/Npcap is installed.\n");
			return -1;
		}
	}
	
	/* Check if the user specified a valid adapter */
	if(inum < 1 || inum > i)
	{
		out_printf("\nAdapter number out of range.\n");
		
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);
	
	/* Open the adapter */
	if ((adhandle= pcap_open_live(d->name,	// name of the device
							 65536,			// portion of the packet to capture. 
											// 65536 grants that the whole packet will be captured on all the MACs.
							 1,				// promiscuous mode (nonzero means promiscuous)
							 1000,			// read timeout
							 errbuf			// error buffer
							 )) == NULL)
	{
		out_printf("\nUnable to open the adapter: %s\n", errbuf);
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	/* Check the link layer. We support only Ethernet for simplicity. */
	if(pcap_datalink(adhandle) != DLT_EN10MB)
	{
		out_printf("\nThis program works only on Ethernet networks.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	if (d->addresses != NULL) {
		/* Retrieve the mask of the first address of the interface */
		#ifdef __linux__
		if (d->addresses->netmask != NULL) {
		    netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.s_addr;
		}
		else {
		    netmask = PCAP_NETMASK_UNKNOWN;
		}
		#else
		netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
		#endif
		
	}
	else {
		//netmask = 0xffffff;
		netmask = PCAP_NETMASK_UNKNOWN;
	}


	/* Compile the BPF filter */
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) <0 )
	{
		out_printf("\nUnable to compile the packet filter. Check the syntax.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	/* Apply the filter to adapter handle (ADhandle) */
	if (pcap_setfilter(adhandle, &fcode)<0)
	{
		out_printf("\nError setting the filter.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	if (opts & OPT_DEBUG) {
		out_printf("\n[DEBUG] Listening on '%s' ...\n\n", d->description ? d->description : d->name);
	}

	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);
	
	/* start the capture */
	pcap_loop(adhandle, 0, packet_handler, NULL);

	/* Free no longer needed variables */
	free(packet_filter);
	free(config_file);

	return 0;
}

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	struct tm* ltime;
	char timestr[16];
	ip_header* ih;
	udp_header* uh;
	tcp_header* th;
	u_int ip_len;
	u_short sport, dport;
	time_t local_tv_sec;
	u_int start_position;
	u_int last_position;
	char pkt_data_hex[81920];
	char xpath[102400];
	char cond_type[4];

	/*
	 * unused parameter
	 */
	//(VOID)(param);

	/* convert the timestamp to readable format */
	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

	/* retrieve the position of the ip header */
	ih = (ip_header*)(pkt_data + 14); //14 bytes is the length of ethernet header, 2x MAC address (6 bytes) + Ethernet type (2 bytes)

	/* retrieve the position of the UDP header */
	ip_len = (ih->ver_ihl & 0xf) * 4;

	if (opts & OPT_DEBUG) {
		/* print timestamp and length of the packet */
		out_printf("[DEBUG] %s.%.6d len:%d  ", timestr, header->ts.tv_usec, header->len);
	}

	memset(pkt_data_hex, 0, sizeof(pkt_data_hex));

	/* IP protocol for TCP */
	if (ih->proto == 6) {
		th = (tcp_header*)((u_char*)ih + ip_len);
		int data_offset = (th->data_offset >> 4);
		int data_length = ntohs(ih->tlen) - (((ih->ver_ihl & 0xf) + data_offset) * 4);

		/* Set condition type to 'tcp' */
		strncpy(cond_type, "tcp", sizeof(cond_type));

		/* convert from network byte order to host byte order */
		sport = ntohs(th->sport);
		dport = ntohs(th->dport);

		/* Calculate start and last position */
		start_position = ntohs(ih->tlen) - data_length + 14; // 14 bytes of Ethernet header
		last_position = ntohs(ih->tlen) + 14; // 14 bytes of Ethernet header
	}
	else /* IP protocol for UDP */
		if (ih->proto == 17) {
			uh = (udp_header*)((u_char*)ih + ip_len);

			/* Set condition type to 'udp' */
			strncpy(cond_type, "udp", sizeof(cond_type));

			/* convert from network byte order to host byte order */
			sport = ntohs(uh->sport);
			dport = ntohs(uh->dport);

			/* convert from network byte order to host byte order */
			uh->len = htons(uh->len);

			/* Calculate start and last position */
			start_position = 14 + 8 + ip_len;
			last_position = start_position + (uh->len - 8);
		}

	if (opts & OPT_DEBUG) {
		/* print ip addresses and ports */
		out_printf("%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d (proto %d)   ",
			ih->saddr.byte1,
			ih->saddr.byte2,
			ih->saddr.byte3,
			ih->saddr.byte4,
			sport,
			ih->daddr.byte1,
			ih->daddr.byte2,
			ih->daddr.byte3,
			ih->daddr.byte4,
			dport, ih->proto);
	}

	for (unsigned int i = start_position; i < last_position; i++) {
		char pkt_char[3];
		memset(pkt_char, 0, sizeof(pkt_char));
		snprintf(pkt_char, sizeof(pkt_char), "%02x", pkt_data[i]);

		if (strlen(pkt_data_hex) + strlen(pkt_char) + 1 < sizeof(pkt_data_hex)) {
			strcat(pkt_data_hex, pkt_char);
		}
	}

	if (strlen(pkt_data_hex) > 0) {
		if (opts & OPT_VERBOSE) {
			out_printf("\n[VERBOSE] HEX: '%s'\n", pkt_data_hex);

			char pkt_data_bin[8192];
			memset(pkt_data_bin, 0, sizeof(pkt_data_bin));
			for (unsigned int i = start_position; i < last_position; i++) {
				char pkt_char[2];
				memset(pkt_char, 0, sizeof(pkt_char));
				snprintf(pkt_char, sizeof(pkt_char), "%c", pkt_data[i]);

				if (strlen(pkt_data_bin) + strlen(pkt_char) + 1 < sizeof(pkt_data_bin)) {
					strcat(pkt_data_bin, pkt_char);
				}
			}
			out_printf("[VERBOSE] BIN: '%s'\n", pkt_data_bin);
		}

        char distro[1024];
        snprintf(distro, sizeof(distro), "%s %d.%d", current_distro, current_major, current_minor);

		while (strlen(pkt_data_hex) > 0) {
			snprintf(xpath, sizeof(xpath), "//port-knocker-configuration/system[@type='%s'][@version='%s']/conditions[@protocol='%s']/condition[@port=%d][@payload='%s']|//port-knocker-configuration/system[@type='%s'][@version='%s']/conditions[@protocol='%s']/condition[@port=-1][@payload='%s']|//port-knocker-configuration/system[@type='%s']/conditions[@protocol='%s']/condition[@port=%d][@payload='%s']|//port-knocker-configuration/system[@type='%s']/conditions[@protocol='%s']/condition[@port=-1][@payload='%s']",
				os_type_str, distro, cond_type, dport, pkt_data_hex, os_type_str, distro, cond_type, pkt_data_hex, os_type_str, cond_type, dport, pkt_data_hex, os_type_str,
                cond_type, pkt_data_hex);

			char *command = xpath_get(config_file, xpath);

			if (command != NULL) {
				/* Substitute source and destination IPs and ports */
				if (strstr(command, "%SOURCE_IP%") != NULL) {
					char tmp[128];
					snprintf(tmp, sizeof(tmp), "%d.%d.%d.%d", ih->saddr.byte1, ih->saddr.byte2, ih->saddr.byte3, ih->saddr.byte4);
					command = str_replace(command, "%SOURCE_IP%", tmp);
				}
				if (strstr(command, "%SOURCE_PORT%") != NULL) {
					char tmp[8];
					snprintf(tmp, sizeof(tmp), "%d", sport);
					command = str_replace(command, "%SOURCE_PORT%", tmp);
				}
				if (strstr(command, "%DESTINATION_IP%") != NULL) {
					char tmp[128];
					snprintf(tmp, sizeof(tmp), "%d.%d.%d.%d", ih->daddr.byte1, ih->daddr.byte2, ih->daddr.byte3, ih->daddr.byte4);
					command = str_replace(command, "%DESTINATION_IP%", tmp);
				}
				if (strstr(command, "%DESTINATION_PORT%") != NULL) {
					char tmp[8];
					snprintf(tmp, sizeof(tmp), "%d", dport);
					command = str_replace(command, "%DESTINATION_PORT%", tmp);
				}
				if (opts & OPT_VERBOSE) {
					out_printf("[VERBOSE] Command found by xPath: '%s'\n", xpath);
				}
				if (opts & OPT_DEBUG) {
					out_printf("[DEBUG] Running '%s'\n", command);
				}
				system(command);
				free(command);
				break;
			}
			free(command);

			pkt_data_hex[strlen(pkt_data_hex) - 2] = 0;
		}
	}
	if (opts & OPT_DEBUG) {
		out_printf("\n");
	}
}
