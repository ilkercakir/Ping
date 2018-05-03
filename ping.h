#ifndef ping_H
#define ping_H

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <setjmp.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <sched.h>
#include <pthread.h>
#include <gtk/gtk.h>
#include <math.h>

#define PACKET_SIZE 4096
#define MAX_NO_PACKETS 3

#define MAX_THREADS 100

typedef struct
{
	char sendpacket[PACKET_SIZE];
	char recvpacket[PACKET_SIZE];
	int sockfd, datalen;
	int nsend, nreceived;
	struct sockaddr_in dest_addr;
	pid_t pid;
	struct sockaddr_in from;
	struct timeval tvrecv;
	struct hostent *host;
	struct protoent *protocol;
	unsigned long inaddr;
	double rtt;

	void *parent;
	int id;
	char pingaddress[256];
	char description[256];
	pthread_t tid;
	int retval_thread;
	cpu_set_t cpu;

	pthread_mutex_t initmutex;
	pthread_cond_t initcond;
	int initialized;

	GtkWidget *hbox;
	GtkWidget *icon;
	GtkWidget *label;
	GtkWidget *descr;
	GtkWidget *rttim;
}pingdata;

typedef enum
{
	RUNNING,
	STOPPED
}threadstatus;

typedef struct
{
	pingdata *p;
	int count;
	threadstatus status;
	int seconds;

	pthread_t tid;
	int retval;
	cpu_set_t cpu;

	GdkPixbuf *pbred;
	GdkPixbuf *pbgreen;
	GtkWidget *hbox;
	GtkWidget *frame;
	GtkWidget *vbox;
}pingthread;

typedef struct
{
	long long usecs;
	long long remainingusecs;
	int secs;
}pinginterval;

typedef enum
{
	icon_red,
	icon_green
}iconcolour;

typedef struct
{
	pingthread *pt;
	int i;
	iconcolour ic;
}iconidle;

void tv_sub(struct timeval *out, struct timeval *in);
int init_ping(pingdata *p);
unsigned short cal_chksum(unsigned short *addr, int len);
int pack(pingdata *p);
int unpack(pingdata *p, int len);
void send_packet(pingdata *p);
void recv_packet(pingdata *p);
void close_ping(pingdata *p);
#endif
