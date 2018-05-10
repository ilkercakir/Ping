/*
 * ping.c
 * 
 * Copyright 2018  <pi@raspberrypi>
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 * 
 * 
 */

// compile with gcc -Wall -c "%f" -D__STDC_CONSTANT_MACROS -D__STDC_LIMIT_MACROS -DTARGET_POSIX -D_LINUX -fPIC -DPIC -D_REENTRANT -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -U_FORTIFY_SOURCE -g -ftree-vectorize -pipe -Wno-deprecated-declarations $(pkg-config --cflags gtk+-3.0)
// link with gcc -Wall -o "%e" "%f" -D_POSIX_C_SOURCE=199309L $(pkg-config --cflags gtk+-3.0) -Wl,--whole-archive -lpthread -lrt -ldl -lm -Wl,--no-whole-archive -rdynamic $(pkg-config --libs gtk+-3.0)

#include "ping.h"

void get_first_time_microseconds(pinginterval *t, int secs)
{
	long long micros;
	struct timespec spec;

	clock_gettime(CLOCK_REALTIME, &spec);

	micros = spec.tv_sec * 1.0e6 + round(spec.tv_nsec / 1000); // Convert nanoseconds to microseconds
	t->usecs = micros;
	t->remainingusecs = secs * 1.0e6;
}

void get_next_time_microseconds(pinginterval *t)
{
	long delta;
	long long micros;
	struct timespec spec;

	clock_gettime(CLOCK_REALTIME, &spec);

	micros = spec.tv_sec * 1.0e6 + round(spec.tv_nsec / 1000); // Convert nanoseconds to microseconds
	delta = micros - t->usecs;
	t->remainingusecs -= delta;
}

void tv_sub(struct timeval *out, struct timeval *in)
{
	if ((out->tv_usec -= in->tv_usec) < 0)
	{
		--out->tv_sec;
		out->tv_usec += 1000000;
	}
	out->tv_sec -= in->tv_sec;
}

int init_ping(pingdata *p)
{
	int size = 50 * 1024;

	setuid(getuid());

	if ((p->protocol = getprotobyname("icmp")) == NULL)
	{
		perror("getprotobyname");
		return -1;
	}
	else
	{
		p->datalen = 56;
		p->nsend = 0;
		p->nreceived = 0;
		p->pid = getpid();
		p->inaddr = 0l;
		if ((p->sockfd = socket(AF_INET, SOCK_RAW, p->protocol->p_proto)) < 0)
		{
			perror("socket error");
			return -2;
		}
		else
		{
			setsockopt(p->sockfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
			bzero(&(p->dest_addr), sizeof(p->dest_addr));
			p->dest_addr.sin_family = AF_INET;
			if ((p->inaddr = inet_addr(p->pingaddress)) == INADDR_NONE)
			{
				if ((p->host = gethostbyname(p->pingaddress)) == NULL)
				{
					perror("gethostbyname error");
					return -3;
				}
				else
				{
					memcpy((char*)&(p->dest_addr.sin_addr), p->host->h_addr, p->host->h_length);
				}
			}
			else
			{
				p->dest_addr.sin_addr.s_addr = inet_addr(p->pingaddress);
			}
//printf("PING %s(%s): %d bytes data in ICMP packets.\n", p->pingaddress, inet_ntoa(p->dest_addr.sin_addr), p->datalen);
		}
	}
	return 0;
}

unsigned short cal_chksum(unsigned short *addr, int len)
{
	int nleft = len;
	int sum = 0;
	unsigned short *w = addr;
	unsigned short answer = 0;

	while (nleft > 1)
	{
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1)
	{
		*(unsigned char*)(&answer) = *(unsigned char*)w;
		sum += answer;
	}
	sum = (sum >> 16) + (sum &0xffff);
	sum += (sum >> 16);
	answer = ~sum;

	return answer;
}

int pack(pingdata *p)
{
	int packsize;
	struct icmp *icmp;
	struct timeval *tval;

	icmp = (struct icmp*)p->sendpacket;
	icmp->icmp_type = ICMP_ECHO;
	icmp->icmp_code = 0;
	icmp->icmp_cksum = 0;
	icmp->icmp_seq = p->nsend;
	icmp->icmp_id = p->pid;

	packsize = 8 + p->datalen;
	tval = (struct timeval*)icmp->icmp_data;
	gettimeofday(tval, NULL); 
	icmp->icmp_cksum = cal_chksum((unsigned short*)icmp, packsize); 

    return packsize;
}

int unpack(pingdata *p, int len)
{
	int iphdrlen;
	struct ip *ip;
	struct icmp *icmp;
	struct timeval *tvsend;
	double rtt;
	char *buf = p->recvpacket;

	ip = (struct ip*)buf;
	iphdrlen = ip->ip_hl << 2; 
	icmp = (struct icmp*)(buf + iphdrlen);
	len -= iphdrlen; 

	if (len < 8)
	{
//printf("ICMP packets\'s length is less than 8, thread %d\n", p->id);
		//return -1;
		return -2;
	} 

	if ((icmp->icmp_type == ICMP_ECHOREPLY) && (icmp->icmp_id == p->pid))
	{
		tvsend = (struct timeval*)icmp->icmp_data;
		tv_sub(&(p->tvrecv), tvsend); 
		rtt = p->tvrecv.tv_sec * 1000 + p->tvrecv.tv_usec / 1000;
//printf("%d byte from %s: icmp_seq=%u ttl=%d rtt=%.3f ms\n", len, inet_ntoa(p->from.sin_addr), icmp->icmp_seq, ip->ip_ttl, rtt);
		p->rtt = rtt;
	}
	else
		return -1;

	return 0;
}

void send_packet(pingdata *p)
{
	int packetsize;

	while (p->nsend < MAX_NO_PACKETS)
	{
		p->nsend++;
		packetsize = pack(p); 
//printf("sendto %d no %d\n", p->id, p->nsend);
		if (sendto(p->sockfd, p->sendpacket, packetsize, 0, (struct sockaddr*)&(p->dest_addr), sizeof(p->dest_addr)) < 0)
		{
			perror("sendto error");
			break;
		}
		//usleep(300000);
	}
}

void recv_packet(pingdata *p)
{
	int n, ret;
	socklen_t fromlen;
	extern int errno;

	fromlen = sizeof(p->from);
	while (p->nreceived < p->nsend)
	{
//printf("recvfrom %d no %d\n", p->id, p->nreceived);
		if ((n = recvfrom(p->sockfd, p->recvpacket, sizeof(p->recvpacket), 0, (struct sockaddr*)&(p->from), &fromlen)) < 0)
		{
			if (errno == EINTR)
				continue;
			perror("recvfrom error");
			break;
		}
		gettimeofday(&(p->tvrecv), NULL); 
		if ((ret=unpack(p, n)) == -1)
			continue;
		else if (ret == -2)
			break;

//printf("received from %ld  dest %ld\n", p->from.sin_addr.s_addr, p->dest_addr.sin_addr.s_addr);
		if (p->from.sin_addr.s_addr==p->dest_addr.sin_addr.s_addr) // Raw sockets pick up all incoming packets, do filtering
			p->nreceived++;
    }
}

void close_ping(pingdata *p)
{
	int ret;

//printf("shutting down socket %d\n", p->id);
	if ((ret=shutdown(p->sockfd, SHUT_RDWR)))
	{
		//perror("shutdown error");
	}
//printf("closing socket %d\n", p->id);
	if ((ret=close(p->sockfd)))
	{
		//perror("close error");
	}
//printf("shutdown/close done %d\n", p->id);
}

void init_pingdata(pingthread *pt, pingdata *p, int i)
{
	int ret;

	p[i].parent = pt;
	p[i].id = i;
	p[i].initialized = 0;

	if ((ret=pthread_mutex_init(&(p[i].initmutex), NULL))!=0)
		printf("initmutex init failed, %d\n", ret);

	if ((ret=pthread_cond_init(&(p[i].initcond), NULL))!=0 )
		printf("initcond init failed, %d\n", ret);
}

void close_pingdata(pingdata *p)
{
	pthread_cond_destroy(&(p->initcond));
	pthread_mutex_destroy(&(p->initmutex));
}

void signal_threadinit(pingdata *p)
{
	pthread_mutex_lock(&(p->initmutex));
	p->initialized = 1;
	pthread_cond_signal(&(p->initcond));
	pthread_mutex_unlock(&(p->initmutex));
}

void wait_threadinit(pingdata *p, int i)
{
	pthread_mutex_lock(&(p->initmutex));
	while(!p->initialized)
		pthread_cond_wait(&(p->initcond), &(p->initmutex));
	pthread_mutex_unlock(&(p->initmutex));
}

gboolean set_icon_colour_idle(gpointer data)
{
	iconidle *ii = (iconidle *)data;
	char s[20];

	switch (ii->ic)
	{
		case icon_red:
			gtk_image_set_from_pixbuf(GTK_IMAGE(ii->pt->p[ii->i].icon), ii->pt->pbred);
			gtk_label_set_text(GTK_LABEL(ii->pt->p[ii->i].rttim), "");
			break;
		case icon_green:
			gtk_image_set_from_pixbuf(GTK_IMAGE(ii->pt->p[ii->i].icon), ii->pt->pbgreen);
			sprintf(s, "%3.2f ms", ii->pt->p[ii->i].rtt);
			gtk_label_set_text(GTK_LABEL(ii->pt->p[ii->i].rttim), s);
			break;
	}
	free(ii);

	return FALSE;
}

void set_icon_colour(pingthread *pt, int i, iconcolour ic)
{
	iconidle *ii = malloc(sizeof(iconidle));
	ii->pt = pt;
	ii->i = i;
	ii->ic = ic;

	gdk_threads_add_idle(set_icon_colour_idle, ii);
}

void* ping_thread(void* args)
{
	int ctype = PTHREAD_CANCEL_ASYNCHRONOUS;
	int ctype_old;
	pthread_setcanceltype(ctype, &ctype_old);

	pingdata *p = (pingdata *)args;
	pingthread *pt = (pingthread *)p->parent;

//printf("started thread %d %d\n", p->id, p->tid);

	if (!init_ping(p))
	{
		signal_threadinit(p);
		send_packet(p); 
		recv_packet(p);

		if (p->nreceived == p->nsend)
			set_icon_colour(pt, p->id, icon_green);
	}

//printf("exiting, ping_thread %d %d\n", p->id, p->tid);
	p->retval_thread = 0;
	pthread_exit(&(p->retval_thread));
}

void start_threads(pingthread *pt, pingdata *p, int count)
{
	int i;

	for(i=0;i<count;i++)
	{
		init_pingdata(pt, p, i);

		int err;
		err = pthread_create(&(p[i].tid), NULL, &ping_thread, (void *)&(p[i]));
		if (err)
		{}

		CPU_ZERO(&(p[i].cpu));
		CPU_SET(1, &(p[i].cpu));
		if ((err = pthread_setaffinity_np(p[i].tid, sizeof(cpu_set_t), &(p[i].cpu))))
		{
//printf("pthread_setaffinity_np error %d\n", err);
		}
//printf("started thread %d %d\n", p[i].tid, i);
	}
}

void stop_threads(pingdata *p, int count)
{
	int i;

	for(i=0;i<count;i++)
	{
//printf("closing %d\n", i);
		close_ping(&(p[i]));
//printf("closed %d\n", i);
		int ret;
		if ((ret=pthread_join(p[i].tid, NULL)))
			printf("pthread_join error, %d\n", (int)p[i].tid);
//printf("joined %d\n", i);

		close_pingdata(&(p[i]));
	}
}

int address_readfromfile(pingdata *p, char *path)
{
	int i = 0;
	char *line = NULL;
	size_t len = 0;
	FILE *f = fopen(path, "r");
	if (f)
	{
		while(getline(&line, &len, f) > 0)
		{
			//printf("%s", line);
			char *p1 = line;
			char *q;
			if ((q = strstr(p1, ";")))
			{
				q[0] = '\0';
				if (strlen(p1))
				{
					strcpy(p[i].pingaddress, p1);
					char *p2 = q + 1;
					if ((q = strstr(p2, "\n"))) 
						q[0] = '\0';
					strcpy(p[i].description, p2);
					i++;
				}
//printf("%s\n", p1);
			}
			free(line); line = NULL; len = 0;
		}
		fclose(f);
	}
	else
	 printf("failed to read addresses from %s\n", path);

	return i;
}

void* thread0(void* args)
{
	int i;

	int ctype = PTHREAD_CANCEL_ASYNCHRONOUS;
	int ctype_old;
	pthread_setcanceltype(ctype, &ctype_old);

	pingthread *pt = (pingthread *)args;
	
	pinginterval t;

//printf("started thread0\n");
	while (pt->status == RUNNING)
	{
//printf("starting %d threads\n", pt->count);
		for(i=0;i<pt->count;i++)
			set_icon_colour(pt, i, icon_red);

		start_threads(pt, pt->p, pt->count);

		for(i=0;i<pt->count;i++)
			wait_threadinit(pt->p, i);

		get_first_time_microseconds(&t, pt->seconds);
		while(t.remainingusecs>0)
		{
			usleep(t.remainingusecs);
			get_next_time_microseconds(&t);
		}

//printf("stopping\n");
		stop_threads(pt->p, pt->count);
	}

//printf("exiting, thread0\n");
	pt->retval = 0;
	pthread_exit(&(pt->retval));
}

void create_thread0(pingthread *pt)
{
	int err;

	err = pthread_create(&(pt->tid), NULL, &thread0, (void*)pt);
	if (err)
	{}
//printf("thread0\n");

	CPU_ZERO(&(pt->cpu));
	CPU_SET(1, &(pt->cpu));
	if ((err=pthread_setaffinity_np(pt->tid, sizeof(cpu_set_t), &(pt->cpu))))
	{
		//printf("pthread_setaffinity_np error %d\n", err);
	}
}

void terminate_thread0(pingthread *pt)
{
	int i;

	pt->status = STOPPED;
	if ((i=pthread_join(pt->tid, NULL)))
		printf("pthread_join error, %d\n", i);
}

void init_widgets(GtkWidget *box, pingthread *pt, char *title)
{
	int i;
	pingdata *p;
	GError *error = NULL;

	// pixbufs
	pt->pbred = gdk_pixbuf_new_from_file("./images/red.png", &error);
	pt->pbgreen = gdk_pixbuf_new_from_file("./images/green.png", &error);

	// frame
	pt->frame = gtk_frame_new(title);
	gtk_widget_set_size_request(pt->frame, 400, 100);
	gtk_container_add(GTK_CONTAINER(box), pt->frame);
	//gtk_box_pack_start(GTK_BOX(box), pt->frame, TRUE, TRUE, 0);

	// vertical box
	pt->vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
	gtk_container_add(GTK_CONTAINER(pt->frame), pt->vbox);

	for(i=0;i<pt->count;i++)
	{
		p = &(pt->p[i]);

		// horizontal box
		p->hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
		gtk_container_add(GTK_CONTAINER(pt->vbox), p->hbox);
		//gtk_box_pack_start(GTK_BOX(pt->vbox), p->hbox, TRUE, TRUE, 0);

		p->icon = gtk_image_new_from_pixbuf(pt->pbred);
		gtk_container_add(GTK_CONTAINER(p->hbox), p->icon);
		//gtk_box_pack_start(GTK_BOX(p->hbox), p->icon, TRUE, TRUE, 0);

		p->label = gtk_label_new(p->pingaddress);
		gtk_container_add(GTK_CONTAINER(p->hbox), p->label);
		//gtk_box_pack_start(GTK_BOX(p->hbox), p->label, TRUE, TRUE, 0);

		p->descr = gtk_label_new(p->description);
		gtk_container_add(GTK_CONTAINER(p->hbox), p->descr);
		//gtk_box_pack_start(GTK_BOX(p->hbox), p->label, TRUE, TRUE, 0);

		p->rttim = gtk_label_new("");
		gtk_container_add(GTK_CONTAINER(p->hbox), p->rttim);
		//gtk_box_pack_start(GTK_BOX(p->hbox), p->label, TRUE, TRUE, 0);
	}
}

static gboolean delete_event(GtkWidget *widget, GdkEvent *event, gpointer data)
{
	return FALSE; // return FALSE to emit destroy signal
}

static void destroy(GtkWidget *widget, gpointer data)
{
	pingthread *pt = (pingthread *)data;

	terminate_thread0(&(pt[0]));
	terminate_thread0(&(pt[1]));

	gtk_main_quit();
}

static void realize_cb(GtkWidget *widget, gpointer data)
{
	pingthread *pt = (pingthread *)data;

	create_thread0(&(pt[0]));
	create_thread0(&(pt[1]));
}

void setup_default_icon(char *filename)
{
	GdkPixbuf *pixbuf;
	GError *err;

	err = NULL;
	pixbuf = gdk_pixbuf_new_from_file(filename, &err);

	if (pixbuf)
	{
		GList *list;      

		list = NULL;
		list = g_list_append(list, pixbuf);
		gtk_window_set_default_icon_list(list);
		g_list_free(list);
		g_object_unref(pixbuf);
    }
}

int main(int argc, char **argv)
{
	pingthread pt[2];
	pingdata p[2][MAX_THREADS];

	pt[0].status = RUNNING;
	pt[0].p = p[0];
	pt[0].count = address_readfromfile(p[0], "./ping_servers.txt");
	pt[0].seconds = 30;

	pt[1].status = RUNNING;
	pt[1].p = p[1];
	pt[1].count = address_readfromfile(p[1], "./ping_switches.txt");
	pt[1].seconds = 30;

	GtkWidget *window;
	GtkWidget *hbox;

	setup_default_icon("./images/Ping.png");

	gtk_init(&argc, &argv);

	/* create a new window */
	window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_window_set_position(GTK_WINDOW(window), GTK_WIN_POS_CENTER);
	gtk_container_set_border_width(GTK_CONTAINER (window), 2);
	//gtk_widget_set_size_request(window, 100, 100);
	gtk_window_set_title(GTK_WINDOW(window), "Ping");
	gtk_window_set_resizable(GTK_WINDOW(window), TRUE);
	/* When the window is given the "delete-event" signal (this is given
	* by the window manager, usually by the "close" option, or on the
	* titlebar), we ask it to call the delete_event () function
	* as defined above. The data passed to the callback
	* function is NULL and is ignored in the callback function. */
	g_signal_connect(window, "delete-event", G_CALLBACK(delete_event), NULL);
	/* Here we connect the "destroy" event to a signal handler.  
	* This event occurs when we call gtk_widget_destroy() on the window,
	* or if we return FALSE in the "delete-event" callback. */
	g_signal_connect(window, "destroy", G_CALLBACK(destroy), (void*)&pt);
	g_signal_connect(window, "realize", G_CALLBACK(realize_cb), (void*)&pt);

	// horizontal box
	hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
	gtk_container_add(GTK_CONTAINER(window), hbox);

	init_widgets(hbox, &(pt[0]), "Servers");
	init_widgets(hbox, &(pt[1]), "Switches");

	gtk_widget_show_all(window);
	gtk_main();

	return 0;
}
