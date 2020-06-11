#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <time.h>
#include <errno.h>
#include "honeypot_process.h"
#include <bits/stdc++.h>
#include <iostream>
#include <fstream>

#define MY_MAX 10 
using namespace std;

struct folder{
	// struct folder* current_directory[];
	struct folder* previous_node=NULL;
	struct folder* next_node=NULL;
	struct folder* head=NULL;
	struct folder* top=NULL;
	struct folder* bottom=NULL;                                  

	string name;
};



map<string,string>m={
	{"ls","ls: not found"},
	{"dir","dir: not found"},
	{"echo *","bin dev etc lib linuxrc mnt proc sbin usr var webs"},
	{"cat /proc/version","Linux version 2.6.8.1 (root@localhost.localdomain) (gcc version 3.4.2) #1 Tue Sep 20 15:52:07 EDT 2005"}
	};

struct Arg
{
    int con_num;
    int port_num;
    int socketFD;
    int connectFD;
    struct sockaddr_in addr;
};

stack<string>stack_directory;
ofstream myfile;

static void* worker (void* arg);
static void timestamp (FILE* fd, int con_num, int colon);
static void my_sleep (void);
static int timed_read (int d, void* buf, size_t nbyte, unsigned int seconds);

static pthread_mutex_t print_mutex = PTHREAD_MUTEX_INITIALIZER;

int process_connection (int con_num, int port_num, int socketFD)
{
    int optval;
    int connectFD;
    pthread_t thread_handle;
    struct sockaddr_in addr;
    socklen_t addrlen = (socklen_t)sizeof(addr);
    struct Arg* parg;

    optval = 1;
    if (setsockopt (
	socketFD, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval))
	< 0)
    {
	perror("cannot set keepalive");
	exit (EXIT_FAILURE);
    }

    if ((parg = (struct Arg*)malloc (sizeof (struct Arg))) == NULL)
    {
	timestamp (stderr, parg->con_num, 0);
        perror ("malloc failed");
	return 1;
    }

    connectFD = accept (socketFD, (struct sockaddr*)(&addr), &addrlen);
    if (0 > connectFD)
    {
	timestamp (stderr, parg->con_num, 0);
	perror ("accept failed");
	free ((void*)parg);
	if (errno == EMFILE) return 1;
	return 0;
    }

    parg->con_num = con_num;
    parg->port_num = port_num;
    parg->socketFD = socketFD;
    parg->connectFD = connectFD;
    parg->addr = addr;

    /* Keep con_num in order on stdout */
    my_sleep();

    if (pthread_create (&thread_handle, NULL, worker, (void*)parg) != 0)
    {
	timestamp (stderr, parg->con_num, 0);
        perror ("pthread_create failed");
	free ((void*)parg);
	return 1;
    }
    if (pthread_detach (thread_handle) != 0)
    {
        perror ("pthread_detach failed");
	free ((void*)parg);
	return 1;
    }

    return 0;
}

static void* worker (void* arg)
{
	myfile.open("log.txt");
    char chr;
    int retval;
    FILE* writeFD;
    struct sockaddr_in local_sa;
    socklen_t local_length = (socklen_t)sizeof (local_sa);
    struct Arg* parg = (struct Arg*)arg;
    int printing = 0;    /* 2 if a \n, time stamp, and char(s) have been sent,
                          * 1 if a \n, time stamp have been sent,
			  * 0 if a \n has been sent.
			  * NO OTHER CONDITIONS ALLOWED.
			  */
    int iline = 0;
    int finished;

    /* Lock mutex early to keep connection numbers (con_num) in order. */
    pthread_mutex_lock (&print_mutex);

    if (getsockname (
	parg->connectFD, (struct sockaddr*)(&local_sa), &local_length) == -1)
    {
	timestamp (stderr, parg->con_num, 0);
	perror ("getsockname failed");
	close (parg->connectFD);
	free ((void*)parg);
	pthread_mutex_unlock (&print_mutex);
	pthread_exit (NULL);
    }

    if ((writeFD = fdopen (parg->connectFD, "w")) == NULL)
    {
	timestamp (stderr, parg->con_num, 0);
        perror ("fdopen failed");
	close (parg->connectFD);
	free ((void*)parg);
	pthread_mutex_unlock (&print_mutex);
	pthread_exit (NULL);
    }

    fprintf(writeFD, "BCM96328 Broadband Router");
    fprintf (writeFD, "\nLogin: ");

    myfile<<"Login:  ";

    fflush (writeFD);
    timestamp (stdout, parg->con_num, 0);
    printf ("open connection %s -> ", inet_ntoa (parg->addr.sin_addr));
    printf ("%s:%d\n",
	inet_ntoa (local_sa.sin_addr), parg->port_num);
    fflush (stdout);
    pthread_mutex_unlock (&print_mutex);
    printing = 0;
    finished = 0;



    for(auto x: m)
    	cout<<x.first<<x.second<<endl;

    




    string sysinfo_string="Number of processes: 64";
	sysinfo_string+="\n";
	sysinfo_string+="load avrage: 1 min:0.00, 5 min:0.00, 15 min:0.00";
	sysinfo_string+="\n";
	sysinfo_string+="		  total		   used 	   free";
	sysinfo_string+="\n";
	sysinfo_string+="  Mem:		  60528		   35804	   24724";
	sysinfo_string+="\n";
	sysinfo_string+="  Swap:	  	 0		       0     	   0";
	sysinfo_string+="\n";
	sysinfo_string+="  Total:	  60258		   35804       24724";
	sysinfo_string+="\n";

	m["sysinfo"]=sysinfo_string;



    vector<string>v={"bin","dev","etc","lib","linuxrc","mnt","proc","sbin","usr","var","webs"};
	struct folder* top=NULL;
	struct folder* parent_head=NULL;
	for(int i=0;i<v.size();i++)
	{
		struct folder* n=NULL;
		n=(struct folder *)malloc(sizeof(struct folder));
		n->previous_node=NULL;
		n->next_node=NULL;
		if(top!=NULL)top->bottom=n;
		else parent_head=n;
		n->head=parent_head;
		n->top=top;
		n->bottom=NULL;
		n->name=v[i];
		top=n;
	}
	struct folder * temp_folder=parent_head;
	while(temp_folder->name!="var")
		temp_folder=temp_folder->bottom;
	// v={"bcmupnp.pid","group","hosts","hwaddr","mcpd.conf","nvram","passwd",
		v={"cache","wl0","wl0_assoc","wl0_authe","wl0-autho","wl0bands","wl0cap","wlver"};

	top=NULL;
	struct folder* head=NULL;
	for(int i=0;i<v.size();i++)
	{
		struct folder* n=NULL;
		n=(struct folder *)malloc(sizeof(struct folder));
		n->previous_node=NULL;
		n->next_node=NULL;
		if(top!=NULL)top->bottom=n;
		else head=n;
		n->head=head;
		n->top=top;
		n->bottom=NULL;
		n->name=v[i];
		top=n;
	}
	temp_folder->next_node=head;
	head->previous_node=temp_folder;
	

	cout<<"head name: "<<head->name<<endl;
	struct folder *n=NULL;
	n=(struct folder *)malloc(sizeof(struct folder));
	head->next_node=n;
	n->previous_node=head;
	n->head=n;

	cout<<"head-next"<<head->next_node->name<<endl;
	cout<<"n-name"<<n->name<<endl;
	cout<<"n-previous"<<n->previous_node->name<<endl;




	temp_folder=parent_head;
	while(temp_folder->name!="webs")
	{
		temp_folder=temp_folder->bottom;
	}
	v={"dnscfg.html","dnsproxycfg.html","ethadderr.html","util.js","wlcfg.html","wlsetup.html"};
	top=NULL;
	head=NULL;
	for(int i=0;i<v.size();i++)
	{
		struct folder* n=NULL;
		n=(struct folder *)malloc(sizeof(struct folder));
		n->previous_node=NULL;
		n->next_node=NULL;
		if(top!=NULL)top->bottom=n;
		else head=n;
		n->head=head;
		n->top=top;
		n->bottom=NULL;
		n->name=v[i];
		top=n;
	}
	temp_folder->next_node=head;
	head->previous_node=temp_folder;


	temp_folder=parent_head;
	while(temp_folder->name!="sbin")
	{
		temp_folder=temp_folder->bottom;
	}
	v={"ethctl","ifconfig","insmod","logread","reboot","route","vconfig"};
	top=NULL;
	head=NULL;
	for(int i=0;i<v.size();i++)
	{
		struct folder* n=NULL;
		n=(struct folder *)malloc(sizeof(struct folder));
		n->previous_node=NULL;
		n->next_node=NULL;
		if(top!=NULL)top->bottom=n;
		else head=n;
		n->head=head;
		n->top=top;
		n->bottom=NULL;
		n->name=v[i];
		top=n;
	}
	temp_folder->next_node=head;
	head->previous_node=temp_folder;


	temp_folder=parent_head;
	while(temp_folder->name!="bin")
	{
		temp_folder=temp_folder->bottom;
	}
	v={"apt","apt-get","chfn","chgrp","dconf","echo","info","ip","lscpu", "passwd","ssh", "sudo"};
	top=NULL;
	head=NULL;
	for(int i=0;i<v.size();i++)
	{
		struct folder* n=NULL;
		n=(struct folder *)malloc(sizeof(struct folder));
		n->previous_node=NULL;
		n->next_node=NULL;
		if(top!=NULL)top->bottom=n;
		else head=n;
		n->head=head;
		n->top=top;
		n->bottom=NULL;
		n->name=v[i];
		top=n;
	}
	temp_folder->next_node=head;
	head->previous_node=temp_folder;




	temp_folder=parent_head;
	while(temp_folder->name!="dev")
	{
		temp_folder=temp_folder->bottom;
	}
	v={"autofs","core","cpu","fuse","log","loop","mem","null","port", "random","tty", "vhost-net"};
	top=NULL;
	head=NULL;
	for(int i=0;i<v.size();i++)
	{
		struct folder* n=NULL;
		n=(struct folder *)malloc(sizeof(struct folder));
		n->previous_node=NULL;
		n->next_node=NULL;
		if(top!=NULL)top->bottom=n;
		else head=n;
		n->head=head;
		n->top=top;
		n->bottom=NULL;
		n->name=v[i];
		top=n;
	}
	temp_folder->next_node=head;
	head->previous_node=temp_folder;




	temp_folder=parent_head;
	while(temp_folder->name!="etc")
	{
		temp_folder=temp_folder->bottom;
	}
	v={"alsa","bash.bashrc","dbus-1","dconf","dhcp","group","hostname","init","kernel", "legal","passwd", "ssh"};
	top=NULL;
	head=NULL;
	for(int i=0;i<v.size();i++)
	{
		struct folder* n=NULL;
		n=(struct folder *)malloc(sizeof(struct folder));
		n->previous_node=NULL;
		n->next_node=NULL;
		if(top!=NULL)top->bottom=n;
		else head=n;
		n->head=head;
		n->top=top;
		n->bottom=NULL;
		n->name=v[i];
		top=n;
	}
	temp_folder->next_node=head;
	head->previous_node=temp_folder;



	temp_folder=parent_head;
	while(temp_folder->name!="lib")
	{
		temp_folder=temp_folder->bottom;
	}
	v={"apg","apparmor","apt","aspell","avahi","cups","dkms","gjs","init", "telnetlogin","ufw", "xorg"};
	top=NULL;
	head=NULL;
	for(int i=0;i<v.size();i++)
	{
		struct folder* n=NULL;
		n=(struct folder *)malloc(sizeof(struct folder));
		n->previous_node=NULL;
		n->next_node=NULL;
		if(top!=NULL)top->bottom=n;
		else head=n;
		n->head=head;
		n->top=top;
		n->bottom=NULL;
		n->name=v[i];
		top=n;
	}
	temp_folder->next_node=head;
	head->previous_node=temp_folder;



	temp_folder=parent_head;
	while(temp_folder->name!="proc")
	{
		temp_folder=temp_folder->bottom;
	}
	v={"1","10","2023","31060","31279","41","455","62","707", "899","903", "keys","zoneinfo"};
	top=NULL;
	head=NULL;
	for(int i=0;i<v.size();i++)
	{
		struct folder* n=NULL;
		n=(struct folder *)malloc(sizeof(struct folder));
		n->previous_node=NULL;
		n->next_node=NULL;
		if(top!=NULL)top->bottom=n;
		else head=n;
		n->head=head;
		n->top=top;
		n->bottom=NULL;
		n->name=v[i];
		top=n;
	}
	temp_folder->next_node=head;
	head->previous_node=temp_folder;


	temp_folder=parent_head;
	while(temp_folder->name!="usr")
	{
		temp_folder=temp_folder->bottom;
	}
	v={"bin","include","lib32","local","share","lib","libx32","sbin","src"};
	top=NULL;
	head=NULL;
	for(int i=0;i<v.size();i++)
	{
		struct folder* n=NULL;
		n=(struct folder *)malloc(sizeof(struct folder));
		n->previous_node=NULL;
		n->next_node=NULL;
		if(top!=NULL)top->bottom=n;
		else head=n;
		n->head=head;
		n->top=top;
		n->bottom=NULL;
		n->name=v[i];
		top=n;
	}
	temp_folder->next_node=head;
	head->previous_node=temp_folder;





	temp_folder=parent_head;
    string temp;
    while (1)
    {
    	
		retval = timed_read (parg->connectFD, &chr, 1, 30);
		switch (retval)
		{
			case 0:
			    /* Got no character */
			    finished = 1;
			    break;
			case 1:
			    /* Got a character, keep going */
			    break;
			case -1:
			    /* Read error */
			    finished = 1;
			    break;
			case -2:
			    /* timeout */

		    switch (printing)
		    {
			    case 0:
				/* Mutex already unlocked, nothing to do. */
			        break;
			    case 1:
			        /* Mutex has been locked and a timestamp has been printed */
				printf("(tinypot_wait)\n");
				fflush (stdout);
				pthread_mutex_unlock (&print_mutex);
			        break;
			    case 2:
				/* Mutex has been locked and some characters have been echoed */
				printf ("\n");
				timestamp (stdout, parg->con_num, 0);
				printf("(tinypot_flush)\n");
				fflush (stdout);
				pthread_mutex_unlock (&print_mutex);
				fflush (writeFD);
			        break;
			    default:
				fprintf(stderr, "Programming error, printing.\n");
				fflush(stderr);
				finished = 1;
	        	break;
	    	}
		    printing = 0;
		    continue;
		    break;
			default:
		    fprintf(stderr, "Programming error, read.\n");
		    fflush(stderr);
		    finished = 1;
		    break;
		}
		if (finished) break;
		/* Programming note: chr contains a valid character now. */

    	if (printing == 0)
		{
		    pthread_mutex_lock (&print_mutex);
		    timestamp (stdout, parg->con_num, 1);
		    fflush (stdout);
		    printing = 1;
		}
		if (iline > 1)
		{
		    // putc (chr, writeFD);
		}

		// putchar (chr);
		cout<<chr;
		temp+=chr;
		if (chr == '\n')
		{
			temp.pop_back();
			temp.pop_back();
			myfile<<temp<<endl;
			if(iline>1)
			{
				if(m.find(temp)!=m.end())
				{
					if(temp=="echo *")
					{
						struct folder* go=temp_folder;
						while(go!=NULL)
						{
							temp=go->name;
							temp+="   ";
							for(int i=0;i<temp.length();i++)				
							{	
								char t=temp[i];
								putc (t, writeFD);
							}
							go=go->bottom;
						}
					}

					else
					for(int i=0;i<m[temp].length();i++)
					{
						char t=m[temp][i];
						putc(t,writeFD);
					}
					putc('\n',writeFD);
				}

				else if(temp.length()>3 && temp[0]=='c' && temp[1]=='d' && (temp[3]=='/' || temp[3]=='~'))
				{
					while(!stack_directory.empty())stack_directory.pop();
					temp_folder=parent_head;
				}

				else if(temp.length()>3 && temp[0]=='c' && temp[1]=='d' &&temp[3]!='.')
				{
					string folder;
					for(int i=3;i<temp.length();i++)
						folder+=temp[i];

					struct folder* go=temp_folder;
					int flag=0;
						while(go!=NULL)
						{
							temp=go->name;
							if(temp==folder)
							{
								flag=1;
								break;
							}
							go=go->bottom;
						}
						if(flag==1 && go->next_node!=NULL)
						{
							stack_directory.push(go->name);
							temp_folder=go->next_node;
						}
						else if(flag==0 || go->next_node==NULL)
						{
							string t="bash: cd: "+folder+": No such file or directory\n";
							cout<<"folder not found"<<endl;
							for(int i=0;i<t.length();i++)
							{
								char a=t[i];
								putc(a,writeFD);
							}
						}
				}

				else if(temp.length()==5 && temp[0]=='c' && temp[1]=='d' && temp[3]=='.' && temp[4]=='.' )
				{
					if(temp_folder->head!=parent_head)
					{
						if(!stack_directory.empty())stack_directory.pop();
						temp_folder=temp_folder->head;
						temp_folder=temp_folder->previous_node->head;
						if(!stack_directory.empty())cout<<stack_directory.top()<<endl;
					}
					else
					{
						//do nothing
					}
				}

				else
				{

					for(int i=0;i<temp.length();i++)
					{

						char t=temp[i];
						putc (t, writeFD);
					}
					temp=": not found";
					for(int i=0;i<temp.length();i++)
					{
						char t=temp[i];
						putc(t,writeFD);
					}
					putc('\n',writeFD);
				}
			}
			
			temp.clear();
		    fflush (stdout);
		    printing = 0;
		    pthread_mutex_unlock (&print_mutex);
		    if (iline == 0)
		    {
		        fprintf (writeFD, "Password: ");
		        myfile<<"Password ";
		    }
		    /* TODO: delete this clause */
		    // else if (iline == 1)
		    // {
		    //     fprintf (writeFD, "$ ");
		    // }
		    // else
		    // {
		    //     fprintf (writeFD, "$ ");
		    // }
		    else if(iline!=0)
		    {
		    	if(!stack_directory.empty())
		    	{
		    		stack<string>temp_stack=stack_directory;
		    		vector<string>temp_vector;
		    		while(!temp_stack.empty())
		    		{
		    			temp_vector.push_back(temp_stack.top());
		    			temp_stack.pop();
		    		}
		    		for(int i=temp_vector.size()-1;i>=0;i--)
		    		{
		    			string s=temp_vector[i];
		    			char forward_slash=47;
	    				putc(forward_slash,writeFD);
		    			for(int j=0;j<s.length();j++)
		    			{
		    				char t=s[j];
		    				putc(t,writeFD);
		    			}

		    		}
		    	}
		    	fprintf(writeFD, "$ ");
		    }
		    ++iline;
		    fflush (writeFD);
		    my_sleep();
		}
		else
		{
		    printing = 2;
		}
   	} /* Loop over incoming characters */

    if (printing == 2)
    {
	printf ("\n");
	timestamp (stdout, parg->con_num, 0);
        printf ("(Missing newline)\n");
	pthread_mutex_unlock (&print_mutex);
	printing = 0;
    }
    if (printing == 0)
    {
	pthread_mutex_lock (&print_mutex);
	timestamp (stdout, parg->con_num, 0);
	printing = 1;
    }
    fflush (stdout);
    if (retval == -1)
	perror ("close connection");
    else
	fprintf (stderr, "close connection: end of file\n");
    fflush (stderr);
    pthread_mutex_unlock (&print_mutex);
    printing = 0;

    /* This fails so often with "endpoint is not connected" that it is not
     * interesting */
    shutdown (parg->connectFD, SHUT_RDWR);

    fclose (writeFD);
    close (parg->connectFD);
    free ((void*)parg);
    pthread_exit (NULL);
}

static void timestamp (FILE* fd, int con_num, int colon)
{
    fprintf (fd, "%s #%d", my_time(), con_num);
    fprintf (fd, "%s ", (colon ? ":" : " "));
}

char* my_time (void)
{
    time_t tt;
    struct tm tm;
    static __thread char buf[128];
    if ((tt = time (NULL)) == -1)
    {
	perror ("time failed");
	pthread_exit (NULL);
    }
    tm = *localtime (&tt);
    snprintf (buf, sizeof(buf), "%04d/%02d/%02d %02d:%02d:%02d",
        tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday,
	tm.tm_hour, tm.tm_min, tm.tm_sec);
    return &buf[0];
}

static void my_sleep (void)
{
    static const double my_scale = (double)MY_MAX * 1000000 / RAND_MAX;
    unsigned int sleep_time = rand();
    sleep_time = (unsigned int)(my_scale * sleep_time);  /* seconds */
    while (sleep_time >= 500000)
    {
	usleep (500000);
	sleep_time -= 500000;
    }
    usleep (sleep_time);
}

static int timed_read (int d, void* buf, size_t nbyte, unsigned int seconds)
{
    struct timeval wait;
    fd_set read_fds;
    int status;
    int retval;

    wait.tv_sec = seconds;
    wait.tv_usec = 0;
    FD_ZERO (&read_fds);
    FD_SET (d, &read_fds);
    status = select (d+1, &read_fds, NULL, NULL, &wait);
    switch (status)
    {
    case 0:
        /* timeout */
	retval = -2;
        break;
    case 1:
        /* A character is available */
	retval = read(d, buf, nbyte);
        break;
    default:
        retval = -3;
        break;
    }
    return retval;
}
