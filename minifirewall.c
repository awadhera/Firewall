#include<stdio.h>
#include<stdlib.h>
#include<getopt.h>
#include<string.h>
#include<ctype.h>
#include<unistd.h>
#include<fcntl.h>
#include<sys/types.h>
#include<sys/uio.h>
#include<sys/stat.h>

char procFsName[30] = "/proc/netfilter";
char procFshelperName[30] = "/proc/netfilterhelper";
int mfWIndex;

/*struct containing firewall configuration variables */
struct MiniFirewall
{
	int direct;
	int protocol;
	char sourceIp[17];
	char destIp[17];
	char sourceMsk[17];
	char destMsk[17];
	char sourcePrt[10];
	char destPrt[10];
	int action;
};
/*Function to print all the firewall policies*/
void printPolicies()
{
/*helper proc file contains the current write index*/
FILE *fdhelper = fopen(procFshelperName, "rb");
fread(&mfWIndex,sizeof(int), 1, fdhelper);
FILE *fd = fopen(procFsName, "rb");
if(fd != NULL)
{
	struct MiniFirewall mf[10];
	int count = 0;
	int i = 0; 
	char protoStr[10],directStr[30],actionStr[8];
	/*read all the policies from the proc file*/
	if(fread(&mf,mfWIndex*sizeof(struct MiniFirewall), 1, fd)==1)
	{
		for(i = 0;i < mfWIndex;i++)
		{
		count++;
		printf("Policy:%d :-\n",count);
		switch(mf[i].protocol)
		{
			case -1:
				strcpy(protoStr,"");
				break;
			case 0:
				strcpy(protoStr,"TCP");
				break;
			case 1:
				strcpy(protoStr,"UDP");
				break;
			case 2:
				strcpy(protoStr,"ICMP");
				break;
		}				
		printf("Protocol:%s\nSource IP:%s\nDestination IP:%s\n",protoStr,mf[i].sourceIp,mf[i].destIp);
		printf("Source NetMask:%s\nDestination NetMask:%s\n", mf[i].sourceMsk,mf[i].destMsk);
		printf("Source Port:%s\nDestination Port:%s\n", mf[i].sourcePrt, mf[i].destPrt);
		switch(mf[i].direct)
		{
			case 0:
				strcpy(directStr,"Incoming & outgoing");
				break;
			case 1: 
				strcpy(directStr,"Incoming");
				break;
			case 2:
				strcpy(directStr,"Outgoing");
				break;
		}
		printf("Type:%s\n",directStr);
		switch(mf[i].action)
		{
			case -1:
				strcpy(actionStr,"");
				break;
			case 0:
				strcpy(actionStr,"Block");
				break;
			case 1:
				strcpy(actionStr,"UnBlock");
				break;
		}
		printf("Action:%s\n", actionStr);
		printf("\n");
		}
	}
	fclose(fd);
}
fclose(fdhelper);
}

/*function to delete policy*/
int deletePolicy(int num)
{
FILE *fdhelper = fopen(procFshelperName, "rb");
fread(&mfWIndex,sizeof(int), 1, fdhelper);
fclose(fdhelper);
int mfWIndexStore = mfWIndex;
if(num<1 || num>mfWIndex)
{
	return 1;
}
else
{
FILE *fd = fopen(procFsName, "rb");
if(fd != NULL)
{
	struct MiniFirewall mf[10];
	struct MiniFirewall newmf[10];
	int count = 0;
	int i = 0;
	int j = 0; 
	/*read all the policies, delete the one required and then write all the policies again*/
	if(fread(&mf,mfWIndex*sizeof(struct MiniFirewall), 1, fd)==1)
	{
		fclose(fd);
		for(i = 0;i < mfWIndex;i++)
		{
			if(i!=(num-1))
				newmf[i] = mf[i];
			else
				break;
		}
		for(j=num;j < mfWIndex;j++)
		{
			newmf[j-1] = mf[j];	
		}
		fdhelper = fopen(procFshelperName,"wb");
		mfWIndex = 0;
		fwrite(&mfWIndex, sizeof(int),1,fd);
		fclose(fdhelper);
		fd = fopen(procFsName, "wb");
		if(mfWIndexStore-1!=0)
		{
			fwrite(&newmf[0], sizeof(struct MiniFirewall),1,fd);
			fclose(fd);
			fd = fopen(procFsName,"ab");
		}
		for(i = 1;i < mfWIndexStore-1;i++)
		{
			fwrite(&newmf[i], sizeof(struct MiniFirewall),1,fd);
		}
		fclose(fd);		
		
	}
	else
		fclose(fd);
}
return 0;
}			
}

int main(int argc, char **argv)
{
struct MiniFirewall mf = {0,-1,"","","","","","",-1};
int writeSet = 0;
int c;
int option_index = 0;
int ret;
char formatString[1000];
strcpy(formatString,"Error in input. Please conform to the following formats(shown by examples):-\n\n./minifirewall --in --action BLOCK\n./minifirewall --out --action UNBLOCK\n./minifirewall --print\n./minifirewall --delete 2\n./minifirewall --in --proto TCP --srcip 127.0.0.1 --destip 192.168.0.1 --srcnetmask 255.255.255.0 --destnetmask 255.255.0.0 --srcport 80 --destport 100 --action BLOCK\n\n");
if(argc==1)
{
	printf("%s",formatString);
	abort();
}
static struct option util_options[] = 
{	{"in",no_argument,0,'i'},
 	{"out",no_argument,0,'o'},
 	{"proto",required_argument,0,'p'},
 	{"srcip",required_argument,0,'s'},
 	{"destip",required_argument,0,'d'},
 	{"srcnetmask",required_argument,0,'t'},
 	{"destnetmask",required_argument,0,'e'},
 	{"srcport",required_argument,0,'u'},
 	{"destport",required_argument,0,'f'},
 	{"action",required_argument,0,'a'},
 	{"print",no_argument,0,'r'},
 	{"delete",required_argument,0,'l'}
};
while( (c = getopt_long_only(argc,argv,"iop:s:d:t:e:u:f:a:rd:",util_options,&option_index)) != -1)
{
	switch(c)
	{
		case 'i':
			mf.direct = 1;
			writeSet = 1;
			break;
		case 'o':
			mf.direct = 2;
			writeSet = 1;			
			break;
		case 'p':
			writeSet = 1;
			if(!strcmp(optarg,"TCP"))
			{
				mf.protocol = 0;
			}
			else if(!strcmp(optarg,"UDP"))
			{
				mf.protocol = 1;
			}
			else if(!strcmp(optarg,"ICMP"))
			{
				mf.protocol = 2;
			}
			else
				abort();
			break;
		case 's':
			strcpy(mf.sourceIp,optarg);
			writeSet = 1;			
			break;
		case 'd':
			strcpy(mf.destIp,optarg);
			writeSet = 1;			
			break;
		case 't':
			strcpy(mf.sourceMsk,optarg);
			writeSet = 1;
			break;
		case 'e':
			strcpy(mf.destMsk,optarg);
			writeSet = 1;			
			break;
		case 'u':
			strcpy(mf.sourcePrt,optarg);
			writeSet = 1;			
			break;
		case 'f':
			strcpy(mf.destPrt,optarg);
			writeSet = 1;			
			break;
		case 'a':
			writeSet = 1;
			if(!strcmp(optarg,"BLOCK"))
			{			
				mf.action = 0;
			}
			else if(!strcmp(optarg,"UNBLOCK"))
			{
				mf.action = 1;
			}
			else
			{	
				abort();	
			}
			break;
		case 'r':
			printPolicies();
			break;
		case 'l':
			ret = deletePolicy(atoi(optarg));
			if(ret)
			{
				printf("Policy number invalid.Aborting\n");
				abort();
			}
			else
			{
				printf("Policy:%d deleted successfully\n",atoi(optarg));
			}
			break;
		default:
			printf("%s",formatString);
			abort();
	}
}
if(writeSet==1)
{
FILE *fd = fopen(procFsName,"ab");
if(fd != NULL)
{
	/*write the policy to proc file */
	fwrite(&mf, sizeof(struct MiniFirewall),1,fd);
	fclose(fd);
}
}
}
