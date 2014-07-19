#include<linux/module.h>
#include<linux/kernel.h>
#include<linux/proc_fs.h>
#include<linux/init.h>
#include<linux/cdev.h>
#include<linux/netdevice.h>
#include<linux/netfilter.h>
#include<linux/netfilter_ipv4.h>
#include<linux/string.h>
#include<linux/vmalloc.h>
#include<linux/ip.h>
#include<linux/udp.h>
#include<linux/tcp.h>
#include<asm/uaccess.h>
#include<linux/cred.h>


MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Netfilter for minifirewall");
MODULE_AUTHOR("Anshuman Wadhera");

static struct proc_dir_entry *proc_entry;
static struct proc_dir_entry *proc_entry_helper;

/*struct for firewall configuration variables - Same as in utility*/
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

static struct MiniFirewall mf[10];
static int mfWIndex;
static struct nf_hook_ops nfho_in;
static struct nf_hook_ops nfho_out;

/*function to convert the address from string to unsigned int*/
unsigned int inet_addr(char *str)
{
  int a,b,c,d;
  char arr[4];
  sscanf(str,"%d.%d.%d.%d",&a,&b,&c,&d);
  arr[0] = a; arr[1] = b; arr[2] = c; arr[3] = d;
  return *(unsigned int*)arr;
}

/*function to convert the string to unsigned short*/
unsigned short stringToshort(char *str)
{
	unsigned short val;
	sscanf(str, "%hu", &val);
	return val;
}

/*this function checks if ip agrees to the netmask provided*/
int check_ip(unsigned int cip,unsigned int ip,unsigned int mask) 
{
 	unsigned int tmp = cip;    
 	int cmp_len = 32;
 	int i = 0, j = 0;
	if (mask != 0) 
	{
	 	cmp_len = 0;
	        for (i = 0; i < 32; ++i) 
		{ 
	 	      if (mask & (1 << (32-1-i)))
	 	         cmp_len++;
	 	      else
	 		 break;
	        }
	 }
        for (i = 31, j = 0; j < cmp_len; --i, ++j) 
	{
	        if ((tmp & (1 << i)) != (ip & (1 << i))) 
		{
	            return 0;
	        }
	}
	return 1;
}

/*hook function for incoming packets*/
unsigned int hook_func_in(unsigned int hooksum,struct sk_buff *skb,const struct net_device *in,const struct net_device *out,int (*okfn)(struct sk_buff *))
{
	int protocol,sPort,dPort,i,ret;
	unsigned short port;
	struct iphdr *iph = (struct iphdr *)skb_network_header(skb);
	struct tcphdr *tcp_header;     
	struct udphdr *udp_header;
	sPort = -1;
	dPort = -1;
	if(iph->protocol == IPPROTO_TCP)
	{
		protocol = 0;
		tcp_header = (struct tcphdr *)skb_transport_header(skb);
		sPort = ntohs((unsigned short int) tcp_header->source);
		dPort = ntohs((unsigned short int) tcp_header->dest);
	}
	else if(iph->protocol == IPPROTO_UDP)
	{
		protocol = 1;
		udp_header = (struct udphdr *)skb_transport_header(skb);
		sPort = ntohs((unsigned short int) udp_header->source);
		dPort = ntohs((unsigned short int) udp_header->dest);
	}
	else if(iph->protocol == IPPROTO_ICMP)
		protocol = 2;
	else
		return NF_ACCEPT;
	for(i=0;i<mfWIndex;i++)
	{	
		/*loop through all the policies and check if the current packet matches any rule*/
		if(mf[i].direct==2)
			continue;
		if(mf[i].protocol!=-1)
		{
			if(mf[i].protocol!=protocol)
			continue;
		}
		if(strlen(mf[i].sourceIp)!=0)
		{
			if(strlen(mf[i].sourceMsk)!=0)
			{
				ret = check_ip(ntohl(inet_addr(mf[i].sourceIp)),ntohl(iph->saddr),ntohl(inet_addr(mf[i].sourceMsk)));
				if(ret==0)
					continue;
			}
			else
			{
				if(iph->saddr != inet_addr(mf[i].sourceIp))
					continue;
			}
		}
		if(strlen(mf[i].destIp)!=0)
		{
			if(strlen(mf[i].destMsk)!=0)
			{
				ret = check_ip(ntohl(inet_addr(mf[i].destIp)),ntohl(iph->daddr),ntohl(inet_addr(mf[i].destMsk)));
				if(ret==0)
					continue;
			}
			else
			{
				if(iph->daddr != inet_addr(mf[i].destIp))
					continue;
			}
		}
		if(strlen(mf[i].sourcePrt)!=0)
		{
			if(protocol!=2)
			{
				port = stringToshort(mf[i].sourcePrt);
				if(port!=sPort)
					continue;
			}
		}
		if(strlen(mf[i].destPrt)!=0)
		{
			if(protocol!=2)
			{
				port = stringToshort(mf[i].destPrt);
				if(port!=dPort)
					continue;
			}
		}
		if(mf[i].action==0)
			return NF_DROP;
		else
			return NF_ACCEPT;
	}
return NF_ACCEPT;
}

/*hook function for outgoing packets*/
unsigned int hook_func_out(unsigned int hooksum,struct sk_buff *skb,const struct net_device *in,const struct net_device *out,int (*okfn)(struct sk_buff *))
{
	int protocol,sPort,dPort,i,ret;
	unsigned short port;
	struct iphdr *iph = (struct iphdr *)skb_network_header(skb);
	struct tcphdr *tcp_header;     
	struct udphdr *udp_header;
	sPort = -1;
	dPort = -1;
	if(iph->protocol == IPPROTO_TCP)
	{
		protocol = 0;
		tcp_header = (struct tcphdr *)skb_transport_header(skb);
		sPort = ntohs((unsigned short int) tcp_header->source);
		dPort = ntohs((unsigned short int) tcp_header->dest);
	}
	else if(iph->protocol == IPPROTO_UDP)
	{
		protocol = 1;
		udp_header = (struct udphdr *)skb_transport_header(skb);
		sPort = ntohs((unsigned short int) udp_header->source);
		dPort = ntohs((unsigned short int) udp_header->dest);
	}
	else if(iph->protocol == IPPROTO_ICMP)
		protocol = 2;
	else
		return NF_ACCEPT;
	for(i=0;i<mfWIndex;i++)
	{	
		/*loop through all the policies and check if current packet matches any rule*/
		if(mf[i].direct==1)
			continue;
		if(mf[i].protocol!=-1)
		{
			if(mf[i].protocol!=protocol)
			continue;
		}
		if(strlen(mf[i].sourceIp)!=0)
		{
			if(strlen(mf[i].sourceMsk)!=0)
			{
				ret = check_ip(ntohl(inet_addr(mf[i].sourceIp)),ntohl(iph->saddr),ntohl(inet_addr(mf[i].sourceMsk)));
				if(ret==0)
					continue;
			}
			else
			{
				if(iph->saddr != inet_addr(mf[i].sourceIp))
					continue;
			}
		}
		if(strlen(mf[i].destIp)!=0)
		{
			if(strlen(mf[i].destMsk)!=0)
			{
				ret = check_ip(ntohl(inet_addr(mf[i].destIp)),ntohl(iph->daddr),ntohl(inet_addr(mf[i].destMsk)));
				if(ret==0)
					continue;
			}
			else
			{
				if(iph->daddr != inet_addr(mf[i].destIp))
					continue;
			}
		}
		if(strlen(mf[i].sourcePrt)!=0)
		{
			if(protocol!=2)
			{
				port = stringToshort(mf[i].sourcePrt);
				if(port!=sPort)
					continue;
			}
		}
		if(strlen(mf[i].destPrt)!=0)
		{
			if(protocol!=2)
			{
				port = stringToshort(mf[i].destPrt);
				if(port!=dPort)
					continue;
			}
		}
		if(mf[i].action==0)
			return NF_DROP;
		else
			return NF_ACCEPT;
	}
return NF_ACCEPT;
}

ssize_t netfilter_write(struct file *filp,const char __user *buff, unsigned long len, void *data)
{
	/*allow only root and user with id:1000 to write to proc file*/
	if(current_uid()==0||current_uid()==1000)
	{
	if(copy_from_user(&mf[mfWIndex],buff,len))
	{
		printk(KERN_INFO "netfilter: error in netfilter_write \n");
		return -EFAULT;
	}
	mfWIndex++;	
	return len;
	}
	else
	{
		return -EFAULT;
	}
}

int netfilter_read(char *page, char **start, off_t off, int count, int *eof, void *data)
{
	memcpy(page,&mf,sizeof(struct MiniFirewall)*mfWIndex);
	return (mfWIndex*sizeof(struct MiniFirewall));
}

ssize_t netfilterhelper_write(struct file *filp,const char __user *buff, unsigned long len, void *data)
{
	/*allow only root and user with id:1000 to write to proc file*/
	if(current_uid()==0||current_uid()==1000)
	{
	if (len > sizeof(int)) 
	{
		printk(KERN_INFO "netfilterhelper: Unexpected size of argument - len!\n");
    		return -ENOSPC;
	}
	if(copy_from_user(&mfWIndex,buff,len))
	{
		printk(KERN_INFO "netfilterhelper: error in write \n");
		return -EFAULT;
	}
	return len;
	}
	else
		return -EFAULT;
}

int netfilterhelper_read(char *page, char **start, off_t off, int count, int *eof, void *data)
{
	memcpy(page,&mfWIndex,sizeof(int));	
	return (sizeof(int));
}

int init_netfilter(void)
{
	int ret = 0;
	memset(mf,0,10*sizeof(struct MiniFirewall));
	/*set permissions for proc file*/
	proc_entry = create_proc_entry("netfilter",0646,NULL);
	proc_entry_helper = create_proc_entry("netfilterhelper",0646,NULL);
	if(proc_entry == NULL)
	{
		ret = -ENOMEM;
		printk(KERN_INFO "netfilter: Couldn't create proc entry for netfilter\n");
	}
	else if(proc_entry_helper == NULL)
	{
		ret = -ENOMEM;
		printk(KERN_INFO "netfilter: Couldn't create proc entry for netfilterhelper\n");
	}
	else
	{
		mfWIndex = 0;
		proc_entry->read_proc = netfilter_read;
		proc_entry->write_proc = netfilter_write;
		proc_entry_helper->read_proc = netfilterhelper_read;
		proc_entry_helper->write_proc = netfilterhelper_write;
		printk(KERN_INFO "netfiler:Module loaded \n");
	}
	/*define and register the hooking functions for incoming and outgoing packets*/
	nfho_in.hook = hook_func_in;
	nfho_in.hooknum = NF_INET_PRE_ROUTING; 
	nfho_in.pf = PF_INET;
	nfho_in.priority = NF_IP_PRI_FIRST;
	nf_register_hook(&nfho_in);

	nfho_out.hook = hook_func_out;
	nfho_out.hooknum = NF_INET_LOCAL_OUT; 
	nfho_out.pf = PF_INET;
	nfho_out.priority = NF_IP_PRI_FIRST;
	nf_register_hook(&nfho_out);
	return ret;
}

void cleanup_netfilter(void)
{
	remove_proc_entry("netfilter",NULL);
	remove_proc_entry("netfilterhelper",NULL);
	nf_unregister_hook(&nfho_in);	
	nf_unregister_hook(&nfho_out);
	printk(KERN_INFO "netfilter: Module unloaded \n");
}

module_init(init_netfilter);
module_exit(cleanup_netfilter);


