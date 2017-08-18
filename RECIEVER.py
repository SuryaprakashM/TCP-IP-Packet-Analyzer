import socket
import time
from struct import *
from copy import copy
from binascii import hexlify

sniff = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
count=15

#print "Waiting To Recieve Packets..Please browse for something : "
counter = 0

def carry_around_add(a, b):
    c = a + b
    return (c & 0xffff) + (c >> 16)

def chkSum(msg):
    s = 0
    for i in range(0, len(msg), 2):
        w = ord(msg[i]) + (ord(msg[i+1]) << 8)
        s = carry_around_add(s, w)
    return ~s & 0xffff

soc = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
host = '14.139.134.35'
port = 2335
#addr = soc.bind((host,port))
soc.connect((host,port))
#soc.send('HI')
packet=soc.recv(2048)
#execfile('newGetpckt.py')
#print("Received data is :",data)
soc.close()

if 1 :
	'''
	packet = sniff.recvfrom(65565)
	counter += 1
	print "\n******NEW PACKET******"
	print "\n-------------------------------- IP HEADER ---------------------------------------\n"
	print packet
	host = socket.gethostbyname(socket.gethostname())
	print "\n\nThe Host IP Address is : "+str(host)
	packet = packet[0]
	'''
	ip_header = packet[0:20]
	iphme = copy(packet[0:20])
	print hexlify(iphme[10:12])
	iph = unpack('!BBHHHBBH4s4s',ip_header)

	counter =1
	print 'IP header:'+ str(iph)
	count=count-1
	ip_head_len = iph[0] & 0x0F
	ip_version=iph[0]>>4
	tot_len     = iph[2]
	ip_ID       = iph[3]
	ttl         = iph[5]
	protocol    = iph[6]
	checksum    = iph[7]
	source      = iph[8]
	dest        = iph[9]
	counter = counter + 1 
	print("IP Version = %s \nIP_head_len = %s\ntot_len = %s" %(ip_version,ip_head_len,tot_len))
	print("IP id = %s \nTTL = %s\nprotocol = %s" %(ip_ID,ttl,protocol))
	print("Check Sum = %s \nSource = %s \nDestination =%s \n" %(checksum,socket.inet_ntoa(source),socket.inet_ntoa(dest)))
	print("NUMBER OF PACKETS RECIEVED = %d\n" % counter)
	
	tcp_head=packet[20:40]
	tph = unpack('!HHIIHHHH',tcp_head)
	src_port=tph[0]
	dst_port=tph[1]
	seq_NO=tph[2]
	ack_NO=tph[3]
	head_len=tph[4] >> 12
	resv=(tph[4] >> 6) & 0x003F
	flags=tph[4] & 0x003F
	window=tph[5]
	checksum=tph[6]
	urg_ptr=tph[7]
	
	#flags
	
	fin=flags & 0x0001
	ack=(flags >> 1) & 0x0001
	syn=(flags >> 2) & 0x0001
	rst=(flags >> 3) & 0x0001
	psh=(flags >> 4) & 0x0001
	urg=(flags >> 5) & 0x0001 

 
	print("---------------------------------- TCP HEADER -----------------------------------------\n")
	print "source Port =",src_port,"\nDestination port=",dst_port,"\nsequence number=",seq_NO,"\nacknowledge=",ack_NO,"\nHeadlength=",head_len
	print "Reserve=",resv,"\nflag=",flags,"\nwindow=",window,"\nchecksum=",checksum,"\nUrgentPointer=",urg_ptr,"\nFLAGS :\nFIN=",fin,"\nACK=",ack
	print"SYN=",syn,"\nRST=",rst,"\nPSH=",psh,"\nURG=",urg
	#print"%s",%ip_header
	CheckSum=hexlify(pack('H', (chkSum(iphme[:10]+pack('!H',0)+iphme[12:20]))))
	print"\nCHECK SUM=",CheckSum
	if CheckSum!=0 :
		try:
			reply_s=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_TCP)
		except socket.error , msg:
			print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
   	 		sys.exit()
	
	#IP HEADER
	source_ip='14.139.134.62'
	dest_ip='14.139.134.35'
	ip_head_len =5
	ip_version  =4
	ip_TOS	    =0
	ip_TOTLEN   =0
	ip_ID       = 1000
	ip_fragOff  = 0
	ip_ttl         = 255
	ip_protocol    = socket.IPPROTO_TCP
	ip_checksum    = 0
	ip_src_addr      = socket.inet_aton(source_ip)
	ip_dst_addr = socket.inet_aton(dest_ip)

	ip_HL_VER = (ip_version << 4) +ip_head_len


	newIPpack=pack('!BBHHHBBH4s4s',ip_HL_VER,ip_TOS,ip_TOTLEN,ip_ID,ip_fragOff,ip_ttl,ip_protocol,ip_checksum,ip_src_addr,ip_dst_addr)
	#tcp header fields		 

	temp = ip_src_addr
	src_port= 2023
	dst_port = 2023
	seq_NO =0
	ack_NO =0
	head_len =8
	resv =0
	flags =18
	window =0#socket.htons (5840)
	checksum =0
	urg_ptr =0
	
	#replying_tcp_flags
	
	fin=0
	ack=1
	syn=0
	rst=0
	psh=1
	urg=0

	urg = urg << 5
	ack = ack << 4
	psh = psh << 3
	rst = rst << 2
	syn = syn << 1
	resv = resv << 6
	head_len = head_len << 12

	tcp_flg=(head_len)+(resv)+(urg)+(ack)+(psh)+(rst)+(syn)+(fin)
	tcp_header=pack('!HHIIHHHH',src_port,dst_port,seq_NO,ack_NO,tcp_flg,window,checksum,urg_ptr)
	
	user_data = 'HELLO'

	packet = newIPpack + tcp_header + user_data
	reply_s.sendto(packet ,(dest_ip,0))
	
	






















































