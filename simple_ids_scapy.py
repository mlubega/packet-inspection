#!/usr/bin/env python

#Python Version 2.7.6

from scapy.all import *
from sets import Set
import argparse  # Version 1.2.1
import sys  # Version Scapy 2.2.0

ETH_ARP = 2054
ARP_TABLE = {'7c:d1:c3:94:9e:b8':'192.168.0.100' , 'd8:96:95:01:a5:c9': '192.168.0.103', 'f8:1a:67:cd:57:6e':  '192.168.0.1'}
ARP_RES = 0x2
IPV4 = 0x800
IPV6 = 0x86dd
TCP = 0x6
SYN = 0x2
UDP = 0x11 # 17 in decimal

# Dictionary of [SrcIP,DstIP] -> Set(dport)  of TCP SYN Packets to detect Port
tcpSynPorts = dict() 
# Dictionary of [SrcIP, DstIP] -> Set(dport) of UDP Packets to detect Port 
udpPorts = dict()
# Dictionary of [timestamp,SrcIP,DstIP] -> List of Tuples[pktNum, SrcIP, DstIP]) 
tcpSynLog = dict()
# Dictionary of [timestamp, SrcIP, DstIP] -> True/False if we're printed this list
tcpFloodPrintedHosts = dict()
# List of Offender IPs
offenderIPs = []
# Dictionary of Port Scanning [SrcIP,DstIP] -> list of Tuples[pktNu, SrcIP, DstIP] 
portScanPackets = dict()
# List of Port Scan Offenders/Victim
portScanOffenders = []

def printPortScanWarning( srcDstPair, pktList):
		for i in range(100):
        		print 'Port Scan Warning--Packet: {}, Offender : {} , Target: {} '.format(pktList[i][0], pktList[i][1], pktList[i][2])
		portScanOffenders.append(srcDstPair)

def printFloodPkts(srcIP, dataList):
	if(srcIP not in offenderIPs):
		for i in range(100):
			print 'TCP SYN FLOOD WARNING--Packet: {}, Offender: {}, Target: {} '.format(dataList[i][0], dataList[i][1], dataList[i][2] )
		offenderIPs.append(srcIP)

def logPkt(ts, pktNum, srcIP, dstIP):
	key = str(int(ts))+ ', ' + srcIP + ', '+dstIP
	pktData = (pktNum, srcIP, dstIP)
	if( key in tcpSynLog):
		listOfTuples = tcpSynLog[key]
		listOfTuples.append(pktData)
		if((len(listOfTuples) >= 100) and (not tcpFloodPrintedHosts[key])):
			tcpFloodPrintedHosts[key] = True
			printFloodPkts(srcIP, listOfTuples)
	else:
		tcpSynLog[key] = [pktData]
		tcpFloodPrintedHosts[key] = False
		

def logPorts(pktNum, srcIP, dstIP, dport, portlog):
        
	srcDstPair = srcIP + dstIP
	packetData = (pktNum, srcIP, dstIP)
        if( srcDstPair in portlog):
        	setOfPorts = portlog[srcDstPair]
                setOfPorts.add(dport)
		portScanPackets[srcDstPair].append(packetData)
		if((len(setOfPorts) >= 100) and (srcDstPair not in portScanOffenders)):
			printPortScanWarning(srcDstPair, portScanPackets[srcDstPair])
        else:
           	portlog[srcDstPair] = set([dport])
		portScanPackets[srcDstPair] = [packetData]
		


def detectMalicious(pkt, pktNum):
	#Detect ARP Spoofing
	if( pkt[0].type == ETH_ARP and pkt[1].op == ARP_RES):
		
		if( (pkt[1].hwsrc in ARP_TABLE) and (ARP_TABLE[pkt[1].hwsrc]  != pkt[1].psrc)):
			print 'ARP Spoofing Warning-- Packet: {}, Offender: {}'.format(pktNum, pkt[0].src)

	# Detect Port Scanning
	elif( pkt[0].type == IPV4):
		if(pkt[1].proto == TCP and pkt[2].flags == SYN  ):
			logPorts(pktNum, pkt[1].src, pkt[1].dst, pkt[2].dport, tcpSynPorts)
			logPkt(pkt.time, pktNum, pkt[1].src, pkt[1].dst)
		if(pkt[1].proto == UDP):
			logPorts(pktNum, pkt[1].src, pkt[1].dst, pkt[2].dport, udpPorts)

	elif (pkt[0].type == IPV6):
		if(pkt[1].nh == TCP and pkt[2].flags == SYN  ):
			logPorts(pktNum, pkt[1].src, pkt[1].dst, pkt[2].dport, tcpSynPorts)
			logPkt(pkt.time, pktNum, pkt[1].src, pkt[1].dst)
		if(pkt[1].nh  == UDP):
			logPorts(pktNum, pkt[1].src, pkt[1].dst, pkt[2].dport, udpPorts)

			

def main():
	parser = argparse.ArgumentParser(description='Simple IDS')
	parser.add_argument(dest='pcapFileString')
	args = parser.parse_args()

	if(args.pcapFileString is None):
		print "Please specify a pcap file"
		return 1
	else:
		pcapName = args.pcapFileString
		pcapFile = rdpcap(pcapName)
		i = 1
		for pkt in pcapFile:
			detectMalicious(pkt, i)
			i += 1	

			



main()

