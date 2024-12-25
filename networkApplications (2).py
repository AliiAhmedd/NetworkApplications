#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import argparse
import socket
import os
import sys
import struct
import time
import random
import traceback
import threading
# NOTE: Do NOT import other libraries!

UDP_CODE = socket.IPPROTO_UDP
ICMP_ECHO_REQUEST = 8
MAX_DATA_RECV = 65535
MAX_TTL = 30

def setupArgumentParser() -> argparse.Namespace:
        parser = argparse.ArgumentParser(
            description='A collection of Network Applications developed for SCC.231.')
        parser.set_defaults(func=ICMPPing, hostname='lancaster.ac.uk')
        subparsers = parser.add_subparsers(help='sub-command help')
        
        parser_p = subparsers.add_parser('ping', aliases=['p'], help='run ping')
        parser_p.set_defaults(timeout=2, count=10)
        parser_p.add_argument('hostname', type=str, help='host to ping towards')
        parser_p.add_argument('--count', '-c', nargs='?', type=int,
                              help='number of times to ping the host before stopping')
        parser_p.add_argument('--timeout', '-t', nargs='?',
                              type=int,
                              help='maximum timeout before considering request lost')
        parser_p.set_defaults(func=ICMPPing)

        parser_t = subparsers.add_parser('traceroute', aliases=['t'],
                                         help='run traceroute')
        parser_t.set_defaults(timeout=2, protocol='udp')
        parser_t.add_argument('hostname', type=str, help='host to traceroute towards')
        parser_t.add_argument('--timeout', '-t', nargs='?', type=int,
                              help='maximum timeout before considering request lost')
        parser_t.add_argument('--protocol', '-p', nargs='?', type=str,
                              help='protocol to send request with (UDP/ICMP)')
        parser_t.set_defaults(func=Traceroute)
        
        parser_m = subparsers.add_parser('mtroute', aliases=['mt'],
                                         help='run traceroute')
        parser_m.set_defaults(timeout=2, protocol='udp')
        parser_m.add_argument('hostname', type=str, help='host to traceroute towards')
        parser_m.add_argument('--timeout', '-t', nargs='?', type=int,
                              help='maximum timeout before considering request lost')
        parser_m.add_argument('--protocol', '-p', nargs='?', type=str,
                              help='protocol to send request with (UDP/ICMP)')
        parser_m.set_defaults(func=MultiThreadedTraceRoute)

        parser_w = subparsers.add_parser('web', aliases=['w'], help='run web server')
        parser_w.set_defaults(port=8080)
        parser_w.add_argument('--port', '-p', type=int, nargs='?',
                              help='port number to start web server listening on')
        parser_w.set_defaults(func=WebServer)

        parser_x = subparsers.add_parser('proxy', aliases=['x'], help='run proxy')
        parser_x.set_defaults(port=8000)
        parser_x.add_argument('--port', '-p', type=int, nargs='?',
                              help='port number to start web server listening on')
        parser_x.set_defaults(func=Proxy)

        if len(sys.argv) < 2:
            parser.print_help()
            sys.exit(1)

        args = parser.parse_args()

        return args


class NetworkApplication:

    def checksum(self, dataToChecksum: bytes) -> int: 
        csum = 0
        countTo = (len(dataToChecksum) // 2) * 2
        count = 0

        while count < countTo:
            thisVal = dataToChecksum[count+1] * 256 + dataToChecksum[count]
            csum = csum + thisVal
            csum = csum & 0xffffffff
            count = count + 2

        if countTo < len(dataToChecksum):
            csum = csum + dataToChecksum[len(dataToChecksum) - 1]
            csum = csum & 0xffffffff

        csum = (csum >> 16) + (csum & 0xffff)
        csum = csum + (csum >> 16)
        answer = ~csum
        answer = answer & 0xffff
        answer = answer >> 8 | (answer << 8 & 0xff00)

        answer = socket.htons(answer)

        return answer

    # Print Ping output
    def printOneResult(self, destinationAddress: str, packetLength: int, time: float, seq: int, ttl: int, destinationHostname=''):
        if destinationHostname:
            print("%d bytes from %s (%s): icmp_seq=%d ttl=%d time=%.3f ms" % (packetLength, destinationHostname, destinationAddress, seq, ttl, time))
        else:
            print("%d bytes from %s: icmp_seq=%d ttl=%d time=%.3f ms" % (packetLength, destinationAddress, seq, ttl, time))

    def printAdditionalDetails(self, host, numPacketsTransmitted, rtts):
        if len(rtts) > 0:
            print(f'--- {host} ping statistics ---')
            lossPercent = int((100.0 - 100.0*(len(rtts)/numPacketsTransmitted)))
            print(f'{numPacketsTransmitted} packets transmitted, {len(rtts)} received, {lossPercent}% packet loss')
            avgRTT = sum(rtts) / len(rtts)
            deviations = [abs(rtt - avgRTT) for rtt in rtts]
            mdev = sum(deviations) / len(deviations)
            minRTT = min(rtts)
            maxRTT = max(rtts)
            print("rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f ms" % (1000*minRTT, 1000*avgRTT, 1000*maxRTT, 1000*mdev))

    def printMultiThreadedResults(self, ttl, pkt_keys, hop_addrs, rtts, destination):
        print(rtts)
        print(f"\nTraceroute to {destination} ({self.dstAddress}):")
        print("Hop  TTL  RTT   Address")

        sorted_ttl = sorted(hop_addrs.keys())
        print("Failed")
        print(sorted_ttl)

        for ttl_num in sorted_ttl:
            if ttl_num <= ttl:
                for packet_id in pkt_keys:
                    if packet_id in hop_addrs and packet_id in rtts:
                        hop_address = hop_addrs[packet_id]
                        rtt = rtts[packet_id]
                        print(f"{ttl_num:<4} {ttl_num:<4} {rtt*1000:.2f} ms  {hop_address}")
                    else:
                        print(f"{ttl_num:<4} {ttl_num:<4} * * *  (Request timed out)")



    # Print one line of traceroute output
    def printMultipleResults(self, ttl, pkt_keys, hop_addrs, rtts, destinationHostname, function, hop_addrs_to_rtts, rtttts):
        #print(rtttts)
        x = 0
        y = 0
        counter= 0
        if function == "traceroute":
            
            if pkt_keys is None:
                print(str(ttl) + '   * * *')
                return
            # Sort packet keys (sequence numbers or UDP ports)
            pkt_keys = sorted(pkt_keys)
            
            output = str(ttl) + '   '
            
            last_hop_addr = None
            last_hop_name = None

            for pkt_key in pkt_keys:
                # If packet key is missing in hop addresses, this means no response received: print '*'
                if pkt_key not in hop_addrs.keys():
                    output += '* '
                    continue
                hop_addr = hop_addrs[pkt_key]

                # Get the RTT for the probe
                rtt = rtts[pkt_key]
                if last_hop_addr is None or hop_addr != last_hop_addr:
                    hostName = None
                    try:
                        # Get the hostname for the hop
                        hostName = socket.gethostbyaddr(hop_addr)[0]
                        if last_hop_addr is None:
                            output += hostName + ' '
                        else: 
                            output += ' ' + hostName + ' '
                    except socket.herror:
                        output += hop_addr + ' '
                    last_hop_addr = hop_addr
                    last_hop_name = hostName
                    output += '(' + hop_addr + ') '

                output += str(round(1000*rtt, 3))
                output += ' ms  '
                    
            print(output) 

        if function == "Multi-threaded traceroute":
            if args.protocol == "icmp":
                ttl = 1  # Start the ttl at 1
                hop_addrs_to_rtts_keys = hop_addrs_to_rtts.keys()
                if pkt_keys is None:
                    print(str(ttl) + '   * * *')
                    return
                
                last_hop_addr = None
                last_hop_name = None
                for pkt_key in pkt_keys:
                    counter += 1
                    if pkt_key not in hop_addrs.keys():
                        output = str()
                        output += "* "
                        continue 

                    hop_addr = hop_addrs[pkt_key]
                    hostName = None
                    try:
                        if counter % 3 == 0:
                            # Get the hostname and IP address for the hop
                            #print(str(list(hop_addrs_to_rtts_keys)[y]))
                            hostName_list = socket.gethostbyaddr(str(list(hop_addrs_to_rtts_keys)[y]))
                            hostName = hostName_list[0]
                            hop_ip = hostName_list[2][0]  # Extract the IP address 

                            y += 1  # Move to the next hop

                            output = f"{ttl}   {hostName} ({hop_ip})"
                            for rttNum in range(len(rtttts[x])):
                                output += f" {round(1000 * rtttts[x][rttNum], 3)}  ms  "

                            print(output)
                            ttl += 1  # Increment the ttl
                            x += 1  # Move to the next RTT list for the current hop

                    except socket.herror as e:
                        y += 1
                        output = f"{ttl}   {hop_addr} ({hop_addr})"
                        for rttNum in range(len(rtttts[x])):
                            output += f" {round(1000 * rtttts[x][rttNum], 3)} ms  "
                        print(output)
                        x += 1  # Move to the next RTT list for the current hop
                        ttl += 1  # Increment the ttl

            elif args.protocol == "udp":
                ttl = 1  # Start the ttl at 1
                if pkt_keys is None:
                    print(str(ttl) + '   * * *')
                    return

                last_hop_addr = None
                last_hop_name = None
                for pkt_key in pkt_keys:
                    counter += 1
                    if pkt_key not in hop_addrs.keys():
                        output = str()
                        output += "* "
                        continue

                    hop_addr = hop_addrs[pkt_key]
                    hostName = None
                        
                    try:
                        if counter % 3 == 0:
                            # Get the hostname and IP address for the hop
                            #print(str(list(hop_addrs_to_rtts_keys)[y]))
                            hostName_list = socket.gethostbyaddr(hop_addr)
                            hostName = hostName_list[0]
                            hop_ip = hostName_list[2][0]  # Extract the IP address 

                            y += 1  # Move to the next hop

                            output = f"{ttl}   {hostName} ({hop_ip})"
                            for rttNum in range(len(rtttts[x])):
                                output += f" {round(1000 * rtttts[x][rttNum], 3)}  ms  "

                            print(output)
                            ttl += 1  # Increment the ttl
                            x += 1  # Move to the next RTT list for the current hop

                    except socket.herror as e:
                        y += 1
                        output = f"{ttl}   {hop_addr} ({hop_addr})"
                        for rttNum in range(len(rtttts[x])):
                            output += f" {round(1000 * rtttts[x][rttNum], 3)} ms  "
                        print(output)
                        x += 1  # Move to the next RTT list for the current hop
                        ttl += 1  # Increment the ttl


class ICMPPing(NetworkApplication):
    
    def __init__(self, args):
        host = None
        # 1. Look up hostname, resolving it to an IP address
        try:
            host = socket.gethostbyname(args.hostname)
        except socket.gaierror:
            print('Invalid hostname: ', args.hostname) 
            return

        print('Ping to: %s (%s)...' % (args.hostname, host))

        # 1. Create an ICMP socket 
        try:
            self.icmpSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        except socket.error as err:
            traceback.print_exception(err)
            exit(1)

        # 2. Set a timeout on the socket
        self.icmpSocket.settimeout(args.timeout)

        # 3. Send ping probes and collect responses 
        numPings = args.count
        seq_num = 0
        numPingsSent = numPings
        rtts = [] 
        while(numPings > 0):

            # 4. Do one ping approximately every second
            rtt, ttl, packetSize, seq = self.doOnePing(host, args.timeout, seq_num)

            # 5. Print out the RTT (and other relevant details) using the printOneResult method
            if rtt is not None:
                self.printOneResult(host, packetSize, rtt*1000, seq, ttl) 
                rtts.append(rtt)

            # 6. Sleep for a second
            time.sleep(1) 

            # 7. Update sequence number and number of pings
            seq_num += 1
            numPings -= 1

        # 8. Print loss and RTT statistics (average, max, min, etc.)
        self.printAdditionalDetails(args.hostname, numPingsSent, rtts)
        
        # 9. Close ICMP socket
        self.icmpSocket.close()

    # Receive Echo ping reply
    def receiveOnePing(self, destinationAddress, packetID, sequenceNumSent, timeout):
        
        # 1. Wait for the socket to receive a reply
        echoReplyPacket = None
        isTimedout = False
        try:
            echoReplyPacket, addr = self.icmpSocket.recvfrom(MAX_DATA_RECV)
        except socket.timeout as e:
            isTimedout = True

        # 2. Once received, record time of receipt, otherwise, handle a timeout
        timeRecvd = time.time()
        if isTimedout: # timeout
            return None, None, None, None

        # 3. Extract the IP header: 

        # The first 20 bytes is the IP header:  
        # (see: https://en.wikipedia.org/wiki/IPv4#/media/File:IPv4_Packet-en.svg):
        # 0          4             8          16          24           32 bits
        # |  Version | IP Hdr  Len |     TOS   |      Total Length     |
        # |         Identification             |Flag |  Fragment offset|
        # |        TTL             |  Protocol |     Header Checksum   |
        # |           Source IP  Address(32 bits, i.e., 4 bytes)       |
        # |           Destination IP Address (32 bits, i.e., 4 bytes)  |
        # |     Option (up to 40 bytes) this is an optional field      |

        ip_header = echoReplyPacket[:20]
        version_ihl, tos, total_length, identification, flags_offset, ttl, proto, checksum, src_ip, dest_ip = struct.unpack('!BBHHHBBH4s4s', ip_header)

        # Read the IP Header Length (using bit masking) 
        ip_header_len_field = (version_ihl & 0x0F)

        # This field contains the length of the IP header in terms of 
        # the number of 4-byte words. So value 5 indicates 5*4 = 20 bytes. 
        ip_header_len = ip_header_len_field * 4

        payloadSize = total_length - ip_header_len

        # Now parse the ICMP header:
        # 0         8           16         24          32 bits
        #     Type  |    Code   |       Checksum       |
        #     Packet Identifier |       Sequence num   |
        #        <Optional timestamp (8 bytes) for     |
        #        a stateless ping>                     |        
        icmpHeader = echoReplyPacket[ip_header_len:ip_header_len + 8]
        icmpType, code, checksum, p_id, sequenceNumReceived = struct.unpack('!BBHHH', icmpHeader)

        # 5. Check that the ID and sequence numbers match between the request and reply
        if packetID != p_id or sequenceNumReceived != sequenceNumSent:
            return None, None, None, None

        # 6. Return the time of Receipt
        return timeRecvd, ttl, payloadSize, sequenceNumReceived

    # NOTE: This method can be re-used by ICMP traceroute
    # Send Echo Ping Request
    def sendOnePing(self, destinationAddress, packetID, sequenceNumber, ttl=None, dataLength=0):
        # 1. Build ICMP header
        header = struct.pack('!BBHHH', ICMP_ECHO_REQUEST, 0, 0, packetID, sequenceNumber)
        
        # 2. Checksum ICMP packet using given function
        # include some bytes 'AAA...' in the data (payload) of ping
        data = str.encode(dataLength * 'A')
        my_checksum = self.checksum(header+data)

        # 3. Insert checksum into packet
        # NOTE: it is optional to include an additional 8-byte timestamp (time when probe is sent)
        # in which case, a stateless ping can be implemented: the response will contain
        # the sending time so no need to keep that state, 
        # but we don't do that here (instead, we record sending time state in step 5)
        packet = struct.pack('!BBHHH', ICMP_ECHO_REQUEST, 0, socket.htons(my_checksum), packetID, sequenceNumber)

        if ttl is not None:
            self.icmpSocket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

        # 4. Send packet using socket
        self.icmpSocket.sendto(packet+data, (destinationAddress, 1))

        # 5. Record time of sending (state)
        timeSent = time.time()
        return timeSent

    def doOnePing(self, destinationAddress, timeout, seq_num):

        # 3. Call sendOnePing function
        packetID = random.randint(1, 65535)
        timeSent = self.sendOnePing(destinationAddress, packetID, seq_num, dataLength=48)

        # 4. Call receiveOnePing function
        timeReceipt, ttl, packetSize, seq = self.receiveOnePing(destinationAddress, packetID, seq_num, timeout)

        # 5. Compute RTT
        rtt = None
        if timeReceipt is None:
            print("Error receiveOnePing() has timed out")
        else:
            rtt = timeReceipt - timeSent

        # 6. Return total network delay, ttl, size and sequence number
        return rtt, ttl, packetSize, seq

# A partially implemented traceroute 
class Traceroute(ICMPPing):

    def __init__(self, args):
        self.function = None
        args.protocol = args.protocol.lower()
        self.function = "traceroute"

        # 1. Look up hostname, resolving it to an IP address
        self.dstAddress = None
        try:
            self.dstAddress = socket.gethostbyname(args.hostname)
            #socket.getaddrinfo(args.hostname, None, socket.AF_INET6)
        except socket.gaierror:
            print('Invalid hostname: ', args.hostname) 
            return
        print('%s %s to: %s (%s) ...' % (args.protocol, self.function, args.hostname, self.dstAddress))

        # 2. Initialise instance variables
        self.isDestinationReached = False

        # 3. Create a raw socket bound to ICMP protocol
        self.icmpSocket = None
        try:
            self.icmpSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        except socket.error as err:
            traceback.print_exception(err)
            exit(1)

        # 4. Set a timeout on the socket
        self.icmpSocket.settimeout(args.timeout)

        # 5. Run traceroute
        self.runTraceroute()

        # 6. Close ICMP socket
        self.icmpSocket.close()

    def runTraceroute(self):

        hopAddr = None
        pkt_keys = []
        hop_addrs = dict()
        rtts = dict()
        ttl = 1

        while(ttl <= MAX_TTL and self.isDestinationReached == False):
            if args.protocol == "icmp":
                self.sendIcmpProbesAndCollectResponses(ttl)

            elif args.protocol == "udp":
                self.sendUdpProbesAndCollectResponses(ttl)
            else:
                print(f"Error: invalid protocol {args.protocol}. Use udp or icmp")
                sys.exit(1)
            ttl += 1


    # TODO: send 3 ICMP traceroute probes per TTL and collect responses
    def sendIcmpProbesAndCollectResponses(self, ttl):
 
        hopAddr = None
        pkt_keys = []
        hop_addrs = dict()
        rtts = dict()
        numBytes = 52

        for _ in range(3): 
            # 1. Send one ICMP traceroute probe
            packetID = random.randint(1, 65535)
            timeSent,seqNumSent = self.sendOneICMPProbe(self.dstAddress, packetID, ttl, numBytes)

            # 2. Record a unique key (packet ID) associated with the probe
            pkt_keys.append(packetID)

            # 3. Receive the response (if one arrives within the timeout)
            trReplyPacket, hopAddr, timeRecvd = self.receiveOneTraceRouteResponse()
            if trReplyPacket is None:
                continue  # Nothing received within the timeout

            if timeRecvd is None:
                print("Error receiving tracert response has timed out")

            # 4. Parse the response
            p_ID, seqNumReceived, icmpType= self.parseICMPTracerouteResponse(trReplyPacket)

            # 5. Check if we reached the destination 
            if self.dstAddress == hopAddr and icmpType == 0:
                self.isDestinationReached = True
                # Directly add final destination information to hop_addrs and rtts
                hop_addrs[packetID] = hopAddr
                rtts[packetID] = timeRecvd - timeSent

            # 6. If response matches request, record RTT and hop address
            if packetID == p_ID and seqNumReceived == seqNumSent:
                rtts[packetID] = timeRecvd - timeSent
                hop_addrs[packetID] = hopAddr


        # 7. Print results for this TTL
        
        self.printMultipleResults(ttl, pkt_keys, hop_addrs, rtts, args.hostname, self.function, 0, 0)

    # Send 3 UDP traceroute probes per TTL and collect responses
    def sendUdpProbesAndCollectResponses(self, ttl):
        
        hopAddr = None
        icmpType = None
        pkt_keys = []
        hop_addrs = dict()
        rtts = dict()

        numBytes = 52
        dstPort = 33439
        
        for _ in range(3): 
            # 1. Send one UDP traceroute probe
            dstPort += 1
            timeSent = self.sendOneUdpProbe(self.dstAddress, dstPort , ttl, numBytes)

            # 2. Record a unique key (UDP destination port) associated with the probe
            pkt_keys.append(dstPort)

            # 3. Receive the response (if one arrives within the timeout)
            trReplyPacket, hopAddr, timeRecvd = self.receiveOneTraceRouteResponse()
            if trReplyPacket is None:
                # Nothing is received within the timeout period
                continue
            
            # 4. Extract destination port from the reply
            dstPortReceived, icmpType = self.parseUDPTracerouteResponse(trReplyPacket)
        
            # 5. Check if we reached the destination 
            if self.dstAddress == hopAddr and icmpType == 3:
                self.isDestinationReached = True

            # 6. If the response matches the request, record the rtt and the hop address
            if dstPort == dstPortReceived:
                rtts[dstPort] = timeRecvd - timeSent
                hop_addrs[dstPort] = hopAddr

        # 7. Print one line of the results for the 3 probes
        self.printMultipleResults(ttl, pkt_keys, hop_addrs, rtts, args.hostname, self.function, 0, 0)

    # Parse the response to UDP probe 
    def parseUDPTracerouteResponse(self, trReplyPacket):

        # 1. Parse the IP header
        dst_port = None
        # Extract the first 20 bytes 
        ip_header = struct.unpack("!BBHHHBBH4s4s", trReplyPacket[:20])

        # 2. Read the IP Header Length (using bit masking) 
        ip_header_len_field = (ip_header[0] & 0x0F)

        # 3. Compute the IP header length
        # This field contains the length of the IP header in terms of 
        # the number of 4-byte words. So value 5 indicates 5*4 = 20 bytes. 
        ip_header_len = ip_header_len_field * 4
        
        # 4. Parse the outermost ICMP header which is 8 bytes long:
        # 0         8           16         24          32 bits
        #     Type  |    Code   |       Checksum       |
        #     Packet Identifier |       Sequence num   |
        # This header contains type, Code and Checksum + 4 bytes of padding (0's)
        # We only care about type field
        icmpType, _, _, _, _  = struct.unpack("!BBHHH", trReplyPacket[ip_header_len:ip_header_len + 8])
        
        # 5. Parse the ICMP message if it has the expected type
        if icmpType == 3 or icmpType == 11:
            ip_header_inner = struct.unpack("!BBHHHBBH4s4s", trReplyPacket[ip_header_len + 8:ip_header_len+28])

            # This is the original IP header sent in the probe packet
            # It should be 20 bytes, but let's not assume anything and extract the length
            # of the header
            ip_header_len_field = (ip_header_inner[0] & 0x0F)
            ip_header_inner_len = ip_header_len_field * 4
            
            # Extract the destination port and match using source port (UDP)
            _, dst_port, _, _ = struct.unpack('!HHHH', trReplyPacket[ip_header_len + 8 + ip_header_inner_len : ip_header_len + 8 + ip_header_inner_len + 8])

        return dst_port, icmpType
    
    # TODO: parse the response to the ICMP probe
    def parseICMPTracerouteResponse(self, trReplyPacket):

        # 1. Parse the IP header
        dst_port = None
        # Extract the first 20 bytes 
        ip_header = struct.unpack("!BBHHHBBH4s4s", trReplyPacket[:20])

        # 2. Read the IP Header Length (using bit masking) 
        ip_header_len_field = (ip_header[0] & 0x0F)

        # 3. Compute the IP header length
        # This field contains the length of the IP header in terms of 
        # the number of 4-byte words. So value 5 indicates 5*4 = 20 bytes. 
        ip_header_len = ip_header_len_field * 4
        
        # 4. Parse the outermost ICMP header which is 8 bytes long:
        # 0         8           16         24          32 bits
        #     Type  |    Code   |       Checksum       |
        #     Packet Identifier |       Sequence num   |
        # This header contains type, Code and Checksum + 4 bytes of padding (0's)
        # We only care about type field
        icmpType, _, _, _, _  = struct.unpack("!BBHHH", trReplyPacket[ip_header_len:ip_header_len + 8])
        
        # 5. Parse the ICMP message if it has the expected type
        if icmpType == 0 or icmpType == 11:
            ip_header_inner = struct.unpack("!BBHHHBBH4s4s", trReplyPacket[ip_header_len + 8:ip_header_len+28])

            # This is the original IP header sent in the probe packet
            # It should be 20 bytes, but let's not assume anything and extract the length
            # of the header
            ip_header_len_field = (ip_header_inner[0] & 0x0F)
            ip_header_inner_len = ip_header_len_field * 4
            
            # Extract the destination port and match using source port (UDP)
            _, _, checksum, p_ID, seqNum = struct.unpack('!BBHHH', trReplyPacket[ip_header_len + 8 + ip_header_inner_len : ip_header_len + 8 + ip_header_inner_len + 8])

        return p_ID, seqNum, icmpType  

    def receiveOneTraceRouteResponse(self):

        timeReceipt = None
        hopAddr = None
        pkt = None

        # 1. Receive one packet or timeout
        try:
            pkt, addr = self.icmpSocket.recvfrom(MAX_DATA_RECV)
            timeReceipt = time.time()
            hopAddr = addr[0]
        
        # 2. Handler for timeout on receive
        except socket.timeout as e:
            timeReceipt = None

        # 3. Return the packet, hop address and the time of receipt
        return pkt, hopAddr, timeReceipt

    def sendOneUdpProbe(self, destAddress, port, ttl, dataLength):

        # 1. Create a UDP socket
        udpSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, UDP_CODE)

        # 2. Use a socket option to set the TTL in the IP header
        udpSocket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

        # 3. Send the UDP traceroute probe
        udpSocket.sendto(str.encode(dataLength * '0'), (destAddress, port))

        # 4. Record the time of sending
        timeSent = time.time()

        # 5. Close the UDP socket
        udpSocket.close()

        return timeSent
    
    def sendOneICMPProbe(self, destinationAddress, packetID, ttl, dataLength):
        seqNumSent = 0

        header = struct.pack('!BBHHH', ICMP_ECHO_REQUEST, 0, 0, packetID, seqNumSent)
        data = str.encode(dataLength * 'A')
        myy_checksum = self.checksum(header + data)
        packet = struct.pack('!BBHHH', ICMP_ECHO_REQUEST, 0, socket.htons(myy_checksum), packetID, seqNumSent)
        
        if ttl is not None:
            self.icmpSocket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

        self.icmpSocket.sendto(packet + data, (destinationAddress, 1))

        timeSent = time.time()
        return timeSent, seqNumSent

# TODO: A multi-threaded traceroute implementation
class MultiThreadedTraceRoute(Traceroute):

    def __init__(self, args):
        # 1. Initialise instance variables (add others if needed)
        self.pkt_keys = []  # Track packet IDs
        self.p_IDs = []
        self.hop_addrs = {}  # Map packet IDs to hop addresses
        self.hop_addrs_to_rtts = {} # Maps rtts to hop addresses
        self.rtts = {}       # Map packet IDs to RTTs
        self.timesSent = {}  # Map packetIDs to timeSent
        self.timesRecvd = {} # Map packet IDS to timeRecvd
        self.seqNumbersRecvd = {}
        self.seqNumbersSent = {}
        self.probes_received = {}
        self.ttl = None
        self.hopAddr = None # Store Address of each rtr
        self.timeSent = None   # Store sending times of each packet
        self.seqNumSent = 0 # Store sequence numbers of sent packets
        self.packetID = None # Store packetID of packet sent
        self.p_ID = None
        self.seqNumRecvd = None
        self.function = None
        self.isDestinationReached = False
        args.protocol = args.protocol.lower()
        self.timeout = args.timeout
        self.send_complete = threading.Event()
        # NOTE you must use a lock when accessing data shared between the two threads
        self.dest_reached_lock = threading.Lock()  # Destination reached lock
        self.packetID_lock = threading.Lock()  # packetID lock

        # 1. Look up hostname, resolving it to an IP address
        self.dstAddress = None
        self.function = "Multi-threaded traceroute"
        try:
            self.dstAddress = socket.gethostbyname(args.hostname)
            #socket.getaddrinfo(args.hostname, None, socket.AF_INET6)
        except socket.gaierror:
            print('Invalid hostname: ', args.hostname) 
            return
        print('%s %s to: %s (%s) ...' % (args.protocol, self.function, args.hostname, self.dstAddress))

        # 2. Initialise instance variables
        self.isDestinationReached = False

        # 3. Create a raw socket bound to ICMP protocol
        self.icmpSocket = None
        try:
            self.icmpSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        except socket.error as err:
            traceback.print_exception(err)
            exit(1)

        # 4. Set a timeout on the socket
        self.icmpSocket.settimeout(self.timeout)

        # 2. Create a thread to send probes
        self.send_thread = threading.Thread(target=self.send_probes)

        # 3. Create a thread to receive responses 
        self.recv_thread = threading.Thread(target=self.receive_responses)

        # 4. Start the threads
        self.send_thread.start()
        self.recv_thread.start()

        # 5. Wait until both threads are finished executing
        self.send_thread.join()
        self.recv_thread.join()

        # 6. TODO Print results
        self.send_complete.wait()
        #self.printMultipleResults(self.ttl, self.pkt_keys, self.hop_addrs, self.rtts, args.hostname, self.function, self.hop_addrs_to_rtts, self.rtttts)

        # 7. Close Socket
        self.icmpSocket.close()
            
    # Thread to send probes (to be implemented, a skeleton is provided)
    def send_probes(self):
        self.dstPort = 33439
        self.ttl = 1
        while (self.ttl <= MAX_TTL):

            with self.dest_reached_lock:
                # Check if destination is reached, then exit the loop if so
                if self.isDestinationReached:
                    break

            numBytes = 52
            # Send three probes per TTL
            for _ in range(3):
                if args.protocol == "icmp":
                    # 1. Send one ICMP traceroute probe
                    self.packetID = random.randint(1, 65535)
                    self.timesSent[self.packetID],self.seqNumbersSent[self.packetID] = self.sendOneICMPMTProbe(self.dstAddress, self.packetID, self.ttl, numBytes)

                    # 2. Record a unique key (packet ID) associated with the probe
                    with self.packetID_lock:
                        self.pkt_keys.append(self.packetID)      
                        
                elif args.protocol == "udp":
                    # 1. Send one UDP traceroute probe
                    self.dstPort += 1
                    self.timeSent = self.sendOneUdpProbe(self.dstAddress, self.dstPort , self.ttl, numBytes)
                    self.timesSent[self.dstPort] = self.timeSent

                    # 2. Record a unique key (UDP destination port) associated with the probe
                    with self.packetID_lock:
                        self.pkt_keys.append(self.dstPort)
                      

                else:
                    print(f"Error: invalid protocol {args.protocol}. Use udp or icmp")
                    sys.exit(1)    

                # Sleep for a short period between sending probes
                time.sleep(0.05)  # Small delay between probes

            #self.printMultipleResults(self.ttl, self.pkt_keys, self.hop_addrs, self.rtts, args.hostname)
            self.ttl += 1


        # A final sleep before notifying the receive thread to exit
        time.sleep(args.timeout)
        # Notify the other thread that sending is complete
        self.send_complete.set()
        

    def sendOneICMPMTProbe(self, destinationAddress, packetID, ttl, dataLength):
        self.seqNumSent += 1

        header = struct.pack('!BBHHH', ICMP_ECHO_REQUEST, 0, 0, packetID, self.seqNumSent)
        data = str.encode(dataLength * 'A')
        myy_checksum = self.checksum(header + data)
        packet = struct.pack('!BBHHH', ICMP_ECHO_REQUEST, 0, socket.htons(myy_checksum), self.packetID, self.seqNumSent)

        # Acquire lock until line self.icmpSocket.sendto
        #with self.lock:
        if ttl is not None:
            self.icmpSocket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

            self.icmpSocket.sendto(packet + data, (destinationAddress, 1))
            
        self.timeSent = time.time()
        
        return self.timeSent, self.seqNumSent

    # Thread to receive responses (to be implemented, a skeleton is provided)
    def receive_responses(self):
        count = 0
        while not self.send_complete.is_set():
            if args.protocol == "icmp":
                # Receive the response (if one arrives within the timeout)
                trReplyPacket, self.hopAddr, self.timeRecvd = self.receiveOneMTTraceRouteResponse()
                
                if trReplyPacket is None:
                    continue  # Nothing received within the timeout

                if self.timeRecvd is None:
                    print("Error receiving tracert response has timed out")
                
                self.p_ID, self.seqNumReceived, icmpType = self.parseICMPMTTracerouteResponse(trReplyPacket)
                self.p_IDs.append(self.p_ID)
                self.hop_addrs[self.p_ID] = self.hopAddr
                self.seqNumbersRecvd[self.p_ID] = self.seqNumReceived
                self.timesRecvd[self.p_ID] = self.timeRecvd
                # Handle destination reached
                with self.dest_reached_lock:
                    if self.dstAddress == self.hopAddr and icmpType == 0:
                        count += 1
                        if count == 3: #All 3 probes have to be captured first before going printing all results
                            self.isDestinationReached = True
                            self.finalizing_rtts(self.p_IDs, self.seqNumbersRecvd, self.pkt_keys, self.seqNumbersSent, self.hop_addrs)
            
            # Handle UDP protocol (if needed)
            elif args.protocol == "udp":
                trReplyPacket, self.hopAddr, self.timeRecvd = self.receiveOneTraceRouteResponse()
                if trReplyPacket is None:
                    # Nothing is received within the timeout period
                    continue
                
                # 4. Extract destination port from the reply
                dstPortReceived, icmpType = self.parseUDPTracerouteResponse(trReplyPacket)
                self.p_IDs.append(dstPortReceived)
                self.hop_addrs[dstPortReceived] = self.hopAddr
                self.timesRecvd[dstPortReceived] = self.timeRecvd
            
                # 5. Check if we reached the destination 
                with self.dest_reached_lock:
                    if self.dstAddress == self.hopAddr and icmpType == 3:
                        count += 1
                        if count == 3:
                            self.isDestinationReached = True
                            self.finalizing_rtts(self.p_IDs, None, self.pkt_keys, None, self.hop_addrs)
        

            else:
                print(f"Error: invalid protocol {args.protocol}. Use udp or icmp")
                sys.exit(1)
       

    def receiveOneMTTraceRouteResponse(self):
        timeReceipt = None
        pkt = None

        # 1. Receive one packet or timeout
        # If lock is acquired or locked don't enter this try except. if released enter
        #with self.lock:
        try:
            pkt, addr = self.icmpSocket.recvfrom(MAX_DATA_RECV)
            timeReceipt = time.time()
            self.hopAddr = addr[0]
            #print(self.hopAddr)
        
        # 2. Handler for timeout on receive
        except socket.timeout as e:
            timeReceipt = None

        # 3. Return the packet, hop address and the time of receipt
        return pkt, self.hopAddr, timeReceipt

    def parseICMPMTTracerouteResponse(self, trReplyPacket):
        # 1. Parse the IP header
        dst_port = None
        # Extract the first 20 bytes 
        ip_header = struct.unpack("!BBHHHBBH4s4s", trReplyPacket[:20])

        # 2. Read the IP Header Length (using bit masking) 
        ip_header_len_field = (ip_header[0] & 0x0F)

        # 3. Compute the IP header length
        # This field contains the length of the IP header in terms of 
        # the number of 4-byte words. So value 5 indicates 5*4 = 20 bytes. 
        ip_header_len = ip_header_len_field * 4
        
        icmpType, _, _, p_ID, seqNum  = struct.unpack("!BBHHH", trReplyPacket[ip_header_len:ip_header_len + 8])
        
        
        # 5. Parse the ICMP message if it has the expected type
        if icmpType == 11:
            ip_header_inner = struct.unpack("!BBHHHBBH4s4s", trReplyPacket[ip_header_len + 8:ip_header_len+28])

            # This is the original IP header sent in the probe packet
            # It should be 20 bytes, but let's not assume anything and extract the length
            # of the header
            ip_header_len_field = (ip_header_inner[0] & 0x0F)
            ip_header_inner_len = ip_header_len_field * 4
            
            # Extract the destination port and match using source port (UDP)
            _, _, checksum, p_ID, seqNum = struct.unpack('!BBHHH', trReplyPacket[ip_header_len + 8 + ip_header_inner_len : ip_header_len + 8 + ip_header_inner_len + 8])
        elif icmpType == 0:
            return p_ID, seqNum, icmpType
        else:
            p_ID, seqNum = None, None

        return p_ID, seqNum, icmpType
    
    def finalizing_rtts(self, p_IDs, seqNumbersRecvd, pkt_keys, seqNumbersSent, hop_addrs):
        self.rtttts = [[] for _ in range(len(pkt_keys)//3)] #rtttts is a 2D list that stores the rtts for each hop in the second dimension of the list
        x = -1
        if args.protocol == "icmp":
            with self.packetID_lock:
                for packetID, p_ID, seqNumReceived, seqNumSent, hop_addr in zip(pkt_keys, p_IDs, seqNumbersRecvd.values(), seqNumbersSent.values(), hop_addrs.values()):
                    # Check if packet IDs and sequence numbers match
                    if packetID == p_ID and seqNumReceived == seqNumSent:
                        self.rtts[packetID] = self.timesRecvd[packetID] - self.timesSent[packetID]
                        
                        if hop_addr not in self.hop_addrs_to_rtts:
                            x += 1
                            self.rtttts[x].append(self.rtts[packetID])
                            self.hop_addrs_to_rtts[hop_addr] = self.rtttts[x]
                        else:
                            self.rtttts[x].append(self.rtts[packetID])
                            self.hop_addrs_to_rtts[hop_addr] = self.rtttts[x]
                    else:
                        print(f"Mismatch: packetID={packetID}, p_ID={p_ID}, seqNumSent={seqNumSent}, seqNumReceived={seqNumReceived}")
                
            self.printMultipleResults(self.ttl, self.pkt_keys, self.hop_addrs, self.rtts, args.hostname, self.function, self.hop_addrs_to_rtts, self.rtttts)

        elif args.protocol == "udp":
            print(f'pkt_keys: {pkt_keys}')
            print(f'p_IDs: {p_IDs}')
            with self.packetID_lock:
                for packetID, p_ID, hop_addr in zip(pkt_keys, p_IDs, hop_addrs.values()):
                    
                    if packetID == p_ID:
                        self.rtts[packetID] = self.timesRecvd[packetID] - self.timesSent[packetID]

                        if hop_addr not in self.hop_addrs_to_rtts:
                            x += 1
                            self.rtttts[x].append(self.rtts[packetID])
                            self.hop_addrs_to_rtts[hop_addr] = self.rtttts[x]
                        else:
                            self.rtttts[x].append(self.rtts[packetID])
                            self.hop_addrs_to_rtts[hop_addr] = self.rtttts[x]

                    else:
                        print(f"Mismatch: packetID={packetID}, p_ID={p_ID}")
                    
            self.printMultipleResults(self.ttl, self.pkt_keys, self.hop_addrs, self.rtts, args.hostname, self.function, self.hop_addrs_to_rtts, self.rtttts)

# A basic multi-threaded web server implementation

# You can test the web server as follows: 
# First, run the server in the terminal: python3 NetworkApplications.py web 
# Then, copy the following and paste to a browser's address bar: 127.0.0.1:8080/index.html
# NOTE: the index.html file needs to be downloaded from the Moodle (Dummy HTML file)
# and copied to the folder where you run this code
class WebServer(NetworkApplication):

    def __init__(self, args):
        print('Web Server starting on port: %i...' % args.port)
        
        # 1. Create a TCP socket 
        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # 2. Bind the TCP socket to server address and server port
        serverSocket.bind(("", args.port))
        
        # 3. Continuously listen for connections to server socket
        serverSocket.listen(100)
        print("Server listening on port", args.port)
        
        while True:
            # 4. Accept incoming connections
            connectionSocket, addr = serverSocket.accept()
            print(f"Connection established with {addr}")
            
            # 5. Create a new thread to handle each client request
            threading.Thread(target=self.handleRequest, args=(connectionSocket,)).start()

        # Close server socket (this would only happen if the loop was broken, which it isn't in this example)
        serverSocket.close()

    def handleRequest(self, connectionSocket):
        try:
            # 1. Receive request message from the client
            message = connectionSocket.recv(MAX_DATA_RECV).decode()
            print(message)

            # 2. Extract the path of the requested object from the message (second part of the HTTP header)
            filename = message.split()[1]
            print(f"FFIILLEENNAAMMEE: {filename}")

            # 3. Read the corresponding file from disk
            with open(filename[1:], 'r') as f:  # Skip the leading '/'
                content = f.read()

            # 4. Create the HTTP response
            response = 'HTTP/1.1 200 OK\r\n\r\n'
            response += content
            print(response)

            # 5. Send the content of the file to the socket
            connectionSocket.send(response.encode())

        except IOError:
            # Handle file not found error
            error_response = "HTTP/1.1 404 Not Found\r\n\r\n"
            error_response += "<html><head></head><body><h1>404 Not Found</h1></body></html>\r\n"
            connectionSocket.send(error_response.encode())

        except Exception as e:
            print(f"Error handling request: {e}")

        finally:
            # Close the connection socket
            connectionSocket.close()

# TODO: A proxy implementation 
class Proxy(NetworkApplication): #Extra functions: handleReply, extra socket connection, caching function
    # When handling request look for the directory in the cache first if it exists create the response from the proxy else request it from the s

    def __init__(self, args):
        print('Web Proxy starting on port: %i...' % (args.port))

        # 1. Create a TCP socket 
        self.proxySocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.proxySocket.bind(("", args.port))

        proxy_ip, proxy_port = self.proxySocket.getsockname()

        # 3. Continuously listen for connections to Proxy socket
        self.proxySocket.listen(100)
        print("Proxy listening on port", args.port)

        '''self.serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        self.serverSocket.bind(("", 9000))
        
        # 3. Continuously listen for connections to server socket
        self.serverSocket.listen(100)
        print("Server listening on port 9000")''' #Remove comment to test with local host
        
        while True:
            # 4. Accept incoming connections
            proxyConnectionSocket, addr = self.proxySocket.accept()
            print(f"Connection established with {addr}")
            
            # 5. Create a new thread to handle each client request
            threading.Thread(target=self.handleClientRequest, args=(proxyConnectionSocket,)).start()

    def handleClientRequest(self, proxyConnectionSocket):
        try:
            # 1. Receive request message from the client
            message = proxyConnectionSocket.recv(MAX_DATA_RECV).decode()

            # 2. Extract the path of the requested object from the message (second part of the HTTP header)
            filename = message.split()[1]

            cache_location = "./cache"  # Cache folder location
            os.makedirs(cache_location, exist_ok=True)  # Ensure the cache folder exists

            # Full path to the cached file
            cached_file_path = os.path.join(cache_location, filename[7:])

            host = message.split()[4]
            path = filename[7+len(host):]

            if os.path.isdir(cached_file_path):  
                print(f"Cache hit: {cached_file_path}")
                # Directly create and send response to client
                self.create_send_response(cached_file_path, proxyConnectionSocket)

            else: 
                print(f"Cache miss: {cached_file_path}")
                # Add filename to the cache 
                response_message = self.fetch_from_server(host, path, cached_file_path, message)
                #self.fetch_from_server_and_add_to_cache(cached_file_path)

                # Send the response to the client
                # Send the response to the client
                response = "HTTP/1.1 200 OK\r\n\r\n" + response_message
                proxyConnectionSocket.send(response.encode())

        except IOError:
            # Handle file not found error
            error_response = "HTTP/1.1 404 Not Found\r\n\r\n"
            error_response += "<html><head></head><body><h1>404 Not Found</h1></body></html>\r\n"
            proxyConnectionSocket.send(error_response.encode())

        except Exception as e:
            print(f"Error handling request: {e}")

        finally:
            # Close the connection socket
            proxyConnectionSocket.close()

    def create_send_response (self, filename, proxyConnectionSocket):
        # 3. Read the corresponding file from disk
        with open(os.path.join(filename,'index.html'), 'r') as f:  # Skip the leading '/'
            content = f.read()

        # 4. Create the HTTP response
        response = 'HTTP/1.1 200 OK\r\n\r\n'
        response += content

        # 5. Send the content of the file to the socket
        proxyConnectionSocket.send(response.encode())

        
    def fetch_from_server(self, host, path, cached_file_path, message):
        # Create a connection to the neverssl server
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            server_socket.connect((host, 80)) # change to any num greater than 1024 if you want to use the local host
        except Exception as e:
            print(host)
            print(f"Error handling request: {e}")
        # Construct the HTTP request for neverssl.com
        #http_request = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        server_socket.sendall(message.encode())
        server_socket.settimeout(1)

        final_message = ""
        while message:
            try:
                message = server_socket.recv(MAX_DATA_RECV).decode()
                final_message += message
            except Exception as e:
                final_message += message
                break
        
        # Adding the cached_path to the cache
        try:
            os.makedirs(cached_file_path, exist_ok=True)
            with open(os.path.join(cached_file_path,'index.html'), "w") as cache_file:
                cache_file.write(final_message)
            return final_message
            '''
            # Send the response to the client
            response = "HTTP/1.1 200 OK\r\n\r\n" + message
            .send(response.encode())'''
        except Exception as e:
            print(f"Error fetching and caching file: {e}")
        finally:
            # Close the connection socket
            server_socket.close()

pass # TODO: Remove this once this method is implemented       
            

# NOTE: Do NOT delete the code below
if __name__ == "__main__":
        
    args = setupArgumentParser()
    args.func(args)
