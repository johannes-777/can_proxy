#!/usr/bin/pyton3
"""
Author: Johannes.Schabauer@ait.ac.at
Date:   22nd of Dec. 2015

Description:
    1.) Linux supports many CAN-Interfaces via the Berkley Socket API (thanks to Volkswagen Research), 
    but Java only provides a simplified Socket API (which ignores SocketCAN - thanks to Oracle).
    2.) This script solves this problem by providing a proxy which forwards all UDP packets to the CAN Interface.
        -) There is a 1:1:1 relation between CAN-Interfaces and Listening Ports of the UDP-Server and Instances of the UDP-Server
        which is defined at startup with runtime parameters.
        -) Only ONE UDP-CLIENT shall communicate ("connect") to ONE UDP-Server (this script), 
        otherwise there will be a mess with the CAN-Datagrams, which need to be returned to the UDP-Client.
    3.) UDP-Packets are analized and ONLY VALID CAN-Packets are forwarded to the CAN-Interface
        
Parameters:
    1.) CanInterface Name (e.g. can0, slcan0, vcan1 ...)
    2.) UDP-Host and Port (normally localhost and 770..780, use free Ports < 1024)
    Baudrate is set in Shell Script (with ifconfig, ip link set ...), before this script is called 
    
Example:
    python3 can_proxy.py can1 localhost 770
"""



import socket
import struct
import sys
import os
import socketserver
import time
import threading
import logging
import logging.config

logging.config.fileConfig(fname="log4p.properties");
log=logging.getLogger("at.ac.ait.enviro.can_proxy.py");

# CAN frame packing/unpacking (see `struct can_frame` in <linux/can.h>)
#udp_frame_fmt = "!IB3x8s";  #![network Byte Order (big-endian), Java]
udp_frame_fmt = "@IB3x8s";  
can_frame_fmt = "@IB3x8s";  #[Native Byte Order, for some reason socketcan requires native!]
                            #I[long,4Bytes, can_id] 
                            #B[unsigned Char,1Byte, can_len] 
                            #3x[3x pad bytes,3Byte, NA] 
                            #8s[8x char, can_data] 
                            #-> 16 Bytes
messwert_fmt= "=I4B";

#------------------------------------------------------
# CAN Handling
#------------------------------------------------------
def build_can_frame(can_id, data):
        can_dlc = len(data)
        data = data.ljust(8, b'\x00')
        return struct.pack(can_frame_fmt, can_id, can_dlc, data)
 
def dissect_can_frame(frame):
        can_id, can_dlc, data = struct.unpack(udp_frame_fmt, frame)
        return (can_id, can_dlc, data[:can_dlc])
 
 
#------------------------------------------------------
# UDP Server
#------------------------------------------------------ 
class Hell(Exception):
#{
    pass;
#}

   
class UDPHandler(socketserver.BaseRequestHandler):
#{
    """
    This class works similar to the TCP handler class, except that
    self.request consists of a pair of data and client socket, and since
    there is no connection the client address must be given explicitly
    when sending data back via sendto().
    """

    def handle(self):
    #{
        global CAN_IF;
        global client_sock;
        global client_address;
        global can_sock;
        update_host= False;
        
        log.debug("This request is done in the thread/process {}".format(os.getpid()));
        #time.sleep(5);
        datagram = self.request[0].strip();
        socket = self.request[1];
        
        #log.info(client_address);
        #log.info(self.client_address);
        if client_address == None:
        #{
            log.warn("Setting client_address for the first time:");
            update_host= True;
        #}
        elif client_address[0] != self.client_address[0]:  #host
        #{
            log.error("Host changed! This should only happen once after this proxy is restarted");
            update_host= True;
        #}
        elif client_address[1] != self.client_address[1]:   #port
        #{
            log.warn("Port changed! Probably the client was restarted.");
            update_host= True;
        #}
        if update_host == True:
        #{
            log.warn("Setting client_socket from {} to {}".format(client_sock, socket));
            client_sock= socket;
            client_address= self.client_address;
        #}
        log.debug("{} wrote: {}".format(self.client_address, datagram));
        #log.info(datagram);
        
        #Check if the Datagram contains a valid CAN Message
        try:
        #{
            can_id, can_length, can_data= dissect_can_frame(datagram);
            #log.info('This UDP-Packet is valid: id=0x%x, len={}, data={}'.format(can_id, can_length, can_data));
            if (can_length > 8):
                raise Hell('Invalid Length ({}) for CAN-Frame'.format(can_length));
        #}
        except Exception as e:
        #{
            log.warn('This UDP-Packet ({}) from "{}" is NOT a valid CAN-Frame, so it will be discarded'.format(datagram, self.client_address[0]));
            log.warn(e);
            return;
        #}
        
        #CanFrame seems right -> rebuild it in "CORRECT" Byteorder (Little Endian) and send it to CAN-Interface
        canpacket= build_can_frame(can_id, can_data);
        #time.sleep(0.01);  //This is necessary if the receive Function does not continually run in a own thread on the client side; so udp packet might be lost
        log.info("This UDP-Packet is valid: id=0x%x, len=%d, data=%s -> sending to %s", can_id, can_length, can_data, CAN_IF);
        try:
        #{
            can_sock.send(canpacket)
            #can_sock.send(datagram)
        #}
        except Exception as e:
        #{
            log.warn('Error sending CAN frame')
            log.warn(e)
        #}

        #client_sock.sendto(data.upper(), self.client_address);
    #}
#}

#This creates one thread for each request
#class ThreadingUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
#   pass

#This will create one process for each request
#class ThreadingUDPServer(socketserver.ForkingMixIn , socketserver.UDPServer):
#   pass   
   
#------------------------------------------------------
# MAIN (Setup CAN and UDP Sockets)
#------------------------------------------------------        
def main():
    global client_sock;
    global client_address;
    global can_sock;
    global CAN_IF;
    client_sock= None;
    client_address= None;
    can_sock= None;
    CAN_IF= None;
    
    #Logging Initialisieren
    log.warn("********************");
    log.warn("CAN Proxy coming up 25");
    log.warn("********************");
    
    if len(sys.argv) != 4:
    #{
        log.error('Provide CAN device name (can0, slcan0 etc.), UDP-Host (localhost, 10.0.x.x ...) with Listening Port (770-780)');
        sys.exit(0);
    #}
    #Read args
    CAN_IF= sys.argv[1];
    UDP_HOST= sys.argv[2];
    UDP_PORT= int(sys.argv[3]);
    
    # create a raw CAN socket and bind it to the given CAN interface
    log.info("Creating CAN-Socket for Interface '" + CAN_IF + "'");
    can_sock = socket.socket(socket.AF_CAN, socket.SOCK_RAW, socket.CAN_RAW);
    can_sock.settimeout(60.0);
    can_sock.bind((CAN_IF,));
    
    # create a UDP Server socket and bind it to the given Port
    log.info("Creating UDP-Socket for HOST '" + UDP_HOST + ":" + str(UDP_PORT) + "'");
    server = socketserver.UDPServer((UDP_HOST, UDP_PORT), UDPHandler);
    #server = ThreadingUDPServer((UDP_HOST, UDP_PORT), UDPHandler);
    #server.serve_forever();  #This is the single threaded version
    # Start a thread with the server -- that thread will then start one more thread for each request
    server_thread = threading.Thread(target=server.serve_forever);
    # Exit the server thread when the main thread terminates
    server_thread.daemon = True;
    server_thread.start();
    log.info("Server loop running in thread: {}".format(server_thread.name));
    
    #Now that the UDP-Server runs in its own thread, we can use the main thread for 
    #the CAN-Server
    log.info("Starting the CAN-Thread");
    
    # listen for incoming can-datagrams
    while True:
    #{
        try:
        #{
            log.debug('Waiting for a CAN-Frame');
            cf, addr = can_sock.recvfrom(16);
            log.info('CAN-Frame received: {}. Forwarding to {}'.format(cf, client_address[0]));
            client_sock.sendto(cf, client_address);
        #}
        except socket.timeout as t:
            log.info('No CAN-Frame received');
            log.info(t);
        except Exception as e:
        #{
            log.error(e);
        #}
    #}
#}    
        
if __name__ == "__main__":
    main()                
        
