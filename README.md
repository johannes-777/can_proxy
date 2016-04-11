# can_proxy
*Transports UDP/IP Messages to a CAN-Port and back.*

## Description:
1. Linux supports many CAN-Interfaces via the Berkley Socket API (thanks to Volkswagen Research), 
    but Java only provides a simplified Socket API (which ignores SocketCAN - thanks to Oracle).
2. This script solves this problem by providing a proxy which forwards all UDP packets to the CAN Interface.
        - There is a 1:1:1 relation between CAN-Interfaces and Listening Ports of the UDP-Server and Instances of the UDP-Server
        which is defined at startup with runtime parameters.
        - Only ONE UDP-CLIENT shall communicate ("connect") to ONE UDP-Server (this script), 
        otherwise there will be a mess with the CAN-Datagrams, which need to be returned to the UDP-Client.
3. UDP-Packets are analized and ONLY VALID CAN-Packets are forwarded to the CAN-Interface
        
## Parameters:
    1.) CanInterface Name (e.g. can0, slcan0, vcan1 ...)
    2.) UDP-Host and Port (normally localhost and 770..780, use free Ports < 1024)
    Baudrate is set in Shell Script (with ifconfig, ip link set ...), before this script is called 
    
## Example:
    python3 can_proxy.py can1 localhost 770
