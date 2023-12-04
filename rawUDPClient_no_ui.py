import socket  # Importing socket library for network connections
import struct  # Importing struct library for packing and unpacking bytes
import os
import threading
import queue
import time

VERSION_OFF = 0  # Offset for the version field in the IP header
IHL_OFF = VERSION_OFF  # Offset for the IHL field in the IP header
DSCP_OFF = IHL_OFF + 1  # Offset for the DSCP field in the IP header
ECN_OFF = DSCP_OFF  # Offset for the ECN field in the IP header
LENGTH_OFF = DSCP_OFF + 1  # Offset for the total length field in the IP header
ID_OFF = LENGTH_OFF + 2  # Offset for the identification field in the IP header
FLAGS_OFF = ID_OFF + 2  # Offset for the flags field in the IP header
OFF_OFF = FLAGS_OFF  # Offset for the fragment offset field in the IP header
TTL_OFF = OFF_OFF + 2  # Offset for the TTL field in the IP header
PROTOCOL_OFF = TTL_OFF + 1  # Offset for the protocol field in the IP header
IP_CHECKSUM_OFF = PROTOCOL_OFF + 1  # Offset for the header checksum field in the IP header
SRC_IP_OFF = IP_CHECKSUM_OFF + 2  # Offset for the source IP address field in the IP header
DEST_IP_OFF = SRC_IP_OFF + 4  # Offset for the destination IP address field in the IP header
SRC_PORT_OFF = DEST_IP_OFF + 4  # Offset for the source port field in the UDP header
DEST_PORT_OFF = SRC_PORT_OFF + 2  # Offset for the destination port field in the UDP header
UDP_LEN_OFF = DEST_PORT_OFF + 2  # Offset for the length field in the UDP header
UDP_CHECKSUM_OFF = UDP_LEN_OFF + 2  # Offset for the checksum field in the UDP header
SEQ_NUM_OFF = UDP_CHECKSUM_OFF + 2 # Offset for the sequence number field in the UDP header
ACK_NUM_OFF = SEQ_NUM_OFF + 4  # Offset for the acknowledgement number field in the UDP header
DATA_OFF = ACK_NUM_OFF + 4  # Offset for the data field in the UDP header
IP_PACKET_OFF = VERSION_OFF  # Offset for the start of the IP packet
UDP_PACKET_OFF = SRC_PORT_OFF  # Offset for the start of the UDP packet

FILENAME_SIGN = 'FILENAME:'  # Signature for the filename in the data
READY_SIGN = b'READY'  # Signature for the ready status in the data


class PacketParser:  # Class for parsing packets
    def __init__(self, data):  # Constructor takes the data to be parsed
        self.data = data  # Store the data

    def parse(self):  # Method to parse the data
        packet = {}  # Create a dictionary to store the parsed data
        packet['version']       = self.data[VERSION_OFF] >> 4  # Parse the version field
        packet['IHL']           = self.data[IHL_OFF] & 0x0F  # Parse the IHL field
        packet['DSCP']          = self.data[DSCP_OFF] >> 2  # Parse the DSCP field
        packet['ECN']           = self.data[ECN_OFF] & 0x03  # Parse the ECN field
        packet['length']        = (self.data[LENGTH_OFF] << 8) + self.data[LENGTH_OFF + 1]  # Parse the total length field
        packet['Identification']= (self.data[ID_OFF] << 8) + self.data[ID_OFF + 1]  # Parse the identification field
        packet['Flags']         = self.data[FLAGS_OFF] >> 5  # Parse the flags field
        packet['Offset']        = ((self.data[OFF_OFF] & 0b11111) << 8) + self.data[OFF_OFF + 1]  # Parse the fragment offset field
        packet['TTL']           = self.data[TTL_OFF]  # Parse the TTL field
        packet['Protocol']      = self.data[PROTOCOL_OFF]  # Parse the protocol field
        packet['Checksum']      = (self.data[IP_CHECKSUM_OFF] << 8) + self.data[IP_CHECKSUM_OFF + 1]  # Parse the header checksum field
        packet['src_ip']        = '.'.join(map(str, [self.data[x] for x in range(SRC_IP_OFF, SRC_IP_OFF + 4)]))  # Parse the source IP address field
        packet['dest_ip']       = '.'.join(map(str, [self.data[x] for x in range(DEST_IP_OFF, DEST_IP_OFF + 4)]))  # Parse the destination IP address field
        packet['src_port']      = (self.data[SRC_PORT_OFF] << 8) + self.data[SRC_PORT_OFF + 1]  # Parse the source port field
        packet['dest_port']     = (self.data[DEST_PORT_OFF] << 8) + self.data[DEST_PORT_OFF + 1]  # Parse the destination port field
        packet['udp_length']    = (self.data[UDP_LEN_OFF] << 8) + self.data[UDP_LEN_OFF + 1]  # Parse the length field
        packet['UDP_checksum']  = (self.data[UDP_CHECKSUM_OFF] << 8) + self.data[UDP_CHECKSUM_OFF + 1]  # Parse the checksum field
        packet['seq_num']       = (self.data[SEQ_NUM_OFF] << 24) + (self.data[SEQ_NUM_OFF + 1] << 16) + (self.data[SEQ_NUM_OFF + 2] << 8) + self.data[SEQ_NUM_OFF + 3]  # Parse the sequence number field
        packet['ack_num']       = (self.data[ACK_NUM_OFF] << 24) + (self.data[ACK_NUM_OFF + 1] << 16) + (self.data[ACK_NUM_OFF + 2] << 8) + self.data[ACK_NUM_OFF + 3]  # Parse the acknowledgement number field
        packet['data'] = self.data[DATA_OFF:]  # Parse the data field
        return packet  # Return the parsed data

class UDPSender:  # Class for sending UDP packets

    def __init__(self, local_ip, remote_ip, sendfrom_port, rcv_port, todst_port):  # Constructor takes the local IP, remote IP, sending port, receiving port, and destination port
        self.local_ip = local_ip  # Store the local IP
        self.remote_ip = remote_ip  # Store the remote IP
        self.sendfrom_port = sendfrom_port  # Store the sending port
        self.rcv_port = rcv_port  # Store the receiving port
        self.todst_port = todst_port  # Store the destination port
        self.timeout = 0.5  # Set the timeout to 1 second
        self.zero = 0  # Set the zero field to 0
        self.protocol = socket.IPPROTO_UDP  # Set the protocol to UDP
        self.running = True
        self.s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        # self.s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        # self.s.bind((self.local_ip, self.rcv_port))
        self.s.settimeout(self.timeout)

    def receiver_thread(self):
        global packet_queue, timeout
        while self.running:
            try:
                data, src_addr = self.s.recvfrom(65534)
                print('Received data from: ', src_addr)
                self.add_to_queue(data)
            except socket.timeout:
                timeout = True
                print('Socket Timeout')
            continue
        # s.close()

    def processor_thread(self):
        global packet_queue,timeout
        while self.running and not stop:
            try:
                data = packet_queue.get()
                # print('queue size: ', packet_queue.qsize())
                self.process(data)
            except queue.Empty:
                # print('Queue Empty')
                continue

    def sender_thread(self):
        global timeout, seq, ack, server_online, file_name_got, stop, want_next
        while self.running:
            if not server_online:
                data = b'READY'
            elif not file_name_got:
                data = filename.encode()
            else:
                data = b'OK'

            if timeout or want_next:
                if seq == ack:
                    self.udp_send(data, seq, ack)
                    # print('Send seq: ', seq, 'Send ack: ', ack)
                    timeout = False
                    want_next = False  
            continue
    
    def add_to_queue(self,item):
        global packet_queue
        packet_queue.put(item)

    def udp_send(self, data, seq, ack):  # Method to send UDP packets
        #Generate pseudo header
        src_ip, dest_ip = self.ip2int(self.local_ip), self.ip2int(self.remote_ip)  # Convert the source and destination IP addresses to integers
        src_ip = struct.pack('!4B', *src_ip)  # Pack the source IP into 4 bytes
        dest_ip = struct.pack('!4B', *dest_ip)  # Pack the destination IP into 4 bytes
        zero = 0  # Set the zero field to 0
        protocol = socket.IPPROTO_UDP  # Set the protocol to UDP
        ip_ihl = 5
        ip_ver = 4
        ip_tos = 0
        ip_tot_len = 20  # kernel will fill the correct total length
        ip_id = 54321   #Id of this packet
        ip_frag_off = 0
        ip_ttl = 255
        ip_proto = protocol
        ip_check = 0    # kernel will fill the correct checksum
        ip_ihl_ver = (ip_ver << 4) + ip_ihl
        ip_header = struct.pack('!BBHHHBBH', ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check)+src_ip+dest_ip

        #Check the type of data
        try:
            data = data.encode()  # Try to encode the data
        except AttributeError:
            pass  # If the data is already encoded, pass
        src_port = self.sendfrom_port  # Set the source port
        dest_port = self.todst_port  # Set the destination port
        data_len = len(data) + 8 #  add the length of ack and seq
        udp_length = 8 + data_len  #  add the length of udp header
        checksum = 0  # Initialize the checksum to 0
        pseudo_header = src_ip + dest_ip + struct.pack('!2BH', zero, protocol, udp_length)  # Create the pseudo UDP header
        udp_header = struct.pack('!4H', src_port, dest_port, udp_length, checksum)  #  add the length of udp header
        udp_header = udp_header + struct.pack('!II', seq, ack)  # Add the sequence and acknowledgement numbers to the UDP header
        checksum = self.checksum_func(pseudo_header + udp_header + data)  #  calculate the checksum
        udp_header = struct.pack('!4H', src_port, dest_port, udp_length, checksum)  # Recreate the UDP header with the calculated checksum
        udp_header = udp_header + struct.pack('!II', seq, ack)  # Add the sequence and acknowledgement numbers to the UDP header
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as s_send:  #  create a socket
            s_send.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            s_send.sendto(ip_header + udp_header + data, (self.remote_ip, self.todst_port))  # Send the UDP packet

    def checksum_func(self, data):  # Method to calculate the checksum
        checksum = 0  # Initialize the checksum to 0
        data_len = len(data)  # Get the length of the data
        if (data_len % 2):  # If the length of the data is odd
            data_len += 1  # Increment the length of the data
            data += struct.pack('!B', 0)  # Add a zero byte to the data
        
        for i in range(0, data_len, 2):  # For each pair of bytes in the data
            w = (data[i] << 8) + (data[i + 1])  # Combine the pair of bytes into a word
            checksum += w  # Add the word to the checksum

        checksum = (checksum >> 16) + (checksum & 0xFFFF)  # Fold the checksum
        checksum = ~checksum & 0xFFFF  # Take the one's complement of the checksum
        return checksum  # Return the checksum

    def ip2int(self, ip_addr):  # Method to convert an IP address to an integer
        return [int(x) for x in ip_addr.split('.')]  # Split the IP address at the dots and convert each part to an integer

    def verify_checksum(self, data, checksum):  # Method to verify the checksum
        data_len = len(data)  # Get the length of the data
        if (data_len % 2) == 1:  # If the length of the data is odd
            data_len += 1  # Increment the length of the data
            data += struct.pack('!B', 0)  # Add a zero byte to the data
        
        for i in range(0, data_len, 2):  # For each pair of bytes in the data
            w = (data[i] << 8) + (data[i + 1])  # Combine the pair of bytes into a word
            checksum += w  # Add the word to the checksum
            checksum = (checksum >> 16) + (checksum & 0xFFFF)  # Fold the checksum

        return checksum  # Return the checksum
    
    def start_threads(self):
        # 创建并启动接收线程
        
        self.recv_thread = threading.Thread(target=self.receiver_thread)
        self.recv_thread.daemon = True
        self.recv_thread.start()

        # 创建并启动处理线程
        self.proc_thread = threading.Thread(target=self.processor_thread)
        self.proc_thread.daemon = True
        self.proc_thread.start()

        # 创建并启动发送线程
        self.send_thread = threading.Thread(target=self.sender_thread)
        self.send_thread.daemon = True
        self.send_thread.start()

    def stop_threads(self):
        # 停止线程运行
        self.running = False
        # self.s.close()
        self.recv_thread.join()
        self.proc_thread.join()
        self.send_thread.join()
    
    def process(self,data):  # Method to send and receive data
        global seq  # Use the global sequence number
        global ack  # Use the global acknowledgement number
        global total_file_size  # Use the global total file size
        global server_online
        global file_name_got
        global save_name
        global want_next
        global stop
        global seq_sum
        try:
            packet = PacketParser(data).parse()  # Parse the received data
        except IndexError:
            print('IndexError')
            return
        # if packet['dest_port'] != self.rcv_port:  # If the destination port in the packet is not the receiving port
        #     print("Not the port we want, waiting...")  # Print a message
        #     return
        ip_addr = struct.pack('!8B', *[data[x] for x in range(SRC_IP_OFF, SRC_IP_OFF + 8)])  # Pack the IP address into 8 bytes
        udp_psuedo = struct.pack('!BB5H2I', self.zero, socket.IPPROTO_UDP, packet['udp_length'], packet['src_port'], packet['dest_port'], packet['udp_length'], self.zero, packet['seq_num'], packet['ack_num'])  # Create the pseudo UDP header
        verify = self.verify_checksum(ip_addr + udp_psuedo + packet['data'], packet['UDP_checksum'])  # Verify the checksum
        seq_num = packet['seq_num']  # Get the sequence number from the packet
        ack_num = packet['ack_num']  # Get the acknowledgement number from the packet
        # print('seq_num: ', seq_num, 'ack_num: ', ack_num)
        # seq_sum += seq_num
        # if seq_sum != 0 and (seq_sum == seq_num*2):
        #     # print('Conjestion detected, slowing down')
        #     # wait for a while
        #     sleep(0.01)
        #     seq_sum = 0
        #     # clear the queue
        #     packet_queue.queue.clear()
        # elif seq_sum != 0 and (seq_sum - seq_num)!=seq_num:
        #     seq_sum = seq_num

        if verify == 0xFFFF:  # If the checksum is valid
            # print('local_seq: ', seq, 'local_ack: ', ack)  # Print the local sequence and acknowledgement numbers
            # print('remote_seq: ', seq_num, 'remote_ack: ', ack_num)  # Print the remote sequence and acknowledgement numbers
            if seq_num == seq + 1 and ack_num == ack:  # If the sequence and acknowledgement numbers are as expected
                if seq_num == 1 and ack_num == 0 and not server_online:  # If the sequence and acknowledgement numbers are as expected
                    print('Server is now online. Ready to receive request.')  # Print a message
                    seq  = 1  # Set the sequence number to 1
                    ack  = 1  # Set the acknowledgement number to 1
                    server_online = True
                    want_next = True
                    # print('Want seq: ', seq+1, 'Want ack: ', ack)
                    return  # Return from the method
                elif seq_num == 2 and ack_num == 1 and not file_name_got:  # If the data type is 'FILENAME' and the sequence and acknowledgement numbers are as expected
                    if packet['data'].startswith(b'NF'):
                        print('Requested File not found!')
                        exit()
                    print('Filename got, receiving...')  # Print a message
                    total_file_size = int(packet['data'].decode())  # Get the total file size from the packet
                    print('Total file size: ', total_file_size,'Bytes')  # Print the total file size
                    ack = 2  # Increment the acknowledgement number
                    seq = 2  # Set the sequence number to the sequence number from the packet
                    file_name_got = True
                    want_next = True
                    # print('Want seq: ', seq+1, 'Want ack: ', ack)
                    return  # Return from the method
                elif not stop:  # If the data type is 'OK'
                    if not packet['data'].startswith(b'STOP'):  # If the data does not start with 'STOP'
                        # print('writing...')  # Print a message
                        with open(save_name, "ab") as file:  # Open the file in append binary mode
                            file.write(packet['data'])  # Write the data to the file
                        # show the progress
                        print('Progress: ', os.path.getsize(save_name), '/', total_file_size, 'Bytes', '(', os.path.getsize(save_name) / total_file_size * 100, '%)')
                        ack += 1  # Increment the acknowledgement number
                        seq = seq_num  # Set the sequence number to the sequence number from the packet
                        assert ack == seq  # Assert that the acknowledgement number is equal to the sequence number
                        want_next = True
                        # print('Want seq: ', seq+1, 'Want ack: ', ack)
                        return
                    else:  # If the data starts with 'STOP'
                        print("Finish Transmission.")  # Print a message
                        ack = 0  # Reset the acknowledgement number
                        seq = 0  # Reset the sequence number
                        stop = True
                        want_next = False
                        return  # Return from the method
            else:  # If the sequence and acknowledgement numbers are not as expected
                print('Sequence or Acknowledgement Error! Packet is discarded')  # Print a message
                return
        else:  # If the checksum is not valid
            print('Checksum Error! Packet is discarded')  # Print a message
            return
  

if __name__ == '__main__':
    # Initialize sequence and acknowledgement numbers
    local_ip = '10.0.0.2'  # Set the local IP
    remote_ip = '10.0.0.1'  # Set the remote IP
    # local_ip = '192.168.8.19'  # Set the local IP
    # remote_ip = '192.168.8.2'  # Set the remote IP
    sendfrom_port = 35001  # Set the sending port
    rcv_port = 35002  # Set the receiving port
    todst_port = 45001  # Set the destination port
    seq = 0
    ack = 0
    total_file_size = 0
    packet_queue = queue.LifoQueue()
    timeout = False
    server_online = False
    file_name_got = False
    stop = False
    want_next = True
    seq_sum = 0
    
    filename = 'sent/' + 'google.png'
    filename = 'FILENAME:' + filename  # Add 'FILENAME:' to the filename
    save_name = 'received/' + 'google.png'
    if os.path.exists(save_name):
        os.remove(save_name)
    # check save_name directory
    if not os.path.exists('received'):
        os.makedirs('received')

    udp_sender = UDPSender(local_ip, remote_ip, sendfrom_port, rcv_port, todst_port)  # Create a UDPSender object
    udp_sender.start_threads()

    while True:
        try:
            if stop:
                udp_sender.stop_threads()
                break
            continue
        except KeyboardInterrupt:
            udp_sender.stop_threads()
            break

