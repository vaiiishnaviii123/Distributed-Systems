# Created by Vaishnavi Kulkarni during university course - Dustributed systems.
import pickle
import socket
import time
import random
import hashlib
import struct
from time import gmtime, strftime

HDR_SZ = 24  # Header Size
P2P_HOST = '5.45.73.13'  # peer host
P2P_PORT = 8333  # peer Port
TARGET_BLOCK = 4177662 % 10000  # Block number to find SU_ID % 10000
BUF_SZ = 2024  # buffer size to receive data
WRONG = 'WRONG'
IP = '127.0.0.1'  # localhost
BACKLOG = 100  # socket listen arge
MAX_NUM_CONNECTIONS = 100



def compactsize_t(n):
    if n < 252:
        return uint8_t(n)
    if n < 0xffff:
        return uint8_t(0xfd) + uint16_t(n)
    if n < 0xffffffff:
        return uint8_t(0xfe) + uint32_t(n)
    return uint8_t(0xff) + uint64_t(n)


def unmarshal_compactsize(b):
    key = b[0]
    if key == 0xff:
        return b[0:9], unmarshal_uint(b[1:9])
    if key == 0xfe:
        return b[0:5], unmarshal_uint(b[1:5])
    if key == 0xfd:
        return b[0:3], unmarshal_uint(b[1:3])
    return b[0:1], unmarshal_uint(b[0:1])


def bool_t(flag):
    return uint8_t(1 if flag else 0)


def ipv6_from_ipv4(ipv4_str):
    pchIPv4 = bytearray([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff])
    return pchIPv4 + bytearray((int(x) for x in ipv4_str.split('.')))


def ipv6_to_ipv4(ipv6):
    return '.'.join([str(b) for b in ipv6[12:]])


def uint8_t(n):
    return int(n).to_bytes(1, byteorder='little', signed=False)


def uint16_t(n):
    return int(n).to_bytes(2, byteorder='little', signed=False)


def int32_t(n):
    return int(n).to_bytes(4, byteorder='little', signed=True)


def uint32_t(n):
    return int(n).to_bytes(4, byteorder='little', signed=False)


def int64_t(n):
    return int(n).to_bytes(8, byteorder='little', signed=True)


def uint64_t(n):
    return int(n).to_bytes(8, byteorder='little', signed=False)


def unmarshal_int(b):
    return int.from_bytes(b, byteorder='little', signed=True)


def unmarshal_uint(b):
    return int.from_bytes(b, byteorder='little', signed=False)


def print_message(msg, text=None, blockCount=0):
    """
    Report the contents of the given bitcoin message
    :param headerNumber:
    :param text: Check for sending/receiving messages
    :param msg: bitcoin message including header
    :return: message type
    """
    msgInfo = '\n{}MESSAGE\n'.format('' if text is None else (text + ' '))
    msgInfo += '({}) {}\n'.format(len(msg), msg[:60].hex() + ('' if len(msg) < 60 else '...'))
    payload = msg[HDR_SZ:]

    # Process header
    command = print_header(msg[:HDR_SZ], msgInfo, checksum(payload))
    if command == 'version':
        print_version_msg(payload)
    elif command == 'inv' and text == 'Receiving':
        return command, processInvMessage(payload, blockCount)
    elif command == 'block':
        printBlockMessage(payload)
    elif command == 'WRONG':
        return 'WRONG', []
    return command, []


def checksum(payload):
    return hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]


def print_version_msg(b):
    """
    Report the contents of the given bitcoin version message (sans the header)
    :param payload: version message contents
    """
    # pull out fields
    version, my_services, epoch_time, your_services = b[:4], b[4:12], b[12:20], b[20:28]
    rec_host, rec_port, my_services2, my_host, my_port = b[28:44], b[44:46], b[46:54], b[54:70], b[70:72]
    nonce = b[72:80]
    user_agent_size, uasz = unmarshal_compactsize(b[80:])
    i = 80 + len(user_agent_size)
    user_agent = b[i:i + uasz]
    i += uasz
    start_height, relay = b[i:i + 4], b[i + 4:i + 5]
    extra = b[i + 5:]

    # print report
    prefix = '  '
    print(prefix + 'VERSION')
    print(prefix + '-' * 56)
    prefix *= 2
    print('{}{:32} version {}'.format(prefix, version.hex(), unmarshal_int(version)))
    print('{}{:32} my services'.format(prefix, my_services.hex()))
    time_str = strftime("%a, %d %b %Y %H:%M:%S GMT", gmtime(unmarshal_int(epoch_time)))
    print('{}{:32} epoch time {}'.format(prefix, epoch_time.hex(), time_str))
    print('{}{:32} your services'.format(prefix, your_services.hex()))
    print('{}{:32} your host {}'.format(prefix, rec_host.hex(), ipv6_to_ipv4(rec_host)))
    print('{}{:32} your port {}'.format(prefix, rec_port.hex(), unmarshal_uint(rec_port)))
    print('{}{:32} my services (again)'.format(prefix, my_services2.hex()))
    print('{}{:32} my host {}'.format(prefix, my_host.hex(), ipv6_to_ipv4(my_host)))
    print('{}{:32} my port {}'.format(prefix, my_port.hex(), unmarshal_uint(my_port)))
    print('{}{:32} nonce'.format(prefix, nonce.hex()))
    print('{}{:32} user agent size {}'.format(prefix, user_agent_size.hex(), uasz))
    print('{}{:32} user agent \'{}\''.format(prefix, user_agent.hex(), str(user_agent, encoding='utf-8')))
    print('{}{:32} start height {}'.format(prefix, start_height.hex(), unmarshal_uint(start_height)))
    print('{}{:32} relay {}'.format(prefix, relay.hex(), bytes(relay) != b'\0'))
    if len(extra) > 0:
        print('{}{:32} EXTRA!!'.format(prefix, extra.hex()))


def print_header(header, msgInfo, expected_cksum=None):
    """
    Report the contents of the given bitcoin message header
    :param msgInfo:
    :param header: bitcoin message header (bytes or bytearray)
    :param expected_cksum: the expected checksum for this version message, if known
    :return: message type
    """
    magic, command_hex, payload_size, cksum = header[:4], header[4:16], header[16:20], header[20:]
    command = str(bytearray([b for b in command_hex if b != 0]), encoding='utf-8')
    psz = unmarshal_uint(payload_size)
    if expected_cksum is None:
        verified = ''
    elif expected_cksum == cksum:
        verified = '(verified)'
    else:
        verified = '(WRONG!! ' + expected_cksum.hex() + ')'

    if verified[1:6] != 'WRONG':
        print(msgInfo)
        prefix = '  '
        print(prefix + 'HEADER')
        print(prefix + '-' * 56)
        prefix *= 2
        print('{}{:32} magic'.format(prefix, magic.hex()))
        print('{}{:32} command: {}'.format(prefix, command_hex.hex(), command))
        print('{}{:32} payload size: {}'.format(prefix, payload_size.hex(), psz))
        print('{}{:32} checksum {}'.format(prefix, cksum.hex(), verified))
    else:
        return 'WRONG'
    return command

def convertLittleBig(string):
    """
    CHANGE THIS

    Helper function to convert from little endian to big endian.
    It can also convert in an inverse way (from big endian to little endian).
    :param string: String of bytes to convert
    :return: Return the converted string of bytes
    """
    t = bytearray.fromhex(string)
    t.reverse()
    return ''.join(format(x, '02x') for x in t)


def processInvMessage(payload, blockCount=0):

    count = 1
    targetBlock = ["", -1]
    blockHeaderHash = ''
    n = 36  # total bytes of 1 inv

    for i in range(3, len(payload), n):
        try:
            block = payload[i:i + n].hex()
            blockHash = convertLittleBig(block[8:])  # Hash of the object

            if blockCount == TARGET_BLOCK:
                targetBlock = [blockHash, blockCount]
            blockCount += 1
            blockHeaderHash = blockHash
        except Exception:
            continue
    if targetBlock[1] == TARGET_BLOCK:
        return targetBlock
    return [blockHeaderHash, blockCount]


def printBlockMessage(payload):
    # print("I am in print block message", payload)
    version, prev_header, merkle_root = payload[:4], payload[4:36], payload[36:68]
    timestamp, bits, nonce = payload[68:72], payload[72:76], payload[76:80]
    txn_count = payload[80:90].split(bytes.fromhex('01000000'))[0]
    txn_count = unmarshal_compactsize(txn_count)

    # Print report
    prefix = '  '
    print(prefix + 'BLOCK TRANSACTION')
    print(prefix + '-' * 56)
    prefix *= 2
    print('{}{:67} Version {}'.format(prefix, version.hex(), unmarshal_int(version)))
    print('{}{:67} Previous Block'.format(prefix, convertLittleBig(prev_header.hex())))
    print('{}{:67} Merkle Root'.format(prefix, convertLittleBig(merkle_root.hex())))
    time_str = strftime("%a, %d %b %Y %H:%M:%S GMT", gmtime(unmarshal_int(timestamp)))
    print('{}{:67} Epoch time {}'.format(prefix, timestamp.hex(), time_str))
    print('{}{:67} Bits'.format(prefix, convertLittleBig(bits.hex())))
    print('{}{:67} Nonce'.format(prefix, convertLittleBig(nonce.hex())))
    print('{}{:67} Number of transactions: {}'.format(prefix, txn_count[0].hex(), txn_count[1]))


class Lab5(object):

    def __init__(self):
        """
        Constructor to instantiate object
        """
        # self.b2bPeer = (P2P_HOST, P2P_PORT)
        self.listener, self.listener_address = self.start_a_server()
        self.version = 70015
        self.magic = "f9beb4d9"

    @staticmethod
    def start_a_server():
        """
         Start a server at given port and ip
        :param ip: ip address to start a server on
        :param port: port number to start a server on
        :return: listening socket and its address (P2P_HOST, P2P_PORT)
        """
        address = ('', 0)
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(address)
        # print("listening on address", listener.getsockname()[0], listener.getsockname()[1])
        return listener, listener.getsockname()

    def startCommunicationWithPeer(self):
        try:
            addr = (P2P_HOST, P2P_PORT)
            self.listener.connect(addr)

            print("<------ Version Message ------->")
            versionMessage = self.addHeader('version')
            self.sendMessageToPeer(versionMessage)

            print("\n<------ Verack Message ------->")
            verackMessage = self.createVerackMessage('verack')
            self.sendMessageToPeer(verackMessage)

            print("\n<------ GetBlocks Message ------->")
            block = 0
            initialBlock = block.to_bytes(1, 'big')
            getBlocksMessage = self.addHeader('getblocks', initialBlock)
            blockHeaderHash = self.sendMessageToPeer(getBlocksMessage, 'inv', 0, True)

            while blockHeaderHash[1] < TARGET_BLOCK:
                getBlocksMessage = self.addHeader('getblocks', bytearray.fromhex(convertLittleBig(blockHeaderHash[0])))
                blockHeaderHash = self.sendMessageToPeer(getBlocksMessage, 'inv', blockHeaderHash[1], True)

            print('\nSuccessfully found the Block #{}: {}'.format(TARGET_BLOCK, blockHeaderHash[0]))
            target = blockHeaderHash[0]

            print("\n<------ GetData Message ------->")
            blockDataMessage = self.addHeader('getdata', target)
            self.sendMessageToPeer(blockDataMessage, 'block', 0, True)
        except Exception as e:
            print(e)

    def addHeader(self, command, data=None):

        payload = None

        if command == 'version':
            payload = self.createVersionMessage()
        if command == 'getblocks':
            print("createGetBlocksMessage:: data", data)
            payload = self.createGetBlocksMessage(data)
        if command == 'getdata':
            payload = self.createBlockDataMessage(data)

        start_string = bytes.fromhex(self.magic)
        command = struct.pack("12s", command.encode())
        size = uint32_t(len(payload))
        checkSum = checksum(payload)
        message = start_string + command + size + checkSum + payload
        # print('Sending message ', command, ": ", message)
        return message

    def createVersionMessage(self):
        """
        Here transmission node is me and recv node is peer node.
        :return: version message
        """
        version = int32_t(self.version)
        services = uint64_t(0)
        timestamp = int64_t(time.time())
        addr_recv_services = uint64_t(0)  # peer services
        addr_recv_ip_address = ipv6_from_ipv4(P2P_HOST)  # peer ip address
        addr_recv_port = uint16_t(P2P_PORT)  # peer port number
        addr_trans_services = uint64_t(0)
        addr_trans_ip = ipv6_from_ipv4(self.listener_address[0])
        addr_trans_port = uint16_t(self.listener_address[1])
        nonce = uint64_t(random.getrandbits(64))
        user_agent_bytes = compactsize_t(0)
        start_height = int32_t(0)
        relay = bool_t(False)

        payload = version + services + timestamp + addr_recv_services + \
                  addr_recv_ip_address + addr_recv_port + addr_trans_services + \
                  addr_trans_ip + addr_trans_port + nonce + user_agent_bytes + \
                  start_height + relay

        return payload

    def createVerackMessage(self, command):

        start_string = bytes.fromhex(self.magic)
        command = struct.pack("12s", command.encode())
        size = uint32_t(0)
        checkSum = bytes.fromhex('5df6e0e2')
        message = start_string + command + size + checkSum
        # print('Sending Verack message ', command, ": ", message)
        return message

    def createGetBlocksMessage(self, latestHeader):

        version = int32_t(self.version)
        hash_count = compactsize_t(1)
        block_header_hashes = struct.pack('32s', latestHeader)
        stop_hash = struct.pack('32s', int(0).to_bytes(1, 'big'))
        # stop_hash = struct.pack('32s', b'\x00')
        payload = version + hash_count + block_header_hashes + stop_hash
        return payload


    def createBlockDataMessage(self, targetBlock):
        blocks_count = compactsize_t(1)
        block_type = uint32_t(2)
        block = bytes.fromhex(convertLittleBig(targetBlock))
        payload = blocks_count + block_type + block
        return payload

    def sendMessageToPeer(self, message, action='', lastHeaderNumber=0, isBlock=False):
        try:
            print_message(message, 'Sending')
            # addr = (P2P_HOST, P2P_PORT)
            # self.listener.connect(addr)
            self.listener.send(message)
            if not isBlock:
                response = self.listener.recv(BUF_SZ)
                # print("received:", response)

                array = self.getMessageArray(response)
                # print('parsedMessage', len(parsedMessage))
                for msg in array:
                    checkSum, lastHeader = print_message(msg, 'Receiving')
                    while checkSum == WRONG:
                        if checkSum != WRONG:
                            break
                        else:
                            next_messages = self.listener.recv(BUF_SZ)
                            msg = msg + next_messages
                        array = self.getMessageArray(msg)
                        for y in array:
                            checkSum, lastHeader = print_message(y, 'Receiving')
            elif isBlock:
                checkSum, lastHeader = "", []
                while True:
                    response = self.listener.recv(BUF_SZ)
                    # print("received:", response)

                    parsedMessage = self.getMessageArray(response)
                    # print('parsedMessage', len(parsedMessage))
                    for msg in parsedMessage:
                        checkSum, lastHeader = print_message(msg, 'Receiving')
                        while checkSum == 'WRONG':
                            if checkSum != 'WRONG':
                                break
                            else:
                                next_messages = self.listener.recv(BUF_SZ)
                                msg = msg + next_messages
                            parsedMessage = self.getMessageArray(msg)
                            # print('parsedMessage', len(parsedMessage))
                            for y in parsedMessage:
                                checkSum, lastHeader = print_message(y, 'Receiving', lastHeaderNumber)
                                if action == checkSum:
                                    break
                    if action == checkSum:
                        break
                return lastHeader
        except Exception as e:
            print('failed to connect to node: {}', e)

    def getMessageArray(self, message):
        """
        Creating array of messages
        :param message: message received from peer that needs to be converted to array/list
        :return: message list
        """
        array = message.split(bytearray.fromhex(self.magic))
        messages = []
        for i in range(1, len(array)):
            messages.append(bytes.fromhex(self.magic) + array[i])
        return messages


if __name__ == '__main__':
    lab5 = Lab5()
    lab5.startCommunicationWithPeer()
