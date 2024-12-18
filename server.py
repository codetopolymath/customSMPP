import logging
import sys
import socket
import struct
import threading
from datetime import datetime
import requests
import uuid
import binascii

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s %(levelname)-8s %(module)s:%(lineno)d - %(message)s',
    handlers=[
        logging.FileHandler('smpp_server.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

# SMPP Constants
SMPP_HEADER_LENGTH = 16
BIND_TRANSCEIVER = 0x00000009
BIND_TRANSCEIVER_RESP = 0x80000009
SUBMIT_SM = 0x00000004
SUBMIT_SM_RESP = 0x80000004
DELIVER_SM = 0x00000005
DELIVER_SM_RESP = 0x80000005
ENQUIRE_LINK = 0x00000015
ENQUIRE_LINK_RESP = 0x80000015
UNBIND = 0x00000006
UNBIND_RESP = 0x80000006
GENERIC_NACK = 0x80000000
ESME_ROK = 0x00000000

def hex_dump(data, prefix=''):
    """Helper function to create readable hex dumps of binary data"""
    hex_data = binascii.hexlify(data).decode()
    chunks = [hex_data[i:i+2] for i in range(0, len(hex_data), 2)]
    lines = [chunks[i:i+16] for i in range(0, len(chunks), 16)]
    result = []
    for line in lines:
        hex_part = ' '.join(line)
        ascii_part = ''.join(chr(int(c, 16)) if 32 <= int(c, 16) <= 126 else '.' for c in line)
        result.append(f"{prefix}{hex_part:<48} | {ascii_part}")
    return '\n'.join(result)

class SMPPServer:
    def __init__(self, host, port, system_id, password, api_url):
        self.host = host
        self.port = port
        self.system_id = system_id
        self.password = password
        self.api_url = api_url
        self.server_socket = None
        self.clients = {}
        self.running = False

    def start(self):
        """Start the SMPP server with enhanced logging"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True
            
            logging.info(f"SMPP Server started on {self.host}:{self.port}")
            
            while self.running:
                client_socket, address = self.server_socket.accept()
                logging.info(f"New connection from {address}")
                client_handler = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, address)
                )
                client_handler.start()
                
        except Exception as e:
            logging.error(f"Server error: {str(e)}", exc_info=True)
            self.stop()

    def stop(self):
        """Stop the SMPP server"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        for client in self.clients.values():
            client.close()
        logging.info("Server stopped")

    def read_pdu(self, client_socket):
        """Read a complete PDU with enhanced logging"""
        try:
            # Read initial chunk to get header
            header_data = client_socket.recv(SMPP_HEADER_LENGTH)
            if not header_data or len(header_data) < SMPP_HEADER_LENGTH:
                logging.warning("Incomplete or empty header received")
                return None, None, None, None, None

            logging.debug(f"PDU Header received:\n{hex_dump(header_data, '    ')}")
            command_length, command_id, command_status, sequence_number = struct.unpack('!IIII', header_data)
            
            logging.debug(f"PDU Header decoded - Length: {command_length}, Command: 0x{command_id:08X}, " 
                         f"Status: 0x{command_status:08X}, Sequence: {sequence_number}")

            # Read body if present
            body = b''
            body_length = command_length - SMPP_HEADER_LENGTH
            if body_length > 0:
                while len(body) < body_length:
                    remaining = body_length - len(body)
                    chunk = client_socket.recv(min(remaining, 8192))
                    if not chunk:
                        logging.error(f"Connection closed while reading PDU body. "
                                    f"Expected {body_length} bytes, got {len(body)}")
                        return None, None, None, None, None
                    body += chunk

                logging.debug(f"PDU Body received ({len(body)} bytes):\n{hex_dump(body, '    ')}")

            return command_length, command_id, command_status, sequence_number, body
        except Exception as e:
            logging.error(f"Error reading PDU: {str(e)}", exc_info=True)
            return None, None, None, None, None

    def handle_client(self, client_socket, address):
        """Handle individual client connections"""
        try:
            while self.running:
                pdu_data = self.read_pdu(client_socket)
                if not pdu_data[0]:  # If read_pdu returns None values
                    break

                command_length, command_id, command_status, sequence_number, body = pdu_data

                # Handle different PDU types
                if command_id == BIND_TRANSCEIVER:
                    self.handle_bind_transceiver(client_socket, body, sequence_number)
                elif command_id == SUBMIT_SM:
                    self.handle_submit_sm(client_socket, body, sequence_number)
                elif command_id == ENQUIRE_LINK:
                    self.handle_enquire_link(client_socket, sequence_number)
                elif command_id == UNBIND:
                    self.handle_unbind(client_socket, sequence_number)
                    break
                else:
                    logging.warning(f"Unhandled command ID: 0x{command_id:08X}")
                    self.send_generic_nack(client_socket, sequence_number)

        except Exception as e:
            logging.error(f"Error handling client {address}: {str(e)}", exc_info=True)
        finally:
            client_socket.close()
            if address in self.clients:
                del self.clients[address]
            logging.info(f"Client {address} disconnected")

    def handle_bind_transceiver(self, client_socket, body, sequence_number):
        """Handle bind transceiver request"""
        try:
            # Parse bind parameters
            system_id_length = body.find(b'\x00')
            received_system_id = body[:system_id_length].decode()
            
            password_start = system_id_length + 1
            password_length = body[password_start:].find(b'\x00')
            received_password = body[password_start:password_start + password_length].decode()

            logging.debug(f"Bind attempt - System ID: {received_system_id}, Password length: {len(received_password)}")

            # Authenticate
            if received_system_id == self.system_id and received_password == self.password:
                response = struct.pack(
                    '!IIII', 
                    SMPP_HEADER_LENGTH + len(self.system_id) + 1, 
                    BIND_TRANSCEIVER_RESP,
                    ESME_ROK,
                    sequence_number
                ) + self.system_id.encode() + b'\x00'
                
                client_socket.send(response)
                self.clients[client_socket.getpeername()] = client_socket
                logging.info(f"Client {client_socket.getpeername()} successfully bound as transceiver")
            else:
                response = struct.pack(
                    '!IIII',
                    SMPP_HEADER_LENGTH,
                    BIND_TRANSCEIVER_RESP,
                    0x0000000E,  # Invalid password
                    sequence_number
                )
                client_socket.send(response)
                logging.warning(f"Authentication failed for {client_socket.getpeername()}")

        except Exception as e:
            logging.error(f"Error in bind_transceiver: {str(e)}", exc_info=True)
            self.send_generic_nack(client_socket, sequence_number)

    def parse_tlv_parameters(self, body, offset, body_length):
        """Parse TLV parameters with detailed logging"""
        tlv_params = {}
        original_offset = offset
        
        try:
            logging.debug(f"Raw TLV data: {body[offset:].hex()}")
            while offset < body_length:
                remaining = body_length - offset
                if remaining < 4:
                    logging.debug(f"TLV Parsing: Insufficient data for TLV header at offset {offset}. "
                                f"Remaining bytes: {remaining}")
                    break
                    
                tag = struct.unpack('!H', body[offset:offset + 2])[0]
                length = struct.unpack('!H', body[offset + 2:offset + 4])[0]
                
                logging.debug(f"TLV Found - Tag: 0x{tag:04X}, Length: {length}, "
                            f"Offset: {offset}, Remaining: {remaining}")
                
                if offset + 4 + length > body_length:
                    logging.warning(f"TLV value exceeds PDU bounds - Tag: 0x{tag:04X}, "
                                  f"Length: {length}, Remaining: {remaining}")
                    break
                    
                value = body[offset + 4:offset + 4 + length]
                offset += 4 + length
                
                logging.debug(f"TLV Value:\n{hex_dump(value, '    ')}")
                
                try:
                    decoded_value = value.decode().rstrip('\x00')
                    logging.debug(f"Decoded TLV value: {decoded_value}")
                except UnicodeDecodeError:
                    logging.debug(f"Binary TLV value: {value.hex()}")
                
                tlv_params[tag] = value
                
            logging.debug(f"TLV Parsing Summary - Start: {original_offset}, End: {offset}, "
                         f"Parameters Found: {len(tlv_params)}")
            
            return tlv_params
            
        except Exception as e:
            logging.error(f"Error parsing TLV parameters: {str(e)}", exc_info=True)
            return {}

    def handle_submit_sm(self, client_socket, body, sequence_number):
        """Handle submit_sm request with enhanced TLV support and logging"""
        try:
            logging.debug(f"Processing submit_sm PDU:\n{hex_dump(body, '    ')}")
            
            # Parse mandatory parameters first
            offset = 0
            
            # Skip service_type
            offset += body[:offset + 256].find(b'\x00') + 1
            logging.debug(f"After service_type offset: {offset}")
            
            # Source address parameters
            source_addr_ton = body[offset]
            offset += 1
            source_addr_npi = body[offset]
            offset += 1
            
            # Get source_addr
            source_addr_length = body[offset:].find(b'\x00')
            source_addr = body[offset:offset + source_addr_length].decode()
            offset += source_addr_length + 1
            
            # Destination address parameters
            dest_addr_ton = body[offset]
            offset += 1
            dest_addr_npi = body[offset]
            offset += 1
            
            # Get destination_addr
            dest_addr_length = body[offset:].find(b'\x00')
            destination_addr = body[offset:offset + dest_addr_length].decode()
            offset += dest_addr_length + 1
            
            # Skip other mandatory fields
            offset += 3  # esm_class, protocol_id, priority_flag
            offset += body[offset:].find(b'\x00') + 1  # schedule_delivery_time
            offset += body[offset:].find(b'\x00') + 1  # validity_period
            offset += 3  # registered_delivery, replace_if_present_flag, data_coding
            offset += 1  # sm_default_msg_id
            
            # Get message length and content
            sm_length = body[offset]
            offset += 1
            short_message = body[offset:offset + sm_length].decode()
            offset += sm_length

            logging.debug(f"Parsed Mandatory Parameters:")
            logging.debug(f"Source: {source_addr} (TON: {source_addr_ton}, NPI: {source_addr_npi})")
            logging.debug(f"Destination: {destination_addr} (TON: {dest_addr_ton}, NPI: {dest_addr_npi})")
            logging.debug(f"Message: {short_message}")
            logging.debug(f"Current offset: {offset}, Total PDU length: {len(body)}")

            # Parse TLV parameters
            tlv_params = {}
            if offset < len(body):
                logging.debug(f"Starting TLV parsing at offset {offset}")
                tlv_params = self.parse_tlv_parameters(body, offset, len(body))
                logging.debug(f"Found TLV parameters: {tlv_params}")

            # Prepare message data for API
            message_data = {
                'authcode': tlv_params.get(0x1405, b'').decode().rstrip('\x00') if 0x1405 in tlv_params else None,
                'sequence_number': sequence_number,
                'source_addr': source_addr,
                'destination_addr': destination_addr,
                'short_message': short_message,
                'timestamp': datetime.now().isoformat(),
                'source_addr_ton': source_addr_ton,
                'source_addr_npi': source_addr_npi,
                'dest_addr_ton': dest_addr_ton,
                'dest_addr_npi': dest_addr_npi,
                'template_id': tlv_params.get(0x1400, b'').decode().rstrip('\x00') if 0x1400 in tlv_params else None,
                'pe_id': tlv_params.get(0x1401, b'').decode().rstrip('\x00') if 0x1401 in tlv_params else None
            }

            # Send to API
            self.send_to_api(message_data)

            # Send submit_sm_resp
            response = struct.pack(
                '!IIII',
                SMPP_HEADER_LENGTH + 1,
                SUBMIT_SM_RESP,
                ESME_ROK,
                sequence_number
            ) + b'\x00'  # message_id
            
            client_socket.send(response)
            logging.info(f"Processed submit_sm from {client_socket.getpeername()}")

        except Exception as e:
            logging.error(f"Error in submit_sm: {str(e)}", exc_info=True)
            self.send_generic_nack(client_socket, sequence_number)

    def handle_enquire_link(self, client_socket, sequence_number):
            """Handle enquire_link request"""
            response = struct.pack(
                '!IIII',
                SMPP_HEADER_LENGTH,
                ENQUIRE_LINK_RESP,
                ESME_ROK,
                sequence_number
            )
            client_socket.send(response)
            logging.debug(f"Responded to enquire_link from {client_socket.getpeername()}")

    def handle_unbind(self, client_socket, sequence_number):
        """Handle unbind request"""
        response = struct.pack(
            '!IIII',
            SMPP_HEADER_LENGTH,
            UNBIND_RESP,
            ESME_ROK,
            sequence_number
        )
        client_socket.send(response)
        logging.info(f"Client {client_socket.getpeername()} unbound")

    def send_generic_nack(self, client_socket, sequence_number, error_code=0x00000003):
        """Send generic_nack PDU"""
        response = struct.pack(
            '!IIII',
            SMPP_HEADER_LENGTH,
            GENERIC_NACK,
            error_code,
            sequence_number
        )
        client_socket.send(response)
        logging.debug(f"Sent generic_nack with error code 0x{error_code:08X}")

    def send_to_api(self, message_data):
        """Send message data to API endpoint"""
        try:
            logging.info(f"Sending message to API: {message_data}")
            base_url = self.api_url

            authcode = message_data.get('authcode') or str(uuid.uuid4())
            pe_id = message_data.get("pe_id") or "1501664220000010227"
            senderid = message_data.get("source_addr") or "SANJUP"
            content_id = message_data.get("content_id") or "1507167577648640421"

            number = message_data["destination_addr"]
            message = message_data["short_message"]

            params = {
                'authcode': authcode,
                'content_id': content_id,
                'message': message,
                'number': number,
                'pe_id': pe_id,
                'senderid': senderid
            }

            logging.debug(f"API Request Parameters: {params}")
            # printing complete url for debugging [before sending request]
            logging.debug(f"API Request URL: {base_url}")

            response = requests.get(base_url, params=params)
            
            logging.debug(f"API Response Status Code: {response.status_code}")
            logging.debug(f"API Response Content: {response.text}")
            
            try:
                response_json = response.json()
                if response_json.get('status') == 'true' and response_json.get("dlr_code") in ["200", "201"]:
                    logging.info(f"API call successful for message: {message_data['sequence_number']}")
                else:
                    logging.error(f"API call failed for message: {message_data['sequence_number']} with response: {response_json}")
            except ValueError as e:
                logging.error(f"Failed to parse API response as JSON: {str(e)}")
                logging.error(f"Raw response: {response.text}")
                
        except requests.exceptions.RequestException as e:
            logging.error(f"API call failed: {str(e)}", exc_info=True)
        except Exception as e:
            logging.error(f"Unexpected error in send_to_api: {str(e)}", exc_info=True)


def main():
    # Configuration
    CONFIG = {
        'host': '0.0.0.0',
        'port': 2775,
        'system_id': 'rohitghawale',
        'password': 'rohit',
        'api_url': 'https://smartping-backend.goflipo.com/api/main/verify-scrubbing-logs/'
    }
    
    logging.info("Starting SMPP Server with configuration:")
    for key, value in CONFIG.items():
        if key != 'password':
            logging.info(f"  {key}: {value}")
    
    server = SMPPServer(**CONFIG)
    try:
        server.start()
    except KeyboardInterrupt:
        logging.info("Shutting down server...")
        server.stop()
    except Exception as e:
        logging.error(f"Server error: {str(e)}", exc_info=True)

if __name__ == "__main__":
    main()