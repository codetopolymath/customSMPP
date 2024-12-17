import logging
import sys
import smpplib.gsm
import smpplib.client
import smpplib.consts
import time
import uuid
import struct
import binascii

# Configure logging with more detailed format
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s %(levelname)-8s %(name)s:%(lineno)d %(message)s',
    handlers=[
        logging.FileHandler('smpp_client.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

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

class SMPPClient:
    def __init__(self, host, port, system_id, password):
        self.host = host
        self.port = port
        self.system_id = system_id
        self.password = password
        self.client = None
        self.connected = False
        
        # Define TLV tag constants
        self.TLV_TEMPLATE_ID = 0x1400  # 5120 in decimal
        self.TLV_PE_ID = 0x1401       # 5121 in decimal
        self.TLV_AUTH_CODE = 0x1405   # Auth code tag

    def connect(self):
        """Establish connection with SMPP server"""
        try:
            # Create client instance with extended timeout
            self.client = smpplib.client.Client(self.host, self.port, timeout=30, allow_unknown_opt_params=True)
            
            # Set interface version
            self.client.interface_version = smpplib.consts.SMPP_VERSION_34
            
            logging.info(f"Connecting to {self.host}:{self.port}")
            self.client.connect()


            
            # Debug logging
            logging.debug(f"System ID: {self.system_id}")
            logging.debug(f"Password length: {len(self.password)}")
            
            # Bind as transceiver with additional parameters
            self.client.bind_transceiver(
                system_id=self.system_id,
                password=self.password,
                interface_version=smpplib.consts.SMPP_VERSION_34,
                addr_ton=smpplib.consts.SMPP_TON_INTL,
                addr_npi=smpplib.consts.SMPP_NPI_ISDN,
                address_range=None
            )
            
            self.connected = True
            logging.info("Successfully bound as transceiver")
            return True
            
        except Exception as e:
            logging.error(f"Connection failed: {str(e)}", exc_info=True)
            self.disconnect()
            return False

    def send_message(self, source_addr, destination_addr, message, template_id=None, pe_id=None, auth_code=None):
        """Send message with optional TLV parameters"""
        if not self.connected:
            logging.error("Not connected to SMPP server")
            return False

        try:
            # Encode message
            parts, encoding_flag, msg_type_flag = smpplib.gsm.make_parts(message)
            
            logging.info(f"Sending message: {message}")
            logging.debug(f"Source: {source_addr}")
            logging.debug(f"Destination: {destination_addr}")
            
            # Prepare optional parameters dictionary
            optional_params = {}
            
            # Add Template ID if provided
            if template_id is not None:
                # Convert to string and encode as bytes
                template_id_str = str(template_id)
                optional_params[self.TLV_TEMPLATE_ID] = template_id_str.encode()
                logging.debug(f"Added Template ID TLV: {template_id}")
            
            # Add PE ID if provided
            if pe_id is not None:
                # Convert to string and encode as bytes
                pe_id_str = str(pe_id)
                optional_params[self.TLV_PE_ID] = pe_id_str.encode()
                logging.debug(f"Added PE ID TLV: {pe_id}")
            
            # Add Auth Code if provided
            if auth_code is not None:
                # For auth code, add a null terminator to the string
                optional_params[self.TLV_AUTH_CODE] = auth_code.encode() + b'\0'
                logging.debug(f"Added Auth Code TLV: {auth_code}")
            
            logging.debug(f"Optional parameters before sending: {optional_params}")
            
            # Send message with optional parameters

            logging.debug(f"hex dump before sending PDU:\n{hex_dump(message.encode())}")
            response = self.client.send_message(
                source_addr=source_addr,
                destination_addr=destination_addr,
                short_message=message.encode(),
                data_coding=encoding_flag,
                esm_class=msg_type_flag,
                registered_delivery=True,
                source_addr_ton=smpplib.consts.SMPP_TON_INTL,
                source_addr_npi=smpplib.consts.SMPP_NPI_ISDN,
                dest_addr_ton=smpplib.consts.SMPP_TON_INTL,
                dest_addr_npi=smpplib.consts.SMPP_NPI_ISDN,
                optional_parameters=optional_params
            )
            logging.debug(f"Hex dump of sent PDU:\n{hex_dump(response)}")
            
            return True
            
        except Exception as e:
            logging.error(f"Failed to send message: {str(e)}", exc_info=True)
            return False

    def disconnect(self):
        """Disconnect from SMPP server"""
        try:
            if self.client:
                if self.connected:
                    try:
                        self.client.unbind()
                        logging.info("Unbound from server")
                    except Exception as e:
                        logging.error(f"Error unbinding: {str(e)}")
                self.client.disconnect()
                self.connected = False
                logging.info("Disconnected from SMPP server")
        except Exception as e:
            logging.error(f"Error disconnecting: {str(e)}")

def main():
    # Configuration
    CONFIG = {
        'host': '34.47.244.104',
        'port': 2775,
        'system_id': 'rohitghawale',
        'password': 'rohit'
    }
    
    client = SMPPClient(**CONFIG)
    
    try:
        if client.connect():
            logging.info("Connected and bound successfully")
            
            # Generate a unique auth code
            auth_code = str(uuid.uuid4())
            
            # Send message with TLV parameters
            client.send_message(
                source_addr="SANJUP",
                destination_addr="1234567890",
                message="Hello, this is a test message!",
                template_id="1507167577648640421",
                pe_id="1501664220000010227",
                auth_code=auth_code
            )
            
            # Keep connection alive and handle incoming messages
            while True:
                try:
                    client.client.read_once()
                    time.sleep(0.1)  # Prevent CPU overload
                except Exception as e:
                    logging.error(f"Error reading PDU: {str(e)}")
                    break
                    
    except KeyboardInterrupt:
        logging.info("Shutting down...")
    finally:
        client.disconnect()

if __name__ == "__main__":
    main()