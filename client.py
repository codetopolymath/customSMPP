import logging
import sys
import smpplib.gsm
import smpplib.client
import smpplib.consts
import time
import uuid
from smpplib.command import Command, SubmitSM, Param

# First patch the OPTIONAL_PARAMS to include our custom TLVs
smpplib.consts.OPTIONAL_PARAMS.update({
    'template_id': 0x1400,
    'pe_id': 0x1401,
    'auth_code': 0x1405
})

# Patch SubmitSM to include our custom TLVs
SubmitSM.params.update({
    'template_id': Param(type=str, max=65),
    'pe_id': Param(type=str, max=65),
    'auth_code': Param(type=str, max=65)
})

# Add our parameters to params_order
SubmitSM.params_order = SubmitSM.params_order + ('template_id', 'pe_id', 'auth_code')

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s %(levelname)-8s %(name)s:%(lineno)d %(message)s',
    handlers=[
        logging.FileHandler('smpp_client.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

class SMPPClient:
    def __init__(self, host, port, system_id, password):
        self.host = host
        self.port = port
        self.system_id = system_id
        self.password = password
        self.client = None
        self.connected = False

    def connect(self):
        """Establish connection with SMPP server"""
        try:
            self.client = smpplib.client(self.host, self.port, timeout=30, allow_unknown_opt_params=True)
            self.client.interface_version = smpplib.consts.SMPP_VERSION_34
            
            logging.info(f"Connecting to {self.host}:{self.port}")
            self.client.connect()
            
            logging.debug(f"System ID: {self.system_id}")
            logging.debug(f"Password length: {len(self.password)}")
            
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
        """Send message with TLV parameters"""
        if not self.connected:
            logging.error("Not connected to SMPP server")
            return False

        try:
            parts, encoding_flag, msg_type_flag = smpplib.gsm.make_parts(message)
            
            logging.info(f"Sending message: {message}")
            logging.debug(f"Source: {source_addr}")
            logging.debug(f"Destination: {destination_addr}")

            # Create PDU
            pdu = self.client.send_message(
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
                template_id=template_id,
                pe_id=pe_id,
                auth_code=auth_code
            )
            
            logging.debug(f"PDU command: {pdu.command}")
            logging.debug(f"PDU sequence: {pdu.sequence}")
            logging.debug(f"PDU template_id: {getattr(pdu, 'template_id', None)}")
            logging.debug(f"PDU pe_id: {getattr(pdu, 'pe_id', None)}")
            logging.debug(f"PDU auth_code: {getattr(pdu, 'auth_code', None)}")
            
            # Log the raw PDU for debugging
            packed_pdu = pdu.pack()
            logging.debug(f"Raw PDU hex: {packed_pdu.hex()}")
            
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
            
            # Keep connection alive
            while True:
                try:
                    client.client.read_once()
                    time.sleep(0.1)
                except Exception as e:
                    logging.error(f"Error reading PDU: {str(e)}")
                    break
                    
    except KeyboardInterrupt:
        logging.info("Shutting down...")
    finally:
        client.disconnect()

if __name__ == "__main__":
    main()