import socket
from collections import defaultdict
import threading
from queue import Queue
import time

from crypto import Crypto
from Utils.protocol import *

VERSION = 1
HOST = '127.0.0.1'
PORT = 8080
MESSAGE_SIZE = 1000
PACKET_SIZE = 2048


class Client:
    """
    The Client class is responsible for sending and receiving messages from clients.

    Attributes:
        host (str): The host address of the client.
        port (int): The port of the client.
        sock (socket.socket): The socket object of the client.
        is_connected (bool): Whether the client is connected to the server.
        crypto (Crypto): The cryptography object of the client.
        phone (str): The phone number of the client.
        request (Request): The request object of the client.
        response (Response): The response object of the client.
        recipient (str): The recipient phone number.
        pending_messages (dict): A queue of pending messages.
        receive_thread (threading.Thread): A thread responsible for receiving messages.
        message_queue (Queue): A queue of messages.
        running (bool): Whether the thread is running.
    """
    def __init__(self, host=HOST, port=PORT):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.is_connected = False
        self.crypto = Crypto()
        self.phone = None
        self.request = None
        self.response = None
        self.recipient = None
        self.pending_messages = defaultdict(list)
        self.receive_thread = None
        self.message_queue = Queue()
        self.running = False

    def start_receive_thread(self):
        """Start a separate thread for receiving messages"""
        self.running = True
        self.receive_thread = threading.Thread(target=self.receive_messages)
        self.receive_thread.daemon = True  # Thread will exit when main thread exits
        self.receive_thread.start()

    def receive_messages(self):
        """Continuously receive and handle messages in a separate thread"""
        while self.running and self.is_connected:
            try:
                data = self.sock.recv(PACKET_SIZE)
                if not data:
                    print("Server connection closed")
                    self.disconnect()
                    break

                response = Response.deserialize(data)
                self.message_queue.put(response)

                # Handle response in the receive thread
                self.response = response
                if not self.handle_response():
                    self.disconnect()
                    break

            except Exception as e:
                print(f"Error receiving message: {e}")
                self.disconnect()
                break

    def connect(self) -> bool:
        """Connect the client to the server"""
        try:
            self.sock.connect((self.host, self.port))
            self.is_connected = True
            print(f'Connected to the server {self.host}:{self.port}')
            return True
        except ConnectionRefusedError:
            print('Connection refused.')
            return False

    def disconnect(self):
        """Safely disconnect from the server and clean up threads"""
        self.running = False
        if self.is_connected:
            try:
                self.sock.close()
                self.is_connected = False
                print('Disconnected from the server.')
            except Exception as e:
                print(e)
        if self.receive_thread and self.receive_thread.is_alive() and threading.current_thread() != self.receive_thread:
            self.receive_thread.join(timeout=1.0)

    def is_phone_number(self, phone_num: str) -> bool:
        """Check whether the phone number is valid"""
        return phone_num.isdigit() and len(phone_num) == 10

    def start(self):
        """Starts the client"""
        try:
            self.crypto.load_server_public_key()
        except Exception as e:
            print(e)
            return

        if not self.connect():
            return

        # Start the receive thread after successful connection
        self.start_receive_thread()

        if not self.login():
            self.register()
            self.request = Request(
                self.phone,
                RequestCode.REQUEST_REGISTER,
                EmptyPayload()
            )
        else:
            self.request = Request(
                self.phone,
                RequestCode.REQUEST_LOGIN,
                EmptyPayload()
            )

        # Main loop now handles sending and user input
        while self.is_connected:
            if self.request is None:
                # Handle user input when signaled by receive thread
                if not self.recipient:
                    self.recipient = self.get_recipient()
                    self.request = Request(
                        self.phone,
                        RequestCode.REQUEST_RECIPIENT_KEYS,
                        Phone(self.recipient)
                    )
                else:
                    # Handle messaging
                    if not self.handle_messaging():
                        break
            elif not self.send_request():
                break

            # Small delay to prevent busy waiting
            time.sleep(0.1)

    def register(self):
        """Register the client and updates the client's phone number,
            creates a me.info file that has the client's phone number.
        """

        phone_num = input('Enter your phone number: ')
        while not self.is_phone_number(phone_num):
            print('Invalid phone number.')
            phone_num = input('Enter your phone number: ')

        self.phone = phone_num
        with open('me.info', 'w') as f:
            f.write(self.phone)
        print('Your phone number has been saved successfully.')

    def login(self) -> bool:
        """ Takes the login info from the file me.info. """
        try:
            with open('me.info', 'r') as f:
                phone_num = f.read()
        except FileNotFoundError:
            return False

        if self.is_phone_number(phone_num):
            self.phone = phone_num
            print('Trying to login.')
            return True
        else:
            print('Invalid phone number.')
            return False

    def send_request(self):
        """Send request with thread-safe handling"""
        if not self.is_connected:
            return False

        serialized_request = Request.serialize(self.request)
        if len(serialized_request) > PACKET_SIZE:
            print('Request is too big.')
            self.disconnect()
            return False

        try:
            with threading.Lock():  # Ensure thread-safe sending
                sent = self.sock.send(serialized_request)
                if sent == 0:
                    print('Connection closed.')
                    return False
            return True
        except Exception as e:
            print(f'Error sending message: {e}')
            self.disconnect()
            return False

    def read(self):
        """Read data from the socket and return it."""
        data = self.sock.recv(PACKET_SIZE)
        if not data:  # Connection closed by the server
            self.disconnect()
        return data

    def get_response(self) -> bool:
        """ Gets a response from the server. """
        try:
            self.response = Response.deserialize(self.read())
            return True
        except Exception as e:
            print(e)
            self.disconnect()
            return False

    def send_and_receive(self):
        """ An event loop for handling the packets between the server and the client """
        while self.is_connected:
            if not self.send_request():
                return False
            if not self.get_response():
                return False
            if not self.handle_response():
                return False
        return True

    def handle_response(self) -> bool:
        """ Handles the server's response by its opcode. """
        code = self.response.opcode

        if code == ResponseCode.RESPONSE_REGISTRATION:
            otp = self.response.payload.otp_code
            if not 100000 <= otp <= 999999:
                print(f'Invalid OTP from the server: \'{otp}\'')
                return False

            with threading.Lock():  # Thread-safe request setting
                self.request = Request(
                    self.phone,
                    RequestCode.REQUEST_OTP,
                    OTP(otp)
                )
            return True

        elif code == ResponseCode.RESPONSE_LOGIN or code == ResponseCode.RESPONSE_KEYS_SET:
            print('Logged in successfully.\n')

            with threading.Lock():
                if not self.recipient:  # Only get recipient if not already set
                    self.recipient = None  # Signal main thread to get recipient
                    self.request = None
                else:
                    self.request = Request(
                        self.phone,
                        RequestCode.REQUEST_RECIPIENT_KEYS,
                        Phone(self.recipient)
                    )
            return True

        elif code == ResponseCode.RESPONSE_OTP_OK:
            with threading.Lock():
                dh_key, rsa_key = self.crypto.get_public_keys()
                self.request = Request(
                    self.phone,
                    RequestCode.REQUEST_SEND_PUBLIC_KEYS,
                    PublicKeys(dh_key, rsa_key)
                )
            return True

        elif code == ResponseCode.RESPONSE_RECIPIENT_KEYS:
            dh_key = self.response.payload.dh_key
            rsa_key = self.response.payload.rsa_key
            dh_sign = self.response.payload.dh_sign
            rsa_sign = self.response.payload.rsa_sign
            if not self.crypto.verify_signed_key(dh_key, dh_sign):
                print(f'Invalid signature for the recipient\'s {self.recipient} DH public key.')
                return False
            if not self.crypto.verify_signed_key(rsa_key, rsa_sign):
                print(f'Invalid signature for the recipient\'s {self.recipient} RSA public key.')
                return False

            with threading.Lock():
                self.crypto.sender_keys[self.recipient] = dh_key, rsa_key
                self.crypto.recipient_dh_key = dh_key
                # Signal main thread to handle messaging
                self.request = None  # Will be set by handle_messaging in main thread
            return True

        elif code == ResponseCode.RESPONSE_MESSAGE_SENT:
            print('Message sent.\n')
            with threading.Lock():
                self.request = None  # Signal main thread to get next message
            return True

        elif code == ResponseCode.RESPONSE_MESSAGE:
            sender = self.response.payload.phone
            msg = self.response.payload.msg
            encrypted_msg = self.crypto.unpack_encrypted_message(msg, SIGNATURE_SIZE)

            with threading.Lock():
                # Handle sender keys and message decryption
                if sender in self.crypto.sender_keys:
                    sender_dh_key, sender_rsa_key = self.crypto.sender_keys[sender]
                    decrypted_msg = self.crypto.decrypt_message(encrypted_msg, sender_dh_key, sender_rsa_key)
                    print(f'\nReceived message from {sender}: {decrypted_msg}\n')
                    self.request = Request(
                        self.phone,
                        RequestCode.REQUEST_MESSAGE_RECEIVED,
                        Phone(sender)
                    )
                else:
                    self.pending_messages[sender].append(encrypted_msg)
                    self.request = Request(
                        self.phone,
                        RequestCode.REQUEST_SENDER_KEYS,
                        Phone(sender)
                    )
            return True

        elif code == ResponseCode.RESPONSE_SENDER_KEYS:
            sender = self.response.payload.phone
            dh_key = self.response.payload.dh_key
            rsa_key = self.response.payload.rsa_key
            dh_sign = self.response.payload.dh_sign
            rsa_sign = self.response.payload.rsa_sign

            if not self.crypto.verify_signed_key(dh_key, dh_sign):
                print(f'Invalid signature for the sender\'s {self.recipient} DH public key.')
                return False
            if not self.crypto.verify_signed_key(rsa_key, rsa_sign):
                print(f'Invalid signature for the sender\'s {self.recipient} RSA public key.')
                return False

            with threading.Lock():
                self.crypto.sender_keys[sender] = dh_key, rsa_key
                print(f'\n{sender} public keys have been verified.')

                # Process any pending messages
                for message in self.pending_messages[sender]:
                    decrypted_message = self.crypto.decrypt_message(message, dh_key, rsa_key)
                    print(f'Received message from {sender}: {decrypted_message}')

                self.pending_messages[sender] = []  # Clear pending messages
                self.request = Request(
                    self.phone,
                    RequestCode.REQUEST_MESSAGE_RECEIVED,
                    Phone(sender)
                )
            return True

        elif code == ResponseCode.RESPONSE_LISTENING:
            with threading.Lock():
                if not self.recipient:
                    self.recipient = None  # Signal main thread to get recipient
                    self.request = None
                elif self.recipient in self.crypto.sender_keys:
                    self.crypto.recipient_dh_key = self.crypto.sender_keys[self.recipient][0]
                    self.request = None  # Signal main thread to handle messaging
                else:
                    self.request = Request(
                        self.phone,
                        RequestCode.REQUEST_RECIPIENT_KEYS,
                        Phone(self.recipient)
                    )
            return True

        elif code == ResponseCode.RESPONSE_REGISTRATION_FAILED:
            print('Registration failed.')
            return False

        elif code == ResponseCode.RESPONSE_LOGIN_FAILED:
            print('Login failed.')
            return False

        elif code == ResponseCode.RESPONSE_ERROR:
            print('Unexpected error from the server.')
            return False

        else:
            print('Unknown response code.')
            return False

    def get_recipient(self) -> str:
        """ Get the recipient phone number of the messages. """
        recipient = input('Enter the recipient\'s phone number: ')
        while not self.is_phone_number(recipient):
            print('Invalid phone number, enter again.')
            recipient = input('Enter the recipient\'s phone number: ')
        return recipient

    def get_message(self) -> str:
        """ Gets a message. """
        message = input('Enter your message, to quit type q.\n')
        while not message or len(message) > MESSAGE_SIZE:
            print(f'The message is too long, the maximum length is {MESSAGE_SIZE}.')
            message = input('Enter your message, to quit type q.\n')
        return message

    def handle_messaging(self):
        """ Handles the messaging logic """
        message = self.get_message()

        if message.lower() == 'q':
            ans = input('Would you like to message someone else? Y/N ')
            if ans.lower() == 'y':
                self.recipient = self.get_recipient()
                self.request = Request(
                    self.phone,
                    RequestCode.REQUEST_RECIPIENT_KEYS,
                    Phone(self.recipient)
                )
                return True
            else:
                return False
        else:
            try:
                encrypted_message = self.crypto.encrypt_message(message)
                serialized_message = self.crypto.pack_encrypted_message(encrypted_message)
                self.request = Request(
                    self.phone,
                    RequestCode.REQUEST_MESSAGE,
                    Message(self.recipient, serialized_message)
                )
                return True
            except Exception as e:
                print(e)
                return False


if __name__ == '__main__':
    client = Client()
    try:
        client.start()
    except KeyboardInterrupt:
        print('Interrupted.')
    except Exception as ex:
        print(ex)
    finally:
        client.disconnect()
