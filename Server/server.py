import socket
import selectors
import random
from RSA import RSA
from connection import Connection
from database import Database
from Utils.protocol import *


MAX_CONNECTIONS = 10


class Server:
    """
    The Server class is responsible for handling multiple clients and applying the protocol on the requests
    and the responses.

    Attributes:
        host (str): The host address of the server.
        port (int): The port of the server.
        selector (selectors.DefaultSelector): A selector object that allows selecting clients.
        database (Database): A Database object that allows accessing databases.
        rsa (RSA): A RSA object that allows accessing RSA signature.
        connections (Dictionary): A Dictionary of connections.
        ready_phones (Dictionary): A Dictionary of connections that are ready to talk.

    Args:
        host (str): The host address of the server.
        port (int): The port of the server.
    """
    def __init__(self, host='localhost', port=8080):
        self.host = host
        self.port = port
        self.selector = selectors.DefaultSelector()
        self.database = Database()
        self.rsa = RSA()
        self.connections = {}
        self.ready_phones = {}

    def start(self):
        """Start the server."""
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.bind((self.host, self.port))
        server_sock.listen()
        print(f'Listening on {self.host}:{self.port}')
        server_sock.setblocking(False)

        # Register the server socket for read events
        self.selector.register(server_sock, selectors.EVENT_READ, data=None)

        try:
            self.run_event_loop()
        except KeyboardInterrupt:
            print('Shutting down...')
        finally:
            self.selector.close()

    def run_event_loop(self):
        """Run the main event loop for handling client connections."""
        while True:
            events = self.selector.select(timeout=None)
            for key, mask in events:
                if key.data is None:
                    # If the event is on the server socket, accept a new connection
                    self.accept_connection(key.fileobj)
                else:
                    # If the event is on a client connection, handle the data
                    connection = key.data
                    if mask & selectors.EVENT_READ:
                        self.handle_read(connection)
                    if mask & selectors.EVENT_WRITE:
                        self.handle_write(connection)

    def accept_connection(self, server_sock: socket.socket):
        """Accept a new client connection."""
        conn, addr = server_sock.accept()
        print(f"Accepted connection from {addr}")

        if len(self.connections) > MAX_CONNECTIONS:
            print(f'Max connections reached, rejecting new connection.')
            conn.close()
            return

        conn.setblocking(False)
        # Create a Connection instance and store it in the dictionary
        connection = Connection(conn, addr, self.selector)
        self.connections[conn] = connection

    def handle_read(self, connection: Connection):
        """Read data from the connection, deserialize, and process."""
        data = connection.read()
        if data:
            try:
                connection.request = Request.deserialize(data)
                is_fine = self.handle_request(connection)
                response_bytes = connection.response.serialize()
                connection.queue_data(response_bytes)
                if not is_fine:
                    connection.error = True
                    self.cleanup_connection(connection)
            except Exception as e:
                print(e)
                self.cleanup_connection(connection)
                connection.close()

    def cleanup_connection(self, connection: Connection):
        """ Clean up the connection. """
        self.connections.pop(connection.sock, None)
        if connection.request and connection.request.phone:
            self.ready_phones.pop(connection.request.phone, None)

    def handle_write(self, connection: Connection):
        """Send any queued data in the connection's buffer."""
        connection.write()

    def send_by_secure_channel(self, data):
        """ Send data in a secure channel."""
        return True

    def handle_request(self, connection: Connection) -> bool:
        """Handle the incoming request and generate a response."""
        opcode = connection.request.opcode

        if opcode == RequestCode.REQUEST_REGISTER:
            phone = connection.request.phone
            if len(phone) != 10:
                print(f'Invalid phone number: {phone}')
                return False

            otp = random.randint(100000, 999999)
            if self.database.add_client(phone, otp):  # added client
                connection.response = Response(
                    ResponseCode.RESPONSE_REGISTRATION,
                    OTP(otp)
                )
            else:   # client already exists.
                print(f'Client {phone} is already registered.')
                connection.response = Response(
                    ResponseCode.RESPONSE_REGISTRATION_FAILED,
                    EmptyPayload()
                )
                return False

            self.send_by_secure_channel(connection.request)
            return True

        elif opcode == RequestCode.REQUEST_OTP:
            phone = connection.request.phone
            otp = connection.request.payload.otp_code
            if self.database.check_otp(phone, otp):
                connection.response = Response(
                    ResponseCode.RESPONSE_OTP_OK,
                    EmptyPayload()
                )
                return True
            else:
                connection.response = Response(
                    ResponseCode.RESPONSE_ERROR,
                    EmptyPayload()
                )
                return False

        elif opcode == RequestCode.REQUEST_LOGIN:
            phone = connection.request.phone

            # User exists
            if self.database.check_login(phone):
                self.database.update_last_seen(phone)
                print(f'Client {phone} logged in.')

                # Get first stored message if any exists
                sender, message = self.database.get_message(phone)

                if sender and message:
                    # Send first stored message
                    connection.response = Response(
                        ResponseCode.RESPONSE_MESSAGE,
                        Message(sender, message)
                    )
                else:
                    # No stored messages, proceed with normal login response
                    connection.response = Response(
                        ResponseCode.RESPONSE_LOGIN,
                        EmptyPayload()
                    )
                self.ready_phones[phone] = connection
                return True

            else:
                connection.response = Response(
                    ResponseCode.RESPONSE_LOGIN_FAILED,
                    EmptyPayload()
                )
                return False

        elif opcode == RequestCode.REQUEST_SEND_PUBLIC_KEYS:
            phone = connection.request.phone
            dh_key = connection.request.payload.dh_key
            rsa_key = connection.request.payload.rsa_key

            if self.database.set_public_keys(phone, dh_key, rsa_key):
                connection.response = Response(
                    ResponseCode.RESPONSE_KEYS_SET,
                    EmptyPayload()
                )
                print(f'Client {phone} public keys were set in the database.')
                self.ready_phones[phone] = connection
                return True
            else:
                print(f'Client {phone} public keys were not set in the database.')
                connection.response = Response(
                    ResponseCode.RESPONSE_ERROR,
                    EmptyPayload()
                )
                return False

        elif opcode == RequestCode.REQUEST_RECIPIENT_KEYS:
            phone = connection.request.phone
            recipient = connection.request.payload.phone
            self.database.update_last_seen(phone)
            try:
                dh_key, rsa_key = self.database.get_public_keys(recipient)
                dh_sign = self.rsa.sign_client_key(dh_key)
                rsa_sign = self.rsa.sign_client_key(rsa_key)
            except Exception as e:
                print(e)
                connection.response = Response(
                    ResponseCode.RESPONSE_ERROR,
                    EmptyPayload()
                )
                return False

            connection.response = Response(
                ResponseCode.RESPONSE_RECIPIENT_KEYS,
                SignedPublicKeys(dh_key, rsa_key, dh_sign, rsa_sign)
            )
            print(f'Sending client {recipient} public keys to {phone}.')
            return True

        elif opcode == RequestCode.REQUEST_MESSAGE:
            sender = connection.request.phone
            receiver = connection.request.payload.phone
            message = connection.request.payload.msg
            self.database.update_last_seen(sender)

            # Recipient is offline
            if receiver not in self.ready_phones:
                self.database.store_message(receiver, sender, message)
                print(f'Client {receiver} is offline, storing the message in the database.')

            # Recipient is online
            else:
                receiver_connection = self.ready_phones[receiver]
                response = Response(
                    ResponseCode.RESPONSE_MESSAGE,
                    Message(sender, message)
                )
                try:
                    serialized_response = response.serialize()
                    receiver_connection.queue_data(serialized_response)
                    self.handle_write(receiver_connection)
                except Exception as e:
                    print(f'error in message response: {str(e)}')
                    return False

            connection.response = Response(
                ResponseCode.RESPONSE_MESSAGE_SENT,
                EmptyPayload()
            )
            return True

        elif opcode == RequestCode.REQUEST_SENDER_KEYS:
            phone = connection.request.phone
            sender = connection.request.payload.phone
            self.database.update_last_seen(sender)

            try:
                dh_key, rsa_key = self.database.get_public_keys(sender)
                dh_sign = self.rsa.sign_client_key(dh_key)
                rsa_sign = self.rsa.sign_client_key(rsa_key)
            except Exception as e:
                print(e)
                connection.response = Response(
                    ResponseCode.RESPONSE_ERROR,
                    EmptyPayload()
                )
                return False

            connection.response = Response(
                ResponseCode.RESPONSE_SENDER_KEYS,
                SenderPublicKeys(sender, dh_key, rsa_key, dh_sign, rsa_sign)
            )
            print(f'Sending client {sender} public keys to {phone}.')
            return True

        elif opcode == RequestCode.REQUEST_MESSAGE_RECEIVED:
            receiver = connection.request.phone
            sender = connection.request.payload.phone
            self.database.update_last_seen(receiver)

            _, msg = self.database.get_message(receiver, sender)

            # More messages to send in the database
            if msg:
                connection.response = Response(
                    ResponseCode.RESPONSE_MESSAGE,
                    Message(sender, msg)
                )

            # Listening for incoming requests
            else:
                connection.response = Response(
                    ResponseCode.RESPONSE_LISTENING,
                    EmptyPayload()
                )
            return True

        # Error
        else:
            connection.response = Response(
                ResponseCode.RESPONSE_ERROR,
                EmptyPayload()
            )
            return False


if __name__ == '__main__':
    Server().start()
