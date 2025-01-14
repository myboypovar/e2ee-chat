import socket
import selectors

from Utils.protocol import Request, Response


PACKET_SIZE = 2048  # 2KB


class Connection:
    """
    The Connection class manages a socket connection to a server.

    Attributes:
        sock (socket): The socket object for the connection.
        addr (tuple): The address of the connected client (IP, port).
        selector (selectors): The selector for managing I/O events.
        _send_buffer (bytes): Buffer for outgoing data.
        is_closed (bool): Flag indicating if the connection is closed.
        request (Request): Placeholder for the request to be sent or received.
        response (Response): Placeholder for the response to be sent or received.
        error (bool): Flag indicating if there is an error.

    Args:
        sock (socket.socket): The socket object representing the connection.
        addr (tuple): The address of the connected client (IP, port).
        selector (selectors.DefaultSelector): The selector for managing I/O events.
    """
    def __init__(self, sock: socket.socket, addr: tuple, selector: selectors.DefaultSelector):
        """ Constructor for the Connection class."""
        self.sock = sock
        self.addr = addr
        self.selector = selector
        self._send_buffer = b''
        self.is_closed = False
        self.request = None
        self.response = None
        self.error = False

        # Register for read events initially
        self.selector.register(self.sock, selectors.EVENT_READ, data=self)

    def read(self) -> bytes:
        """Read data from the socket and return it."""
        try:
            data = self.sock.recv(PACKET_SIZE)
            if not data:   # Connection closed by the client
                self.close()
            return data
        except IOError as e:
            print(f"Error reading from {self.addr}: {e}")
            self.close()
            return b''

    def write(self):
        """Write data from the send buffer to the socket."""
        if self._send_buffer:
            if len(self._send_buffer) > PACKET_SIZE:
                print('Packet is too big')
                self.close()
                return

            try:
                sent = self.sock.send(self._send_buffer)
                self._send_buffer = self._send_buffer[sent:]
                if len(self._send_buffer) == 0:
                    # Switch back to read mode if all data is sent
                    self.selector.modify(self.sock, selectors.EVENT_READ, data=self)
                if self.error:
                    self.close()
            except IOError as e:
                print(f"Error writing to {self.addr}: {e}")
                self.close()

    def queue_data(self, data: bytes):
        """Queue data to be sent and register for write events."""
        self._send_buffer += data
        self.selector.modify(self.sock, selectors.EVENT_WRITE, data=self)

    def close(self):
        """Close the connection and unregister from the selector."""
        if not self.is_closed:
            print(f"Closing connection to {self.addr}")
            self.selector.unregister(self.sock)
            self.sock.close()
            self.is_closed = True
