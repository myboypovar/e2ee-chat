import sqlite3
from datetime import datetime

DATABASE_NAME = 'E2EE_clients.db'
OTP_EXPIRATION = 60
MAX_LENGTH = 1000


class Database:
    """
    SQL Lite3 Database Class that contains the clients and their files that were sent.

    Attributes:
        connection (sqlite3.Connection): Connection to the database
    """
    def __init__(self):
        """ Initializes the database """
        self.connection = sqlite3.connect(DATABASE_NAME)
        self.create_client_table()
        self.create_message_table()

    def create_client_table(self):
        """Create the client table if it doesn't already exist."""
        with self.connection:
            self.connection.execute('''
                CREATE TABLE IF NOT EXISTS CLIENT_TABLE (
                    Phone TEXT NOT NULL PRIMARY KEY,
                    DHKey BLOB,
                    RSAKey BLOB,
                    Verified BOOLEAN NOT NULL,
                    LastSeen TIMESTAMP,
                    OTP INTEGER
                )
            ''')

    def create_message_table(self):
        """Create the message table if it doesn't already exist."""
        with self.connection:
            self.connection.execute('''
                CREATE TABLE IF NOT EXISTS MESSAGE_TABLE (
                Receiver TEXT NOT NULL,
                Sender TEXT NOT NULL,
                Message TEXT NOT NULL,
                Time TIMESTAMP NOT NULL,
                PRIMARY KEY (Receiver, Sender, Time),
                FOREIGN KEY (Receiver) REFERENCES CLIENT_TABLE (Phone) ON DELETE CASCADE
                )
            ''')

    def check_user_exists(self, phone: str) -> bool:
        """Check whether a user exists."""
        cursor = self.connection.cursor()
        cursor.execute('SELECT 1 FROM CLIENT_TABLE WHERE Phone = ?', (phone,))
        return cursor.fetchone() is not None

    def check_login(self, phone: str) -> bool:
        """Check whether a user and his public key exists."""
        cursor = self.connection.cursor()
        cursor.execute('''
            SELECT 1
            FROM CLIENT_TABLE
            WHERE Phone = ?
            AND DHKey IS NOT NULL
            AND RSAKey IS NOT NULL 
            AND Verified = ?
            ''', (phone, True))
        result = cursor.fetchone()
        if result is None:
            print(f'{phone} can\'t login')
        return result is not None

    def get_public_keys(self, phone: str) -> tuple[bytes, bytes]:
        """Get the public keys (DH and RSA) of a user."""
        cursor = self.connection.cursor()
        cursor.execute('SELECT DHKey, RSAKey FROM CLIENT_TABLE WHERE Phone = ?', (phone,))
        result = cursor.fetchone()
        if result is None:
            raise KeyError(f'No public keys found for client {phone}')

        self.update_last_seen(phone)
        return result[0], result[1]

    def add_client(self, phone: str, otp: int) -> bool:
        """Add a new client to the database."""
        if self.check_user_exists(phone):
            return False
        if not 100000 <= otp <= 999999:
            return False

        with self.connection:
            self.connection.execute('''
                INSERT INTO CLIENT_TABLE (Phone, DHKey, RSAKey, Verified, LastSeen, OTP)
                VALUES (?, NULL, NULL, FALSE, ?, ?)
            ''', (phone, datetime.now(), otp))

        return True

    def check_otp(self, phone: str, otp: int) -> bool:
        """ Check whether a user has an otp is correct and not expired. """
        if not self.check_user_exists(phone):
            print('User does not exist')
            return False
        if not 100000 <= otp <= 999999:
            print('Invalid otp')
            return False

        cursor = self.connection.cursor()
        cursor.execute('''
            SELECT OTP, LastSeen 
            FROM CLIENT_TABLE 
            WHERE Phone = ?
            ''', (phone,))

        result = cursor.fetchone()
        if result:
            database_otp, timestamp = result

            if database_otp != otp:
                print(f'OTP mismatch, expected {database_otp} got {otp}')
                return False

            try:
                last_seen = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S.%f')
            except ValueError:
                last_seen = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')

            time_diff = datetime.now() - last_seen

            if time_diff.total_seconds() > OTP_EXPIRATION:
                print('OTP expired')
                self.delete_client(phone)
                return False
        else:
            print('User does not exist')
            return False

        # Mark user as verified and clear OTP
        with self.connection:
            self.connection.execute('''
                    UPDATE CLIENT_TABLE
                    SET Verified = ?,
                        OTP = NULL,
                        LastSeen = ?
                    WHERE Phone = ?
                ''', (True, datetime.now(), phone))

        return True

    def update_last_seen(self, phone: str):
        """Update the last seen timestamp of a client."""
        with self.connection:
            self.connection.execute('''
                UPDATE CLIENT_TABLE
                SET LastSeen = ?
                WHERE Phone = ?
            ''', (phone, datetime.now()))

    def set_public_keys(self, phone: str, dh_public_key: bytes, rsa_public_key: bytes) -> bool:
        """
        Set the public keys of a client, but only if they haven't been set before.
        Returns True if keys were updated, False if keys already existed.
        """
        if dh_public_key is None or rsa_public_key is None:
            return False
        if len(dh_public_key) > MAX_LENGTH or len(rsa_public_key) > MAX_LENGTH:
            return False

        with self.connection:
            cursor = self.connection.execute('''
            UPDATE CLIENT_TABLE
            SET DHKey = ?, RSAKey = ?
            WHERE Phone = ?
            AND DHKey IS NULL 
            AND RSAKey IS NULL
            AND Verified = TRUE
            ''', (dh_public_key, rsa_public_key, phone))

            return cursor.rowcount > 0  # Returns True if an update occurred

    def store_message(self, receiver: str, sender: str, message: str):
        """Insert a new message using timestamp-based ordering."""
        with self.connection:
            self.connection.execute('''
                INSERT INTO MESSAGE_TABLE (Receiver, Sender, Message, Time)
                VALUES (?, ?, ?, ?)
            ''', (receiver, sender, message, datetime.now()))

    def get_message(self, receiver: str, sender: str = None) -> tuple[str, bytes]:
        """
         Retrieve and delete (pop) the oldest message for a receiver.
         If sender is specified, get message from that specific sender.
         Returns tuple of (sender, message) or (None, None) if no messages.
         """
        with self.connection:
            if sender:
                cursor = self.connection.execute('''
                     WITH oldest_message AS (
                         SELECT Sender, Message, Time
                         FROM MESSAGE_TABLE
                         WHERE Receiver = ? AND Sender = ?
                         ORDER BY Time ASC
                         LIMIT 1
                     )
                     DELETE FROM MESSAGE_TABLE
                     WHERE Receiver = ? 
                     AND Sender = ?
                     AND Time = (SELECT Time FROM oldest_message)
                     RETURNING Sender, Message
                 ''', (receiver, sender, receiver, sender))

            else:
                cursor = self.connection.execute('''
                     WITH oldest_message AS (
                         SELECT Sender, Message, Time
                         FROM MESSAGE_TABLE
                         WHERE Receiver = ?
                         ORDER BY Time ASC
                         LIMIT 1
                     )
                     DELETE FROM MESSAGE_TABLE
                     WHERE Receiver = ? 
                     AND Time = (SELECT Time FROM oldest_message)
                     RETURNING Sender, Message
                 ''', (receiver, receiver))

            result = cursor.fetchone()
            return result if result else (None, None)

    def delete_client(self, phone: str):
        """Delete a client from the database."""
        with self.connection:
            cursor = self.connection.execute('''
            DELETE FROM CLIENT_TABLE WHERE Phone = ?
            ''', (phone,))

        if cursor.rowcount > 0:
            print(f'Client {phone} deleted.')

    def close(self):
        """Close the database connection."""
        self.connection.close()
