"""
Sec Lope De Vega external connector
=================================================
Module: ext_comm_controller.py
Author: Alberto Dominguez

This is the one in charge of controlling the communication with external elements
    - starting it
    - get information from outside
    - sending information
    - ending the communication
"""
import logging
import queue
import selectors
import socket
import ssl
import threading
import time

from dtls import do_patch
from utils.connection_utils import load_protected_private_key, get_client_socket_id_list
from utils.interoperability_py_go import interlanguage_bool_check

# logger
logger = logging.getLogger(__name__)

# Constants for the external socket initialization
DEFAULT_BYTES_TO_READ = 1024
TRANSPORT_PROTOCOL_UDP = "UDP"
MODE_CLIENT = "CLIENT"
TLS_CLIENT_NO = "NO"
DEFAULT_NUMBER_MAX_CONCURRENT_CONNNECTIONS = 5
DEFAULT_IP = "127.0.0.1"

# Constants for the addr result of the sockets
ADDR_IP = 0
ADDR_PORT = 1

# UDP constants for message delivery
UDP_MESSAGE_DATA = 0
UDP_MESSAGE_DESTINATION = 1

# Reply delivery control
MAX_NUMBER_DELIVERY_ATTEMPTS = 3
TLS_CONNECTION_ATTEMPTS_MODIFIER = 3
SLEEPING_TIME_BETWEEN_ATTEMPTS = 1  # seconds

# Client mode connection check
TIME_BETWEEN_CONNECTION_CHECKS = 0.01  # Seconds

# Socket listening time
SOCKET_LISTENING_TIME = 1  # seconds

# Socket status
CLOSED_SOCKET = -1

# Socket port reuse
ONE_REUSE_FOR_LISTENING_SOCKET = 1

# Number of  max attempts for the client mode when an connection is not established
CLIENT_MAX_NUMBER_CONNECTION_ATTEMPTS = 3


# ==========================================================================================
# External socket class
# ==========================================================================================


class ExtConnController:
    '''
    Object for managing the external socket and contain all elements needed
    '''

    def __init__(self,  socket_ip_version, ip, port, client_mode, transport_protocol,
                 socket_timeout, config_max_connections_queue, max_input_bytes, encrypted, cleaning_register,
                 selector=None, client_sockets=None, ext_socket=None, tls_client_default_settings=None,
                 tls_client_cabundle_pem=None, time_between_client_sockets_connection=None,
                 time_between_client_socket_close_connect=None, tls_validate_server_certificate=None,
                 tls_key_protected=None, tls_server_key_password=None, tls_client_authentication=None,
                 tls_client_certchain_pem=None, tls_client_priv_key_pem=None, dtls_mode=None,
                 tls_client_key_password=None, tls_server_certchain_pem=None, tls_server_priv_key_pem=None,):

        self.socket = ext_socket
        self.ip_version = socket_ip_version
        self.ip = ip
        self.port = port
        self.client_mode = client_mode
        self.max_input_bytes = max_input_bytes
        self.ext_socket_lock = threading.Lock()
        self.others_lock = threading.Lock()
        self.client_sockets = client_sockets
        self.tls_client_default_settings = tls_client_default_settings
        self.tls_client_cabundle_pem = tls_client_cabundle_pem
        self.tls_validate_server_certificate = tls_validate_server_certificate
        self.tls_key_protected = tls_key_protected
        self.tls_server_key_password = tls_server_key_password
        self.tls_client_authentication = tls_client_authentication
        self.tls_client_certchain_pem = tls_client_certchain_pem
        self.tls_client_priv_key_pem = tls_client_priv_key_pem
        self.tls_client_key_password = tls_client_key_password
        self.tls_server_certchain_pem = tls_server_certchain_pem
        self.tls_server_priv_key_pem = tls_server_priv_key_pem
        self.dtls_mode = dtls_mode
        self.encrypted = encrypted
        self.time_between_client_sockets_connection = time_between_client_sockets_connection
        self.time_between_client_socket_close_connect = time_between_client_socket_close_connect
        self.selector = selector
        self.selector_lock = threading.Lock()
        self.socket_timeout = socket_timeout
        self.cleaning_register = cleaning_register

        # UDP protocol?
        if transport_protocol.upper() == TRANSPORT_PROTOCOL_UDP:
            self.udp_protocol = True
            # UDP message delivery queue
            self.udp_sending_queue = queue.Queue()

        else:  # TCP
            self.udp_protocol = False

        # Max number of connections in queue
        if isinstance(config_max_connections_queue, int) and config_max_connections_queue > 0:
            self.config_max_connections_queue = config_max_connections_queue
        else:
            self.config_max_connections_queue = DEFAULT_NUMBER_MAX_CONCURRENT_CONNNECTIONS
            logger.debug(
                "Using default value for max number of connections in queue")

# ==========================================================================================
# Auxiliary methods
# ==========================================================================================
    def get_max_input_size(self):
        '''
        Auxiliary function to return the max input size of the socket object
        '''
        max_size = 0
        with self.others_lock:
            max_size = self.max_input_bytes

        return max_size

    def deregister_socket_in_selector(self, socket_to_close):
        '''
        Method to deregister a socket from the selector
        '''
        logger.info("Socket unregistered from the socket selector")
        with self.selector_lock:
            self.selector.unregister(socket_to_close)

    def register_socket_in_selector(self, socket, events, data):
        '''
        Method to register a socket from the selector
        '''
        with self.selector_lock:
            self.selector.register(socket, events, data=data)

    def close_socket(self, socket_to_close=None):
        '''
        Method to close a socket gracefully. if no socket is passed as parameter,
        then the external listening socket (TCP server case) is the one to be closed,
        or the client sockets
        '''
        if socket_to_close is not None:
            if socket_to_close.fileno() != CLOSED_SOCKET:

                # the only case where the selector is not used is in the server udp (no DTLS)
                if not (self.udp_protocol and not self.client_mode and not self.encrypted):
                    self.deregister_socket_in_selector(socket_to_close)
                # this is only applicable for TCP sockets
                if not self.udp_protocol:
                    try:
                        socket_to_close.shutdown(socket.SHUT_RD)
                    except:
                        logger.info(
                            "Error shutting down the socket, this means the connection was ended before")
                socket_to_close.close()
                logger.info("Socket closed successfully")
        else:
            if self.socket is not None:
                logger.warning("Closing the external/listening socket...")
                with self.ext_socket_lock:
                    self.close_socket(self.socket)
            else:
                if self.client_sockets is not None:
                    logger.warning("External/listening socket, it is Null/None." +
                                   "Trying to close the client sockets...")
                    for client_socket_to_close in self.client_sockets:
                        if client_socket_to_close.fileno() != CLOSED_SOCKET:
                            with self.ext_socket_lock:
                                self.close_socket(client_socket_to_close)
                else:
                    logger.warning(
                        "Not possible to close the client sockets, They are Null/None too!")

    def modify_ip_and_port(self, ip, port, number_of_connections):
        '''
        Method to modify the ip and port for the context of conditional execution of the external connector
        '''
        ip_change_flag = False
        port_change_flag = False

        if ip is not None and len(ip) >= 0:
            self.ip = ip
            ip_change_flag = True
            logger.info(f"IP value changed, new value: '{ip}'")

        if port is not None and len(port) >= 0:
            if type(port) == str:
                try:
                    port = int(port)
                    self.port = port
                    port_change_flag = True
                    logger.info(f"Port value changed, new value: '{port}'")
                except Exception as ex:
                    logger.exception(
                        "Not possible to change the listening port", ex)

        # if something has been changed, then reset the socket
        if ip_change_flag or port_change_flag:
            logger.info(
                f"Modifying the sockets with the new values of 'ip' and 'port'")

            if self.udp_protocol:
                transport_protocol = TRANSPORT_PROTOCOL_UDP
                socket_transport_protocol = socket.SOCK_DGRAM
            else:
                transport_protocol = "TCP"
                socket_transport_protocol = socket.SOCK_STREAM

            if self.client_mode:
                socket_id_list = get_client_socket_id_list(
                    number_of_connections)

                new_client_sockets, new_selector = get_client_sockets(
                    number_of_connections, self.ip_version, socket_transport_protocol,
                    transport_protocol, self.encrypted, self.socket_timeout, self.tls_client_default_settings,
                    self.tls_client_cabundle_pem, socket_id_list, self.ip, self.port, self.dtls_mode,
                    self.tls_validate_server_certificate, self.tls_client_authentication,
                    self.tls_client_certchain_pem, self.tls_client_priv_key_pem, self.tls_key_protected,
                    self.tls_client_key_password, self.cleaning_register)

                self.client_sockets = new_client_sockets
            else:
                # Create a new socket
                new_ext_socket, new_selector = get_server_socket(
                    self.ip_version, socket_transport_protocol, self.ip, self.port, transport_protocol,
                    self.encrypted, self.socket_timeout, self.tls_server_certchain_pem, self.tls_server_priv_key_pem,
                    self.dtls_mode, self.tls_key_protected, self.tls_server_key_password, self.tls_client_authentication,
                    self.tls_client_cabundle_pem, self.cleaning_register)

                self.socket = new_ext_socket

            self.selector = new_selector


# ==========================================================================================
# Sending socket methods
# ==========================================================================================

    def udp_add_data_to_sending_queue(self, data_bytes, ip=None, port=None):
        '''
        Method to save a message in the UDP sending queue to be sent later on
        '''
        # Selecting IP to use
        if ip is not None:
            ip_to_use = ip
        else:
            ip_to_use = self.ip

        # Selecting port to use
        if port is not None:
            port_to_use = port
        else:
            port_to_use = self.port

        logger.info(
            f"Adding a UDP message in the UDP sending queue to IP:{ip_to_use}, and port:{port_to_use}")
        self.udp_sending_queue.put((data_bytes, (ip_to_use, port_to_use)))

        # Since UDP is not really sending nothing, just adding in a sending queue,
        # this values are not used to keep the rest of the code as it is
        return True, False

    def udp_send_data(self, message, udp_sock=None):
        '''
        Method to send data via an UDP socket
        '''
        result = False
        conn_broken = False

        try:
            if udp_sock is None:
                self.socket.sendto(
                    message[UDP_MESSAGE_DATA], message[UDP_MESSAGE_DESTINATION])
            else:
                udp_sock.sendto(
                    message[UDP_MESSAGE_DATA], message[UDP_MESSAGE_DESTINATION])

            result = True
            logger.info("UDP message sent from the UDP sending queue to " +
                        f"IP:{message[UDP_MESSAGE_DESTINATION][ADDR_IP]}, " +
                        f"and port: {message[UDP_MESSAGE_DESTINATION][ADDR_PORT]}")
        except Exception:
            conn_broken = True
            logger.exception("Error sending an udp message")

        return result, conn_broken

    def udp_send_messages_from_sending_queue(self):
        '''
        Method to send all messages that are waiting in the sending queue of udp
        '''
        while not self.udp_sending_queue.empty():
            message = self.udp_sending_queue.get()
            _, _ = self.udp_send_data(message)

    def tcp_or_dtls_send_data(self, data_bytes, socket_conn, ip, port):
        '''
        Method to send data using a TCP connection already established
        Since it's a different socket from the listening socket, it should not require to be thred safe.
        That is why the only thread that is using the socket connection is an operation worker thread,
        oner per connection.
        '''
        result = False
        logger.info(
            f"Sending data via TCP or DTLS to IP:{ip}, and port:{port}")
        logger.debug(f"Data to be sent:{data_bytes}")
        conn_broken = False
        attempts = 0
        if self.encrypted:
            max_delivery_attempts = MAX_NUMBER_DELIVERY_ATTEMPTS * \
                TLS_CONNECTION_ATTEMPTS_MODIFIER
        else:
            max_delivery_attempts = MAX_NUMBER_DELIVERY_ATTEMPTS

        if socket_conn is not None and (socket_conn.fileno() != CLOSED_SOCKET):
            while (not result and not conn_broken):
                try:
                    number_bytes_sent = socket_conn.send(data_bytes)
                    if number_bytes_sent > 0:
                        result = True
                        logger.info(f"Data sent sucessfully")
                # https://docs.python.org/3/library/ssl.html#ssl-nonblocking
                except ssl.SSLWantReadError:
                    logger.debug(
                        "TLS or DTLS Socket not ready to read while sending data")
                except ssl.SSLWantWriteError:
                    logger.debug(
                        "TLS or DTLS Socket not ready to write while sending data")
                except:
                    logger.exception(
                        "Error sending data in a TCP or DTLS socket")
                # update attempts counter
                attempts += 1

                if attempts >= max_delivery_attempts:
                    conn_broken = True
                    logger.warn(
                        "Socket connection broken! Closing connection...")
                    self.close_socket(socket_conn)
                else:
                    time.sleep(SLEEPING_TIME_BETWEEN_ATTEMPTS)
        else:
            conn_broken = True
            logger.info("Socket was 'None' or closed at the time to send the message, " +
                        "so the answer was not sent")
        return result, conn_broken

    def send_data(self, data_bytes, ip, port, socket_conn=None):
        '''
        Method to work as interface for sending data to external parties.
        '''
        # UDP Server
        if self.udp_protocol and not self.client_mode and not self.encrypted:
            result, conn_broken = self.udp_add_data_to_sending_queue(
                data_bytes, ip, port)
        # UDP Client
        elif self.udp_protocol and self.client_mode and not self.encrypted:
            message = (data_bytes, (ip, port))
            result, conn_broken = self.udp_send_data(message, socket_conn)
        # TCP or DTLS
        else:
            result, conn_broken = self.tcp_or_dtls_send_data(
                data_bytes, socket_conn, ip, port)

        return result, conn_broken

# ==========================================================================================
# Receiving socket methods
# ==========================================================================================
    def receive_data(self, socket_conn):
        '''
        Method to get data from a tcp socket. This socket is not shared among threads beacuse
        it is creted once the connection is accepted, therefore there is not need to use
        parallel control measures
        '''
        ext_input = None
        if socket_conn is not None and (socket_conn.fileno() != CLOSED_SOCKET):
            try:
                ext_input = socket_conn.recv(self.get_max_input_size())
                logger.debug(f"Data received from outside:{ext_input} from:" +
                             f"{socket_conn.getpeername()}")
                # https://docs.python.org/3/library/ssl.html#ssl-nonblocking
            except ssl.SSLWantReadError:
                logger.debug("TLS Socket not ready to read while reading data")
            except ssl.SSLWantWriteError:
                logger.debug(
                    "TLS Socket not ready to write while reading data")
        return ext_input

# ==========================================================================================
# Listening socket related methods
# ==========================================================================================
    def udp_listen_socket(self, udp_sock=None):
        '''
        Method to listen the external socket for new connections.
        '''
        message = None
        source_ip = None
        source_port = None
        try:
            if udp_sock is None:
                [message, (source_ip, source_port)] = self.socket.recvfrom(
                    self.max_input_bytes)
            else:
                [message, (source_ip, source_port)] = udp_sock.recvfrom(
                    self.max_input_bytes)
            logger.debug(
                f"Data received from outside (if any):{message}; from ip:{source_ip} " +
                f"& port:{source_port}")
        except socket.timeout:
            pass
        return message, source_ip, source_port

    def accept_new_connection(self, listening_socket):
        '''
        Method to accept a new tcp or UDP+DTLS connection
        '''
        # conn is a new socket for the new tcp  or dtls connection
        conn = None
        addr = None
        if listening_socket is not None and (listening_socket.fileno() != CLOSED_SOCKET):
            try:
                conn, addr = listening_socket.accept()

                logger.info(
                    f"Accepted a new TCP or DTLS connection from {addr}")
                conn.setblocking(False)
                events = selectors.EVENT_READ | selectors.EVENT_WRITE
                self.register_socket_in_selector(conn, events, data=addr)

            except ssl.SSLError:
                logger.exception(
                    "TLS error accepting a new TLS/TCP or DTLS/UDP connection")
            except (TypeError, socket.error):
                logger.exception("Error accepting a new connection")
        return conn, addr

    def enable_listen_socket(self):
        '''
        Method to start listening the external socket for new connections.
        '''
        if self.socket is not None:
            self.socket.listen(self.config_max_connections_queue)

        logger.info(f"Listening the socket in the port: {self.port}")

    def wait_for_events(self):
        '''
        Method to events in the sockets registered in the selector.
        '''
        events = None
        try:
            # wait for events
            events = self.selector.select(timeout=self.socket_timeout)
        except socket.timeout:
            logger.debug("Timeout waiting for events int the socket selector")

        return events
# ==========================================================================================
# Client connection methods
# ==========================================================================================

    def tcp_connect_one_socket(self, socket_to_connect):
        '''
        Method to connect a tcp socket working as client to the corresponding target
        '''
        addr = (self.ip, self.port)
        success = False

        try:
            socket_to_connect.connect_ex(addr)
            success = True
        except:
            logger.exception("Error connecting one socket")

        return success

    def tcp_connect_all_sockets(self):
        '''
        Method to connect the tcp client sockets during the first time with a given target.
        It returns a flag indication if the operation was successful or not
        '''
        for socket_to_connect in self.client_sockets:
            self.tcp_connect_one_socket(socket_to_connect)
            time.sleep(self.time_between_client_sockets_connection)

        logger.info("Waiting a while for TLS handshake")
        time.sleep(self.time_between_client_socket_close_connect)

    def tcp_or_dtls_new_client_socket(self, client_socket_id, cleaning_register):
        '''
        Method to create a new tcp/tls client connection
        '''
        # Define the network transport protocol
        if self.udp_protocol:
            socket_transport_protocol = socket.SOCK_DGRAM
        else:
            socket_transport_protocol = socket.SOCK_STREAM

        ext_socket_candidate = socket.socket(
            self.ip_version, socket_transport_protocol)

        # encryption + TCP?
        if self.encrypted and not self.udp_protocol:
            ext_socket = tls_tcp_client_socket_promotion(
                ext_socket_candidate,
                self.tls_client_default_settings,
                self.tls_client_cabundle_pem,
                self.ip,
                self.tls_validate_server_certificate,
                self.tls_client_authentication,
                self.tls_client_certchain_pem,
                self.tls_client_priv_key_pem,
                self.tls_key_protected,
                self.tls_client_key_password)

        # not encryption + TCP
        elif not self.encrypted and not self.udp_protocol:
            ext_socket = ext_socket_candidate

        # encryption + UDP = DTLS
        elif self.encrypted and self.udp_protocol:
            ext_socket = dtls_client_socket_promotion(
                ext_socket_candidate=ext_socket_candidate,
                tls_client_default_settings=self.tls_client_default_settings,
                tls_client_cabundle_pem=self.tls_client_cabundle_pem,
                tls_validate_server_certificate=self.tls_validate_server_certificate,
                tls_client_authentication=self.tls_client_authentication,
                tls_client_certchain_pem=self.tls_client_certchain_pem,
                tls_client_priv_key_pem=self.tls_client_priv_key_pem,
                tls_key_protected=self.tls_key_protected,
                tls_client_key_password=self.tls_client_key_password,
                dtls_mode=self.dtls_mode,
                cleaning_register=cleaning_register)

        # register in the selector
        socket_data = (self.ip, self.port, client_socket_id)
        events = selectors.EVENT_READ | selectors.EVENT_WRITE
        self.register_socket_in_selector(ext_socket, events, socket_data)

        # connect the client socket
        success = self.tcp_connect_one_socket(ext_socket)
        logger.info(
            f"Was the new tcp client socket with the 'id:{client_socket_id}' created successfully? {success}")

        return success, ext_socket

# ==========================================================================================
# Other D/TLS socket functions
# ==========================================================================================


def tls_tcp_server_socket_promotion(ext_socket_candidate, tls_server_certchain_pem,
                                    tls_server_priv_key_pem, tls_key_protected,
                                    tls_server_key_password, tls_client_authentication,
                                    tls_client_cabundle_pem):
    '''
    Function to apply TLS to a tcp server socket
    '''
    if interlanguage_bool_check(tls_client_authentication):
        # https://www.electricmonk.nl/log/2018/06/02/ssl-tls-client-certificate-verification-with-python-v3-4-sslcontext/
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(tls_client_cabundle_pem)
    else:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    if tls_key_protected.upper() == TLS_CLIENT_NO:
        context.load_cert_chain(
            tls_server_certchain_pem, tls_server_priv_key_pem)
    else:
        context.load_cert_chain(
            tls_server_certchain_pem, tls_server_priv_key_pem, tls_server_key_password)

    ext_socket = context.wrap_socket(ext_socket_candidate)

    return ext_socket


def tls_tcp_client_socket_promotion(
        ext_socket_candidate, tls_client_default_settings,
        tls_client_cabundle_pem, ip, tls_validate_server_certificate,
        tls_client_authentication, tls_client_certchain_pem,
        tls_client_priv_key_pem, tls_key_protected, tls_client_key_password):
    '''
    Function to apply TLS to a TCP client socket
    '''
    if interlanguage_bool_check(tls_client_authentication):
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        if tls_key_protected.upper() == TLS_CLIENT_NO:
            context.load_cert_chain(
                tls_client_certchain_pem, tls_client_priv_key_pem)
        else:
            context.load_cert_chain(
                tls_client_certchain_pem, tls_client_priv_key_pem, tls_client_key_password)
    else:
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)

    if tls_client_default_settings.upper() == TLS_CLIENT_NO:
        context.load_verify_locations(tls_client_cabundle_pem)

    if tls_validate_server_certificate.upper() == TLS_CLIENT_NO:
        context.verify_mode = ssl.CERT_OPTIONAL
        context.check_hostname = False

    ext_socket = context.wrap_socket(ext_socket_candidate, server_hostname=ip)

    return ext_socket


def get_dtls_mode(dtls_mode):
    '''
    Function to get the DTLS value mode
    '''
    # DTLS mode
    if dtls_mode.upper() == "DTLS":
        dtls = ssl.PROTOCOL_DTLS
    elif dtls_mode.upper() == "DTLSV1":
        dtls = ssl.PROTOCOL_DTLSv1
    else:
        dtls = ssl.PROTOCOL_DTLSv1_2
    return dtls


def dtls_server_socket_promotion(
        ext_socket_candidate, tls_server_certchain_pem,
        tls_server_priv_key_pem, tls_key_protected,
        tls_server_key_password, tls_client_authentication,
        tls_client_cabundle_pem, dtls_mode, cleaning_register):
    '''
    Function to enable the DTLS option for UDP server sockets
    '''
    logger.info("Using DTLS with UDP for the external server socket")
    error = False
    key_protected = tls_key_protected.upper() != TLS_CLIENT_NO
    do_patch()
    dtls = get_dtls_mode(dtls_mode)

    if len(tls_client_cabundle_pem) == 0:
        tls_client_cabundle_pem = None

    if key_protected:
        tls_server_priv_key_pem, error = load_protected_private_key(
            tls_server_priv_key_pem, tls_server_key_password)
        # add the temp file for the private key to be remvoed at the end of the execution
        cleaning_register.add_new_temp_file_location(tls_server_priv_key_pem)

    if not error:
        if interlanguage_bool_check(tls_client_authentication):
            ext_socket = ssl.wrap_socket(
                ext_socket_candidate,
                server_side=True,
                cert_reqs=ssl.CERT_REQUIRED,
                certfile=tls_server_certchain_pem,
                keyfile=tls_server_priv_key_pem,
                ssl_version=dtls,
                ca_certs=tls_client_cabundle_pem)
        else:
            ext_socket = ssl.wrap_socket(
                ext_socket_candidate,
                server_side=True,
                cert_reqs=ssl.CERT_NONE,
                certfile=tls_server_certchain_pem,
                keyfile=tls_server_priv_key_pem,
                ssl_version=dtls)
    else:
        ext_socket = None

    return ext_socket


def dtls_client_socket_promotion(
        ext_socket_candidate, tls_client_default_settings,
        tls_client_cabundle_pem, tls_validate_server_certificate,
        tls_client_authentication, tls_client_certchain_pem,
        tls_client_priv_key_pem, tls_key_protected,
        tls_client_key_password, dtls_mode, cleaning_register):
    '''
    Function to enable the DTLS option for UDP client sockets
    '''
    # https://github.com/mcfreis/pydtls
    logger.info("Using DTLS with UDP for an external client socket")
    error = False
    key_protected = tls_key_protected.upper() != TLS_CLIENT_NO
    do_patch()
    dtls = get_dtls_mode(dtls_mode)

    if key_protected:
        tls_client_priv_key_pem, error = load_protected_private_key(
            tls_client_priv_key_pem,
            tls_client_key_password)
        # add the temp file for the private key to be remvoed at the end of the execution
        cleaning_register.add_new_temp_file_location(tls_client_priv_key_pem)

    if not error:
        # Client authentication + not validate server certificate + do not use by default machine CAs
        if interlanguage_bool_check(tls_client_authentication) and (
                tls_validate_server_certificate.upper() == TLS_CLIENT_NO) and (
                tls_client_default_settings.upper() == TLS_CLIENT_NO):

            ext_socket = ssl.wrap_socket(
                ext_socket_candidate,
                keyfile=tls_client_priv_key_pem,
                cert_reqs=ssl.CERT_OPTIONAL,
                certfile=tls_client_certchain_pem,
                server_side=False,
                ca_certs=tls_client_cabundle_pem,
                ssl_version=dtls,)

        # Client authentication + not validate server certificate + use by default machine CAs
        elif interlanguage_bool_check(tls_client_authentication) and (
                tls_validate_server_certificate.upper() == TLS_CLIENT_NO) and (
                tls_client_default_settings.upper() != TLS_CLIENT_NO):

            ext_socket = ssl.wrap_socket(
                ext_socket_candidate,
                keyfile=tls_client_priv_key_pem,
                cert_reqs=ssl.CERT_OPTIONAL,
                certfile=tls_client_certchain_pem,
                server_side=False,
                ssl_version=dtls,)

        # Client authentication + validate server certificate + do not use by default machine CAs
        elif interlanguage_bool_check(tls_client_authentication) and (
                tls_validate_server_certificate.upper() != TLS_CLIENT_NO) and (
                tls_client_default_settings.upper() == TLS_CLIENT_NO):

            ext_socket = ssl.wrap_socket(
                ext_socket_candidate,
                keyfile=tls_client_priv_key_pem,
                cert_reqs=ssl.CERT_REQUIRED,
                certfile=tls_client_certchain_pem,
                server_side=False,
                ssl_version=dtls,
                ca_certs=tls_client_cabundle_pem)

        # Client authentication + validate server certificate + use by default machine CAs
        elif interlanguage_bool_check(tls_client_authentication) and (
                tls_validate_server_certificate.upper() != TLS_CLIENT_NO) and (
                tls_client_default_settings.upper() != TLS_CLIENT_NO):

            ext_socket = ssl.wrap_socket(
                ext_socket_candidate,
                keyfile=tls_client_priv_key_pem,
                cert_reqs=ssl.CERT_REQUIRED,
                certfile=tls_client_certchain_pem,
                server_side=False,
                ssl_version=dtls,)

        # not client authentication + not validate server certificate + do not use by default machine CAs
        elif not interlanguage_bool_check(tls_client_authentication) and (
                tls_validate_server_certificate.upper() == TLS_CLIENT_NO) and (
                tls_client_default_settings.upper() == TLS_CLIENT_NO):

            ext_socket = ssl.wrap_socket(
                ext_socket_candidate,
                cert_reqs=ssl.CERT_OPTIONAL,
                server_side=False,
                ssl_version=dtls,
                ca_certs=tls_client_cabundle_pem)

        # not client authentication + not validate server certificate + use by default machine CAs
        elif not interlanguage_bool_check(tls_client_authentication) and (
                tls_validate_server_certificate.upper() == TLS_CLIENT_NO) and (
                tls_client_default_settings.upper() != TLS_CLIENT_NO):

            ext_socket = ssl.wrap_socket(
                ext_socket_candidate,
                cert_reqs=ssl.CERT_OPTIONAL,
                server_side=False,
                ssl_version=dtls,)

        # not client authentication + validate server certificate + do not use by default machine CAs
        elif not interlanguage_bool_check(tls_client_authentication) and (
                tls_validate_server_certificate.upper() != TLS_CLIENT_NO) and (
                tls_client_default_settings.upper() == TLS_CLIENT_NO):

            ext_socket = ssl.wrap_socket(
                ext_socket_candidate,
                cert_reqs=ssl.CERT_REQUIRED,
                server_side=False,
                ssl_version=dtls,
                ca_certs=tls_client_cabundle_pem,)

        # not client authentication + validate server certificate + use by default machine CAs
        else:
            ext_socket = ssl.wrap_socket(
                ext_socket_candidate,
                server_side=False,
                cert_reqs=ssl.CERT_REQUIRED,
                ssl_version=dtls)
    else:
        ext_socket = None

    return ext_socket

# ==========================================================================================
# External socket initialization functions
# ==========================================================================================


def get_network_transport_protocol(transport_protocol):
    '''
    This functions provides the socket type according to the defined transport protocol  
    '''
    transport_protocol = transport_protocol.upper()
    # Define the network transport protocol
    if (transport_protocol == TRANSPORT_PROTOCOL_UDP):
        socket_transport_protocol = socket.SOCK_DGRAM
    else:
        socket_transport_protocol = socket.SOCK_STREAM

    logger.info(
        f"The external socket transport protocol is: '{transport_protocol}'")

    return socket_transport_protocol


def get_ip_version(use_ip6):
    '''
    This functions provides the socket type according to the transport protocol defined 
    '''
    # Define the network transport protocol
    if interlanguage_bool_check(use_ip6):
        socket_ip_version = socket.AF_INET6
    else:
        socket_ip_version = socket.AF_INET

    logger.info(f"Is the external socket using IPv6? {use_ip6}")

    return socket_ip_version


def init_selector(selector, client_mode, ip, port, socket_id_list, ext_socket):
    '''
    Function to initialise the selector
    '''
    # If a selector is not provided, create a new one
    if selector is None:
        selector = selectors.DefaultSelector()

    # initialization of fields of the selector
    if client_mode:  # Client
        socket_data = (ip, port, socket_id_list.pop())
        events = selectors.EVENT_READ | selectors.EVENT_WRITE
    else:  # Server
        socket_data = None
        events = selectors.EVENT_READ

    # register the tcp socket in the selector
    selector.register(ext_socket, events, data=socket_data)

    return selector


def promote_socket_candidate(
        ext_socket_candidate, transport_protocol, encrypted, client_mode, socket_timeout,
        cleaning_register, tls_server_certchain_pem=None, tls_server_priv_key_pem=None, selector=None,
        tls_client_default_settings=None, tls_client_cabundle_pem=None, socket_id_list=None,
        ip=None, port=None, dtls_mode=None, tls_validate_server_certificate=None,
        tls_key_protected=None, tls_server_key_password=None, tls_client_authentication=None,
        tls_client_certchain_pem=None, tls_client_priv_key_pem=None, tls_client_key_password=None,):
    '''
    Function to get a socket candidate and prepare it for being a final external socket
    '''
    if transport_protocol.upper() != TRANSPORT_PROTOCOL_UDP:  # TCP
        ext_socket_candidate.setblocking(False)
        if encrypted:
            logger.info("Using TLS with TCP for the external socket")
            if not client_mode:  # Server
                ext_socket = tls_tcp_server_socket_promotion(
                    ext_socket_candidate, tls_server_certchain_pem,
                    tls_server_priv_key_pem, tls_key_protected,
                    tls_server_key_password, tls_client_authentication,
                    tls_client_cabundle_pem)
            else:  # Client
                ext_socket = tls_tcp_client_socket_promotion(
                    ext_socket_candidate, tls_client_default_settings,
                    tls_client_cabundle_pem, ip, tls_validate_server_certificate,
                    tls_client_authentication, tls_client_certchain_pem,
                    tls_client_priv_key_pem, tls_key_protected,
                    tls_client_key_password)
        else:
            ext_socket = ext_socket_candidate
            logger.info("NOT Using TLS with TCP for the external socket")

        selector = init_selector(
            selector, client_mode, ip, port, socket_id_list, ext_socket)

    else:  # UDP
        ext_socket_candidate.settimeout(socket_timeout)
        if client_mode:  # CLIENT
            if encrypted:
                ext_socket = dtls_client_socket_promotion(
                    ext_socket_candidate, tls_client_default_settings,
                    tls_client_cabundle_pem, tls_validate_server_certificate,
                    tls_client_authentication, tls_client_certchain_pem,
                    tls_client_priv_key_pem, tls_key_protected,
                    tls_client_key_password, dtls_mode, cleaning_register)
            else:
                ext_socket = ext_socket_candidate
            # register the udp socket in the selector
            selector = init_selector(
                selector, client_mode, ip, port, socket_id_list, ext_socket)

        else:  # SERVER
            if encrypted:
                ext_socket = dtls_server_socket_promotion(
                    ext_socket_candidate, tls_server_certchain_pem,
                    tls_server_priv_key_pem, tls_key_protected,
                    tls_server_key_password, tls_client_authentication,
                    tls_client_cabundle_pem, dtls_mode, cleaning_register)
                # register the udp socket in the selector
                selector = init_selector(
                    selector, client_mode, ip, port, socket_id_list, ext_socket)
            else:
                ext_socket = ext_socket_candidate

    return ext_socket, selector


def get_client_sockets(num_client_conns, socket_ip_version, socket_transport_protocol,
                       transport_protocol, encrypted, socket_timeout, tls_client_default_settings,
                       tls_client_cabundle_pem, socket_id_list, ip, port, dtls_mode,
                       tls_validate_server_certificate, tls_client_authentication,
                       tls_client_certchain_pem, tls_client_priv_key_pem, tls_key_protected,
                       tls_client_key_password, cleaning_register):
    '''
    Function to create a new set of client sockets
    '''

    client_sockets = set()
    selector = None
    for i in range(0, num_client_conns):
        ext_socket_candidate = socket.socket(
            socket_ip_version, socket_transport_protocol)
        ext_socket, selector = promote_socket_candidate(
            ext_socket_candidate=ext_socket_candidate,
            transport_protocol=transport_protocol,
            encrypted=encrypted,
            client_mode=True,
            socket_timeout=socket_timeout,
            selector=selector,
            tls_client_default_settings=tls_client_default_settings,
            tls_client_cabundle_pem=tls_client_cabundle_pem,
            socket_id_list=socket_id_list,
            ip=ip,
            port=port,
            dtls_mode=dtls_mode,
            tls_validate_server_certificate=tls_validate_server_certificate,
            tls_client_authentication=tls_client_authentication,
            tls_client_certchain_pem=tls_client_certchain_pem,
            tls_client_priv_key_pem=tls_client_priv_key_pem,
            tls_key_protected=tls_key_protected,
            tls_client_key_password=tls_client_key_password,
            cleaning_register=cleaning_register)
        client_sockets.add(ext_socket)
        logger.debug(
            f"Added new client socket ready, so far: {i+1}/{num_client_conns}")

    return client_sockets, selector


def init_client_external_socket(
        ip, port, max_input_bytes, transport_protocol, socket_timeout,
        config_max_connections_queue, use_ip6, encrypted,
        tls_client_default_settings, tls_client_cabundle_pem,
        num_client_conns, socket_id_list, time_between_client_sockets_connection,
        dtls_mode, time_between_client_socket_close_connect,
        tls_validate_server_certificate, tls_client_authentication,
        tls_client_certchain_pem, tls_client_priv_key_pem,
        tls_key_protected, tls_client_key_password, cleaning_register):
    '''
    Function to initialize the external connector as a set of client sockets
    '''
    socket_transport_protocol = get_network_transport_protocol(
        transport_protocol)
    socket_ip_version = get_ip_version(use_ip6)

    # Get pythonic value of the flag 'encrypted'
    encrypted = interlanguage_bool_check(encrypted)

    client_sockets, selector = get_client_sockets(
        num_client_conns, socket_ip_version, socket_transport_protocol,
        transport_protocol, encrypted, socket_timeout, tls_client_default_settings,
        tls_client_cabundle_pem, socket_id_list, ip, port, dtls_mode,
        tls_validate_server_certificate, tls_client_authentication,
        tls_client_certchain_pem, tls_client_priv_key_pem, tls_key_protected,
        tls_client_key_password, cleaning_register)

    # External connection controller creation
    ext_conn_controller = ExtConnController(
        client_sockets=client_sockets,
        socket_ip_version=socket_ip_version,
        ip=ip,
        port=port,
        client_mode=True,
        transport_protocol=transport_protocol,
        socket_timeout=socket_timeout,
        config_max_connections_queue=config_max_connections_queue,
        max_input_bytes=max_input_bytes,
        selector=selector,
        tls_client_default_settings=tls_client_default_settings,
        tls_client_cabundle_pem=tls_client_cabundle_pem,
        encrypted=encrypted,
        time_between_client_sockets_connection=time_between_client_sockets_connection,
        time_between_client_socket_close_connect=time_between_client_socket_close_connect,
        tls_client_authentication=tls_client_authentication,
        tls_validate_server_certificate=tls_validate_server_certificate,
        tls_client_certchain_pem=tls_client_certchain_pem,
        tls_client_priv_key_pem=tls_client_priv_key_pem,
        tls_key_protected=tls_key_protected,
        tls_client_key_password=tls_client_key_password,
        dtls_mode=dtls_mode,
        cleaning_register=cleaning_register)

    return ext_conn_controller


def get_server_socket(socket_ip_version, socket_transport_protocol, ip, port, transport_protocol,
                      encrypted, socket_timeout, tls_server_certchain_pem, tls_server_priv_key_pem,
                      dtls_mode, tls_key_protected, tls_server_key_password, tls_client_authentication,
                      tls_client_cabundle_pem, cleaning_register):
    '''
    Function to create a new server side socket
    '''
    # Create a new socket
    ext_socket = None
    selector = None
    success = False
    ext_socket_candidate = socket.socket(
        socket_ip_version, socket_transport_protocol)
    try:
        ext_socket_candidate.setsockopt(
            socket.SOL_SOCKET, socket.SO_REUSEADDR, ONE_REUSE_FOR_LISTENING_SOCKET)
        ext_socket_candidate.bind((ip, port))
        success = True
    except OSError as oer:
        logging.exception(
            f"Error starting the port for listening in the port: {port}", oer)

    if success:
        ext_socket, selector = promote_socket_candidate(
            ext_socket_candidate=ext_socket_candidate,
            transport_protocol=transport_protocol,
            encrypted=encrypted,
            client_mode=False,
            socket_timeout=socket_timeout,
            tls_server_certchain_pem=tls_server_certchain_pem,
            tls_server_priv_key_pem=tls_server_priv_key_pem,
            dtls_mode=dtls_mode,
            tls_key_protected=tls_key_protected,
            tls_server_key_password=tls_server_key_password,
            tls_client_authentication=tls_client_authentication,
            tls_client_cabundle_pem=tls_client_cabundle_pem,
            cleaning_register=cleaning_register)

    return ext_socket, selector


def init_server_external_socket(
        ip, port, max_input_bytes, transport_protocol, socket_timeout,
        config_max_connections_queue, use_ip6, encrypted,
        tls_server_certchain_pem, tls_server_priv_key_pem, dtls_mode,
        tls_key_protected, tls_server_key_password, tls_client_authentication,
        tls_client_cabundle_pem, cleaning_register):
    '''
    Function to initialize the external connector as a socket server
    '''

    socket_transport_protocol = get_network_transport_protocol(
        transport_protocol)
    socket_ip_version = get_ip_version(use_ip6)

    # Get pythonic value of the flag 'encrypted'
    encrypted = interlanguage_bool_check(encrypted)

    # Create a new socket
    ext_socket, selector = get_server_socket(
        socket_ip_version, socket_transport_protocol, ip, port, transport_protocol,
        encrypted, socket_timeout, tls_server_certchain_pem, tls_server_priv_key_pem,
        dtls_mode, tls_key_protected, tls_server_key_password, tls_client_authentication,
        tls_client_cabundle_pem, cleaning_register)

    if ext_socket is not None:
        # External connection controller creation
        ext_conn_controller = ExtConnController(
            ext_socket=ext_socket,
            socket_ip_version=socket_ip_version,
            ip=ip,
            port=port,
            client_mode=False,
            transport_protocol=transport_protocol,
            socket_timeout=socket_timeout,
            config_max_connections_queue=config_max_connections_queue,
            max_input_bytes=max_input_bytes,
            encrypted=encrypted,
            selector=selector,
            tls_key_protected=tls_key_protected,
            tls_server_key_password=tls_server_key_password,
            tls_client_authentication=tls_client_authentication,
            tls_client_cabundle_pem=tls_client_cabundle_pem,
            tls_server_certchain_pem=tls_server_certchain_pem,
            tls_server_priv_key_pem=tls_server_priv_key_pem,
            dtls_mode=dtls_mode,
            cleaning_register=cleaning_register)

    return ext_conn_controller


def init_external_socket(
        ip, port, mode, transport_protocol, config_max_connections_queue,
        config_max_input_bytes, use_ip6, encrypted, tls_client_default_settings,
        tls_client_cabundle_pem, tls_server_certchain_pem, tls_server_priv_key_pem,
        num_client_conns, listening_time, socket_id_list, time_between_client_sockets_connection,
        dtls_mode, time_between_client_socket_close_connect, tls_validate_server_certificate,
        tls_key_protected, tls_server_key_password, tls_client_authentication,
        tls_client_certchain_pem, tls_client_priv_key_pem, tls_client_key_password,
        cleaning_register):
    '''
    This function initialise the external socket that interact with potential external parties. 
    Depending on the mode, it can work as client or server. In server mode, the ip means the origin 
    of connectiosn allowed; when empty, means all. In client mode, the ip is the destination to connect. 
    It returns an object with the external socket
    '''
    # https://docs.python.org/3/library/socket.html
    # https://docs.python.org/3/howto/sockets.html#socket-howto
    # https://realpython.com/python-sockets/
    # https://pythontic.com/modules/socket/udp-client-server-example
    # https://docs.python.org/3/library/ssl.html#module-ssl

    # Max number of bytes to read from the external connection
    if ((type(config_max_input_bytes) == int) and (config_max_input_bytes > 0)):
        max_input_bytes = config_max_input_bytes
    else:
        max_input_bytes = DEFAULT_BYTES_TO_READ
        logger.info(f"Default value used for max number of bytes")

    try:
        # Define the operation mode
        if mode.upper() == MODE_CLIENT:
            logger.debug("Starting the external socket in client mode...")
            ext_conn_controller = init_client_external_socket(
                ip, port, max_input_bytes, transport_protocol,
                listening_time, config_max_connections_queue,
                use_ip6, encrypted, tls_client_default_settings,
                tls_client_cabundle_pem, num_client_conns,
                socket_id_list, time_between_client_sockets_connection,
                dtls_mode, time_between_client_socket_close_connect,
                tls_validate_server_certificate, tls_client_authentication,
                tls_client_certchain_pem, tls_client_priv_key_pem,
                tls_key_protected, tls_client_key_password,
                cleaning_register)
        else:
            logger.debug("Starting the external socket in server mode...")
            ext_conn_controller = init_server_external_socket(
                ip, port, max_input_bytes, transport_protocol,
                listening_time, config_max_connections_queue,
                use_ip6, encrypted, tls_server_certchain_pem,
                tls_server_priv_key_pem, dtls_mode, tls_key_protected,
                tls_server_key_password, tls_client_authentication,
                tls_client_cabundle_pem, cleaning_register)
        # error check
        if ext_conn_controller is not None:
            success = True
            logger.info("External socket initialised successfully")
        else:
            success = False
            logger.warning("External socket cannot be initialised")

    except Exception:
        ext_conn_controller = None
        success = False
        logger.exception("Exception starting the external socket")

    return success, ext_conn_controller
