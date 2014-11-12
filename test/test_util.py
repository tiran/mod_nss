import socket
import time
import subprocess

def host_port_open(host, port, socket_type=socket.SOCK_STREAM, socket_timeout=None):
    for res in socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket_type):
        af, socktype, proto, canonname, sa = res
        try:
            try:
                s = socket.socket(af, socktype, proto)
            except socket.error:
                s = None
                continue

            if socket_timeout is not None:
                s.settimeout(socket_timeout)

            s.connect(sa)

            if socket_type == socket.SOCK_DGRAM:
                s.send('')
                s.recv(512)

            return True
        except socket.error, e:
            pass
        finally:
            if s:
                s.close()

    return False

def wait_for_open_ports(host, ports, timeout=0):
    """
    Wait until the specified port(s) on the remote host are open. Timeout
    in seconds may be specified to limit the wait. If the timeout is
    exceeded, socket.timeout exception is raised.
    """
    if not isinstance(ports, (tuple, list)):
        ports = [ports]

    op_timeout = time.time() + timeout

    for port in ports:
        while True:
            port_open = host_port_open(host, port)

            if port_open:
                break
            if timeout and time.time() > op_timeout: # timeout exceeded
                raise socket.timeout()
            time.sleep(1)

def shell_quote(string):
    return "'" + string.replace("'", "'\\''") + "'"

def run(args):
    """
    Execute a command and return stdin, stdout and the process return code.

    :param args: List of arguments for the command
    """
    p_in = None
    p_out = None

    p_out = subprocess.PIPE
    p_err = subprocess.PIPE

    arg_string = ' '.join(shell_quote(a) for a in args)

    try:
        p = subprocess.Popen(args, stdout=p_out, stderr=p_err,
                             close_fds=True)
        stdout,stderr = p.communicate(None)
    except KeyboardInterrupt:
        p.wait()
        raise

    return (stdout, stderr, p.returncode)


def assert_equal(got, expected):
    if got.strip() != expected.strip():
        raise AssertionError(
            "assert_deepequal: expected != got. " \
            "expected = %r got = %r" %
            (expected, got)
        )
