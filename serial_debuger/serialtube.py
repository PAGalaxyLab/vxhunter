# !/usr/bin/env python2
# coding=utf-8
import platform
import glob
import serial
import time


class Buffer(Exception):
    """
    List of strings with some helper routines.

    Example:

        >>> b = Buffer()
        >>> b.add("A" * 10)
        >>> b.add("B" * 10)
        >>> len(b)
        20
        >>> b.get(1)
        'A'
        >>> len(b)
        19
        >>> b.get(9999)
        'AAAAAAAAABBBBBBBBBB'
        >>> len(b)
        0
        >>> b.get(1)
        ''

    Implementation Details:

        Implemented as a list.  Strings are added onto the end.
        The ``0th`` item in the buffer is the oldest item, and
        will be received first.
    """
    def __init__(self, buffer_fill_size=None):
        self.data = []  # Buffer
        self.size = 0  # Length
        self.buffer_fill_size = buffer_fill_size

    def __len__(self):
        """
        >>> b = Buffer()
        >>> b.add('lol')
        >>> len(b) == 3
        True
        >>> b.add('foobar')
        >>> len(b) == 9
        True
        """
        return self.size

    def __nonzero__(self):
        return len(self) > 0

    def __contains__(self, x):
        """
        >>> b = Buffer()
        >>> b.add('asdf')
        >>> 'x' in b
        False
        >>> b.add('x')
        >>> 'x' in b
        True
        """
        for b in self.data:
            if x in b:
                return True
        return False

    def index(self, x):
        """
        >>> b = Buffer()
        >>> b.add('asdf')
        >>> b.add('qwert')
        >>> b.index('t') == len(b) - 1
        True
        """
        sofar = 0
        for b in self.data:
            if x in b:
                return sofar + b.index(x)
            sofar += len(b)
        raise IndexError()

    def add(self, data):
        """
        Adds data to the buffer.

        Arguments:
            data(str,Buffer): Data to add
        """
        # Fast path for ''
        if not data:
            return

        if isinstance(data, Buffer):
            self.size += data.size
            self.data += data.data
        else:
            self.size += len(data)
            self.data.append(data)

    def unget(self, data):
        """
        Places data at the front of the buffer.

        Arguments:
            data(str,Buffer): Data to place at the beginning of the buffer.

        Example:

            >>> b = Buffer()
            >>> b.add("hello")
            >>> b.add("world")
            >>> b.get(5)
            'hello'
            >>> b.unget("goodbye")
            >>> b.get()
            'goodbyeworld'
        """
        if isinstance(data, Buffer):
            self.data = data.data + self.data
            self.size += data.size
        else:
            self.data.insert(0, data)
            self.size += len(data)

    def get(self, want=float('inf')):
        """
        Retrieves bytes from the buffer.

        Arguments:
            want(int): Maximum number of bytes to fetch

        Returns:
            Data as string

        Example:

            >>> b = Buffer()
            >>> b.add('hello')
            >>> b.add('world')
            >>> b.get(1)
            'h'
            >>> b.get()
            'elloworld'
        """
        # Fast path, get all of the data
        if want >= self.size:
            data = ''.join(self.data)
            self.size = 0
            self.data = []
            return data

        # Slow path, find the correct-index chunk
        have = 0
        i = 0
        while want >= have:
            have += len(self.data[i])
            i += 1

        # Join the chunks, evict from the buffer
        data = ''.join(self.data[:i])
        self.data = self.data[i:]

        # If the last chunk puts us over the limit,
        # stick the extra back at the beginning.
        if have > want:
            extra = data[want:]
            data = data[:want]
            self.data.insert(0, extra)

        # Size update
        self.size -= len(data)

        return data

    def get_fill_size(self, size=None):
        """
        Retrieves the default fill size for this buffer class.

        Arguments:
            size (int): (Optional) If set and not None, returns the size variable back.

        Returns:
            Fill size as integer if size == None, else size.
        """
        if size is None:
            size = self.buffer_fill_size

        return size


class serialtube(object):
    def __init__(self, port=None, baudrate=115200, convert_newlines=True, bytesize=8, parity='N',
                 stopbits=1, xonxoff=False, rtscts=False, dsrdtr=False, timeout=1, newline='\r'):

        if port is None:
            if platform.system() == 'Darwin':
                port = glob.glob('/dev/tty.usbserial*')[0]
            else:
                port = '/dev/ttyUSB0'
        self.convert_newlines = convert_newlines
        self.newline = newline
        self.conn = serial.Serial(
            port=port,
            baudrate=baudrate,
            bytesize=bytesize,
            parity=parity,
            stopbits=stopbits,
            timeout=0,
            xonxoff=xonxoff,
            rtscts=rtscts,
            writeTimeout=None,
            dsrdtr=dsrdtr,
            interCharTimeout=0
        )
        self.timeout = timeout
        self.buffer = Buffer(buffer_fill_size=4096)

    @staticmethod
    def countdown_active(end_time):
        if (end_time - time.time()) >= 0:
            return True
        else:
            return False

    def recv_raw(self, numb, timeout=1.0):
        end_time = time.time() + timeout
        if not self.conn:
            raise EOFError
        while self.conn and self.countdown_active(end_time):
            data = self.conn.read(numb)
            if data:
                return data
            time.sleep(0.1)

        return None

    def send_raw(self, data):
        if not self.conn:
            raise EOFError

        if self.convert_newlines:
            data = data.replace('\n', '\r\n')

        while data:
            n = self.conn.write(data)
            data = data[n:]
        self.conn.flush()

    def settimeout_raw(self, timeout):
        pass

    def can_recv_raw(self, timeout):
        end_time = time.time() + timeout
        while self.conn and self.countdown_active(end_time):
            if self.conn.inWaiting():
                return True
            time.sleep(0.1)
        return False

    def connected_raw(self, direction):
        return self.conn is not None

    def close(self):
        if self.conn:
            self.conn.close()
            self.conn = None

    def shutdown_raw(self, direction):
        self.close()

    def sendlinethen(self, delim, data, timeout=1.0):
        self.send(data + self.newline)
        return self.recvuntil(delims=delim, timeout=timeout)

    def recvuntil(self, delims, drop=False, timeout=1.0):
        # Convert string into singleton tupple
        if isinstance(delims, (str, unicode)):
            delims = (delims,)

        # Longest delimiter for tracking purposes
        longest = max(map(len, delims))

        # Cumulative data to search
        data = []
        top = ''

        end_time = time.time() + timeout
        while self.countdown_active(end_time):
            try:
                res = self.recv(timeout=self.timeout)
            except Exception:
                self.unrecv(''.join(data) + top)
                raise

            if not res:
                self.unrecv(''.join(data) + top)
                return ''

            top += res
            start = len(top)
            for d in delims:
                j = top.find(d)
                if start > j > -1:
                    start = j
                    end = j + len(d)
            if start < len(top):
                self.unrecv(top[end:])
                if drop:
                    top = top[:start]
                else:
                    top = top[:end]
                return ''.join(data) + top
            if len(top) > longest:
                i = -longest - 1
                data.append(top[:i])
                top = top[i:]

        return ''

    def send(self, data):
        self.send_raw(data)

    def recvrepeat(self, timeout):
        '''

        :param timeout:
        :return:
        '''
        try:
            while self._fillbuffer(timeout=timeout):
                pass
        except EOFError:
            pass

        return self.buffer

    def _fillbuffer(self, timeout=1.0):
        data = self.recv_raw(self.buffer.get_fill_size(), timeout=timeout)

        if data:
            self.buffer.add(data)

        return data

    def recv(self, numb=4096, timeout=1.0):
        numb = self.buffer.get_fill_size(numb)
        return self._recv(numb, timeout) or ''

    def unrecv(self, data):
        self.buffer.unget(data)

    def _recv(self, numb=None, timeout=1.0):
        """_recv(numb = 4096, timeout = default) -> str

        Receives one chunk of from the internal buffer or from the OS if the
        buffer is empty.
        """
        numb = self.buffer.get_fill_size(numb)

        # No buffered data, could not put anything in the buffer
        # before timeout.
        if not self.buffer and not self._fillbuffer(timeout):
            return ''

        return self.buffer.get(numb)