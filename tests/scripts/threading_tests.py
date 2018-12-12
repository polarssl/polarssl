#! /usr/bin/env python

import sys
import subprocess
import time
import signal
import threading
import os
import queue
import argparse

CLIENT_CMD               = ["./programs/ssl/ssl_client2"]
CLIENT_TIMEOUT_SEC       = 10
CLIENT_POLL_INTERVAL_SEC = 1
SERVER_CMD               = ["./programs/ssl/ssl_pthread_server"]
SERVER_TIMEOUT_SEC       = 10
SERVER_POLL_INTERVAL_SEC = 5
SERVER_STOP_TIMEOUT_SEC  = 3
SERVER_TERM_SIGNAL       = signal.SIGUSR1
SERVER_KILL_SIGNAL       = signal.SIGKILL

TOTAL_CLIENTS            = 5

"""
Parent class that represents an end point (client or server).

This class is not intended to be instanciated directly. It contains member
functions that can be used to monitor the state of a process over some
specified time.
"""
class EndPointThread(threading.Thread):
    """
    Initialise the object.

    @param[in] queue
               The shared, thread-safe queue that can be used to post mesages
               from the main thread.
    @param[in] timeout
               Length of time in seconds to supervise the process for.
    @param[in] poll_interval
               The interval of time in seconds before the process is monitored.
    @param[in] cmd
               List containing the shell command that is passed to
               subprocess.Popen() to start the process.
    """
    def __init__(self, queue, timeout, poll_interval, cmd):
        threading.Thread.__init__(self)
        self.timeout = timeout
        self.poll_interval = poll_interval
        self.process = None
        self.cmd = cmd
        self.ret_code = None
        self.output = None
        self.queue = queue
        self.killed = False

    """
    Supervise an active process.

    Supervise the process pointed to by the internal members of this object.
    """
    def poll_process(self):
        acc_time = 0

        # Apparently we cannot spawn a process and wait with a timeout if
        # we pipe stdout and stderr, so we use the subprocess.poll() call
        # periodically to check whether the client process terminated.
        while acc_time <= self.timeout:
            time.sleep(self.poll_interval)
            # Poll the queue to see if we need to stop. This normally happens
            # when the test application has been killed.
            if not self.queue.empty():
                self.queue.get(block=True)
                self.killed = True
                break
            self.ret_code = self.process.poll()
            if self.ret_code is not None:
                break
            acc_time += self.poll_interval

"""
Class that can be used to start and monitor SSL clients.
"""
class Client(EndPointThread):
    """
    Initialise a Client object.

    @param[in] queue
               The shared, thread-safe queue that can be used to post mesages
               from the main thread.
    @param[in] timeout
               Length of time in seconds to supervise the process for.
    @param[in] poll_interval
               The interval of time in seconds before the process is monitored.
    @param[in] cmd
               List containing the shell command that is passed to
               subprocess.Popen() to start the process.
    """
    def __init__(self, queue, timeout, poll_interval, cmd):
        EndPointThread.__init__(self, queue, timeout, poll_interval, cmd)

    """
    Overwridden threading.run().

    This is the method called by the threading API to start the Client in a
    separate thread. It starts the SSL client with the configured parameters
    and supervises the child process.
    """
    def run(self):
        self.process = subprocess.Popen(self.cmd, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT)

        self.poll_process()

        self.ret_code = self.process.poll()
        if self.killed:
            # The test program was killed.
            self.process.kill()
            return
        elif self.ret_code is None:
            # Process has not terminated, kill it.
            self.process.kill()
        self.output = self.process.communicate()[0]

"""
Class that can be used to start and monitor SSL servers.
"""
class Server(EndPointThread):
    """
    Initialise a Client object.

    @param[in] queue
               The shared, thread-safe queue that can be used to post mesages
               from the main thread.
    @param[in] timeout
               Length of time in seconds to supervise the process for.
    @param[in] poll_interval
               The interval of time in seconds before the process is monitored.
    @param[in] cmd
               List containing the shell command that is passed to
               subprocess.Popen() to start the process.
    """
    def __init__(self, queue, timeout, poll_interval, cmd, term_signal, kill_signal):
        EndPointThread.__init__(self, queue, timeout, poll_interval, cmd)
        self.term_signal = term_signal
        self.kill_signal = kill_signal

    """
    Overwridden threading.run().

    This is the method called by the threading API to start the Server in a
    separate thread. It starts the SSL server with the configured parameters
    and supervises the child process.
    """
    def run(self):
        self.process = subprocess.Popen(self.cmd, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT)

        self.poll_process()

        self.ret_code = self.process.poll()
        if self.killed and self.ret_code is None:
            # The test program has been killed.
            self.process.kill()
            return
        elif self.ret_code is None:
            # Finished test, gracefully stop the server.
            self.process.send_signal(self.term_signal)
            time.sleep(SERVER_STOP_TIMEOUT_SEC)
            self.ret_code = self.process.poll()
            if self.ret_code is None:
                self.process.kill()
        self.output = self.process.communicate()[0]

"""
Class that encapsulates the components of a multithreaded test.
"""
class Test:
    """
    Create a test object.

    @param[in] cmdline_args
               List of command line arguments.
    """
    def __init__(self, cmdline_args):
        self.is_pass = True
        self.server = None
        self.clients = []
        self.queue = queue.Queue()

        signal.signal(signal.SIGINT, self.signal_handler)

        self.parse_cmdline_args(cmdline_args)

    """
    Parse the command line arguments passed to the test program.

    @param[in] cmdline_args
               List of command line arguments.
    """
    def parse_cmdline_args(self, cmdline_args):
        parser = argparse.ArgumentParser(description="This program runs a "
            "stress test for mbed TLS multithreaded servers using pthreads.")

        parser.add_argument("-l", "--log-dir", action="store", type=str,
            required=False, default=None, help="Directory where log files will"
            " be stored.")
        parser.add_argument("-j", "--max-clients", action="store", type=int,
            required=False, default=TOTAL_CLIENTS, help="Maximum number of "
            "client threads to use for the test.")
        parser.add_argument("-s", "--server-timeout", action="store", type=int,
            required=False, default=SERVER_TIMEOUT_SEC, help="Server timeout "
            "in seconds.")
        parser.add_argument("-c", "--client-timeout", action="store", type=int,
            required=False, default=CLIENT_TIMEOUT_SEC, help="Client timeout "
            "in seconds.")

        parsed_args = parser.parse_args()
        self.log_dir = parsed_args.log_dir
        self.log_filename_fmt = "o-{0}-" + str(int(time.time())) + ".log"
        self.max_clients = parsed_args.max_clients
        self.server_timeout = parsed_args.server_timeout
        self.client_timeout = parsed_args.client_timeout

        if self.max_clients <= 0:
            raise ValueError("Maximum clients must be a positive integer "
                "greater than 0.")
        elif self.server_timeout <= 0:
            raise ValueError("Server timeout must be a positive integer "
                "greater than 0.")
        elif self.client_timeout <= 0:
            raise ValueError("Client timeout must be a positive integer "
                "greater than 0.")

    """
    Signal handler registered to handle SIGTERM.

    @param[in] signum
               The signal number.
    @param[in] frame
    """
    def signal_handler(self, signum, frame):
        exit_code = os.EX_OK

        if signum == signal.SIGINT:
            print "Received signal SIGINT. Stopping all threads, please wait..."
            for i in range(len(self.clients) + 1):
                self.queue.put(signal.SIGINT, block=False)
                time.sleep(max(SERVER_POLL_INTERVAL_SEC, CLIENT_POLL_INTERVAL_SEC) + 1)
                if threading.active_count() > 1:
                    print "Failed to stop threads before timeout!"
                    exit_code = os.EX_SOFTWARE
            print "Writing log files (if any)..."
            self.check_endpoints_status()
            sys.exit(exit_code)

    """
    Write a string to a log file.

    @param[in] endpoint
               String describing the endpoint (server or client).
    @param[in] ret_code
               The return code of the end point.
    @param[in] output
               String containing the console output.
    """
    def write_log_file(self, endpoint, ret_code, output):
        if self.log_dir is None:
            return
        filepath = os.path.join(self.log_dir,
            self.log_filename_fmt.format(endpoint))
        with open(filepath, "w") as log_file:
            log_file.write("Return code is {0}".format(
                ret_code if ret_code is not None else ""))
            log_file.write(os.linesep)
            log_file.write("Console output:")
            log_file.write(os.linesep)
            log_file.write(output if output is not None else "")

    """
    Check each of the endpoint objects and decide whether the test passed or
    failed. Also write any failures to the log files.
    """
    def check_endpoints_status(self):
        if self.server.ret_code != 0:
            self.write_log_file("serv", self.server.ret_code,
                self.server.output)
            self.is_pass = False

        for index, client in enumerate(self.clients):
            if client.ret_code != 0:
                self.write_log_file("cli" + str(index), client.ret_code,
                    client.output)
                self.is_pass = False

    """
    Start SSL server and clients each in a separate thread. Then based on the
    return code decide if the test passed or failed.
    """
    def run_test(self):
        print "Starting server..."
        self.server = Server(self.queue, self.server_timeout,
            SERVER_POLL_INTERVAL_SEC,
            SERVER_CMD + ["max_threads={0}".format(self.max_clients)],
            SERVER_TERM_SIGNAL, SERVER_KILL_SIGNAL)
        self.server.start()
        time.sleep(3)

        print "Starting {0} clients...".format(self.max_clients)
        for i in range(self.max_clients):
            if not self.server.is_alive():
                # Stop if the server has terminated.
                break
            self.clients.append(Client(self.queue, self.client_timeout,
                CLIENT_POLL_INTERVAL_SEC, CLIENT_CMD))
            self.clients[-1].start()

        print "Waiting for server to complete..."
        if self.server.is_alive():
            self.server.join()

        print "Waiting for clients to complete..."
        for index, client in enumerate(self.clients):
            if client.is_alive():
                print ("ERROR: Client {0} still running after end of test. " +
                    "Waiting for timeout").format(index)
                client.join()
                self.is_pass = False

        print "Writing log files (if any)..."
        self.check_endpoints_status()

def main():
    test = Test(sys.argv[1:])
    test.run_test()
    exit_code = os.EX_SOFTWARE

    if test.is_pass:
        print "Result:", "PASS"
        exit_code = os.EX_OK
    else:
        print "Result:", "FAIL"

    sys.exit(exit_code)

if __name__ == "__main__":
    main()
