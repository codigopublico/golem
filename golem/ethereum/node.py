import atexit
import shutil

from devp2p.crypto import privtopub
from ethereum.keys import privtoaddr
from ethereum.transactions import Transaction
from ethereum.utils import normalize_address, denoms
from datetime import datetime
from distutils.version import StrictVersion
import logging
import os
import re
import requests
import subprocess
import sys
import tempfile
import threading
import time
from web3 import Web3, IPCProvider

from golem.core.common import is_windows, DEVNULL, is_frozen
from golem.environments.utils import find_program
from golem.report import report_calls, Component
from golem.utils import encode_hex, decode_hex
from golem.utils import find_free_net_port
from golem.utils import tee_target

log = logging.getLogger('golem.ethereum')


GENESES = {
    '0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3':
        'mainnet',  # noqa
    '0x41941023680923e0fe4d74a34bdac8141f2540e3ae90623718e47d66d1ca4a2d':
        'ropsten',  # noqa
    '0x6341fd3daf94b748c72ced5a5b26028f2474f5f00d824504e4fa37a75767e177':
        'rinkeby',  # noqa
}

BLOCK_HASHES = {
    'rinkeby': {
        1035301: ''
    }
}


def tETH_faucet_donate(addr):
    addr = normalize_address(addr)
    URL_TEMPLATE = "http://188.165.227.180:4000/donate/{}"
    request = URL_TEMPLATE.format(addr.hex())
    response = requests.get(request)
    if response.status_code != 200:
        log.error("tETH Faucet error code {}".format(response.status_code))
        return False
    response = response.json()
    if response['paydate'] == 0:
        log.warning("tETH Faucet warning {}".format(response['message']))
        return False
    # The paydate is not actually very reliable, usually some day in the past.
    paydate = datetime.fromtimestamp(response['paydate'])
    amount = int(response['amount']) / denoms.ether
    log.info("Faucet: {:.6f} ETH on {}".format(amount, paydate))
    return True


class Faucet(object):
    PRIVKEY = "{:32}".format("Golem Faucet").encode()
    PUBKEY = privtopub(PRIVKEY)
    ADDR = privtoaddr(PRIVKEY)

    @staticmethod
    def gimme_money(ethnode, addr, value):
        nonce = ethnode.get_transaction_count(encode_hex(Faucet.ADDR))
        addr = normalize_address(addr)
        tx = Transaction(nonce, 1, 21000, addr, value, '')
        tx.sign(Faucet.PRIVKEY)
        h = ethnode.send(tx)
        log.info("Faucet --({} ETH)--> {} ({})".format(value / denoms.ether,
                                                       encode_hex(addr), h))
        h = decode_hex(h[2:])
        return h


class NodeProcess(object):
    MIN_GETH_VERSION = '1.7.2'
    MAX_GETH_VERSION = '1.7.999'
    IPC_CONNECTION_TIMEOUT = 10

    SUBPROCESS_PIPES = dict(
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=DEVNULL
    )

    def __init__(self, datadir):
        self.datadir = datadir
        self.__prog = find_program('geth')
        if not self.__prog:
            raise OSError("Ethereum client 'geth' not found")

        output, _ = subprocess.Popen(
            [self.__prog, 'version'],
            **self.SUBPROCESS_PIPES
        ).communicate()

        match = re.search("Version: (\d+\.\d+\.\d+)",
                          str(output, 'utf-8')).group(1)
        ver = StrictVersion(match)
        if ver < self.MIN_GETH_VERSION or ver > self.MAX_GETH_VERSION:
            e_description =\
                "Incompatible geth version: {}. Expected >= {} and <= {}".\
                format(ver, self.MIN_GETH_VERSION, self.MAX_GETH_VERSION)
            raise OSError(e_description)
        log.info("geth {}: {}".format(ver, self.__prog))

        self.__ps = None  # child process

    def is_running(self):
        return self.__ps is not None

    @report_calls(Component.ethereum, 'node.start')
    def start(self, port=None, init_chain=True):
        if self.__ps is not None:
            raise RuntimeError("Ethereum node already started by us")

        # Init geth datadir
        chain = 'rinkeby'
        geth_log_dir = os.path.join(self.datadir, "logs")
        geth_log_path = os.path.join(geth_log_dir, "geth.log")
        geth_datadir = os.path.join(self.datadir, 'ethereum', chain)

        os.makedirs(geth_log_dir, exist_ok=True)
        os.makedirs(geth_datadir, exist_ok=True)

        if port is None:
            port = find_free_net_port()

        # Build unique IPC/socket path. We have to use system temp dir to
        # make sure the path has length shorter that ~100 chars.
        tempdir = tempfile.gettempdir()
        ipc_file = '{}-{}'.format(chain, port)
        ipc_path = os.path.join(tempdir, ipc_file)

        common_args = [
            self.__prog,
            '--rinkeby',
            '--syncmode=light',
            '--datadir={}'.format(geth_datadir),
        ]

        args = common_args + [
            '--port={}'.format(port),
            '--ipcpath={}'.format(ipc_path),
            '--nousb',
            '--verbosity', '3',
        ]

        if init_chain:
            self._init_chain(common_args, chain)

        log.info("Starting Ethereum node: `{}`".format(" ".join(args)))
        self.__ps = subprocess.Popen(args, **self.SUBPROCESS_PIPES)

        # tee_kwargs = {
        #     'prefix': 'geth: ',
        #     'proc': self.__ps,
        #     'path': geth_log_path,
        # }
        # tee_thread = threading.Thread(name='geth-tee', target=tee_target,
        #                               kwargs=tee_kwargs)
        # tee_thread.start()

        atexit.register(lambda: self.stop())

        if is_windows():
            # On Windows expand to full named pipe path.
            ipc_path = r'\\.\pipe\{}'.format(ipc_path)

        self.web3 = Web3(IPCProvider(ipc_path))
        CHECK_PERIOD = 0.1
        wait_time = 0
        while not self.web3.isConnected():
            if wait_time > self.IPC_CONNECTION_TIMEOUT:
                raise OSError("Cannot connect to geth at {}".format(ipc_path))
            time.sleep(CHECK_PERIOD)
            wait_time += CHECK_PERIOD

        identified_chain = self._identify_chain()
        if identified_chain != chain:
            raise OSError("Wrong '{}' Ethereum chain".format(identified_chain))

        if not self._validate_chain(chain):
            self.stop()
            self._remove_chain(geth_datadir)
            return self.start()

        log.info("Node started in %ss: `%s`", wait_time, " ".join(args))

    @report_calls(Component.ethereum, 'node.stop')
    def stop(self):
        if self.__ps:
            start_time = time.clock()

            try:
                self.__ps.terminate()
                self.__ps.wait()
            except subprocess.CompletedProcess:
                log.warning("Cannot terminate node: process {} no longer exists"
                            .format(self.__ps.pid))

            self.__ps = None
            duration = time.clock() - start_time
            log.info("Node terminated in {:.2f} s".format(duration))

    def _init_chain(self, common_args, chain):
        if is_frozen():
            pipes = self.SUBPROCESS_PIPES
            this_dir = os.path.join(os.path.dirname(sys.executable),
                                    'golem', 'ethereum')
        else:
            pipes = dict()
            this_dir = os.path.dirname(__file__)

        init_file = os.path.join(this_dir, chain + '.json')
        log.info("init file: {}".format(init_file))

        args = common_args + [
            'init',
            init_file
        ]

        process = subprocess.Popen(args, **pipes)
        process.wait()

        if process.returncode != 0:
            error = "geth init failed with code {}".format(process.returncode)
            log.error(error)
            raise OSError(error)

    @staticmethod
    def _remove_chain(geth_datadir):
        """Remove current chain data"""
        log.info("Removing geth's chain database")

        chaindata = os.path.join(geth_datadir, 'geth', 'chaindata')
        lightchaindata = os.path.join(geth_datadir, 'geth', 'lightchaindata')

        for directory in [chaindata, lightchaindata]:
            if os.path.exists(directory):
                shutil.rmtree(directory)

        log.info("Geth's chain database removed")

    def _identify_chain(self):
        """Check what chain the Ethereum node is running."""
        genesis = self.web3.eth.getBlock(0)['hash']
        chain = GENESES.get(genesis, 'unknown')
        log.info("{} chain ({})".format(chain, genesis))
        return chain

    def _validate_chain(self, chain):
        blocks = BLOCK_HASHES.get(chain)
        if not blocks:
            return True

        for block_num, block_hash in blocks.items():

            try:
                block = self.web3.eth.getBlock(block_num)
            except ValueError as err:
                message = self._parse_web3_error_message(err).lower()

                if message == 'no trusted canonical hash trie':
                    log.warning('Block not downloaded: %s', block_num)
                elif message == 'no suitable peers available':
                    log.warning('Malformed chain: %s', message)
                    return False

            if block and block_hash != block['hash']:
                log.warning('Invalid hash of block {}: {}, expected {}'
                            .format(block_num, block['hash'], block_hash))
                return False

        return True

    @staticmethod
    def _parse_web3_error_message(err: ValueError):
        if not err or not err.args or not isinstance(err.args[0], dict):
            return
        return err.args[0].get('message')

