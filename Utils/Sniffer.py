from scapy.all import *
from multiprocessing import Process


class Sniffer(object):
    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs
        self.process = None

    def _setup_process(self) -> None:
        self.process = Process(
            target=self._run,
            args=self.args,
            kwargs=self.kwargs,
            name='sniffing_process'
        )
        self.process.daemon = True

    def _run(self, *args, **kwargs):
        sniff(*args, **kwargs)

    def start(self):
        try:
            if self.process.is_alive():
                return
        except AttributeError:
            pass
        self._setup_process()
        if self.process is not None:
            self.process.start()

    def stop(self):
        if self.process.is_alive():
            self.process.terminate()
        self.process.join()
