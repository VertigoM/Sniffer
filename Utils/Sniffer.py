from scapy.all import *
from multiprocessing import Process

logger = logging.getLogger('standard')

class Sniffer(object):
    # def __init__(self, *args, **kwargs):
    #     self.args = args
    #     self.kwargs = kwargs
    #     self.process: Process = None
    def __new__(cls):
        if not hasattr(cls, 'instance'):
            cls.instance = super(Sniffer, cls).__new__(cls)
            cls.process: Process = None
            
            cls.M_MAC = Ether().src
        return cls.instance

    """Setup wrapper over a multiprocessing Process which
    can be started/stopped programatically via start & stop functions
    """
    @classmethod
    def _setup_process(cls, **kwargs) -> None:
        cls.process = Process(
            target=cls._run,
            kwargs=kwargs,
            daemon=True
        )

    def _run(**kwargs):
        sniff(**kwargs)

    @classmethod
    def start(cls, **kwargs):
        try:
            if cls.process.is_alive():
                logger.debug(f"Process already running: PID:{cls.process.pid}")
                return
            
        except AttributeError as attributeError:
            logger.error(f"Sniffer not set up yet:{attributeError}")
            pass
        
        logger.info("\tSetting up sniffer...")
        cls._setup_process(**kwargs)
        if cls.process is not None:
            cls.process.start()
            logger.debug(f"Started Sniffer process with PID: {cls.process.pid}")

    @classmethod
    def stop(cls):
        if not cls.process:
            return
        if cls.process.is_alive():
            logger.info("Stopping sniffer.")
            cls.process.terminate()
        cls.process.join()
    
    @staticmethod    
    def get_offline_process(offline, **kwargs):
        packets = sniff(offline=offline, **kwargs, session=TCPSession)
        sessions = packets.sessions()
        return packets, sessions
