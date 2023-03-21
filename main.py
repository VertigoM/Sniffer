import logging
import logging.config
import yaml
from UI.ui import *


def main():
    play()


if __name__ == '__main__':
    with open("./logging.yaml", "r") as stream:
        config = yaml.load(stream, Loader=yaml.FullLoader)
    logging.config.dictConfig(config)
    main()
