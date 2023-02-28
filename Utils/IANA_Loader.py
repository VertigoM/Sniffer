import pandas as pd
"""
    Internet Assigned Numbers Authority
"""
class IANA_Loader(object):
    __slots__ = [
        '_ieee_802_numbers_dict',
        '_protocol_numbers_dict'
    ]

    def __init__(self, *args, **kwargs):
        self._ieee_802_numbers_dict = self._load_ieee_802_numbers_into_memory()
        self._protocol_numbers_dict = self._load_protocol_numbers_into_memory()

    def _load_protocol_numbers_into_memory(self) -> dict:
        print('called:_load_protocol_numbers_into_memory')
        dataframe = pd.read_csv('resources/protocol-numbers.csv')
        dataframe.set_index('Decimal', inplace=True)
        return dataframe.to_dict()['Keyword']

    def _load_ieee_802_numbers_into_memory(self):
        print('called:_load_ieee_802_numbers_into_memory')
        dataframe = pd.read_csv('resources/ieee-802-numbers.csv')
        # dataframe.set_index()
        
    def get_protocol(self, value: int) -> str:
        return self._protocol_numbers_dict.get(str(value))
