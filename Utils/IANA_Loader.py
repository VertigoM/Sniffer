import pandas as pd
"""
    Internet Assigned Numbers Authority
"""
class IANA_Loader(object):
    def __new__(cls):
        if not hasattr(cls, 'instance'):
            cls.instance = super(IANA_Loader, cls).__new__(cls)
            
            dataframe = pd.read_csv('resources/protocol-numbers.csv')
            dataframe.set_index('Decimal', inplace=True)
            
            cls._protocol_number_dict = dataframe.to_dict()['Keyword']
        return cls.instance

    @classmethod
    def get_protocol(cls, value: int) -> str:
        return cls._protocol_numbers_dict.get(str(value))
