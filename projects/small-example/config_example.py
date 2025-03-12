import configparser

class Config:
    def __init__(self, ini_file):
        self.config = configparser.ConfigParser()
        self.config.read(ini_file)

        for section in self.config.sections():
            section_obj = type(section, (), {})
            for key, value in self.config.items(section):
                setattr(section_obj, key, value)
            setattr(self, section, section_obj)

config = Config('./targets/examples/config.ini')

database_host = config.database.host
api_key = config.api.api_key

print(database_host)
print(api_key)