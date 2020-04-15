import logging
import uuid


LOGGER = logging.getLogger(__name__)


class Registry:

    _REGISTRATION_NAME = {}
    _REGISTRATION_ID = {}

    def __init__(self):
        pass

    @classmethod
    def register(cls, name, ext_instance):
        try:
            cls._REGISTRATION_NAME[name]
            LOGGER.error('')
            LOGGER.error('!!!!!!! --------------------------------------------------------- !!!!!!!')
            LOGGER.error('Duplicate extension name: "{}". Extension names have to be unique!'.format(name))
            LOGGER.error('This will lead to undesired side effects (your extension will probably not work)!')
            LOGGER.error('YOU SHOULD FIX THIS!')
            LOGGER.error('!!!!!!! --------------------------------------------------------- !!!!!!!')
            LOGGER.error('')
        except KeyError:
            pass
        reg_id = cls.generate_id()
        cls._REGISTRATION_NAME[name] = ext_instance
        cls._REGISTRATION_ID[reg_id] = ext_instance

        return reg_id

    @classmethod
    def unregister(cls, name):
        try:
            instance = cls._REGISTRATION_NAME[name]
            del cls._REGISTRATION_ID[instance.reg_id]
            del cls._REGISTRATION_NAME[name]
            LOGGER.info('Removed extension: {}'.format(name))
        except KeyError:
            LOGGER.error('Unknown extension: {}'.format(name))

    @classmethod
    def unregister_all(cls):
        cls._REGISTRATION_ID = {}
        cls._REGISTRATION_NAME = {}

    @classmethod
    def get_by_id(cls, reg_id):
        try:
            return cls._REGISTRATION_ID[reg_id]
        except KeyError:
            LOGGER.warning('Unknown id: {}'.format(reg_id))
        return None

    @classmethod
    def get_registered_names(cls):
        return cls._REGISTRATION_NAME.keys()

    @classmethod
    def get_registered_ids(cls):
        return list(cls._REGISTRATION_ID.keys())

    @classmethod
    def generate_id(cls):
        return str(uuid.uuid4())
