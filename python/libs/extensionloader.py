import logging
import inspect
import importlib
import threading
import time
import signal
import os
import json
from http.client import HTTPConnection

from extensions.base.burpextensionapi import BurpExtensionApi
from libs.registry import Registry

LOGGER = logging.getLogger(__name__)


class ExtensionLoader(threading.Thread):

    old_handler = None
    old_handler_dev = None

    def __init__(self):
        super().__init__()
        self.ext_args = []

    def run(self):
        self.load_ext()

    def load_ext(self):
        # make sure the flask app is up
        time.sleep(0.4)
        for extension in self.ext_args:
            # noinspection PyBroadException
            try:
                ext_clazz = None
                import_path = 'extensions.{}'.format(extension)
                # try to import module
                mod = importlib.import_module(import_path)
                # get class information, last class counts
                for _, clazz in inspect.getmembers(mod):
                    # make sure everything is as expected and exclude base class
                    if inspect.isclass(clazz) and clazz.__name__ != BurpExtensionApi.__name__ and \
                            issubclass(clazz, BurpExtensionApi) and import_path == clazz.__module__:
                        ext_clazz = clazz
                if ext_clazz is not None:
                    # create extensions object
                    inst = ext_clazz()
                    # register object
                    inst.register()
                    LOGGER.info('Registered extension: {}'.format(extension))
            except Exception:
                LOGGER.exception('Error while trying to load extension: {}'.format(extension))
                exit(1)

    @staticmethod
    def unregister_all(_signal, _frame):
        if 'true' == os.environ.get('WERKZEUG_RUN_MAIN'):
            # noinspection PyBroadException
            try:
                # somehow, calling the function in BurpExtensionApi does not seem to work here
                # -> re-implement
                client = HTTPConnection(BurpExtensionApi.TARGET_HOST, BurpExtensionApi.TARGET_PORT)
                client.request('POST', '/resetall', None,
                               {'Content-type': 'application/json', 'Authorization': BurpExtensionApi.AUTH_TOKEN})
                data = client.getresponse().read()
                json_response = json.loads(data)
                if 'ok' == json_response['status']:
                    Registry.unregister_all()
                    LOGGER.info('Un-Registration for all extensions successful')
                else:
                    LOGGER.warning('Error while un-registering all extensions')
            except Exception:
                LOGGER.exception('Error while cleaning up')
            finally:
                # send signal to old handler
                signal.signal(signal.SIGINT, ExtensionLoader.old_handler)
                # try to exit
                exit(0)
