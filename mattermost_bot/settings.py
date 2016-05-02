import importlib
import sys
import os

DEBUG = False

PLUGINS = [
    'plugins',
]
PLUGINS_ONLY_DOC_STRING = False

BOT_URL = 'http://localhost:8065/api/v1'
BOT_LOGIN = 'bot@rsa.com'
BOT_PASSWORD = 'iocbot'
BOT_TEAM = 'lior'

DATASOURCE_SETTINGS = {
    'vtpriv': {
        'api_key': 'vt_apikey',
        'max_results': 50,
    },
    'vtpub': {
        'api_key': 'vt_apikey',
        'max_results': 25,      # Use low value to avoid large responses that cause
                                # the bot to lose connection with the server
    },
    'atsinc': {
        'user': 'atsinc_user',
        'pass': 'atsinc_pass',
        'host': 'atsinc_ip',
        'db':   'atsinc_db',
        'table': 'atsinc_table',
        'max_results': 50,
    },
    'sparta': {
        'user': 'sparta_user',
        'pass': 'sparta_pass',
        'url':  'sparta_url',
        'max_results': 50,
    },
    'portal': {
        'host_ip': 'ip',
        'host_port': 'port',
        'token': 'fwporta_token',
        'max_results': 50,
    }
}


IGNORE_NOTIFIES = ['@channel', '@all']
WORKERS_NUM = 10

DEFAULT_REPLY_MODULE = None
DEFAULT_REPLY = None

'''
If you use Mattermost Web API to send messages (with send_webapi()
or reply_webapi()), you can customize the bot logo by providing Icon or Emoji.
If you use Mattermost API to send messages (with send() or reply()),
the used icon comes from bot settings and Icon or Emoji has no effect.
'''
# BOT_ICON = 'http://lorempixel.com/64/64/abstract/7/'
# BOT_EMOJI = ':godmode:'


for key in os.environ:
    if key[:15] == 'MATTERMOST_BOT_':
        globals()[key[11:]] = os.environ[key]

settings_module = os.environ.get('MATTERMOST_BOT_SETTINGS_MODULE')

if settings_module is not None:
    pwd = os.getcwd()
    if pwd not in sys.path:
        sys.path.insert(0, pwd)
    settings = importlib.import_module(settings_module)
    execfile(settings.__file__.replace('.pyc', '.py'))

try:
    from mattermost_bot_settings import *
except ImportError:
    try:
        from local_settings import *
    except ImportError:
        pass

if not BOT_URL.endswith('/api/v1'):
    BOT_URL = '%s%sapi/v1' % (BOT_URL, '' if BOT_URL.endswith('/') else '/')
