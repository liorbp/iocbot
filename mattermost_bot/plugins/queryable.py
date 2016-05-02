__author__ = 'exodus'


class QueryableManagerError(Exception):
    pass


class QueryableManager(object):
    '''
    The manager class for all registered Queryable objects
    '''
    # Registered Queryables
    registry = {}
    # Settings for each Queryable type
    settings = {}

    @staticmethod
    def get(alias):
        '''
        Get Queryable object by its alias name

        :arg alias: the given alias name of the object
        '''
        try:
            return QueryableManager.registry[alias](settings=QueryableManager.settings.get(alias,{}))
        except KeyError:
            raise QueryableManagerError, 'asked for "%s" -No Queryable object with that alias.' % alias

    @staticmethod
    def get_all():
        '''
        Get all Queryable objects available
        '''
        qlist = []
        for q in QueryableManager.registry.values():
            qlist.append(q(settings=QueryableManager.settings.get(q._alias,{})))

        return qlist


class MetaClass(type):
    def __new__(cls, clsname, bases, attrs):
        # Register
        newclass = super(MetaClass, cls).__new__(cls, clsname, bases, attrs)
        try:
            QueryableManager.registry[newclass._alias] = newclass
        except AttributeError:
            pass

        return newclass


class Queryable(object):
    __metaclass__ = MetaClass

    def __init__(self, settings={}):
        '''
        Queryable object. The abstract class for all other Queryable objects.

        :param settings: A dict which contain all relevant settings for the object

        :return:
        '''
        self.settings = settings

    def query(self, data):
        records = self._query(data)

        return records

    def _query(self,data):
        '''
        Implement the way we search through the Queryable data source

        :return list of Record objects
        '''
        raise NotImplementedError,'"_query" method must be implemented'


# Quick and stupid solution for data type
class QueryPhrase(object):
    TYPE_HASH   = 1
    TYPE_MAIL   = 2
    TYPE_DOMAIN = 3
    TYPE_URL    = 4
    TYPE_IP     = 5

    def __init__(self, data, type):
        self.data = data
        self.type = type


class Record(object):
    def __init__(self):
        self.id = None
        self.description = None
        self.datetime = None
        self.data = None

    '''
    def __setattr__(self, key, value):
        if hasattr(self, key):
            try:
                getattr('validate_' + self,key)(value)
            except TypeError:
                setattr(self, key, value)

    def validate_datetime(self,value):
        pass
    '''

'''
class RecordViewError(Exception):
    pass


class RecordView(object):
    def __init__(self, record):
        if not isinstance(record, Record):
            raise RecordViewError('first argument must be of "%s" type, got: %s' % (Record, type(record)))
        self._record = record

        # TODO: add functionality for record attribute requirement.


class VtUrlRecordView(RecordView):
    required = ['id','datetime', 'desc', 'data']


    def __str__(self):

        msg = '\n>*ID:* %s\n' % self.record.id
        msg += '>*Date:* %s\n' % self.record.datetime
        msg += '>*Description:* %s\n' % self.record.description
        msg += '>*Data:*\n'
        msg += '>```%s```\n\n' % self.record.data
        return msg


use case
record = Record()
record.id =1
record.view = UrlRecordView(record)


msg.reply(record.view)
'''
