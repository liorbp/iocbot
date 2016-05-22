# -*- coding: utf-8 -*-

import logging
import re
import shlex
from datetime import datetime

from bot import listen_to
from bot import respond_to

from datasource import QueryableManager, QueryableManagerError, QueryPhrase


@respond_to('^(.*)$')
@listen_to('^(.*)$')
def query_dispatcher(message, command_body):
    '''
    The query dispatcher. Intercept messages sent to the bot that starts
    with the word 'query' followed by a command.
    Example:
        @iocbot query 1.1.1.1 @portal
    '''

    # Handle only messaged directed to the bot
    try:
        recipient = message.body['props']['mentions']
    except:
        return

    if message._client.info['id'] not in recipient:
        return

    try:
        args = shlex.split(command_body)
    except ValueError:
        args = command_body.split()
    command = args[0]
    args = args[1:]
    try:
        func = getattr(BotCommands, command)

    except AttributeError:
        message.reply('Hey! I do not have this functionality buddy!')
    else:
        if hasattr(func, '__call__'):
            func(message, *args)
        else:
            message.reply('Hey! I do not have this functionality buddy!')


class BotCommands(object):
    '''
    All of the actual bot commands' functionality is driven from this class.
    Every command is a static function.
    '''

    # Shortcut commands
    @staticmethod
    def q(*args, **kwargs):
        BotCommands.query(*args, **kwargs)

    @staticmethod
    def h(*args, **kwargs):
        BotCommands.help(*args, **kwargs)

    # Commands
    @staticmethod
    def query(message, ioc, where=None, *args):
        '''
        :param message: The message object
        :param ioc: The IOC to be searched
        :param where: The data source to be searched
        :param args: More args for future use

        :return: void
        '''
        logging.info("User %s queried for '%s'" % (message.get_sender_name(), ioc))

        # Detect input type
        domain = re.match(r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$', ioc)
        url = re.match(r'^((https?):((//)|(\\\\))+([\w\d:#@%/;$()~_?\+-=\\\.&](#!)?)*)$', ioc)
        mail = re.match(r'(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)', ioc)
        hash = re.match(r'^([[A-Fa-f0-9]{64}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{32})$', ioc)
        ip = re.match(r'^((?:[0-9]{1,3}\.){3}[0-9]{1,3})$', ioc)

        if domain:
            phrase = QueryPhrase(domain.group(0), QueryPhrase.TYPE_DOMAIN)
        elif url:
            phrase = QueryPhrase(url.group(0), QueryPhrase.TYPE_URL)
        elif mail:
            phrase = QueryPhrase(mail.group(0), QueryPhrase.TYPE_MAIL)
        elif hash:
            phrase = QueryPhrase(hash.group(0), QueryPhrase.TYPE_HASH)
        elif ip:
            phrase = QueryPhrase(ip.group(0), QueryPhrase.TYPE_IP)
        else:
            message.reply('Input data must be a valid URL/Domain/E-mail/Hash/IP')
            return

        # If where is set then query only that source
        if where:
            # Omitting the @ sign
            try:
                queryable = (QueryableManager.get(where[1:]), )
            except QueryableManagerError:
                message.reply("I would have search in %s if i knew where it was." % where)
                return
        else:
            queryable = QueryableManager.get_all()

        total_recs = 0
        message.reply("Hold on %s, let me search for it..." % message.get_sender_name())
        # For each Queryable engine
        for q in queryable:
            # Get all matched records
            records = q.query(phrase)

            # Or proceed to next Queryable object
            if not records:
                continue

            records_len = len(records)
            total_recs += records_len
            msg = '*Found %s records from @%s (aka %s):*\n' % (records_len, q._alias, q._name)
            logging.info("Found %s records from  @%s (aka %s)" % (records_len, q._alias, q._name))
            message.reply(msg)
            msgs = []
            msgs_len = 0

            for record in records:
                msg = '\n>*ID:* %s%s\n' % (q._alias.upper(), record.id)
                msg += '>*Date:* %s\n' % datetime.fromtimestamp(float(record.datetime))
                msg += '>*Description:* %s\n' % record.description
                msg += '>*Data:*\n'
                msg += '>```%s```\n\n' % record.data

                # Message splitting mechanism
                if msgs_len < 4000 < msgs_len + len(msg):
                    # Print all the records
                    message.reply(''.join(msgs))

                    # Reset msgs
                    msgs = []

                    # Add the last one
                    msgs.append(msg)
                    # Reset length to the first msg length
                    msgs_len = len(msg)
                else:
                    # Add message and length
                    msgs.append(msg)
                    msgs_len += len(msg)

            message.reply(''.join(msgs))

        if not total_recs:
            message.reply("I'm sorry %s, I did not find anything using '%s'" % (message.get_sender_name(), phrase.data))


    @staticmethod
    def help(message, command='query'):
        '''
        :param message: The message object
        :param command: Help message for this specific command

        :return: void
        '''
        help_table = {
            'query' : '\nUsage: \n' \
            + '>@iocbot seen <ioc> [%s]\n\n' % '|'.join(['@' + q._alias for q in QueryableManager.get_all()]) \
            + 'Examples:\n' \
            + '> @iocbot [query|q] 2d102d7c1e2c74b46e2701f6689f36d7\n' \
            + '> @iocbot [query|q] evil.com\n' \
            + '> @iocbot [query|q] http://www.evil.com/drop.php @ats\n'\
            + '> @iocbot [query|q] b72f7390e3ae4611286a41841f03003857e96af22b02804cf78d8ee2413bbc12 @sparta\n\n'
        }

        try:
            message.reply(help_table[command])
        except KeyError:
            message.reply('No help exists for command name "%s"' % command)
        pass
