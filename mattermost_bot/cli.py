# -*- coding: utf-8 -*-
import sys
import logging

import bot, settings

from plugins.queryable import QueryableManager



def main():
    logging.basicConfig(**{
        'format': '[%(asctime)s] %(message)s',
        'datefmt': '%m/%d/%Y %H:%M:%S',
        'level': logging.DEBUG if settings.DEBUG else logging.INFO,
        'stream': sys.stdout,
    })

    try:
        QueryableManager.settings = settings.DATASOURCE_SETTINGS
        b = bot.Bot()
        b.run()
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
