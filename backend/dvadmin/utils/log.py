import logging
import os.path
import sys

from django.db import connection
from loguru import logger

from logging.handlers import RotatingFileHandler

# 1.🎖️先声明一个类继承logging.Handler(制作一件品如的衣服)

from application.dispatch import is_tenants_mode


class InterceptTimedRotatingFileHandler(RotatingFileHandler):
    """
    自定义反射时间回滚日志记录器
    缺少命名空间
    """

    def __init__(self, filename, when='d', interval=1, backupCount=5, encoding="utf-8", delay=False, utc=False,
                 maxBytes=1024 * 1024 * 100, atTime=None, logging_levels="all", format=None):
        super(InterceptTimedRotatingFileHandler, self).__init__(filename)
        filename = os.path.abspath(filename)
        # 定义默认格式
        if not format:
            format = "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <green>{extra[client_addr]:^18}</green> | <level>{level: <8}</level>| <cyan>{message}</cyan>"
        when = when.lower()
        # 2.🎖️需要本地用不同的文件名做为不同日志的筛选器
        logger.configure(
            handlers=[
                dict(sink=sys.stderr, format=format),
            ],
        )
        self.logger_ = logger.bind(sime=filename, client_addr="-")
        self.filename = filename
        key_map = {
            'h': 'hour',
            'w': 'week',
            's': 'second',
            'm': 'minute',
            'd': 'day',
        }
        # 根据输入文件格式及时间回滚设立文件名称
        rotation = f"{maxBytes / 1024 / 1024}MB"
        retention = "%d %ss" % (backupCount, key_map[when])
        time_format = "{time:%Y-%m-%d_%H-%M-%S}"
        if when == "s":
            time_format = "{time:%Y-%m-%d_%H-%M-%S}"
        elif when == "m":
            time_format = "{time:%Y-%m-%d_%H-%M}"
        elif when == "h":
            time_format = "{time:%Y-%m-%d_%H}"
        elif when == "d":
            time_format = "{time:%Y-%m-%d}"
        elif when == "w":
            time_format = "{time:%Y-%m-%d}"
        level_keys = ["info"]
        # 3.🎖️构建一个筛选器
        levels = {
            "debug": lambda x: "DEBUG" == x['level'].name.upper() and x['extra'].get('sime') == filename,
            "error": lambda x: "ERROR" == x['level'].name.upper() and x['extra'].get('sime') == filename,
            "info": lambda x: "INFO" == x['level'].name.upper() and x['extra'].get('sime') == filename,
            "warning": lambda x: "WARNING" == x['level'].name.upper() and x['extra'].get('sime') == filename
        }
        # 4. 🎖️根据输出构建筛选器
        if isinstance(logging_levels, str):
            if logging_levels.lower() == "all":
                level_keys = levels.keys()
            elif logging_levels.lower() in levels:
                level_keys = [logging_levels]
        elif isinstance(logging_levels, (list, tuple)):
            level_keys = logging_levels
        for k, f in {_: levels[_] for _ in level_keys}.items():

            # 5.🎖️为防止重复添加sink，而重复写入日志，需要判断是否已经装载了对应sink，防止其使用秘技：反复横跳。
            filename_fmt = filename.replace(".log", "_%s_%s.log" % (time_format, k))
            # noinspection PyUnresolvedReferences,PyProtectedMember
            file_key = {_._name: han_id for han_id, _ in self.logger_._core.handlers.items()}
            filename_fmt_key = "'{}'".format(filename_fmt)
            if filename_fmt_key in file_key:
                continue
                # self.logger_.remove(file_key[filename_fmt_key])
            self.logger_.add(
                filename_fmt,
                format=format,
                retention=retention,
                encoding=encoding,
                level=self.level,
                rotation=rotation,
                compression="zip",  # 日志归档自行压缩文件
                delay=delay,
                enqueue=True,
                backtrace=True,
                filter=f
            )

    def emit(self, record):
        try:
            level = self.logger_.level(record.levelname).name
        except ValueError:
            level = record.levelno

        frame, depth = logging.currentframe(), 2
        # 6.🎖️把当前帧的栈深度回到发生异常的堆栈深度，不然就是当前帧发生异常而无法回溯
        while frame.f_code.co_filename == logging.__file__:
            frame = frame.f_back
            depth += 1
        # 设置自定义属性
        details = frame.f_locals.get('details', None)
        msg = self.format(record)
        bind = {}
        record_client = None
        if isinstance(record.args, dict):
            record_client = record.args.get('client_addr') or record.args.get('client')
        elif isinstance(record.args, tuple) and len(record.args) > 0:
            if ":" in str(record.args[0]):
                record_client = record.args[0]
                if msg.split("-") and len(msg.split("-")) == 2:
                    msg = f"{msg.split('-')[1].strip(' ')}"
            elif isinstance(record.args[0], tuple) and len(record.args[0]) == 2:
                record_client = f"{record.args[0][0]}:{record.args[0][1]}"
                if msg.split("-") and len(msg.split("-")) == 2:
                    msg = f"{msg.split('-')[1].strip(' ')}"
        client = record_client or (details and details.get('client'))
        if client:
            bind["client_addr"] = client
        if is_tenants_mode():
            bind["schema_name"] = connection.tenant.schema_name
            bind["domain_url"] = getattr(connection.tenant, 'domain_url', None)
        self.logger_ \
            .opt(depth=depth, exception=record.exc_info, colors=True, lazy=True) \
            .bind(**bind) \
            .log(level, msg)
