#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys

from libs.loguru import logger


def set_logger(config):
    # 初始化日志
    logger.remove()  # remove()清除之前的设置
    logger_format1 = "[<green>{time:HH:mm:ss}</green>] <level>{message}</level>"
    logger_format2 = "<green>{time:YYYY-MM-DD HH:mm:ss,SSS}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>"
    logger_format3 = "<level>{message}</level>"
    # logger.add(sys.stdout, format=logger_format1, level="DEBUG") #显示DEBUG到桌面
    # logger.add(sys.stdout, format=logger_format1, level="INFO")#显示INFO到桌面
    logger.add(config.log_file_path, format=logger_format3, level="INFO", rotation="10 MB", enqueue=True,
               encoding="utf-8", errors="ignore")
    # logger.add(config.log_file_path, format=logger_format2, level="INFO", rotation="00:00", enqueue=True, encoding="utf-8", errors="ignore")
    logger.add(config.err_log_file_path, rotation="10 MB", level="ERROR", enqueue=True, encoding="utf-8",
               errors="ignore")
    logger.add(config.dbg_log_file_path, rotation="10 MB", level="DEBUG", enqueue=True, encoding="utf-8",
               errors="ignore")
    config.logger = logger  # 注意,不能用config.logger输出config.logger

    # 根据输入的view_detail_flag参数指定窗口输出的日志信息级别,不执行语句会导致没有控制台页面输出
    try:
        if config.view_detail_flag:
            config.logger.add(sys.stdout, format="[<green>{time:HH:mm:ss}</green>] <level>{message}</level>",
                              level="DEBUG")
        else:
            config.logger.add(sys.stdout, format="[<yellow>{time:HH:mm:ss}</yellow>] <level>{message}</level>",
                              level="INFO")
    except AttributeError as e:
        # 如果在ags启动之前调用了view_detail_flag,就按照view_detail_flag=True处理
        config.logger.add(sys.stdout, format="[<green>{time:HH:mm:ss}</green>] <level>{message}</level>", level="DEBUG")
