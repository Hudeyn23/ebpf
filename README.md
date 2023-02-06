## Требования
Версия ядра не ниже 5.15
Я тестировал на чистой виртуалке с Ubuntu 22.04.1 LTS , ядро 5.15.0-58-generic

## Установка
1. На чистой виртуалке было достаточно сделать вот эту инструкцию для сборки из исходников https://github.com/iovisor/bcc/blob/master/INSTALL.md#ubuntu---source
2. Склонировать данный репо

## Запуск для comm
sudo python3 cli.py comm COMM_NAME --p PATH_TO_SCRIPT

## Запуск для cmdline

sudo python3 cli.py cmdline sys-call  COMM_NAME CMDLINE_NAME --p PATH_TO_SCRIPT

sudo python3 cli.py cmdline uprobe CMDLINE_NAME PATH_TO_BIN FUNC_NAME --p PATH_TO_SCRIPT