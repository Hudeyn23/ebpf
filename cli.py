import click

from cmdline import cmdline as cmdline
from comm import comm as comm


@click.group()
def entry_point():
    pass

entry_point.add_command(cmdline.cmdline)
entry_point.add_command(comm.comm)

if __name__ == '__main__':
    entry_point()
