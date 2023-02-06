import click
from scripts import cmdline_script as cmdline_script
from scripts import cmdline_script_uprobe as cmdline_script_uprobe


@click.group()
def cmdline():
    """Catch short-lived process by CMDLINE name"""
    pass


@cmdline.command()
@click.argument('comm_name')
@click.argument('cmdline_name')
@click.option('--p', show_default=True, help="Path to debug script")
def sys_call(comm_name, cmdline_name, p):
    """Catch short-lived process by CMDLINE after syscall"""
    cmdline_script.attach_cmdline(comm_name, cmdline_name,p)


@cmdline.command()
@click.argument('cmdline_name')
@click.argument('path_to_bin')
@click.argument('func_name')
@click.option('--p', show_default=True, help="Path to debug script")
def uprobe(cmdline_name, path_to_bin, func_name, p):
    """Catch short-lived process by CMDLINE after given function"""
    cmdline_script_uprobe.attach_cmdline(cmdline_name, path_to_bin, func_name,p)
