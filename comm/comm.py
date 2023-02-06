import click
from scripts import comm_script as comm_script

@click.command()
@click.argument('comm_name')
@click.option('--p', show_default=True, help="Path to debug script")
def comm(comm_name,p):
    """Catch short-lived process by COMM name"""
    ret = comm_script.attach_comm(comm_name,p)
    print(ret)
    pass
