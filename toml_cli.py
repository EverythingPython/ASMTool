import toml
import json
from pprint import pprint
import click

@click.command()
@click.option('-o','--output')
@click.argument('input',nargs=1)
def main(input,output=None):
    with open(input)  as fd:
        data = toml.load(input)
        pprint(data)

if __name__ == "__main__":
    main()
        