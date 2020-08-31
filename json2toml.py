import toml
import json

import click

@click.command()
@click.option('-o','--output')
@click.argument('input',nargs=1)
def main(input,output=None):
    with open(input)  as fd:
        data = json.load(fd)
    if not output:
        s = toml.dumps(data)
        print(s)
    else:
        with open(output,'w') as fd:
            toml.dump(data,fd)

if __name__ == "__main__":
    main()
        