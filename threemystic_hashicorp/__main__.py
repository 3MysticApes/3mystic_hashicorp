import sys


def main(*args, **kwargs):
  from threemystic_hashicorp.cli import main
  
  main(*args, **kwargs)

if __name__ == '__main__':   
  main(sys.argv[1:])