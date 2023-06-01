import sys


def main(*args, **kwargs):
  from threemystic_hashicorp.common import common

  print(f"Thank you for using the 3 Mystic Apes HashiCorp Library. You currenly have installed 3mystic_hashicorp version {common().version()}")

if __name__ == '__main__':   
  main(sys.argv[1:])