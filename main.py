import sys
from lib.core import *

def main():
	start()
	
if __name__ == "__main__":
	try:
		main()     
	except KeyboardInterrupt:
		sys.exit(0)
