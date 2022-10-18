import sys
import base64 

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} (encode|decode) data ")
        return
    data = sys.argv[2]
    if sys.argv[1] == "decode":
        print(base64.b64decode(data).decode())
    elif sys.argv[1] == "encode":
        print(base64.b64encode(data.encode()).decode())
    else:
        print("Bad args: set to either encode or decode")

if __name__ == "__main__":
    main()