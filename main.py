import sys
from pathlib import Path

if __name__ == "__main__":
    sys.path.append(str(Path(__file__).parent.joinpath("src")))  # register SRC/ folder just in case

    from wacryptolib.__main__ import main
    main()
