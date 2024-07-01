import sys
from pathlib import Path


if __name__ == "__main__":
    sys.path.append(str(Path(__file__).parent.joinpath("src")))
    from wacryptolib.cli import main

    main()
