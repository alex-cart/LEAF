class LEAFInPath(Exception):
    def __init__(self, item):
        super().__init__(f"Target Item {item} in LEAF Working Paths.")


class DoesNotExistError(Exception):
    def __init__(self, item):
        super().__init__(f"Target Item {item} does not Exist.")


class NonMatchingHashes(Exception):
    def __init__(self, src, dst):
        super().__init__(f"Error copying {src} to {dst}, wrong hash.")


class RootNotDetected(Exception):
    def __init__(self):
        super().__init__(f"Root privilege not detected. Please restart as "
                         f"root.\n Exiting...")


class CategoriesEmpty(Exception):
    def __init__(self):
        super().__init__(f"No valid categories were specified. Continuing "
                         f"with default values...")


def verbose(prnt, v):
    if v:
        print(prnt)
