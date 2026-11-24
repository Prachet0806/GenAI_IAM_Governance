"""Disposable subprocess used to kill a real Floci discovery at a fixed boundary."""

import argparse
import os

from common import repo
from lambdas.identity_discovery.handler import discover_identities


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("boundary", choices=("before_publication", "during_publication", "after_commit"))
    boundary = parser.parse_args().boundary

    def terminate(*args, **kwargs):
        os._exit(73)

    if boundary == "before_publication":
        repo.publish_discovery_snapshot = terminate
    elif boundary == "during_publication":
        # This runs after the snapshot insert and before its transaction commits.
        repo.insert_role = terminate
    else:
        # Discovery calls this only after the publication context has committed.
        repo.insert_audit_log = terminate
    discover_identities(None, None)
    raise RuntimeError("The selected termination boundary was never reached")


if __name__ == "__main__":
    main()
