from fairly_random import FairlyRandom
import argparse
import sys
import datetime
import time

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--round', dest='round', type=int, help="The selected round (i.e. previous round + offset)", required=True)
    parser.add_argument('--salt', dest='salt', required=True)
    parser.add_argument('--min', dest='min', type=int, default=1)
    parser.add_argument('--max', dest='max', type=int, required=True)
    parser.add_argument('--poll-interval', dest='poll_interval', type=int, default=3)
    args = parser.parse_args()
    fr = FairlyRandom(None, None, None, None, None, None)

    waited_for_latest = False
    while True:
        randomness_latest = fr.get_randomness("latest", {})
        if randomness_latest is None:
            continue
        cur_round = randomness_latest["round"]
        if cur_round < args.round:
            sys.stderr.write(f"Round {args.round} isn't available yet, currently at round {cur_round}\n")
            sys.stderr.flush()
            waited_for_latest = True
            time.sleep(args.poll_interval)
        else:
            break

    randomness = fr.get_randomness(args.round, {})
    if randomness is None:
        sys.stderr.write("Failed to retrieve randomness from drand\n")
        sys.exit(1)

    result, log, hex_digest, num_retries = fr.randomness_to_int(randomness, args.salt, args.min, args.max)
    sys.stderr.write(f"Using the sha256sum of {log}, we get a hash starting with {hex_digest}.\n")
    sys.stderr.write("The final result should be:\n")
    sys.stderr.flush()
    print(result)

    if not waited_for_latest:
        ts = randomness["timestamp_available_estimate"]
        sys.stderr.write(f'Also make sure to confirm that the timestamp on the declaration comment is earlier than {ts} ({datetime.datetime.fromtimestamp(ts)} UTC)\n')


if __name__ == "__main__":
    main()
