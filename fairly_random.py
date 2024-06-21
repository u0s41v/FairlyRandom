import json
import sys
import argparse
import requests
import os
import hashlib
import time
import re

def try_int(text):
    try:
        text_int = int(text)
        return text_int
    except:
        return None

def try_bool(text):
    if text.lower() in ("false", "no", "0"):
        return False
    if text.lower() in ("true", "yes", "1"):
        return True
    return None

# attribute name, validation function, default value
attrs = {
    "min": (try_int, 1),
    "max": (try_int, None),
    "offset": (try_int, 2),
    "verbose": (try_bool, False)
}

class FairlyRandom:
    def __init__(self, api_key, bot_id, bot_name, group_id, save_file, min_ts):
        self.api_key = api_key
        self.bot_id = bot_id
        self.bot_name = bot_name
        self.group_id = group_id
        self.save_file = save_file

        self.manifold_api_url = "https://api.manifold.markets/v0"
        self.random_api_url = "https://api.drand.sh/8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce/public"

        self.last_comment_ts = min_ts
        self.pending_requests = []

    def do_get(self, path, default=None):
        url = f"{self.manifold_api_url}{path}"
        try:
            req = requests.get(url, timeout=3)
        except Exception as e:
            print(e)
            return default
        try:
            return req.json()
        except requests.exceptions.JSONDecodeError:
            print(req.text)
            return default

    def post_comment(self, contractId, comment):
        url = f"{self.manifold_api_url}/comment"
        try:
            req = requests.post(url, json={'contractId': contractId, 'markdown': comment}, headers={'Authorization': f'Key {self.api_key}'}, timeout=3)
        except Exception as e:
            print(e)
            return False
        if req.status_code == 200:
            return True
        else:
            print(req.text)
            return False

    def randomness_link(self, rounds):
        return f'[{rounds}]({self.random_api_url}/{rounds})'

    def mention_user(self, userdisplay, username):
        def sanitize(name):
            return re.sub('[^a-zA-Z0-9._,]', '', username)
        sanitized = sanitize(username)
        if sanitized == username:
            return f'[@{sanitized}](https://manifold.markets/{sanitized})'
        else:
            return f'@{sanitized}'

    def get_randomness(self, rounds, cache):
        if rounds in cache:
            return cache[rounds]

        url = f"{self.random_api_url}/{rounds}"
        try:
            req = requests.get(url, timeout=3)
        except Exception as e:
            print(e)
            cache[rounds] = None
            return None
        try:
            res = req.json()
            res["timestamp_retrieved"] = int(time.time())

            # Constants from https://drand.cloudflare.com/8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce/info
            res["timestamp_available_estimate"] = 1595431050 + (res["round"]-1) * 30
            cache[rounds] = res
            return res
        except requests.exceptions.JSONDecodeError:
            cache[rounds] = None
            return None

    def load_state(self):
        if not os.path.isfile(self.save_file):
            return

        with open(self.save_file) as f:
            state = json.load(f)

        # timestamp of the last comment that was processed
        self.last_comment_ts = state["last_comment_ts"]
        self.pending_requests = state["pending_requests"]

    def save_state(self):
        state = {
            "last_comment_ts": self.last_comment_ts,
            "pending_requests": self.pending_requests
        }
        with open(self.save_file, "w") as f:
            json.dump(state, f)

    def parse_content(self, content):
        if isinstance(content, list):
            result = {}
            for x in content:
                rec = self.parse_content(x)
                if "number" in rec and "number" in result:
                    result["ambiguous_num"] = True
                if rec:
                    result.update(rec)
            if result:
                return result
            else:
                return {}
        elif isinstance(content, dict):
            if "content" in content:
                return self.parse_content(content["content"])

            cattr = content.get('attrs', {})
            if (content.get("type") == "mention"
                and cattr.get("label") == self.bot_name
                and cattr.get("id") == self.bot_id):
                return {"has_mention": True}

            if "text" in content:
                return self.parse_content(content["text"])

            return {}

        elif isinstance(content, str):
            res = {}
            for part in content.strip().split():
                if part == f"@{self.bot_name}":
                    res["has_mention"] = True

                elif part.count("=") == 1:
                    key, val = part.split("=")
                    if key in attrs:
                        validator, _ = attrs[key]
                        val_parsed = validator(val)
                        if val_parsed is not None:
                            res[key] = val_parsed
                else:
                    text_int = try_int(part)
                    if text_int is not None:
                        if "number" in res:
                            res["ambiguous_num"] = True
                        res["number"] = text_int

            return res
        else:
            return {}

    def check_new_request(self, comment):
        # Don't respond to our own comments or we could create a loop!
        if comment["userUsername"] == self.bot_name or comment["userId"] == self.bot_id:
            return []

        req = self.parse_content(comment.get("content"))
        if req and req.get('has_mention'):
            req["salt"] = comment["id"]
            req["contractId"] = comment["contractId"]
            req["state"] = "init"
            req["userdisplay"] = comment["userName"]
            req["username"] = comment["userUsername"]
            for key, (validator, default) in attrs.items():
                if key not in req:
                    req[key] = default

            if req["max"] is None and "number" in req and not req.get("ambiguous_num", False):
                req["max"] = req["number"]
            return [req]
        return []

    def find_new_requests(self):
        new_ts = 0
        group_markets = self.do_get(f"/group/by-id/{self.group_id}/markets", default=[])
        pending_requests = []
        for market in group_markets:
            if not isinstance(market, dict):
               print("Invalid market:", market)
               continue
            market_id = market["id"]
            last_update = market.get("lastUpdatedTime", 0)
            if last_update <= self.last_comment_ts:
                continue

            comments = self.do_get(f"/comments/?contractId={market_id}", default=[])
            for comment in comments:
                if not isinstance(comment, dict):
                    print("Non-dict comment: " +str(comment))
                    continue
                create_time = comment["createdTime"]
                new_ts = max(new_ts, create_time)
                if create_time <= self.last_comment_ts:
                    break

                pending_requests += self.check_new_request(comment)

        if len(pending_requests) > 0:
            print(f"Added {len(pending_requests)} new requests")
        self.last_comment_ts = max(new_ts, self.last_comment_ts)
        self.pending_requests += pending_requests

    def randomness_to_int(self, randomness, salt, min_num, max_num):
        log = []
        def add_to_hash(data):
            m.update(data)
            log.append(data.decode('ascii'))

        num_retries = 0
        delta = max_num - min_num + 1
        evenly_divisible = ((2**64)//delta)*delta
        m = hashlib.sha256()
        add_to_hash(randomness["randomness"].encode('ascii'))
        add_to_hash(("-" + salt).encode('ascii'))
        while True:
            m_int = int.from_bytes(m.digest()[:8], byteorder='big')
            if m_int < evenly_divisible:
                return (m_int % delta) + min_num, "".join(log), m.hexdigest()[:16], num_retries
            add_to_hash("-RETRY".encode('ascii'))
            num_retries += 1
            print(f"Trying again because {m_int} >= {evenly_divisible} when refining to {min_num}-{max_num}")

    def validate_request(self, req):
        if req["max"] is None:
            if "number" in req and req.get("ambiguous_num", False):
                return "Range is ambiguous. Please include only a single number, or explicitly state max=N"
            else:
                return f"No range specified. Try `@{self.bot_name} 10`"

        if req["max"] <= req["min"]:
            return "Max <= min is not allowed"

        if req["max"] - req["min"] > 2**48:
            return "Range cannot exceed 2**48"

        if abs(req["max"]) >= 2**63 or abs(req["min"]) >= 2**63:
            return "Values must fit in 63 bits"

        if req["offset"] < 1:
            return "Offset must be at least 1"

        if req["offset"] > 100:
            return "Offset cannot exceed 100"

        return None

    def process_request(self, req, randomness_cache):
        if req["state"] == "init":
            max_num = req["max"]
            min_num = req["min"]
            offset = req["offset"]
            salt = req["salt"]

            reject_msg = self.validate_request(req)
            if reject_msg is not None:
                posted = self.post_comment(req["contractId"], f"Not a valid request: {reject_msg}")
                if posted:
                    return None
                else:
                    return req

            randomness = self.get_randomness("latest", randomness_cache)
            if randomness is None:
                return req

            now = int(time.time())
            if now - randomness["timestamp_retrieved"] > 15:
                print(f"timestamp_retrieved on latest is too stale to declare ({now} vs {randomness['timestamp_retrieved']})")
                return req

            if now - randomness["timestamp_available_estimate"] > 27:
                print(f"timestamp_available_estimate is too stale to declare ({now} vs {randomness['timestamp_available_estimate']})")
                return req

            delta = max_num - min_num + 1
            rounds = randomness["round"]
            evenly_divisible = ((2**64)//delta)*delta
            if req["verbose"]:
                details = [
                    'You can view the open-source implementation and usage instructions for this bot on [GitHub](https://github.com/u0s41v/FairlyRandom/).'
                    '',
                    '#### Technical details'
                    '',
                    f'Previous round: {self.randomness_link(rounds)} ({self.randomness_link("latest")}), offset: {offset}, selected round: {self.randomness_link(rounds+offset)}, salt: {req["salt"]}.',
                    'Algorithm:',
                    '```',
                    f'm = hashlib.sha256()',
                    f"m.update(randomness['randomness'].encode('ascii'))",
                    f"m.update('-{salt}'.encode('ascii'))",
                    'while True:',
                    "   m_int = int.from_bytes(m.digest()[:8], byteorder='big')",
                    f'   if m_int < {evenly_divisible}:',
                    f'       return (m_int % {delta}) + {min_num}',
                    '   m.update("-RETRY")',
                    '```',
                    'Randomness details:',
                    '```',
                    json.dumps(randomness),
                    '```'
                ]
            else:
                details = [
                    f'Source: [GitHub](https://github.com/u0s41v/FairlyRandom/), previous round: {self.randomness_link(rounds)} ({self.randomness_link("latest")}), offset: {offset}, selected round: {self.randomness_link(rounds+offset)}, salt: {req["salt"]}.',
                ]
            comment = "\n".join([
                f'### {self.mention_user(req["userdisplay"], req["username"])} you asked for a random integer between {min_num} and {max_num}, inclusive. Coming up shortly!'] + details)
            posted = self.post_comment(req["contractId"], comment)
            if not posted:
                return req

            req["round"] = randomness["round"] + offset
            req["state"] = "declared"
            return req

        if req["state"] == "declared":
            rounds = req["round"]
            latest = self.get_randomness("latest", randomness_cache)
            if latest is None or latest["round"] < rounds:
                return req # round not ready yet

            randomness = self.get_randomness(rounds, randomness_cache)
            if randomness is None:
                return req # round not ready yet

            max_num = req["max"]
            min_num = req["min"]
            delta = max_num - min_num + 1
            salt = req["salt"]
            rand_int, log, hex_digest, num_retries = self.randomness_to_int(randomness, salt, min_num, max_num)
            if req["verbose"]:
                details = [
                    '#### Technical details'
                    '',
                    f'Round: {self.randomness_link(rounds)}, salt: {salt}, retries: {num_retries}.',
                    f'To validate, run the following Linux command: ',
                    f'`echo -n {log} | sha256sum`.',
                    f'Take the first sixteen hex digits of the output (0x{hex_digest} = {int(hex_digest, 16)}) modulo {delta} and add {min_num}.',
                    'Randomness details: ',
                    '```',
                    json.dumps(randomness),
                    '```'
                ]
            else:
                details = [f'Salt: {salt}, round: {self.randomness_link(rounds)} (signature {randomness["signature"]})']

            comment = "\n".join([
                f'### {self.mention_user(req["userdisplay"], req["username"])} your random number is: {rand_int}'] + details)
            posted = self.post_comment(req["contractId"], comment)
            if not posted:
                return req

            return None

    def show_pending_requests(self):
        print(self.pending_requests)

    def process_pending_requests(self):
        randomness_cache = {}
        new_pending_requests = []
        for req in self.pending_requests:
            new_req = self.process_request(req, randomness_cache)
            if new_req is not None:
                new_pending_requests.append(new_req)
        self.pending_requests = new_pending_requests

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--api-key', dest='api_key', required=True)
    parser.add_argument('--bot-name', dest='bot_name', default='FairlyRandom')
    parser.add_argument('--bot-id', dest='bot_id', default='xVf5mxjIgHWPBHnFko05fqtsOft1')
    parser.add_argument('--group-id', dest='group_id', default='J8Z1KAZV31icklA4tgJW') # fairlyrandom
    parser.add_argument('--save-file', dest='save_file', default='state.json')
    parser.add_argument('--default-min-ts', dest='min_ts', default=int(time.time() * 1000), type=int,
                        help='If there is no save_file, what is the earliest timestamp of comment to process? Defaults to now')
    args = parser.parse_args()
    fr = FairlyRandom(args.api_key, args.bot_id, args.bot_name, args.group_id, args.save_file, args.min_ts)
    fr.load_state()

    while True:
        fr.find_new_requests()
        fr.save_state()
        #fr.show_pending_requests()
        fr.process_pending_requests()
        fr.save_state()
        time.sleep(3)

if __name__ == "__main__":
    main()
