import json
import sys
import argparse
import requests
import os
import hashlib
import time

class FairlyRandom:
    def __init__(self, api_key, bot_id, bot_name, group_id, save_file, min_ts):
        self.api_key = api_key
        self.bot_id = bot_id
        self.bot_name = bot_name
        self.group_id = group_id
        self.save_file = save_file

        self.manifold_api_url = "https://manifold.markets/api/v0"
        self.random_api_url = "https://drand.cloudflare.com/8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce/public"

        self.last_comment_ts = min_ts
        self.pending_requests = []

    def do_get(self, path, default=None):
        url = f"{self.manifold_api_url}{path}"
        try:
            req = requests.get(url)
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

    def mention_user(self, user):
        return f'[@{user}](https://manifold.markets/{user})'

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

            res = {}
            text = content.get("text", "").strip()
            tag = f"@{self.bot_name}"
            if text.startswith(tag):
               res = {"has_mention": True}
               text = text[len(tag):].strip()

            try:
                text_int = int(text)
                if text_int <= 1 or text_int > 2**48:
                    return res
                res.update({"number": text_int})
                return res
            except:
                return res
        else:
            return {}

    def check_new_request(self, comment):
        req = self.parse_content(comment.get("content"))
        if req and req.get('has_mention') and req.get('number'):
            req["salt"] = comment["id"]
            req["contractId"] = comment["contractId"]
            req["state"] = "init"
            req["user"] = comment["userName"]
            return [req]
        return []

    def find_new_requests(self):
        new_ts = 0
        group_markets = self.do_get(f"/group/by-id/{self.group_id}/markets", default=[])
        pending_requests = []
        for market in group_markets:
            market_id = market["id"]
            last_update = market["lastUpdatedTime"]
            if last_update <= self.last_comment_ts:
                continue

            comments = self.do_get(f"/comments/?contractId={market_id}", default=[])
            for comment in comments:
                create_time = comment["createdTime"]
                if create_time <= self.last_comment_ts:
                    break

                pending_requests += self.check_new_request(comment)
                new_ts = max(new_ts, create_time)

            new_ts = max(new_ts, last_update)

        if len(pending_requests) > 0:
            print(f"Added {len(pending_requests)} new requests")
        self.last_comment_ts = max(new_ts, self.last_comment_ts)
        self.pending_requests += pending_requests

    def randomness_to_int(self, randomness, salt, max_num):
        log = []
        def add_to_hash(data):
            m.update(data)
            log.append(data.decode('ascii'))

        num_retries = 0
        evenly_divisible = ((2**64)//max_num)*max_num
        m = hashlib.sha256()
        add_to_hash(randomness["randomness"].encode('ascii'))
        add_to_hash(("-" + salt).encode('ascii'))
        while True:
            m_int = int.from_bytes(m.digest()[:8], byteorder='big')
            if m_int < evenly_divisible:
                return (m_int % max_num) + 1, "".join(log), m.hexdigest()[:16], num_retries
            add_to_hash("-RETRY".encode('ascii'))
            num_retries += 1
            print(f"Trying again because {m_int} >= {evenly_divisible} when resizing to {max_num}")

    def process_request(self, req, randomness_cache):
        if req["state"] == "init":
            max_num = req["number"]
            salt = req["salt"]
            randomness = self.get_randomness(0, randomness_cache)
            if randomness is None:
                return req

            rounds = randomness["round"]
            evenly_divisible = ((2**64)//max_num)*max_num
            comment = "\n".join([
                f'### {self.mention_user(req["user"])} you asked for a random integer between 1 and {req["number"]}, inclusive. Coming up shortly!',
                'You can view the open-source implementation and usage instructions for this bot on [GitHub](https://github.com/u0s41v/FairlyRandom/).'
                '',
                '#### Technical details'
                '',
                f'Previous round: {self.randomness_link(rounds)}, next round: {self.randomness_link(rounds+1)}, salt: {req["salt"]}.',
                'Algorithm:',
                '```',
                f'm = hashlib.sha256()',
                f"m.update(randomness['randomness'].encode('ascii'))",
                f"m.update('-{salt}'.encode('ascii'))",
                'while True:',
                "   m_int = int.from_bytes(m.digest()[:8], byteorder='big')",
                f'   if m_int < {evenly_divisible}:',
                f'       return (m_int % {max_num}) + 1',
                '   m.update("-RETRY")',
                '```',
                'Randomness details:',
                '```',
                json.dumps(randomness),
                '```'
            ])
            posted = self.post_comment(req["contractId"], comment)
            if not posted:
                return req

            req["round"] = randomness["round"] + 1
            req["state"] = "declared"
            return req

        if req["state"] == "declared":
            rounds = req["round"]
            randomness = self.get_randomness(rounds, randomness_cache)
            if randomness is None:
                return req # round not ready yet

            max_num = req["number"]
            salt = req["salt"]
            rand_int, log, hex_digest, num_retries = self.randomness_to_int(randomness, salt, max_num)
            comment = "\n".join([
                f'### {self.mention_user(req["user"])} your random number is: {rand_int}',
                '',
                '#### Technical details'
                '',
                f'Round: {self.randomness_link(rounds)}, salt: {salt}, retries: {num_retries}.',
                f'To validate, run the following Linux command: ',
                f'`echo -n {log} | sha256sum`.',
                f'Take the first sixteen hex digits of the output (0x{hex_digest} = {int(hex_digest, 16)}) modulo {max_num} and add one.',
                'Randomness details: ',
                '```',
                json.dumps(randomness),
                '```'
            ])
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
    parser.add_argument('--api-key', dest='api_key')
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
