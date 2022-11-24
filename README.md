# FairlyRandom

A bot for [Manifold Markets](https://manifold.markets/) that generates Random numbers in a Fair way. Specifically it provides the following properties:
 - Any outcome in the specified range is equally likely, and each randomization is independent.
 - Nobody can manipulate the random numbers.
 - Nobody can predict the random numbers in advance.
 - Once the random number does become available, everybody has a fair chance to be first to compute it.
 - These properties hold even against the operator of the bot itself.

Given the following assumptions:
 - SHA256 is pre-image resistant.
 - The first 8 bytes of a SHA256 hash are distributed in a uniformly random way.
 - At least one entity in Cloudflare's [League of Entropy](https://www.cloudflare.com/leagueofentropy/) is trustworthy.
 - Validity of the [drand distributed randomness protocol](https://blog.cloudflare.com/league-of-entropy/) as described in the [paper](https://www.ieee-security.org/TC/SP2017/papers/413.pdf).

#### Usage Instructions

 1. In order to use the bot, you'll need to first add your market to a designated group (currently "FairlyRandom").
 2. When you're ready to inject the randomness, I would recommend temporarily closing your market unless
    "bots racing to be first to respond to the generated randomness" is a desired part of your market structure.
 3. Post a comment on the market tagging @FairlyRandom and containing a single number consisting of your desired range.
    For example, "@FairlyRandom 6" to generate a random number from 1-6. Minimum 2, maximum 2^48.
 4. The bot will respond with a message acknowledging your request and explicitly stating all the parameters to ensure everything is fair.
    Then shortly afterwards it will provide the random number that was requested (along with instructions to verify it, if `verbose=true`).

For more advanced usage, the following attributes are available:
 - `min=N` to change the minimum value of the range (inclusive) to something other than the default 1.
 - `max=N` as an alternative syntax for specifying the maximum value of the range (inclusive).
 - `offset=N` to specify how many rounds to wait before retrieving the randomness. Default is 2, min 1, max 100. Increasing the offset makes the result take longer to provide (about 30 seconds per increment) but can increase the security.
 - `verbose=true` to include full technical details and verification instructions.

For example, to generate a random integer between 10 and 100 (inclusive) with offset set to 5 for increased security:

```
@FairlyRandom min=10 max=100 offset=5
```

#### Running it yourself

If you'd like to run your own copy of this code feel free, but please give your bot a sufficiently distinct name.
If you modify the code, please make sure the comment posted by your bot points to the modified version of the code and not this repo.

#### Verification Details

The general idea here is that we post two comments:
 1. The declaration comment: Defines the key parameters (current round of drand, salt taken from the request comment, and numeric range of the final output)
	and specifies the algorithm that will be used to convert these to our final random number once the next round of drand is available.
 2. The result comment: Once the next round of drand is released, we carry out the algorithm specified in the declaration and provide the final random number.

In theory, the result comment is unnecessary -- anybody could compute its exact text independently just based on the declaration comment and the next round of drand.
That's the key property which means you don't need to trust the bot operator here. Obviously we will still post it though since that makes the bot a lot more convenient
to use!

To verify that the bot hasn't been manipulated by its operator, you should check the following:
 1. In the declaration comment, make sure that the time it was posted corresponds to the round of drand that was used.
	In theory, if the bot used an earlier round of drand that was already known, then it could predict the result in advance.
	To help make this more convenient to check, the bot posts what time it retrieved the current drand round.
 2. In the declaration comment, make sure that the salt is unique from any other declaration comments that were made, in order for the randomness to be independent.
 3. In the declaration comment, make sure that the numeric range to be used matches the one requested.
 4. In the declaration comment, make sure that the algorithm to be used for refining the randomness hasn't been changed unexpectedly.
 5. In the result comment, run the algorithm from the declaration comment (the bot helpfully spells out how to do this but you don't need to take its word for it) and check
    that the result matches.
