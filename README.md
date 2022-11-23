# FairlyRandom

A bot for [Manifold Markets](https://manifold.markets/) that generates random numbers in a fair way. Specifically it provides the following properties:
 - Any outcome in the specified range is equally likely, and each randomization is independent.
 - Nobody can manipulate the random numbers.
 - Nobody can predict the random numbers in advance.
 - Once the random number does become available, everybody has a fair chance to be first to compute it.
 - These properties hold even against the operator of the bot itself.

Given the following assumptions:
 - SHA256 is pre-image resistant.
 - The first 8 bytes of a SHA256 hash are distributed in a uniformly random way.
 - At least one entity in Cloudflare's [League of Entropy](https://www.cloudflare.com/leagueofentropy/) is trustworthy.

Usage instructions and suggestions:
 1. In order to use the bot, you'll need to first add your market to a designated group (currently "fairlyrandom").
 2. When you're ready to inject the randomness, I would recommend temporarily closing your market unless
    "bots racing to be first to respond to the generated randomness" is a desired part of your market structure.
 3. Post a comment on the market tagging @FairlyRandom and containing a single number consisting of your desired range.
    For example, "@FairlyRandom 6" to generate a random number from 1-6.
 4. The bot will respond with a message acknowledging your request and explicitly stating all the parameters to ensure everything is fair.
    Then shortly afterwards it will provide the random number that was requested along with instructions to verify it.

If you'd like to run your own copy of this code feel free, but please give your bot a sufficiently distinct name.
If you modify the code, please make sure the comment posted by your bot points to the modified version of the code and not this repo.
