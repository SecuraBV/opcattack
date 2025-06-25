# OPC UA attack tool

Python tool to automate the OPC UA attacks described in my talk "[No VPN Needed? Cryptographic Attacks Against the OPC UA Protocol](https://www.blackhat.com/us-25/briefings/schedule/index.html#no-vpn-needed-cryptographic-attacks-against-the-opc-ua-protocol-44760)", and to 
evaluate whether an OPC UA endpoint is potentially vulnerable.

## Usage

    $ ./opcattack.py -h
    usage: opcattack.py [-h] attack ...
    
    Proof of concept tool for attacks against the OPC UA security protocol.
    
    positional arguments:
      attack            attack to test
        check           evaluate whether attacks apply to server
        reflect         authentication bypass via reflection attack
        relay           authentication bypass via relay attack between two servers
        cn-inject       path injection via an (untrusted) certificate CN
        auth-check      tests if server allows unauthenticated access
        decrypt         sniffed password and/or traffic decryption via padding
                        oracle
        sigforge        signature forgery via padding oracle
        client-downgrade
                        password stealing downgrade attack against a client
    
    options:
      -h, --help        show this help message and exit

Run `opcattack.py <command> -h` to get help for configuration options of a specific attack.

## Installation

Requires Python 3.10 or higher. Install dependencies via `pip install -r requirements.txt`.

Alternatively, you can build a Docker container:

    docker build -t opcattack .
    docker run -it opcattack <arguments>

When running the `reflect` attack with `--bypass-opn` and `-T` flags, you may want to persist the cache file like this:

    docker run -it -v opccache:/var/cache opcattack reflect -c /var/cache/opcfile --bypass-opn -T <interval> -C <count> opc.tcp://<host>:<port>


## Evaluating an endpoint

The first thing you'll want to do is enumerate the endpoints of an OPC UA server by running the following command 
against either the server itself or a discovery server:

    opcattack.py check opc.tcp://<host>:<port>

Or, if the server supports HTTPS:

    opcattack.py check https://<host>:<port>

The output will list endpoint information as well as which attack may be applicable based on the supported security 
policies and transport protocols.

If you want to determine whether the server is vulnerable to the timing-based padding oracle variant, you can run 
`check -t`, which measures response times for different ciphertext expansion parameters.

## Checking if authentication is required

An OPC UA endpoint may be configured to simply not enforce client or user authentication in the first place. While this 
is not the most exciting vulnerability, it is important to check this first to make sure that either authentication 
bypass actually, well, bypasses something. You can run `opcattack.py auth-check <endpoint>` to try a simple anonymous 
login. 

If successful, it will enumerate all readable nodes within the OPC server. It does not test for write access, however.

## Performing an HTTPS reflect/relay attack (attack 1)

If the `check` command reports at least one HTTPS endpoint, a reflection attack may be possible whenever a server 
trusts its own certificate. A PoC can be executed as follows:

    opcattack.py reflect https://<host>:<port>/

This will carry out all the necessary steps. If succesful, the tool will enumerate all nodes on the server; this 
demonstration can be disabled via the `-n` flag.

If client authentication is succesfully bypassed but the server also requires user authentication this is reported by 
the tool. If certificate based user authentication is allowed the tool will automatically attempt reusing the 
reflected signature to spoof user authentication as well.

HTTPS relay attacks between two different servers can be executed as follows:

    opcattack.py relay https://<source> https://<destination>


## Performing an RSA padding oracle attack (attack 2)

### Error-based variant

If you just want a proof of concept on whether a padding oracle is possible, the most straightforward way to do this
is via the `sigforge` command, which attempts to use a padding oracle attack to forge an RSA signature over any chosen
message with the server's public key. You can then verify this signature using a tool like OpenSSL, to demonstrate that
the signature indeed matches the given message. Run it as follows:

    opcattack.py sigforge opc.tcp://<host>:<port> <hex-encoded message>

All padding oracle commands will first check for a few predefined status codes or messages, and tests their reliability
by submitting many correctly and incorrectly padded encrypted messages. The "quality score" of the padding oracle is 
judged based on its false negative rate. If a single false positive is detected, the method is scored a 0.

Not all OPC UA implementations have been tested with this. If an implementation's error messages need to be 
distinguished in a way not yet accounted for this tool will not be smart enough to find it.

The tool also allows a decryption attack. While this can be done for any RSA ciphertext produced with the same public 
key it is most useful on a passively sniffed secure channel handshake or an encrypted password. See 
`opcattack.py decrypt -h` for instructions on how to extract those. You can run this as follows:

    opcattack.py decrypt opc.tcp://<host>:<port> <hex-encoded ciphertext>

The tool will print the hex-encoded plaintext, if succesful. If the plaintext looks like an encrypted password this
password will be decoded. If the plaintext looks like an OpenSecureChannel message it will be parsed and printed, 
revealing the secret nonce inside. 

When the two nonces of the same handshake are decrypted the channel keys can be derived and used to decrypt the rest
of the communication. That is currently not implemented in this tool, however.

### Timing-based variant

If no error-based oracle is found, you can test a timing-based oracle instead. First, run `opcattack.py check -t` to
test response timings. This will produce results such as the following:

    [*] Timing experiment results:
    [+] Expansion parameter 10:
    [+] Average time with correct padding: 0.018887882232666017
    [+] Average time with incorrect padding: 0.005357732772827148
    [+] Shortest time with correct padding: 0.016694307327270508
    [+] Longest time with incorrect padding: 0.022701740264892578
    [+] -----------------
    [+] Expansion parameter 30:
    [+] Average time with correct padding: 0.03950897693634033
    [+] Average time with incorrect padding: 0.005196962356567383
    [+] Shortest time with correct padding: 0.035872697830200195
    [+] Longest time with incorrect padding: 0.011386394500732422
    [+] -----------------
    [+] Expansion parameter 50:
    [+] Average time with correct padding: 0.06519682884216309
    [+] Average time with incorrect padding: 0.005134844779968261
    [+] Shortest time with correct padding: 0.05526590347290039
    [+] Longest time with incorrect padding: 0.009844779968261719
    [+] -----------------
    [+] Expansion parameter 100:
    [+] Average time with correct padding: 0.1187672519683838
    [+] Average time with incorrect padding: 0.00522763729095459
    [+] Shortest time with correct padding: 0.10398173332214355
    [+] Longest time with incorrect padding: 0.013846635818481445
    [+] -----------------

When a timing-based padding oracle is present then the time with correct padding should be longer than the time with
incorrect padding. Here, that is obviously the case. For executing the attack, you need to pick an "expansion 
parameter" that shows a clear difference between the "shortest time with correct padding" and the 
"longest time with incorrect padding". A bigger expansion parameter will generally be more reliable but less 
performant.

Finally, you need to pick a threshold which is some value in between the "shortest time with correct padding" and
the "longest time with incorrect padding". This value will be used to judge how to classify a padding oracle query. 
When the response is positive, the query will be repeated a few times to reduce the chance of false positives due to
temporary network hiccups.

You can configure these expansion and threshold parameters by adding the flags 
`-T <threshold-parameter> -C <expansion-parameter>` to a `sigforge`, `decrypt` or `reflect` command. Once these 
parameters are added, timing-based padding oracles will be taken into account with these parameters.

### Combining with a reflection attack

The tool also implements the combination of a reflection and two padding oracle attacks to achieve an authentication
bypass over an `opc.tcp` secure channel. You can run this by adding the `--bypass-opn` flag to the `reflect` command:

    opcattack.py reflect https://<host>:<port>/ --bypass-opn

If the padding oracle is timing based you can also add `-T` and `-C` parameters.

The tool will cache the result of the "first half" of the attack (i.e. the signature spoofing phase). If the attack 
fails or halts somewhere during the "second half" (the decryption or reflection phases), you can try running the tool 
again and the first half will be automatically skipped. 

### Miscellaneous attacks

The tool implements two other experimental attacks, but these are not novel protocol flaws:

- `cn-inject`: attempts a path injection attack via the CN of an untrusted certificate. While in theory this would be possible against a naive implementation of the OPC UA [certificate file name conventions](https://reference.opcfoundation.org/GDS/v105/docs/F) I have not actually found an implementation (yet) that is vulnerable to this.
- `client-downgrade`: MitM attack to downgrade encryption of a client connection, attempting to steal the user password. This is already pretty much a known potential flaw, however, and most implementations I found are not affected because they need the user to specify a specific security policy in the client configuration.


