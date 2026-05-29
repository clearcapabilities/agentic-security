# @version 0.3.7

@external
def call_external(target: address, data: Bytes[256]):
    # BUG: no max_outsize specified
    raw_call(target, data)
