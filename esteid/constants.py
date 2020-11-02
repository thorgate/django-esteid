MOBILE_ID_DEMO_URL = "https://tsp.demo.sk.ee/mid-api"
MOBILE_ID_LIVE_URL = "https://mid.sk.ee/mid-api"

SMART_ID_DEMO_URL = "https://sid.demo.sk.ee/smart-id-rp/v1"
SMART_ID_LIVE_URL = "https://rp-api.smart-id.com/v1"

OCSP_DEMO_URL = "http://demo.sk.ee/ocsp"
OCSP_LIVE_URL = "http://ocsp.sk.ee/"

TSA_DEMO_URL = "http://demo.sk.ee/tsa/"
TSA_LIVE_URL = "http://tsa.sk.ee"

# Set of supported hash algorithms. Same for both MobileID and SmartID
# see https://github.com/SK-EID/smart-id-documentation#33-hash-algorithms
# https://github.com/SK-EID/MID#231-supported-hashing-algorithms
HASH_SHA256 = "SHA256"
HASH_SHA384 = "SHA384"
HASH_SHA512 = "SHA512"
HASH_ALGORITHMS = {
    HASH_SHA256,
    HASH_SHA384,
    HASH_SHA512,
}
