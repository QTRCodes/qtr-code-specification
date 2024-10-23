# Quick Trusted Response (QTR) Codes Specification Document

**Title:** Quick Trusted Response (QTR) Codes Specification  
**Version:** 0.2  
**Status:** Drafting  
**Date last updated:** 23th October 2024  

## Table of Contents

1. [Introduction](#1-introduction)
2. [Terminology](#2-terminology)
3. [QTR Parameter Format](#3-qtr-parameter-format)
   - [3.1 Structure](#31-structure)
   - [3.2 Examples](#32-examples)
   - [3.3 Additional Parameters](#33-additional-parameters)
4. [Operational Workflow](#4-operational-workflow)
   - [4.1 QR Code Generation](#41-qr-code-generation)
   - [4.2 QR Code Scanning and Verification](#42-qr-code-scanning-and-verification)
5. [Cryptographic Specifications](#5-cryptographic-specifications)
   - [5.1 Supported Algorithms](#51-supported-algorithms)
   - [5.2 Signature Generation](#52-signature-generation)
   - [5.3 Public Key Format](#53-public-key-format)
6. [Public Key Retrieval Methods](#6-public-key-retrieval-methods)
   - [6.1 DNS Record (`key_location == 'd'`)](#61-dns-record-key_location--d)
   - [6.2 Well-Known JWKS (`key_location == 'w'`)](#62-well-known-jwks-key_location--w)
   - [6.3 Specific Well-Known Endpoint (`key_location == 's'`)](#63-specific-well-known-endpoint-key_location--s)
   - [6.4 HTTP Response Header from Hostname (`key_location == 'h'`)](#64-http-response-header-from-hostname-key_location--h)
   - [6.5 HTTP Response Header from URL (`key_location == 'u'`)](#65-http-response-header-from-url-key_location--u)
7. [Example](#7-example) (with Python proof of concepts)
   - [Generation](#71-generation)
   - [Verification](#72-verification)
9. [Error Handling and Timeouts](#8-error-handling-and-timeouts)
9. [Backward Compatibility](#9-backward-compatibility)
10. [Security Considerations](#10-security-considerations)
11. [Privacy and Ethical Considerations](#11-privacy-and-ethical-considerations)
12. [Future Extensions](#12-future-extensions)
13. [References](#13-references)

---

## 1. Introduction

Quick Trusted Response (QTR) Codes enhance the security and trustworthiness of QR codes by introducing a standardised verification mechanism. This mechanism allows applications to authenticate the content of QR codes before any action is taken, mitigating risks associated with malicious QR codes. The QTR mechanism can be used outside of QR codes by browsers or applications processing links, implementation details for non-QR use-cases is out-of-scope for this document.

## 2. Terminology

- **QTR:** Quick Trusted Response
- **QTR Code:** A QR code that includes mechanisms to verify signed information.
- **JWT:** JSON Web Token is a format encompassing a header, payload and signature.
- **BIMI:** Brand Indicators for Message Identification; used for displaying verified brand logos.
- **Key ID (`kid`):** Identifier for the public key used in signature verification.
- **Key Location:** Method to retrieve the public key:
  - `d`: `{kid}._qtr` DNS record
  - `w`: `.well-known/jwks.json`
  - `s`: `.well-known/qtr/{kid}.json`
  - `h`: `X-QTR-P` header available in HEAD request to hostname
  - `u`: `X-QTR-P` header available in HEAD request to URL

## 3. QTR Parameter Format

### 3.1 Structure

The `x-qtr` parameter utilises JWTs.
``` javascript
x-qtr={jwt: "header . payload . signature"}
```

Where the payload consists of a version and key location identifier: `{"qtr": "1d"}`.

- **version** (1 or more numerical digits): QTR protocol version number (e.g., `1`).
- **key_location** (1 a-z character): Method to retrieve the public key.
- **key_id** (variable length): Identifier for the public key (optional for `h` and `u` key locations).
- **signature** (variable length): base64 URL safe encoded cryptographic signature.

#### 3.1.1 QTR Parameter Regular Expression

`x-qtr` regex:
``` regex
(?i:x-qtr=)?(?P<header>[A-Za-z0-9_-]+)\.(?P<payload>[A-Za-z0-9_-]+)\.(?P<signature>[A-Za-z0-9_-]+)
```

Decoded payload regex:
``` regex
(?:{"qtr":\s*")?(?P<version>\d+)(?P<key_location>[a-z])(?:"})?
```

### 3.2 Examples

1: `x-qtr=eyJhbGciOiJFZERTQSIsImlzcyI6ImV4YW1wbGUuY29tIiwia2lkIjoiMTIzNCJ9.eyJxdHIiOiIxZCJ9.TVuX6dqmmVi-nF8YLo8GquM5MfsLqexcv4KXmGliNt--c2RT6b34sR2dQfD3O20OlhjpDRXAPLh3DAgZ0KClBw`

- **Header:** `eyJhbGciOiJFZERTQSIs...` = `{"alg":"EdDSA","iss":"example.com","kid":"1234"}`
  - **Signing algorithm:** `EdDSA`
  - **Issuer:** `example.com`
  - **Key ID:** `1234`
- **Payload:** `eyJxdHIiOiIxZCJ9` = `{"qtr": "1d"}`
  - **Version:** `1`
  - **Key Location:** `d` (DNS)
- **Signature:** `TVuX6dqmmVi-nF8YLo8GquM5MfsLqexcv4KXmGliNt--c2RT6b34sR2dQfD3O20OlhjpDRXAPLh3DAgZ0KClBw` (Ed25519 signature in base64 URL safe format)

2: `x-qtr=eyJhbGciOiJFZERTQSJ9.eyJxdHIiOiAiMWgifQ.TVuX6dqmmVi-nF8YLo8GquM5MfsLqexcv4KXmGliNt--c2RT6b34sR2dQfD3O20OlhjpDRXAPLh3DAgZ0KClBw`

- **Header:** `eyJhbGciOiJFZERTQSJ9` = `{"alg":"EdDSA"}`
  - **Signing algorithm:** `EdDSA`
  - **Issuer:** _null_ (use domain in URL)
  - **Key ID:** _null_ (public key in `X-QTR-P` response header)
- **Payload:** `eyJxdHIiOiIxZCJ9` = `{"qtr": "1d"}`
  - **Version:** `1`
  - **Key Location:** `h` (`X-QTR-P` response header to hostname request)
- **Signature:** `TVuX6dqmmVi-nF8YLo8GquM5MfsLqexcv4KXmGliNt--c2RT6b34sR2dQfD3O20OlhjpDRXAPLh3DAgZ0KClBw` (Ed25519 signature in base64 URL safe format)

### 3.3 Additional Parameters

- **`x-qtrs`:** (Optional) Specifies the short URL mechanism.
  - Example: `https://example.com?x-qtrs`

## 4. Operational Workflow

### 4.1 QR Code Generation

1. **Data Preparation:**
   - Original data (e.g., URL, Wi-Fi credentials) is prepared.
  
2. **Appending QTR Parameters:**
   - The `x-qtr` parameter is constructed and appended to the data, minus the signature and trailing `.`
   - `x-qtr` should be the last parameter

3. **Signature Generation:**
   - The data is signed using a private key compliant with cryptographic specifications.

4. **Appending QTR Signature:**
   - A `.` is added to the `x-qtr`
   - Signature is appended to the `x-qtr` parameter to create the JWT.

5. **Minifying the QR Code:**
   - The `x-qtrs` parameter can be used to specify the shortening mechanism.

### 4.2 QR Code Scanning and Verification

- **Data Extraction:**
  - Application scans the QR code and extracts data and parameters.

- **Parameter Parsing:**
  - If anyting is set after the host (other than a trailing `/`), then `x-qtr` or `x-qtrs` parameters are required for a possible verified link.
  - In other words, if the data is a URL with only a host (or a path of `/`) then `x-qtr` parameters are optional.
  - BIMI and valid VMC will still be required to be a verified link.
  - If applicable, parse the `x-qtr` or the `x-qtrs` parameter.

- **Handle Shortened URL:**
  - Check the domain for a valid BIMI record.
  - Perform a GET request without following redirects.
  - Continue verification using the `Location` response header.
  - Inform the user if domains differ.

- **Original Data Reconstruction**
  - If applicable, remove the signature from the `x-qtr` JWT and trailing `.` to retrieve the pre-signed data.
  - The data must be trimmed of any trailing `&?#./` characters (regex `[&\?#\.\/]+$`), for example:
    - `https://qtrco.de?` => `https://qtrco.de`
    - `https://qtrco.de?x-qtr=eyJh11.eyJh22.eyJh33&test=1` => `https://qtrco.de?x-qtr=eyJh11.eyJh22&test=1`
    - `tel:+441234567890#x-qtr=eyJh11.eyJh22.eyJh33` => `tel:+441234567890#x-qtr=eyJh11.eyJh22`

- **Domain Determination**
  - Determine the domain from the JWT header `iss` value.

- **Public Key Retrieval**
  - Check cache for existing `key_id`.
  - Retrieve the public key using the specified `key_location` and `key_id`.

- **Signature Verification**
  - Verify the signature using the retrieved public key.

- **BIMI Integration**
  - Check cache for logo and VMC.
  - Retrieve and display the BIMI logo associated with the domain.
    - First at `default._bimi.{domain}`
    - Then at `qtr._bimi.{domain}`

- **User Feedback**
  - Inform the user of the verification result within 4 seconds.

## 5. Cryptographic Specifications

### 5.1 Supported Algorithms

- **Ed25519-SHA256:**
  - Signature Algorithm: EdDSA using Ed25519 curve and SHA-256 hash.

### 5.2 Signature Generation

- **Data to Sign:**
  - The original data plus the `x-qtr` or `x-qtrs` parameters without any signature.

- **Process:**
  - Sign the data using the private key.

- **Signature Encoding:**
  - Encode the signature in URL safe base64 and append to the `x-qtr` parameter to form a JWT.

### 5.3 Public Key Format

- **Encoding:**
  - Public keys are JWKs either as JSON, or URL safe Base64 encoded JSON.

## 6. Public Key Retrieval Methods

### 6.1 DNS Record (`key_location == 'd'`)

- **Query:**
  - TXT record at `{key_id}._qtr.{domain}`
  - Cascades upwards similar to BIMI DNS records.
    - For example, the domain `third.second.first.example.com` will invoke the following lookups until the `key_id` is found:
      - `{key_id}._qtr.third.second.first.example.com`
      - `{key_id}._qtr.second.first.example.com`
      - `{key_id}._qtr.first.example.com`
      - `{key_id}._qtr.example.com`

- **Record Content:**
  - Contains the public key in Base64-encoded JWT format.
  - Example: `eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IkRnU2I1SGtzeHh1aTNEMUljaVFkYjMySXpWbExjUjc3VjJZUWk1b25fVTgifQ`

### 6.2 Well-Known JWKS (`key_location == 'w'`)

- **URL:**
  ```
  https://{domain}/.well-known/jwks.json
  ```

- **Content:**
  - JSON Web Key Set containing public keys.
  - Example: `{"keys":[{"kid":"1234","kty":"OKP","crv":"Ed25519","x":"DgSb5Hksxxui3D1IciQdb32IzVlLcR77V2YQi5on_U8"}]}`

- **Key Identification:**
  - Use `key_id` (`kid`) to select the correct key.

### 6.3 Specific Well-Known Endpoint (`key_location == 's'`)

- **URL:**
  ```
  https://{domain}/.well-known/qtr/{key_id}.json
  ```

- **Content:**
  - JSON Web Key containing public key.
  - Example: `{"kty":"OKP","crv":"Ed25519","x":"DgSb5Hksxxui3D1IciQdb32IzVlLcR77V2YQi5on_U8"}`

### 6.4 HTTP Response Header from Hostname (`key_location == 'h'`)

- **X-QTR-P Header:**
  - `curl -X HEAD https://{domain}`
  - Where one key is used for the whole domain
  - Example: `X-QTR-P: eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IkRnU2I1SGtzeHh1aTNEMUljaVFkYjMySXpWbExjUjc3VjJZUWk1b25fVTgifQ`

- **Content:**
  - Contains the public key in Base64-encoded JWT format.

### 6.5 HTTP Response Header from URL (`key_location == 'u'`)

- **X-QTR-P Header:**
  - `curl -X HEAD https://{domain}/{path}{querystrings}`
  - Where different keys are used for different URLs
  - Remove any `x-qtr` parameters
  - Example: `X-QTR-P: eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IkRnU2I1SGtzeHh1aTNEMUljaVFkYjMySXpWbExjUjc3VjJZUWk1b25fVTgifQ`

- **Content:**
  - Contains the public key in Base64-encoded JWT format.
 
## 7. Example

Using the following example Ed25519 key pair:
- Private key: `XdIlrwpzVw51QcI7SRQYcY8VMjKSrXtvtbxauvsC_tk`
- Public key: `7kyURdPplV85hQ6BcVuvEbcBTMRhosOs5Jv5oGfu28k`

### 7.1 Generation

The following steps generate a signed URL where a public key is set in the response header of a HEAD request to host (e.g. `example.com`).

URL to sign: `https://example.com/testing?test=abc123`

Generate a JWT header with at least an algorithm (`alg`) set (e.g. `{"alg":"EdDSA"}`) and payload of `{"qtr":"1h"}`.

Append the JWT (minus signature and with no trailing `.`) to the URL: `https://example.com/testing?test=abc123&x-qtr=eyJhbGciOiJFZERTQSJ9.eyJxdHIiOiAiMWgifQ`

Sign the URL and append the signature: `https://example.com/testing?test=abc123&x-qtr=eyJhbGciOiJFZERTQSJ9.eyJxdHIiOiAiMWgifQ.pLQJOGWHRL34IA8Lr3T4CHVrnw325AlOnedfRzjDpqiVguOoHpkHKkqouGF449gtcqWulSgexuCTTE9gbzsBDQ`

``` python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import base64
import json

def base64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")

def base64url_decode(data):
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)

# Given data
private_key_b64url = "XdIlrwpzVw51QcI7SRQYcY8VMjKSrXtvtbxauvsC_tk"
private_key_bytes = base64.urlsafe_b64decode(private_key_b64url + "==")
private_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
public_key = private_key.public_key()

# Original URL
original_url = "https://example.com/testing?test=abc123"

# Create JWT header and payload
header = {"alg": "EdDSA"}
payload = {"qtr": "1h"}

header_json = json.dumps(header, separators=(",", ":")).encode("utf-8")
payload_json = json.dumps(payload, separators=(",", ":")).encode("utf-8")

header_b64url = base64url_encode(header_json)
payload_b64url = base64url_encode(payload_json)

partial_jwt = f"{header_b64url}.{payload_b64url}"

# Message to sign is the URL with x-qtr containing the partial JWT
message_to_sign = f"{original_url}&x-qtr={partial_jwt}"

print("Unsigned URL:", message_to_sign)

# Sign the message
signature = private_key.sign(message_to_sign.encode("utf-8"))
signature_b64url = base64url_encode(signature)

# Append the signature to the JWT
full_jwt = f"{partial_jwt}.{signature_b64url}"

# Construct the final URL
final_url = f"{original_url}&x-qtr={full_jwt}"

print("Signed URL:", final_url)

# To verify the signature (optional)
# Extract the message to verify and the signature
signature_to_verify = base64url_decode(signature_b64url)
message_to_verify = message_to_sign.encode("utf-8")

try:
    public_key.verify(signature_to_verify, message_to_verify)
    print("Signature is valid.")
except Exception as e:
    print("Signature is invalid:", str(e))
```

### 7.2 Verification

To verify a signed URL like: `https://example.com/testing?test=abc123&x-qtr=eyJhbGciOiJFZERTQSJ9.eyJxdHIiOiAiMWgifQ.pLQJOGWHRL34IA8Lr3T4CHVrnw325AlOnedfRzjDpqiVguOoHpkHKkqouGF449gtcqWulSgexuCTTE9gbzsBDQ`

Parse QTR JWT, to get version 1 and key location `h` (in the `x-qtr-p` response header from HEAD request to host).

`curl --head -s https://example.com | grep "x-qtr-p:"` =>  
`x-qtr-p: eyJrdHkiOiJPS1AiLCJjcnYiOiAiRWQyNTUxOSIsIngiOiAiN2t5VVJkUHBsVjg1aFE2QmNWdXZFYmNCVE1SaG9zT3M1SnY1b0dmdTI4ayJ9`

Decode the `X-QTR-P` value to get the public key.

Remove the signature: `https://example.com/testing?test=abc123&x-qtr=eyJhbGciOiJFZERTQSJ9.eyJxdHIiOiAiMWgifQ`

Verify the signature using the public key from the JWK that was in the `x-qtr-p` response header.

``` python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
import base64

# url = b"https://example.com/testing?test=abc123&x-qtr=eyJhbGciOiJFZERTQSJ9.eyJxdHIiOiAiMWgifQ.pLQJOGWHRL34IA8Lr3T4CHVrnw325AlOnedfRzjDpqiVguOoHpkHKkqouGF449gtcqWulSgexuCTTE9gbzsBDQ"

# Given data
public_key_b64url = "7kyURdPplV85hQ6BcVuvEbcBTMRhosOs5Jv5oGfu28k"
signature_b64url = "pLQJOGWHRL34IA8Lr3T4CHVrnw325AlOnedfRzjDpqiVguOoHpkHKkqouGF449gtcqWulSgexuCTTE9gbzsBDQ"
message = b"https://example.com/testing?test=abc123&x-qtr=eyJhbGciOiJFZERTQSJ9.eyJxdHIiOiAiMWgifQ"

# Decode the public key from Base64URL to bytes
public_key_bytes = base64.urlsafe_b64decode(public_key_b64url + "==")

# Load the public key
public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)

# Decode the signature from Base64URL to bytes
signature_bytes = base64.urlsafe_b64decode(signature_b64url + "==")

# Verify the signature
try:
    public_key.verify(signature_bytes, message)
    print("Signature is valid.")
except Exception as e:
    print("Signature is invalid:", str(e))
```

## 8. Error Handling and Timeouts

- **Timeouts:**
  - Maximum acceptable latency for verification is **4 seconds**.

- **Error Handling:**
  - If verification cannot be completed within the timeout, **warn the user**.

- **Error Codes:**
  - Implement error codes similar to email specifications (e.g., SMTP error codes).


## 9. Backward Compatibility

- **Compatibility:**
  - QTR Codes are designed to be backward compatible with standard QR code readers.

- **Non-QTR Aware (Standard QR Reader) Applications:**
  - Applications that do not recognise `x-qtr` parameters will ignore them and process the data normally.


## 10. Security Considerations

- **Private Key Security:**
  - Private keys must be securely generated, stored, and managed.

- **Input Validation:**
  - Validate all inputs to prevent injection and other attacks.

- **Key Rotation:**
  - Implement key rotation policies where appropriate.

- **TLS Requirements:**
  - Use HTTPS for all network requests to ensure data integrity and confidentiality.

- **Compliance:**
  - Adhere to relevant industry standards and regulations (e.g., GDPR, PCI DSS).


## 11. Privacy and Ethical Considerations

- **Data Minimisation:**
  - Collect only data necessary for verification.

- **User Consent:**
  - Inform users about data processing activities.

- **Transparency:**
  - Be transparent about how data is used and stored.

- **Ethical Use:**
  - Ensure QTR Codes are not used to track or profile users without consent.


## 12. Future Extensions

- **Quantum-Resistant Algorithms:**
  - Explore the adoption of quantum-resistant cryptographic algorithms.

- **Additional Data Types:**
  - Extend support to other data types as needed.

- **Internationalisation:**
  - Support internationalised domain names and multilingual data.

- **Offline Verification Enhancements:**
  - Improve caching mechanisms for better offline support.


## 13. References

- **DKIM Specifications:** [RFC 6376](https://tools.ietf.org/html/rfc6376)
- **BIMI Specifications:** [AuthIndicators Working Group](https://bimigroup.org/)
- **JSON Web Token (JWT):** [RFC 7519](https://tools.ietf.org/html/rfc7519)
- **JSON Web Key (JWK):** [RFC 7517](https://tools.ietf.org/html/rfc7517)
- **Ed25519 Algorithm:** [RFC 8032](https://tools.ietf.org/html/rfc8032)
