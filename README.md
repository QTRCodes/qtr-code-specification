# Quick Trusted Response (QTR) Codes Specification Document

**Title:** Quick Trusted Response (QTR) Codes Specification  
**Version:** 0.1  
**Status:** Drafting  
**Date last updated:** 17th October 2024  

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
7. [Examples](#7-examples)
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
- **BIMI:** Brand Indicators for Message Identification; used for displaying verified brand logos.
- **Key ID (`kid`):** Identifier for the public key used in signature verification.
- **Key Location:** Method to retrieve the public key:
  - `d`: DNS record
  - `w`: `.well-known/jwks.json`
  - `s`: `.well-known/{kid}.json`
  - `h`: `X-QTR-P` header available in HEAD request to hostname
  - `u`: `X-QTR-P` header available in HEAD request to URL

## 3. QTR Parameter Format

### 3.1 Structure

The `x-qtr` parameter has the following structure:

```
x-qtr={version}{key_location}{key_id}-{signature}
```

- **version** (1 or more numerical digits): QTR protocol version number (e.g., `1`).
- **key_location** (1 a-z character): Method to retrieve the public key.
- **key_id** (variable length): Identifier for the public key (optional for `h` and `u` key locations).
- **signature** (variable length): base64 URL safe encoded cryptographic signature.

#### 3.1.1 QTR Parameter Regular Expression

```
^(?i:x-qtr=)?(?P<version>\d+)(?P<key_location>[a-z])(?P<key_id>[^-]+)?\-(?P<signature>[A-Za-z0-9_-]+)$
```

### 3.2 Examples

1: `x-qtr=1d1234-TVuX6dqmmVi-nF8YLo8GquM5MfsLqexcv4KXmGliNt--c2RT6b34sR2dQfD3O20OlhjpDRXAPLh3DAgZ0KClBw`

- **Version:** `1`
- **Key Location:** `d` (DNS)
- **Key ID:** `1234`
- **Signature:** `TVuX6dqmmVi-nF8YLo8GquM5MfsLqexcv4KXmGliNt--c2RT6b34sR2dQfD3O20OlhjpDRXAPLh3DAgZ0KClBw` (Ed25519 signature in base64 URL safe format)

2: `x-qtr=1h-TVuX6dqmmVi-nF8YLo8GquM5MfsLqexcv4KXmGliNt--c2RT6b34sR2dQfD3O20OlhjpDRXAPLh3DAgZ0KClBw`

- **Version:** `1`
- **Key Location:** `h` (`X-QTR-P` response header to hostname request)
- **Key ID:** _null_
- **Signature:** `TVuX6dqmmVi-nF8YLo8GquM5MfsLqexcv4KXmGliNt--c2RT6b34sR2dQfD3O20OlhjpDRXAPLh3DAgZ0KClBw` (Ed25519 signature in base64 URL safe format)

### 3.3 Additional Parameters

- **`x-qtr-d`:** (Optional) Specifies the domain for non-URL data.
  - Example: `tel:+441234567890?x-qtr-d=github.com`
- **`x-qtr-s`:** (Optional) Specifies the short URL mechanism.
  - Example: `https://example.com?x-qtr-s`

## 4. Operational Workflow

### 4.1 QR Code Generation

1. **Data Preparation:**
   - Original data (e.g., URL, Wi-Fi credentials) is prepared.

2. **Signature Generation:**
   - The data is signed using a private key compliant with cryptographic specifications.

3. **Appending QTR Parameters:**
   - The `x-qtr` parameter is constructed and appended to the data.
   - If applicable, the `x-qtr-d` parameter is also appended.

4. **Minifying the QR Code:**
   - The `x-qtr-s` parameter can be used to specify the shortening mechanism.

### 4.2 QR Code Scanning and Verification

- **Data Extraction:**
  - Application scans the QR code and extracts data and parameters.

- **Parameter Parsing:**
  - If querystrings other than those used for `x-qtr`, then `x-qtr` parameters are required for a possible verified link.
  - In other words, if the data is a URL with only a host (or a path of `/`) then `x-qtr` parameters are optional.
  - BIMI and valid VMC will still required to be a verified link.
  - If applicable, parse the `x-qtr` and `x-qtr-d` parameters, or the `x-qtr-s` parameter.

- **Handle Shortened URL:**
  - Check the domain for a valid BIMI record.
  - Perform a GET request without following redirects.
  - Continue verification using the `Location` response header.
  - Inform the user if domains differ.

- **Original Data Reconstruction**
  - If applicable, remove `x-qtr` and `x-qtr-d` to retrieve the original data.
  - The data should be trimmed of any trailing `&` or `?` characters, for example:
    - `https://qtrco.de?test=123&x-qtr=1d123-...` => `https://qtrco.de?test=123`
    - `https://qtrco.de?x-qtr=1d456-...` => `https://qtrco.de`

- **Domain Determination**
  - Determine the domain from the URL or `x-qtr-d` parameter.

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
  - The original data without any `x-qtr` parameters.

- **Process:**
  - Generate a hash of the data using SHA-256.
  - Sign the hash using the private key corresponding to the public key.

- **Signature Encoding:**
  - Encode the signature in Base64.

### 5.3 Public Key Format

- **Encoding:**
  - Public keys are Base64-encoded.

- **DNS Record Format:**
  - TXT record containing the public key:
    ```
    v=QTR1; p={Base64-encoded public key}
    ```

## 6. Public Key Retrieval Methods

All public keys are stored in JWK format - either as a JSON string, or Base64 URL safe encoded JSON string.

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
  https://{domain}/.well-known/{key_id}.json
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
 
## 7. Examples

Using the following example Ed25519 key pair:
- Private key: `_rHY8zPRGPGMc4wh5QVZ_UFkdijgZlZrlpAYjrwycT8`
- Public key: `DgSb5Hksxxui3D1IciQdb32IzVlLcR77V2YQi5on_U8`

`https://example.com/testing?test=abc123&x-qtr=1h-SQvtNYeVHAL4usW_UCRVRmTb0A6ZEqB-nayOLbgk-eV90wGDt0MIIeEvkUItJvLTIFstpSmLZxYuGc97R9nNAg`

Parse QTR, to get version 1 and key location in the `X-QTR-P` response header.

`curl --head -s https://example.com | grep "x-qtr-p:"` =>  
`x-qtr-p: eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IkRnU2I1SGtzeHh1aTNEMUljaVFkYjMySXpWbExjUjc3VjJZUWk1b25fVTgifQ`

Decode the `X-QTR-P` value to get the public key.

Extract the message from the URL without `x-qtr` parameters: `https://example.com/testing?test=abc123`

Verify the signature using the public key.

``` python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
import base64

# Given data
public_key_b64url = 'DgSb5Hksxxui3D1IciQdb32IzVlLcR77V2YQi5on_U8'
signature_b64url = 'SQvtNYeVHAL4usW_UCRVRmTb0A6ZEqB-nayOLbgk-eV90wGDt0MIIeEvkUItJvLTIFstpSmLZxYuGc97R9nNAg'
message = b'https://example.com/testing?test=abc123'

# Decode the public key from Base64URL to bytes
public_key_bytes = base64.urlsafe_b64decode(public_key_b64url + '==')

# Load the public key
public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)

# Decode the signature from Base64URL to bytes
signature_bytes = base64.urlsafe_b64decode(signature_b64url + '==')

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
- **JSON Web Key (JWK):** [RFC 7517](https://tools.ietf.org/html/rfc7517)
- **Ed25519 Algorithm:** [RFC 8032](https://tools.ietf.org/html/rfc8032)
