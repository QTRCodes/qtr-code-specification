# Quick Trusted Response (QTR) Codes Specification Document

**Title:** Quick Trusted Response (QTR) Codes Specification  
**Version:** 0.1  
**Status:** Drafting  
**Date written and last reviewed:** 30th September 2024  

## Table of Contents

1. [Introduction](#1-introduction)
2. [Terminology](#2-terminology)
3. [QTR Parameter Format](#3-qtr-parameter-format)
   - [3.1 Structure](#31-structure)
   - [3.2 Example](#32-example)
   - [3.3 Additional Parameters](#33-additional-parameters)
4. [Operational Workflow](#4-operational-workflow)
   - [4.1 QR Code Generation](#41-qr-code-generation)
   - [4.2 QR Code Scanning and Verification](#42-qr-code-scanning-and-verification)
5. [Cryptographic Specifications](#5-cryptographic-specifications)
   - [5.1 Supported Algorithms](#51-supported-algorithms)
   - [5.2 Signature Generation](#52-signature-generation)
   - [5.3 Public Key Format](#53-public-key-format)
   - [5.4 Encodings](#54-encodings)
6. [Public Key Retrieval Methods](#6-public-key-retrieval-methods)
   - [6.1 DNS Record (`key_location == 'd'`)](#61-dns-record-key_location--d)
   - [6.2 Well-Known JWKS (`key_location == 'w'`)](#62-well-known-jwks-key_location--w)
   - [6.3 Specific Well-Known Endpoint (`key_location == 's'`)](#63-specific-well-known-endpoint-key_location--s)
7. [Error Handling and Timeouts](#7-error-handling-and-timeouts)
8. [Backward Compatibility](#8-backward-compatibility)
9. [Security Considerations](#9-security-considerations)
10. [Privacy and Ethical Considerations](#10-privacy-and-ethical-considerations)
11. [Future Extensions](#11-future-extensions)
12. [References](#12-references)

---

## 1. Introduction

Quick Trusted Response (QTR) Codes enhance the security and trustworthiness of QR codes by introducing a standardised verification mechanism. This mechanism allows applications to authenticate the content of QR codes before any action is taken, mitigating risks associated with malicious QR codes.

## 2. Terminology

- **QTR Code:** A QR code that includes mechanisms to verify signed information.
- **BIMI:** Brand Indicators for Message Identification; used for displaying verified brand logos.
- **Key ID (`kid`):** Identifier for the public key used in signature verification.
- **Key Location:** Method to retrieve the public key:
  - `d`: DNS record
  - `w`: `.well-known/jwks.json`
  - `s`: `.well-known/{kid}.json`
- **DER Format:** Distinguished Encoding Rules format for encoding public keys.
- **z-base-32 Encoding:** Encoding scheme that represents binary data in an ASCII string format.

## 3. QTR Parameter Format

### 3.1 Structure

The `qtr` parameter has the following structure:

```
qtr={version}{key_location}{key_id}-{signature}
```

- **version** (1 or more numerical digits): QTR protocol version number (e.g., `1`).
- **key_location** (1 a-z character): Method to retrieve the public key.
- **key_id** (variable length): Identifier for the public key.
- **signature** (variable length): z-base-32 encoded cryptographic signature.

#### 3.1.1 QTR Parameter Regular Expression

```
^(?P<version>[0-9]+)(?P<key_location>[a-z])(?P<key_id>.*)\-(?P<signature>[ybndrfg8ejkmcpqxot1uwisza345h769]+)$
```

### 3.2 Example

```
qtr=1d1234-rjuy7pgn9dmagkptxyfhzicf4rhkrnic6851oc96456qr651efso
```

- **Version:** `1`
- **Key Location:** `d` (DNS)
- **Key ID:** `1234`
- **Signature:** `rjuy7pgn9dmagkptxyfhzicf4rhkrnic6851oc96456qr651efso` (SHA256 hash in z-base-32 format)

### 3.3 Additional Parameters

- **`qtr-d`:** (Optional) Specifies the domain for non-URL data.
  - Example: `https://example.com?qtr-d=github.com`
- **`qtr-s`:** (Optional) Specifies the short URL mechanism.
  - Example: `https://example.com?qtr-s`

## 4. Operational Workflow

### 4.1 QR Code Generation

1. **Data Preparation:**
   - Original data (e.g., URL, Wi-Fi credentials) is prepared.

2. **Signature Generation:**
   - The data is signed using a private key compliant with cryptographic specifications.

3. **Appending QTR Parameters:**
   - The `qtr` parameter is constructed and appended to the data.
   - If applicable, the `qtr-d` parameter is also appended.

4. **Minifying the QR Code:**
   - The `qtr-s` parameter can be used to specify the shortening mechanism.

### 4.2 QR Code Scanning and Verification

- **Data Extraction:**
  - Application scans the QR code and extracts data and parameters.

- **Parameter Parsing:**
  - If querystrings other than those used for `qtr`, then `qtr` parameters are required for a possible verified link.
  - In other words, if the data is a URL with only a host (or a path of `/`) then `qtr` parameters are optional.
  - BIMI and valid VMC will still required to be a verified link.
  - If applicable, parse the `qtr` and `qtr-d` parameters, or the `qtr-s` parameter.

- **Handle Shortened URL:**
  - Check the domain for a valid BIMI record.
  - Perform a GET request without following redirects.
  - Continue verification using the `Location` response header.
  - Inform the user if domains differ.

- **Original Data Reconstruction**
  - If applicable, remove `qtr` and `qtr-d` to retrieve the original data.
  - The data should be trimmed of any trailing `&` or `?` characters, for example:
    - `https://qtrco.de?test=123&qtr=1d123-...` => `https://qtrco.de?test=123`
    - `https://qtrco.de?qtr=1d456-...` => `https://qtrco.de`

- **Domain Determination**
  - Determine the domain from the URL or `qtr-d` parameter.

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

- **RSA-SHA256:**
  - Signature Algorithm: RSASSA-PKCS1-v1_5 using SHA-256.

- **Ed25519-SHA256:**
  - Signature Algorithm: EdDSA using Ed25519 curve and SHA-256 hash.

### 5.2 Signature Generation

- **Data to Sign:**
  - The original data without `qtr` and `qtr-d` parameters.

- **Process:**
  - Generate a hash of the data using SHA-256.
  - Sign the hash using the private key corresponding to the public key.

- **Signature Encoding:**
  - Encode the signature in Base64.

### 5.3 Public Key Format

- **Encoding:**
  - Public keys are encoded in DER format and then Base64-encoded.

- **DNS Record Format:**
  - TXT record containing the public key:
    ```
    v=QTR1; p={Base64-encoded DER public key}
    ```

### 5.4 Encodings

- **z-base-32:**
  - **Alphabet:** `ybndrfg8ejkmcpqxot1uwisza345h769`

- **Example:**
  - **Plaintext:** `test`
  - **SHA256 Hash:** `da77e228257194ecf7d6a1f7e1bee8ac5e3ba895ec13bb0bba8942377b64a6c4`
  - **z-base-32 Encoding:** `5j56rkbfqgkq376sw856dxzeitxdzkri7oj5sn74tfbdq65rw5ny`

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
  - Contains the public key in Base64-encoded DER format (similar to DKIM).

### 6.2 Well-Known JWKS (`key_location == 'w'`)

- **URL:**
  ```
  https://{domain}/.well-known/jwks.json
  ```

- **Content:**
  - JSON Web Key Set containing public keys.

- **Key Identification:**
  - Use `key_id` (`kid`) to select the correct key.

### 6.3 Specific Well-Known Endpoint (`key_location == 's'`)

- **URL:**
  ```
  https://{domain}/.well-known/{key_id}.json
  ```

- **Content:**
  - JSON containing the public key.


## 7. Error Handling and Timeouts

- **Timeouts:**
  - Maximum acceptable latency for verification is **2 seconds**.

- **Error Handling:**
  - If verification cannot be completed within the timeout, **warn the user**.

- **Error Codes:**
  - Implement error codes similar to email specifications (e.g., SMTP error codes).


## 8. Backward Compatibility

- **Compatibility:**
  - QTR Codes are designed to be backward compatible with standard QR code readers.

- **Non-QTR Aware (Standard QR Reader) Applications:**
  - Applications that do not recognise `qtr` parameters will ignore them and process the data normally.


## 9. Security Considerations

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


## 10. Privacy and Ethical Considerations

- **Data Minimisation:**
  - Collect only data necessary for verification.

- **User Consent:**
  - Inform users about data processing activities.

- **Transparency:**
  - Be transparent about how data is used and stored.

- **Ethical Use:**
  - Ensure QTR Codes are not used to track or profile users without consent.


## 11. Future Extensions

- **Quantum-Resistant Algorithms:**
  - Explore the adoption of quantum-resistant cryptographic algorithms.

- **Additional Data Types:**
  - Extend support to other data types as needed.

- **Internationalisation:**
  - Support internationalised domain names and multilingual data.

- **Offline Verification Enhancements:**
  - Improve caching mechanisms for better offline support.


## 12. References

- **DKIM Specifications:** [RFC 6376](https://tools.ietf.org/html/rfc6376)
- **BIMI Specifications:** [AuthIndicators Working Group](https://bimigroup.org/)
- **JSON Web Key (JWK):** [RFC 7517](https://tools.ietf.org/html/rfc7517)
- **RSA Cryptography Standard:** [RFC 8017](https://tools.ietf.org/html/rfc8017)
- **Ed25519 Algorithm:** [RFC 8032](https://tools.ietf.org/html/rfc8032)
