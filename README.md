<div align="center">
<img src="./he-saas-logo.svg" alt="HEaaS Logo" width="200"/>
</div>

# Homomorphic Encryption-as-a-Service
## Official Customer User Guide & API Reference

**Version:** 1.0.0  
**Last Updated:** October 2023  
**Support:** support@yourdomain.com | [Insert Phone Number]

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Getting Started](#2-getting-started)
3. [Using the Web Dashboard](#3-using-the-web-dashboard)
4. [API Integration Guide](#4-api-integration-guide)
5. [Troubleshooting](#5-troubleshooting)
6. [FAQs](#6-faqs)
7. [Contact & Support](#7-contact--support)

---

## 1. Introduction

Welcome to **HEaaS**, the world’s first accessible Homomorphic Encryption-as-a-Service platform. 

### What is Homomorphic Encryption?
Homomorphic Encryption (HE) allows computations to be performed on encrypted data without ever decrypting it. This means you can analyze sensitive data (medical records, financial transactions, AI training sets) while maintaining absolute privacy and regulatory compliance (GDPR, HIPAA).

### Why Choose HEaaS?
*   **Zero-Knowledge Architecture:** We never see your plaintext data. Even if our servers are compromised, your data remains secure.
*   **High Performance:** Leveraging optimized lattice-based cryptography (BFV Scheme) for fast computation.
*   **Easy Integration:** Simple REST API and intuitive web dashboard.

---

## 2. Getting Started

### Step 1: Create an Account
1. Navigate to `https://app.yourdomain.com` (replace with your actual URL).
2. Click **"Register"**.
3. Enter your email and a strong password (min. 8 characters).
4. Verify your email address via the link sent to your inbox.

### Step 2: Understand Your Keys
Upon registration, our system generates a unique **Key Pair** for you:
*   **Public Key:** Used to encrypt data before sending it to us.
*   **Private Key:** Used to decrypt results locally. **Never share this key.**

> **Security Note:** For maximum security, we recommend generating keys client-side using our provided SDKs. However, for ease of use, our dashboard manages keys securely for you.

---

## 3. Using the Web Dashboard

The Dashboard is designed for quick testing and manual job submission.

### 3.1 Login
1. Go to the login page.
2. Enter your credentials.
3. You will be redirected to the **Dashboard**.

### 3.2 Submitting a Computation Job
1. Locate the **"New Computation"** card.
2. Enter two integer values (e.g., `Value 1: 5`, `Value 2: 10`).
3. Select the operation: **Add** or **Multiply**.
4. Click **"Compute"**.

### 3.3 Viewing Results
1. The job status will change from `Pending` → `Processing` → `Completed`.
2. Once completed, the **Result (Base64)** will appear.
3. Copy the Base64 string.
4. Use the **"Decrypt Result"** button (if enabled) or your local SDK to decrypt the value.

---

## 4. API Integration Guide

For automated workflows, use our REST API.

### Authentication
All API requests require a Bearer Token.
1. Login via `/api/auth/login`.
2. Store the returned `token`.
3. Include it in headers: `Authorization: Bearer <your_token>`

### Endpoints

#### 1. Register User
**Endpoint:** `POST /api/auth/register`

**Request Body:**
    {
      "email": "user@example.com",
      "password": "securePassword123"
    }

#### 2. Login
**Endpoint:** `POST /api/auth/login`

**Request Body:**
    {
      "email": "user@example.com",
      "password": "securePassword123"
    }

#### 3. Submit Compute Job
**Endpoint:** `POST /api/compute/jobs`

**Request Body:**
    {
      "input_data_b64": "[\"base64_ct1\", \"base64_ct2\"]",
      "operation": "add"
    }

*Note: `input_data_b64` must be a JSON array of two Base64-encoded ciphertexts.*

#### 4. Get Job Status
**Endpoint:** `GET /api/compute/jobs/{job_id}`

**Response Example:**
    {
      "id": "uuid-string-here",
      "status": "completed",
      "result_b64": "base64_result_ciphertext_here",
      "error_message": null
    }

### Python SDK Example

    import requests
    import base64
    import json

    API_URL = "https://api.yourdomain.com"
    TOKEN = "your_jwt_token"

    headers = {
        "Authorization": f"Bearer {TOKEN}",
        "Content-Type": "application/json"
    }

    # Assume ct1_b64 and ct2_b64 are already encrypted using SEAL
    payload = {
        "input_data_b64": json.dumps([ct1_b64, ct2_b64]),
        "operation": "add"
    }

    response = requests.post(f"{API_URL}/api/compute/jobs", json=payload, headers=headers)
    job_id = response.json()["id"]

    # Poll for result
    while True:
        status_resp = requests.get(f"{API_URL}/api/compute/jobs/{job_id}", headers=headers)
        data = status_resp.json()
        if data["status"] == "completed":
            print("Result:", data["result_b64"])
            break
        elif data["status"] == "failed":
            print("Error:", data["error_message"])
            break

---

## 5. Troubleshooting

| Issue | Possible Cause | Solution |
| :--- | :--- | :--- |
| **Invalid Input Format** | Malformed Base64 or JSON. | Ensure ciphertexts are serialized correctly. Check JSON structure. |
| **Decryption Error** | Mismatched parameters. | Verify client-side SEAL params match server config (Poly Modulus Degree: 4096, Plain Modulus: 1024). |
| **Noise Budget Exceeded** | Too many operations. | Reduce computation depth. Contact support for advanced bootstrapping options. |
| **Timeout** | Complex multiplication. | Break large jobs into smaller batches. |
| **401 Unauthorized** | Invalid/Expired Token. | Re-login to get a new JWT token. |

---

## 6. FAQs

**Q: Is my data safe?**  
A: Yes. We use military-grade BFV homomorphic encryption. Your data is encrypted end-to-end. We never store or process plaintext.

**Q: What operations are supported?**  
A: Currently, we support Addition and Multiplication of integers. More complex functions (polynomials, comparisons) are coming soon.

**Q: How do I cancel a subscription?**  
A: Log in to your dashboard, go to **Billing**, and click **Cancel Subscription**. Your access will remain until the end of the billing cycle.

**Q: Do you offer enterprise plans?**  
A: Yes. Contact sales@yourdomain.com for custom SLAs, dedicated instances, and on-premise deployment options.

---

## 7. Contact & Support

We are here to help you succeed with privacy-preserving computation.

*   **Technical Support:** support@yourdomain.com
*   **Sales Inquiries:** sales@yourdomain.com
*   **Status Page:** status.yourdomain.com
*   **Documentation:** docs.yourdomain.com

© 2023 HEaaS Inc. All Rights Reserved.
