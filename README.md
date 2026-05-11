<div align="center">
<img src="./he-saas-logo.svg" alt="HEaaS Logo" width="400"/>
</div>

# Homomorphic Encryption-as-a-Service
## Official Customer User Guide & API Reference

**Version:** 1.0.0  
**Last Updated:** May 2026  
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
2. Click **"Register"** in the top-right corner.
3. Enter your email address and a strong password (minimum 8 characters, including one uppercase letter and one number).
4. Click **"Create Account"**.
5. Check your email inbox for a verification link. Click the link to activate your account.

### Step 2: Understand Your Keys
Upon registration, our system generates a unique **Key Pair** for you:
*   **Public Key:** Used to encrypt data before sending it to us. This key can be shared.
*   **Private Key:** Used to decrypt results locally. **Never share this key.** It is stored securely in your browser's local storage for convenience, but you should export it for backup.

> **Security Note:** For maximum security, we recommend generating keys client-side using our provided SDKs. However, for ease of use, our dashboard manages keys securely for you. To export your private key, go to **Settings > Security > Export Private Key**.

---

## 3. Using the Web Dashboard

The Dashboard is designed for quick testing and manual job submission. Follow these steps precisely to perform your first homomorphic computation.

### 3.1 Login
1. Go to `https://app.yourdomain.com/login`.
2. Enter your registered email and password.
3. Click **"Login"**.
4. You will be redirected to the **Dashboard**. If you see a "Welcome" message, you are successfully logged in.

### 3.2 Submitting a Computation Job
This section details how to submit two integers for addition or multiplication.

1. **Locate the Input Panel**: On the main dashboard, find the card labeled **"New Computation"**. It is typically located in the center of the screen.
2. **Enter Value 1**: In the field labeled **"Value 1"**, enter the first integer you wish to compute. 
    *   *Example*: Type `5`.
    *   *Note*: Only integers between 0 and 1023 are supported in this demo version due to plaintext modulus constraints.
3. **Enter Value 2**: In the field labeled **"Value 2"**, enter the second integer.
    *   *Example*: Type `10`.
4. **Select Operation**: Click the dropdown menu labeled **"Operation"**.
    *   Select **"Add"** to calculate `Value 1 + Value 2`.
    *   Select **"Multiply"** to calculate `Value 1 * Value 2`.
5. **Submit Job**: Click the blue button labeled **"Compute"**.
    *   *Visual Feedback*: The button will change to "Processing..." and a spinner icon will appear.
    *   *Job ID*: A unique Job ID (e.g., `job_123abc`) will appear below the button. Copy this ID for reference.

### 3.3 Viewing Results
After submitting the job, the system processes the encrypted data.

1. **Monitor Status**: Look at the **"Job Status"** indicator below the input panel.
    *   **Pending**: The job is queued.
    *   **Processing**: The server is performing the homomorphic operation. This may take 2-5 seconds.
    *   **Completed**: The result is ready.
    *   **Failed**: An error occurred. See the Troubleshooting section.
2. **Retrieve Result**: Once the status shows **"Completed"**, a new field labeled **"Result (Base64)"** will appear.
    *   This string is the encrypted result of your computation.
3. **Decrypt Result**:
    *   **Option A (Dashboard)**: If enabled, click the **"Decrypt Result"** button next to the Base64 string. The plaintext result (e.g., `15`) will appear in green text.
    *   **Option B (Local SDK)**: Copy the Base64 string. Use your local Python/JavaScript SDK to decrypt it using your Private Key. This is recommended for production workflows.

---

## 4. API Integration Guide

For automated workflows, use our REST API. This guide assumes you have basic knowledge of HTTP requests.

### Authentication
All API requests require a Bearer Token.
1. Login via `/api/auth/login`.
2. Store the returned `token` from the JSON response.
3. Include it in the header of every subsequent request: `Authorization: Bearer <your_token>`

### Endpoints

#### 1. Register User
**Endpoint:** `POST /api/auth/register`

**Request Body:**
    {
      "email": "user@example.com",
      "password": "securePassword123"
    }

**Response:**
    {
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "user": {
        "id": "uuid-string",
        "email": "user@example.com"
      }
    }

#### 2. Login
**Endpoint:** `POST /api/auth/login`

**Request Body:**
    {
      "email": "user@example.com",
      "password": "securePassword123"
    }

**Response:**
    {
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "user": {
        "id": "uuid-string",
        "email": "user@example.com"
      }
    }

#### 3. Submit Compute Job
**Endpoint:** `POST /api/compute/jobs`

**Headers:**
    Authorization: Bearer <your_token>
    Content-Type: application/json

**Request Body:**
    {
      "input_data_b64": "[\"base64_ct1\", \"base64_ct2\"]",
      "operation": "add"
    }

*Note: `input_data_b64` must be a JSON array of two Base64-encoded ciphertexts. These ciphertexts must be generated using the same SEAL parameters as the server (Poly Modulus Degree: 4096, Plain Modulus: 1024).*

**Response:**
    {
      "id": "job_uuid_string",
      "status": "pending",
      "result_b64": null,
      "error_message": null
    }

#### 4. Get Job Status
**Endpoint:** `GET /api/compute/jobs/{job_id}`

**Headers:**
    Authorization: Bearer <your_token>

**Response Example (Completed):**
    {
      "id": "job_uuid_string",
      "status": "completed",
      "result_b64": "base64_result_ciphertext_here",
      "error_message": null
    }

**Response Example (Failed):**
    {
      "id": "job_uuid_string",
      "status": "failed",
      "result_b64": null,
      "error_message": "Noise budget exceeded"
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
    # You must generate these using the seal-rs library or equivalent
    payload = {
        "input_data_b64": json.dumps([ct1_b64, ct2_b64]),
        "operation": "add"
    }

    response = requests.post(f"{API_URL}/api/compute/jobs", json=payload, headers=headers)
    
    if response.status_code == 202:
        job_id = response.json()["id"]
        print(f"Job submitted: {job_id}")
        
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
            else:
                import time
                time.sleep(1) # Wait 1 second before polling again
    else:
        print("Failed to submit job:", response.text)

---

## 5. Troubleshooting

| Issue | Possible Cause | Solution |
| :--- | :--- | :--- |
| **Invalid Input Format** | Malformed Base64 or JSON. | Ensure ciphertexts are serialized correctly using the same SEAL version. Check that `input_data_b64` is a valid JSON array string. |
| **Decryption Error** | Mismatched parameters. | Verify client-side SEAL params match server config: Poly Modulus Degree: 4096, Plain Modulus: 1024. |
| **Noise Budget Exceeded** | Too many operations. | HE has a limited noise budget. Reduce computation depth. Contact support for advanced bootstrapping options. |
| **Timeout** | Complex multiplication. | Break large jobs into smaller batches. Multiplication is more computationally expensive than addition. |
| **401 Unauthorized** | Invalid/Expired Token. | Re-login to get a new JWT token. Tokens expire after 1 hour. |
| **403 Forbidden** | Rate limit exceeded. | Wait 1 minute before retrying. Free tier allows 10 requests per minute. |

---

## 6. FAQs

**Q: Is my data safe?**  
A: Yes. We use military-grade BFV homomorphic encryption. Your data is encrypted end-to-end. We never store or process plaintext. Even if our servers are compromised, attackers only see ciphertext.

**Q: What operations are supported?**  
A: Currently, we support Addition and Multiplication of integers. More complex functions (polynomials, comparisons) are coming soon.

**Q: How do I cancel a subscription?**  
A: Log in to your dashboard, go to **Billing**, and click **Cancel Subscription**. Your access will remain until the end of the billing cycle.

**Q: Do you offer enterprise plans?**  
A: Yes. Contact sales@yourdomain.com for custom SLAs, dedicated instances, and on-premise deployment options.

**Q: Can I use my own keys?**  
A: Yes. In the **Settings** page, you can upload your own Public/Private key pair. Ensure they are compatible with the BFV scheme parameters used by our server.

---

## 7. Contact & Support

We are here to help you succeed with privacy-preserving computation.

*   **Technical Support:** support@yourdomain.com
*   **Sales Inquiries:** sales@yourdomain.com
*   **Status Page:** status.yourdomain.com
*   **Documentation:** docs.yourdomain.com

© 2026 HEaaS Inc. All Rights Reserved.
