<div align="center">
<img src="./he-saas-logo.svg" alt="HEaaS Logo" width="400"/>
</div>

# Homomorphic Encryption-as-a-Service
## Official Customer Guide & Business Workflow Reference

**Version:** 2.0.0  
**Last Updated:** May 2026  
**Support:** support@yourdomain.com | [Insert Phone Number]

---

## Table of Contents

1. [What is HEaaS & Why You Need It](#1-what-is-heaas--why-you-need-it)
2. [How It Works: The Zero-Knowledge Workflow](#2-how-it-works-the-zero-knowledge-workflow)
3. [Real-World Use Cases](#3-real-world-use-cases)
4. [Getting Started](#4-getting-started)
5. [The Dashboard: A Testing Sandbox](#5-the-dashboard-a-testing-sandbox)
6. [Production Workflow: API & SDK Integration](#6-production-workflow-api--sdk-integration)
7. [Troubleshooting](#7-troubleshooting)
8. [FAQs](#8-faqs)
9. [Contact & Support](#9-contact--support)

---

## 1. What is HEaaS & Why You Need It

### The Problem
Your organization handles sensitive data: medical records, financial transactions, customer PII, or proprietary AI training sets. To analyze this data, you traditionally have to decrypt it. The moment data is decrypted, it becomes vulnerable to breaches, insider threats, and compliance violations (GDPR, HIPAA, SOC2). Cloud providers require you to trust them with your plaintext data, which is increasingly unacceptable for regulated industries.

### The Solution
**HEaaS (Homomorphic Encryption-as-a-Service)** allows you to run computations on **encrypted data without ever decrypting it**. 

You send us ciphertext. Our servers perform mathematical operations directly on that ciphertext. We return an encrypted result. You decrypt it locally. **Your actual data is never visible to us, never stored in plaintext, and never exposed during processing.** This is not a policy promise; it is a mathematical guarantee.

### Why Pay For This?
*   **Regulatory Compliance:** Process sensitive data while remaining fully compliant with GDPR, HIPAA, CCPA, and financial regulations.
*   **Breach Immunity:** Even if our infrastructure is compromised, attackers only obtain mathematically useless ciphertext.
*   **Secure Outsourcing:** Leverage cloud compute power for analytics, risk modeling, or AI training without exposing your raw data to third parties.
*   **Zero-Trust Architecture:** Eliminate the need to trust cloud providers with decryption keys or plaintext data.

---

## 2. How It Works: The Zero-Knowledge Workflow

HEaaS follows a strict cryptographic workflow. Understanding this flow is essential to using the platform correctly.

1. **Local Encryption:** You generate a key pair locally. Using your Public Key, you encrypt your sensitive data on your own machines.
2. **Secure Upload:** You send the encrypted data (ciphertext) to HEaaS via our API. We never receive, request, or store your Private Key.
3. **Blind Computation:** Our servers perform the requested operations (addition, multiplication, statistical aggregations) directly on the ciphertext. The math is designed so that operating on encrypted data yields an encrypted result.
4. **Encrypted Return:** We return the computed result, still fully encrypted.
5. **Local Decryption:** You decrypt the result locally using your Private Key. The output matches exactly what you would have gotten if you had computed on plaintext, but your data was never exposed.

**Key Guarantee:** At no point does HEaaS see, log, or process your actual data. The computation happens in a mathematically sealed environment.

---

## 3. Real-World Use Cases

HEaaS is not a calculator. It is a privacy-preserving compute engine for regulated data.

*   **Healthcare Analytics:** Hospitals can aggregate encrypted patient vitals across multiple facilities to calculate average recovery times or detect outbreaks, without ever exposing individual patient records.
*   **Financial Risk Modeling:** Banks can compute portfolio risk scores, fraud detection metrics, or credit assessments on encrypted transaction data, ensuring customer financial data never leaves a protected state.
*   **Confidential AI/ML Training:** Data scientists can train machine learning models on sensitive datasets (e.g., legal documents, proprietary research) by performing gradient updates on encrypted tensors.
*   **Multi-Party Data Collaboration:** Competing organizations can jointly compute market trends or benchmarking metrics by submitting encrypted data to a neutral HEaaS instance, ensuring no party sees another's raw inputs.

---

## 4. Getting Started

### Step 1: Create an Account
1. Navigate to `https://app.yourdomain.com`.
2. Click **Register** and provide your corporate email and a strong password.
3. Verify your email via the activation link.

### Step 2: Key Management
Upon registration, you will be prompted to generate a **Cryptographic Key Pair**.
*   **Public Key:** Used to encrypt data before upload. Safe to share.
*   **Private Key:** Used to decrypt results locally. **Never share this.** It never leaves your environment.

> **Production Recommendation:** Generate keys using our official SDKs on your secure infrastructure. The dashboard key generator is provided for testing convenience only.

---

## 5. The Dashboard: A Testing Sandbox

**Important:** The web dashboard is a **developer sandbox**, not the production interface. It exists solely to verify that your account, keys, and API connectivity are working before you integrate with your actual data pipelines.

### Why Does It Ask for "Value 1" and "Value 2"?
Homomorphic encryption operates on mathematical structures. To prove the system works without requiring you to write code first, the dashboard provides a simplified test interface:
*   **Value 1 / Value 2:** These are placeholder integers used to generate test ciphertexts behind the scenes.
*   **Add / Multiply:** These are the foundational homomorphic operations. All complex analytics (averages, variances, polynomial regressions) are built from these base operations.
*   **The Workflow:** When you click "Compute", the dashboard encrypts your test integers, sends them to the API, performs the operation on ciphertext, and returns the encrypted result. If you use the "Decrypt" button, it simulates local decryption to show you the math worked.

**In production, you will never manually type integers into a web form.** You will use our API/SDK to send encrypted datasets, run batch computations, and retrieve encrypted results programmatically.

---

## 6. Production Workflow: API & SDK Integration

Real customers interact with HEaaS exclusively via the REST API and official SDKs. Below is the standard production flow.

### Authentication
All API requests require a Bearer Token obtained via `/api/auth/login`. Include it in every request header:
    Authorization: Bearer <your_token>

### Submitting a Compute Job
You send a JSON payload containing Base64-encoded ciphertexts and the desired operation.

Endpoint: `POST /api/compute/jobs`

Request Body:
    {
      "input_data_b64": "[\"base64_ciphertext_1\", \"base64_ciphertext_2\"]",
      "operation": "add"
    }

Note: The ciphertexts must be generated using your Public Key and the same cryptographic parameters as the server (Poly Modulus Degree: 4096, Plain Modulus: 1024). Our SDKs handle this automatically.

Response:
    {
      "id": "job_uuid_string",
      "status": "pending",
      "result_b64": null,
      "error_message": null
    }

### Retrieving Results
Poll the job endpoint until completion.

Endpoint: `GET /api/compute/jobs/{job_id}`

Response (Completed):
    {
      "id": "job_uuid_string",
      "status": "completed",
      "result_b64": "base64_encrypted_result",
      "error_message": null
    }

### Python SDK Production Example
    import requests
    import json
    from heaas_sdk import HEClient, KeyManager

    # 1. Initialize client & load keys
    client = HEClient(api_url="https://api.yourdomain.com", token="your_jwt_token")
    keys = KeyManager.load("./keys/private.key", "./keys/public.key")

    # 2. Encrypt real data locally
    sensitive_data_1 = 842  # e.g., encrypted patient age
    sensitive_data_2 = 156  # e.g., encrypted lab value
    ct1 = keys.encrypt(sensitive_data_1)
    ct2 = keys.encrypt(sensitive_data_2)

    # 3. Submit job (server never sees plaintext)
    job = client.submit_job([ct1, ct2], operation="add")
    print(f"Job queued: {job.id}")

    # 4. Poll & retrieve encrypted result
    result_ct = client.wait_for_result(job.id)

    # 5. Decrypt locally
    plaintext_result = keys.decrypt(result_ct)
    print(f"Computed result: {plaintext_result}")  # Outputs: 998

---

## 7. Troubleshooting

| Issue | Cause | Solution |
| :--- | :--- | :--- |
| **Invalid Input Format** | Ciphertexts not serialized correctly or JSON structure malformed. | Use the official SDK to serialize ciphertexts. Ensure `input_data_b64` is a valid JSON array string. |
| **Decryption Fails Locally** | Parameter mismatch between client and server. | Verify your SDK is configured with Poly Modulus Degree: 4096 and Plain Modulus: 1024. Mismatched params break HE math. |
| **Noise Budget Exceeded** | Too many sequential operations on the same ciphertext. | Homomorphic encryption accumulates mathematical "noise" with each operation. Reduce computation depth or request bootstrapping support for deep circuits. |
| **Job Timeout** | Large batch or complex multiplication chain. | Split workloads into smaller batches. Multiplication consumes more noise and compute cycles than addition. |
| **401 Unauthorized** | JWT expired or invalid. | Tokens expire after 1 hour. Re-authenticate via `/api/auth/login` and refresh your header. |
| **403 Forbidden** | Rate limit reached. | Free/Developer tiers are limited to 10 requests/minute. Upgrade your plan or implement exponential backoff. |

---

## 8. FAQs

**Q: Why would I pay for this instead of computing locally?**  
A: Local computation on encrypted data requires specialized hardware, deep cryptographic expertise, and significant engineering overhead. HEaaS abstracts the complexity, provides optimized compute infrastructure, and ensures mathematical correctness, letting your team focus on analytics, not cryptography.

**Q: Can you see my data if I send it to your API?**  
A: No. You send ciphertext. Our servers perform math on ciphertext. We return ciphertext. Without your Private Key (which we never store or request), the data is mathematically indecipherable. This is verifiable via our open cryptographic parameters and third-party audits.

**Q: What data types are supported?**  
A: Currently, integers within the configured plaintext modulus (0-1023 for standard tier). Enterprise tiers support larger integer ranges, fixed-point decimals, and encrypted vector/tensor operations for ML workloads.

**Q: How do I handle compliance audits?**  
A: We provide architectural diagrams, cryptographic parameter sheets, key management policies, and third-party audit reports. Since we never process plaintext, your data processing agreements (DPAs) can classify HEaaS as a zero-knowledge processor, significantly reducing compliance scope.

**Q: Can I cancel or downgrade my plan?**  
A: Yes. Manage subscriptions via Dashboard > Billing. Changes take effect at the end of your current billing cycle. No lock-in contracts.

---

## 9. Contact & Support

We specialize in privacy-preserving infrastructure for regulated industries. Our team includes cryptographers, compliance experts, and cloud security engineers.

*   **Technical Support:** support@yourdomain.com
*   **Sales & Enterprise Plans:** sales@yourdomain.com
*   **System Status:** status.yourdomain.com
*   **API Documentation:** docs.yourdomain.com
*   **Security & Compliance Requests:** security@yourdomain.com

© 2026 HEaaS Inc. All Rights Reserved.
