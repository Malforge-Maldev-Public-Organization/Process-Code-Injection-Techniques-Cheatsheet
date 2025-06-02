# Process Code Injection Techniques Cheatsheet

## Introduction

Welcome to my latest article! Today, I’ve put together a comprehensive cheatsheet covering the most well-known techniques for injecting code into remote processes. This guide will be extensive, so let’s dive right in.

#### Why you need to use Process Code Injection?

- **Time of Living:** If you're using a reverse shell and the user runs your executable, you'll receive the shell. However, if the user closes your executable, the connection is lost. By injecting the reverse shell into a persistent process like explorer.exe, the user can close your original executable without killing your shell — because the malicious code now runs in a separate, stable process.

- **Changing the Working Process:** When your malware communicates with a C2 server, antivirus solutions can flag it — especially if it's an unknown or suspicious application making outbound requests. To avoid this, it's smart to migrate your payload to a trusted process like chrome.exe or another legitimate browser that regularly accesses the internet.

- **Creating Persistence:** You can increase your chances of staying active by injecting your payload into multiple remote processes. Even if one is terminated, others may keep the malware alive.

## Process Code Injection

![image](https://github.com/user-attachments/assets/89c48b7f-6515-41a5-9f79-9aaa28c04725)

### Basic Injection

This is a basic remote process injection — just three essential steps that form the foundation for understanding the technique.

**Pros:**
  - Any…

**Cons:**
  - Very easy to detect by AV
  - Most basic technique

**Steps:**

