## ntlmshared.dll: The New Home of NTLMSSP Parsing—and Its Vulnerabilities

Windows authentication over SMB traditionally relied on the NTLM Security Support Provider (SSP) buried inside **msv1\_0.dll**. Recent Windows releases have refactored that logic into a standalone library—**ntlmshared.dll**—to centralize NTLM parsing across multiple authentication flows (SMB, HTTP, CIFS, etc.). **ntlmshared.dll** now performs SPNEGO unwrapping, NTLMSSP signature and message‐type dispatch, AV-pair enumeration, its core parser is itself ripe for exploitation.

---

### 1. Architectural Shift: From msv1\_0.dll to ntlmshared.dll

* **Legacy (pre-Windows 10 1803):**

  * `msv1_0.dll` contained all NTLMSSP parsing: heap-alloc, raw‐blob `memcpy`, signature checks, message-type switching, and AV-pair loops.
  * Security researchers placed breakpoints in `msv1_0!SpAcceptLsaModeContext` or inside its internal parser routines.

* **Modern (Windows 10 1803+ / Windows Server 2019+):**

  * Core NTLMSSP logic is extracted into **ntlmshared.dll**.
  * `msv1_0.dll` remains as a compatibility shim, delegating to ntlmshared for everything protocol-specific.
  * The key entrypoints in ntlmshared.dll are:

    1. **FUN\_180003A54**: SPNEGO/“NTLMSSP” signature check and unwrap
    2. **FUN\_180004A70**: Heap allocation, unguarded blob copy, and message‐type dispatch
    3. **FUN\_180005274 / FUN\_18000570C**: AV-pair enumeration

---

### 2. SPNEGO & Signature Validation: `FUN_180003A54`

Before any NTLM‐specific parsing, ntlmshared.dll must strip off the SPNEGO wrapper and confirm the presence of the “NTLMSSP\0” magic:

1. **Locate and validate SPNEGO tokens**

   * Checks the ASN.1 framing of a NegTokenInit or NegTokenTarg.
   * Unwraps the inner OCTET STRING carrying the raw NTLM blob.

2. **Check for “NTLMSSP\0” header**

   * Verifies the first eight bytes match the ASCII signature.
   * Ensures the blob is at least 16 bytes long before proceeding.
   * Extracts the 32-bit `MessageType` at offset 8.

By centralizing this in **FUN\_180003A54**, Windows enforces a consistent preamble check—but any flaws here could let through malformed blobs or skip signature checks entirely.

---

### 3. Core Parser: `FUN_180004A70`

This function is the heart of NTLMSSP in modern Windows. Its steps:

```c
// pseudocode based on decompiled FUN_180004A70
if (blobLength < MIN_HEADER_SIZE)  goto error; 
if (blobLength > MAX_ACCEPTABLE)    goto error;

// 1) Allocate heap for the entire incoming blob:
heapCtx = HeapAlloc(GetProcessHeap(), 0, blobLength);
if (!heapCtx) goto error;

// 2) Copy the raw blob—unguarded!
memcpy(heapCtx, blobPtr, blobLength);

// 3) Verify signature & dispatch on message type:
if (*(DWORD*)heapCtx != 'LMSS') goto error;        // "NTLM"
switch (*(DWORD*)(heapCtx + 8)) {
  case 1: handleNegotiate(heapCtx); break;
  case 2: handleChallenge(heapCtx); break;
  case 3: handleAuthenticate(heapCtx); break;
  default: goto error;
}
```

#### 3.1 Unguarded `memcpy` → Immediate Overflow

* **No upper bound check** against a fixed context size (unlike older code’s 0x160-byte limit).
* A maliciously large `blobLength` directly overflows the newly allocated heap region, corrupting adjacent memory or heap metadata—**before** any signature or type checks.

#### 3.2 Message-Type Dispatch

* Reads the **Authenticate** code (`3`) from offset 8 and jumps to the attacker’s chosen handler.
* If heap corruption succeeds, control-flow hijacking can occur in one of the type-specific functions (e.g., parsing LM/NT response fields).

---

### 4. AV-Pair Parsing: `FUN_180005274` and `FUN_18000570C`

After the main dispatch, Type-3 (Authenticate) handlers iterate through AV-pairs:

```c
while (remaining > (lengthField + 4)) {
    if (typeField == targetType) return ptr;
    lengthField = typeLength >> 16;
    ptr        += lengthField + 4;
    remaining  -= lengthField + 4;
}
```

* **Missing overall bounds check**: each TLV loop trusts its internal length, without confirming `ptr + lengthField + 4 ≤ blobEnd`.
* A malformed AV-pair with an excessive length can walk `ptr` off the end of the buffer, causing an out-of-bounds read (or write) and potential crash (DoS) or further memory corruption.

---

### 5. Why Defenders Miss It

* Breakpoints and mitigations are often still targeted at `msv1_0.dll`’s old entrypoints.
* Kernel or user-mode instrumentation that expects signature checks inside msv1\_0 will never see **FUN\_180004A70** fire.
* The unguarded `memcpy` sits “below” usual detection thresholds—heap corruptions happen before any high-level validation or logging.

---

### 6. Exploitation Strategy

1. **Capture or forge a SPNEGO Type-1 token** via SSPI (Negotiate).
2. **Extract the raw NTLM blob** from the server’s Session Setup #1.
3. **Craft a malicious Type-3 Authenticate blob** with an oversized length field.
4. **Wrap it in SPNEGO** and send as Session Setup #2.
5. **Trigger** the unguarded `memcpy` in FUN\_180004A70, overflowing the heap context.
6. **Hijack** the `MessageType=3` handler or overwrite heap metadata to achieve code execution.

---

### 7. Mitigations & Recommendations

* **Bounds Checks**: Enforce `blobLength ≤ MAX_CONTEXT_SIZE` before any heap allocation or memcpy.
* **Integer-Overflow Protections**: Validate all length multiplications and additions against platform limits.
* **Move AV-Pair Loops**: Require a single consolidated bounds check on the entire AV-pair region before parsing.
* **Instrumentation Updates**: Shift defensive breakpoints, tamper-flags, and mitigations to ntlmshared.dll’s core functions (`FUN_180003A54`, `FUN_180004A70`, etc.).
* **Fuzzing Focus**: Target these new entrypoints with malformed NTLM blobs, particularly oversized Authenticate messages.

---

## Conclusion

By refactoring NTLMSSP parsing into **ntlmshared.dll**, Windows aimed for modularity and reuse—but inadvertently centralized a critical memory‐copy vulnerability. **FUN\_180004A70**’s unguarded heap alloc + memcpy presents a single-shot overflow opportunity that legacy defenses overlook. Effective remediation requires both code fixes in ntlmshared.dll and updated detection logic in defender toolchains.
