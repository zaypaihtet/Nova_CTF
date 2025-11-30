# Nova_CTF

## 🏆 CTF Writeup Regeneration

Based on the provided document, here is a regenerated writeup organized by the challenge category and solution.

---

## 💻 Pwn/Binary Exploitation Challenges

### 1. Pypwn (Buffer Overflow)

[cite_start]This challenge involved a **buffer overflow** vulnerability exploited using a Python script[cite: 1, 2].

* [cite_start]**Vulnerability Type:** Buffer Overflow[cite: 3].
* [cite_start]**Exploit Payload:** The exploit used a long string of 'A's (512 bytes) followed by the flag's specific trigger string (`FTC_AVON`)[cite: 2].
* [cite_start]**Command:** The payload was piped to the target service using `netcat`[cite: 2]:
    ```bash
    python3 -c "print('A'*512 + 'FTC_AVON')" | nc 38.60.200.116 9000
    ```
* [cite_start]**Flag:** `NOVA_CTF{pyth0n_c4n_pwn_w1th_buff3r_0v3rfl0w}`[cite: 3].

---

## 🌐 Web Exploitation Challenges

### 2. Simple PHP (Web Bypass)

[cite_start]This challenge appears to have been an exploit against a PHP application using large parameters [cite: 4, 7-11].

* [cite_start]**Exploit Code:** The Python script uses the `requests` library to send an HTTP GET request [cite: 5, 13] [cite_start]to the target URL (`http://38.60.200.116:8081/`)[cite: 6]. [cite_start]It uses extremely long strings (`"0" * 1337`) for the parameters `password`, `x`, and `y` [cite: 7-11].
    ```python
    import requests
    url = "[http://38.60.200.116:8081/](http://38.60.200.116:8081/)"
    payload = {
        "password": "0" * 1337,
        "x": "0" * 1337,
        "y": "0"
    }
    response = requests.get(url, params=payload)
    print(response.text)
    ```
* [cite_start]**Flag:** `NOVA_CTF{1_kN0w_pHp_w3ll_c0855cc0d2d12e6b7af3375d9fa4e8a2}`[cite: 17].

### 3. Baby Bypass (SQL Injection & LFI via `LOAD_FILE`)

[cite_start]This was a multi-step web challenge involving a chained attack of **SQL Injection (SQLi)** and **Local File Inclusion (LFI)**[cite: 243, 257].

* **Step 1: SQL Injection (Union-Based Bypass)**
    * [cite_start]The attacker used the **"Backslash Trick"** to inject a `UNION SELECT` statement into the password field[cite: 245].
    * [cite_start]**Payload:** Username: `\` (URL encoded: `%5C`)[cite: 247]; [cite_start]Password: `UNION SELECT 1,2,3 #`[cite: 248].
    * [cite_start]**Result:** A successful union query was confirmed by the array output[cite: 249].
* **Step 2: Enumeration**
    * [cite_start]Enumeration revealed the database (`sqli`), table (`users`), and columns (`id`, `username`, `password`)[cite: 252, 254].
    * [cite_start]The password was a **Bcrypt hash**, which was insufficient for login due to the script's use of `password_verify()`[cite: 255, 256].
* **Step 3: LFI via `LOAD_FILE()`**
    * [cite_start]The solution was to read the server-side source code using the SQL function `LOAD_FILE()`[cite: 258].
    * [cite_start]The file path `/var/www/html/index.php` was encoded to **Hex** to bypass quote filters[cite: 259, 260].
    * [cite_start]**Hex Path:** `0x2f7661722f7777772f68746d6c2f696e6465782e706870`[cite: 260].
    * [cite_start]**Final cURL Payload:** The payload was used to retrieve the raw PHP source code [cite: 261-263].
    * [cite_start]**Source Code Review:** The flag was found hardcoded in the successful login message logic [cite: 264-268].
* [cite_start]**Flag:** `NOVA_CTF{SQl1_pluS_h@sh1n9_1s_fuN_--------------------}`[cite: 269].

---

## 🔐 Cryptography Challenges

### 4. Simple Sage (Wiener's Attack)

[cite_start]This challenge was an RSA problem solved using **Wiener's Attack**[cite: 68], which targets RSA where the private exponent $d$ is small.

* [cite_start]**Given Parameters:** $n$, $e$, $c$, and `flag_len = 30` [cite: 43-46].
* [cite_start]**Method:** The script calculates the **continued fractions expansion** of $e/n$ [cite: 70] [cite_start]and generates **convergents** $(k/d)$[cite: 71, 72]. [cite_start]It then checks if the exponent $d$ is the private key by attempting to decrypt the message $m \equiv c^d \pmod{n}$[cite: 75].
* [cite_start]**Result:** The attack successfully found the private key $d$ [cite: 81] [cite_start]and the decrypted flag[cite: 82].
* [cite_start]**Flag:** `Nova_ctf{yOu_kNow_YE1L_15_6AY}`[cite: 89].

### 5. DMD (Wiener's Attack Variant)

[cite_start]Another RSA challenge using continued fractions to find a small private key $d$[cite: 90].

* [cite_start]**Given Parameters:** The modulus $N$, public exponent $e$, and the `ciphertext` [cite: 117-119].
* [cite_start]**Method:** The script calculates the continued fractions of $e/N$ [cite: 121] [cite_start]and iterates through the convergents $(k/d)$[cite: 122, 124, 125]. [cite_start]It attempts to decrypt the message $m \equiv ciphertext^d \pmod{N}$ [cite: 128] [cite_start]and checks if the resulting bytes contain the string `"Nova_Ctf"`[cite: 130].
* [cite_start]**Result:** A successful decryption was found[cite: 131, 132].
* [cite_start]**Flag:** `Nova_Ctf{qUAn7um_de73CtoRS_2025}`[cite: 242].

### 6. Baby\_rsa (Hastad's Broadcast Attack / CRT)

[cite_start]This challenge used the **Chinese Remainder Theorem (CRT)** to solve an RSA problem where the same message $m$ was encrypted three times ($c_1, c_2, c_3$) with three different moduli ($n_1, n_2, n_3$) and a small exponent ($e=3$ is implied)[cite: 136].

* [cite_start]**Given Parameters:** Three moduli ($n_1, n_2, n_3$) and their ciphertexts ($c_1, c_2, c_3$) [cite: 138-143].
* **Method (CRT):**
    1.  [cite_start]The overall modulus $N$ is calculated as $N = n_1 \cdot n_2 \cdot n_3$[cite: 144].
    2.  [cite_start]The Chinese Remainder Theorem is applied to combine the ciphertexts into a single value $M$[cite: 151].
    3.  [cite_start]The plaintext $m$ is recovered by taking the **integer cube root** of $M$ (`gmpy2.iroot(M, 3)[0]`)[cite: 152].
    4.  [cite_start]The integer $m$ is converted to bytes and decoded[cite: 153, 154].
* [cite_start]**Flag:** `Nova_ctf{cRyP7O_m@kEs_fun!!}`[cite: 155].

---

## ❓ Miscellaneous/Forensics Challenges

### 7. FIX ME (QR Code Recovery)

[cite_start]This challenge involved fixing and decoding a blurry QR code[cite: 18].

* [cite_start]**Solution:** The script used **OpenCV** and **pyzbar** [cite: 19-21] [cite_start]to preprocess the image (`novactf.png`)[cite: 22].
    1.  [cite_start]**Noise Reduction:** Applied a `cv2.medianBlur`[cite: 23].
    2.  [cite_start]**Binarization:** Applied `cv2.threshold` to convert it to a clean black-and-white image (`fixed_qr.png`)[cite: 24, 25].
    3.  [cite_start]**Decoding:** Used `pyzbar.decode` on the binarized image to extract the data[cite: 27, 28].
* [cite_start]**Found Data:** The decoded data was printed[cite: 29].

### 8. JS\_Obfuscation (De-obfuscation Script)

[cite_start]A multi-layered decryption challenge involving Base64 and XOR[cite: 30].

* **De-obfuscation Steps:**
    1.  [cite_start]**Decode 1 (Base64):** The initial `blob` was Base64-decoded and UTF-8 decoded to `s1` [cite: 31-33].
    2.  [cite_start]**Decode 2 (Base64):** `s1` was Base64-decoded and UTF-8 decoded to `s2`[cite: 34].
    3.  [cite_start]**XOR Decryption:** A loop applied a rotating XOR key defined by `key = ((i * 7) + 19) & 0xFF` to `s2`, resulting in `s3` [cite: 36-38].
    4.  [cite_start]**Reverse:** The resulting string `s3` was reversed (`s3[::-1]`) to obtain the `flag`[cite: 39].
* [cite_start]**Flag:** The script printed the `REAL FLAG`[cite: 40].

### 9. Find me (Geospatial Coordinates)

[cite_start]This challenge required extracting the latitude and longitude from the provided Google Earth screenshot[cite: 156].

* [cite_start]**Coordinates:** The coordinates visible in the screenshot are: **19°35'15.6"N 95°05'55.2"E**[cite: 156].

### 10. NULL Bollon (Steganography/Zip Forensics)

[cite_start]This challenge involved recovering hidden data from a zipped document file[cite: 157, 158].

* [cite_start]**Initial Step:** The file was identified as a ZIP archive (`Suspicious_file`) and its contents, including XML files for document components, were extracted[cite: 157].
* [cite_start]**Recovery:** The flag components were found as two separate Base64 strings [cite: 160] [cite_start]hidden in the document's XML (likely in the header/footer files)[cite: 159].
    * [cite_start]**Base64 1:** `e0hlbGxv` $\to$ Decodes to `{Hello` [cite: 161]
    * [cite_start]**Base64 2:** `X1dvcmxkfQo=` $\to$ Decodes to `_World}` [cite: 161]
* [cite_start]**Final Flag:** The decoded parts were combined[cite: 162].
    * [cite_start]`NOVA_CTF{{Hello_World}`[cite: 162].

### 11. QOTP (Quantum One-Time Pad Analysis)

[cite_start]This challenge used a majority voting technique to recover a message encrypted with a vulnerable encoding scheme[cite: 163].

* [cite_start]**Method:** The message was estimated for each of the 1200 encryptions[cite: 190, 195].
    1.  [cite_start]**Decode Estimate:** The encoding logic was reversed [cite: 200-204].
    2.  [cite_start]**Majority Vote:** A majority vote was performed on the bit estimates at each position to obtain the final, accurate bitstream [cite: 211-215].
    3.  [cite_start]**Cleanup/CRC:** The bitstream was collapsed to its original size (dividing by `REPEAT=4`) [cite: 220, 221][cite_start], converted to bytes, and a **CRC-16 check** was performed [cite: 229-231] to validate the message.
* [cite_start]**Result:** The CRC matched [cite: 232][cite_start], and the message was decoded[cite: 233, 234].
* **Flag:** The recovered message contained the flag.
    * [cite_start]`Nova_Ctf{qUAn7um_de73CtoRS_2025}`[cite: 242].
