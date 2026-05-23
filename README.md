## alu-regex-data-extraction_apiel-max

## What This Project Is About

This project was built as part of a Junior Frontend Developer assignment at ALU. The scenario is simple: imagine you've just graduated and you're working with a system that receives large volumes of raw text from an external API. That text contains all kinds of useful data — emails, phone numbers, URLs, credit card numbers — but it's messy, inconsistent, and most importantly, you can't trust it. Anyone could have put anything in there.

The goal was to write a Python program that can dig through that messy text, pull out the data you actually care about, validate that it's properly formed, and do all of this safely — without letting bad input cause problems downstream.

---

## What the Program Does

The program reads a raw text file (`input/raw-text.txt`), scans it using regular expressions, and extracts four types of data:

- **Email addresses** — including special handling for ALU staff, alumni, and SI emails
- **Credit card numbers** — validated using the Luhn checksum algorithm
- **URLs** — only safe, properly formed web addresses are accepted
- **Phone numbers** — international and local formats from multiple countries

Once extraction is done, the results are written to `output/sample-output.json` as a clean, structured report. A summary is also printed to the console.


---

## How to Run

**Requirements:** Python 3.10+

```bash
python src/main.py
```

The program reads from `input/raw-text.txt` and writes structured results to `output/sample-output.json`. A summary is also printed to the console.

---

## Project Structure

```
alu-regex-data-extraction_apiel-max/
├── input/
│   └── raw-text.txt          # Raw, messy, production-style input text
├── src/
│   └── main.py               # All extraction, validation, and output logic
├── output/
│   └── sample-output.json    # Sample structured output from a real run
└── README.md
```

---

## How It Works

The program reads the entire input file as untrusted text, runs four independent regex extractors over it, validates each match with post-regex checks, and writes a JSON report.

### 1. Email Extraction

**Pattern:** Matches `local@domain.tld` where:
- Local part allows letters, digits, and `. _ % + -` (no leading/trailing dot, no consecutive dots)
- Domain labels are alphanumeric with hyphens
- TLD is 2–24 letters

**ALU-specific classification** — emails are sub-classified into:
| Category | Domain |
|---|---|
| `alu_official` | `@alueducation.com` |
| `alu_alumni` | `@alumni.alueducation.com` |
| `alu_si` | `@si.alueducation.com` |

### 2. Credit Card Extraction

**Pattern:** Matches three formats:
- `XXXX-XXXX-XXXX-XXXX` or `XXXX XXXX XXXX XXXX` (16-digit, grouped 4-4-4-4)
- `XXXX-XXXXXX-XXXXX` (Amex 15-digit, grouped 4-6-5)
- Bare 13–19 digit sequences

Every match is then:
1. Stripped of separators
2. Checked for valid length (13–19 digits)
3. Run through the **Luhn (mod-10) checksum** — rejects random digit strings
4. Identified by brand (Visa, Mastercard, Amex, Discover) via IIN prefix

### 3. URL Extraction

**Pattern:** Matches only `http://` and `https://` URLs with DNS-style hostnames.

Two additional audit passes run first:
- **Unsafe scheme pass** — scans for `javascript:`, `data:`, `vbscript:`, `file:`, `ftp:` and logs them as rejected
- **IP literal pass** — scans for `http(s)://x.x.x.x/...` (SSRF red flag) and logs them as rejected

### 4. Phone Extraction

**Pattern:** Matches international and local formats including:
- `+CC NNN NNN NNNN`
- `(NNN) NNN-NNNN`
- `NNN.NNN.NNNN`
- `+CC-NNN-NNN-NNN`

After matching, digits are stripped and validated against E.164 rules (7–15 digits). Phone extraction runs **last** so that digit spans already claimed by URLs or credit card numbers are blanked out first, preventing false positives.

---

## Security Considerations

The program treats every byte of `raw-text.txt` as **untrusted user-generated content**.

| Threat | Defense |
|---|---|
| DoS via huge file | Input capped at 5 MB; program exits if exceeded |
| DoS via regex catastrophic backtracking | No `(a+)+`-style patterns used |
| Output bloat | Match count capped at 1000 per category |
| Email exposure in logs | Emails masked in all output (`j******e@example.com`) |
| Credit card exposure | Cards masked PCI-style (`4111********1111`); full number never written |
| XSS / link injection | `javascript:`, `data:`, `vbscript:` schemes rejected and audit-logged |
| SSRF via internal hosts | `127.x`, `10.x`, `192.168.x`, `169.254.x`, `172.16–31.x`, `localhost` rejected |
| Phishing / subdomain spoofing | URLs where ALU brand keywords appear in subdomains of a foreign registrable domain are rejected (e.g. `alu-education.com.phishing-domain.ru`) |
| XSS in output/logs | All rejected values are HTML-escaped with `html.escape()` before being stored in JSON output, preventing injection if the report is rendered in a browser |
| SMTP header injection | Control characters (`\x00`, `\r`, `\n`) in email local/domain parts rejected |
| SQL injection in emails | Characters `'`, `"`, `;`, `--`, `<`, `>` in email parts rejected |
| No code execution | No `eval`, `exec`, or shell interpolation of input anywhere |
| Encoding attacks | File read with `errors='replace'` — bad bytes cannot crash the parser |
