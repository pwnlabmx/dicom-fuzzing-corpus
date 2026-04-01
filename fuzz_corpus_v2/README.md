# DICOM C-STORE Fuzz Corpus v2

354 manifest-indexed test cases across 10 categories (~29 MB on disk).

## Corpus Summary

| Category | Cases | What's in there |
|---|---|---|
| `cat01_tag_overflow` | 115 | Boundary, +1, 2x/10x/64KB/1MB overflows across 12 tags (PN, LO, SH, UI, CS). PN with 256 `^` separators, UID with 200 dot components, CS lowercase, invalid AS/DA/TM formats |
| `cat02_vr_mismatch` | 15 | UI-as-LO, US-as-UL, US-as-SS, DA-as-DS, PN-as-OB, OB-as-OW, CS-as-LO, LO-as-UN. Implicit VR cases with binary garbage in PN, 4-byte Rows, all-0xFF date |
| `cat03_sequence_nesting` | 12 | Depth 10/50/100 via pydicom, depth-500 as raw bytes. Wide SQ with 1/100/1000 items. Undefined-length SQ, missing delimiters, stray Sequence/Item Delimitation Items, SQ containing Pixel Data tag, zero-length items |
| `cat04_pixel_data` | 29 | Buffer half/2x/10x/zero/one-byte vs declared Rows x Cols. Zero Rows, zero Cols. BitsAllocated/Stored/HighBit inconsistencies (0, 1, 3, 9, 24, 48, 128). Encapsulated: empty BOT, zero-length fragment, 10K tiny fragments. Photometric mismatch (MONO2+SPP3, RGB+SPP1, invalid/empty PI). Multi-frame: NFrames=0, 999999, buffer-count mismatch |
| `cat05_transfer_syntax` | 3 | Meta declares Explicit but body is Implicit. Corrupt deflate stream (middle-byte flip). Truncated deflate stream |
| `cat06_private_tags` | 14 | Valid private creator+data, private data without creator, command group (0001,xxxx) in dataset, group 0xFFFF tags, stray Item/ItemDelim/SeqDelim outside sequences, tag ordering violation, bulk private elements. Shell injection (`$(id)`, backtick, semicolon), SQL injection, format string payloads in PatientName/ID |
| `cat07_file_meta` | 14 | No preamble/no DICM, 0xFF preamble, 127-byte preamble (off-by-one), missing DICM magic, DICM at offset 0/64/256, Group Length (0002,0000) = zero/one/max/huge, SOP Class mismatch meta vs dataset, invalid Transfer Syntax UID, group 0002 tag mixed into dataset body |
| `cat08_string_encoding` | 16 | Charset declares Latin-1 but UTF-8 payload. Invalid UTF-8: BOM, surrogates, continuation-without-start, overlong. Null bytes at start/mid/end/all in LO fields. Control chars 0x01-0x1F in PN. Format strings (`%s%n`, `%08x`, SSTI `{{7*7}}`). 1000-backslash VM components. RTL override + zero-width chars |
| `cat09_logic_bombs` | 19 | CT SOP Class + wrong Modality (MR/US/NM/invalid). Duplicate (0010,0010) tag. Odd-length values for PN/LO/SH/CS. UID edge cases: 64-char exact, 65-char over, trailing/leading/double/all dots, empty. Group Length tag = 0 (truncates group). UID collision (overwrite test). Dangling ReferencedSOPInstanceUID |
| `cat10_cve_2026_3650` | 117 | Non-standard VR types in File Meta Information targeting CVE-2026-3650 (CWE-401, GDCM 3.2.2). See detailed breakdown below |

## Category 10: CVE-2026-3650 Coverage

CVE-2026-3650 is a memory leak in Grassroots DICOM (GDCM) 3.2.2 (CVSS 3.1: 7.5 HIGH, `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`). The library allocates heap memory for each File Meta element's value based on the declared length but never frees it when the VR code is unrecognised. A single crafted file can exhaust all available memory. CISA advisory ICSMA-26-083-01 (2026-03-24). No vendor patch exists.

| Test Set | Cases | Strategy |
|---|---|---|
| A: Single-element VR replacement | ~84 | Each group-0002 element (0001, 0002, 0003, 0010, 0012, 0013) gets its VR replaced individually with 14 fabricated VR codes: `ZZ`, `XX`, `AA`, `BB`, `QQ`, `\x00\x00`, `\xFF\xFF`, `99`, `sq`, `ob`, `ui`, `sh`, `\x20U`, `U\x20` |
| B: All-VRs-replaced | 14 | Every element in File Meta simultaneously gets the same fake VR, maximising leak per file |
| C: Amplified length | 9 | `(0002,0010)` gets a non-standard VR plus a declared length of 64 KB, 1 MB, or 1 GB, testing whether the library allocates the full declared length before recognising the invalid VR |
| D: Repeated fake elements | 3 | 10, 100, or 1000 copies of a fabricated `(0002,00FF)` with VR=`ZZ` and 256-byte payloads injected into File Meta, multiplying the per-element leak |
| E: Mixed valid/invalid | 2 | Alternating elements valid vs corrupted, testing whether parsers that bail on first unknown VR still leak on elements already processed |
| F: First-element corruption | 5 | `FileMetaInformationVersion (0002,0001)` specifically gets its VR corrupted, hitting the very first VR dispatch in the meta parser |

## Usage

### Run against a target PACS

```bash
nmap -p 104,11112 --script dicom-store-fuzzer \
  --script-args 'dicom-store-fuzzer.corpus=./fuzz_corpus,dicom-store-fuzzer.called_ae=ORTHANC' <target>
```

### Run only CVE-2026-3650 cases

```bash
nmap -p 104,11112 --script dicom-store-fuzzer \
  --script-args 'dicom-store-fuzzer.corpus=./fuzz_corpus,dicom-store-fuzzer.categories=cat10,dicom-store-fuzzer.called_ae=ORTHANC' <target>
```

## References

- [CISA Advisory ICSMA-26-083-01](https://www.cisa.gov/news-events/ics-medical-advisories/icsma-26-083-01)
- [NVD - CVE-2026-3650](https://nvd.nist.gov/vuln/detail/CVE-2026-3650)
- [CSAF Advisory JSON](https://github.com/cisagov/CSAF/blob/develop/csaf_files/OT/white/2026/icsma-26-083-01.json)
