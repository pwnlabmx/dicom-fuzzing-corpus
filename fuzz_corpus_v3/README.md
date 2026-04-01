# DICOM C-STORE Fuzz Corpus v3

594 manifest-indexed test cases across 24 categories (~24 MB on disk).
Covers **26 CVEs** spanning 8 DICOM products/libraries.

## Corpus Summary

| Category | Cases | Target CVE(s) | What's in there |
|---|---|---|---|
| `cat01_tag_overflow` | 115 | — | Boundary, +1, 2x/10x/64KB/1MB overflows across 12 tags (PN, LO, SH, UI, CS). PN with 256 `^` separators, UID with 200 dot components, CS lowercase, invalid AS/DA/TM formats |
| `cat02_vr_mismatch` | 15 | — | UI-as-LO, US-as-UL, US-as-SS, DA-as-DS, PN-as-OB, OB-as-OW, CS-as-LO, LO-as-UN. Implicit VR cases with binary garbage in PN, 4-byte Rows, all-0xFF date |
| `cat03_sequence_nesting` | 12 | — | Depth 10/50/100 via pydicom, depth-500 as raw bytes. Wide SQ 1/100/1000 items. Undefined-length SQ, missing delimiters, stray delimiters, SQ containing PixelData, zero-length items |
| `cat04_pixel_data` | 29 | — | Buffer half/2x/10x/zero/1-byte vs declared dims. Zero Rows/Cols. BitsAllocated/Stored/HighBit inconsistencies. Encapsulated: empty BOT, zero-length fragment, 10K fragments. Photometric mismatch. Multi-frame NFrames=0/999999 |
| `cat05_transfer_syntax` | 3 | — | Meta declares Explicit but body is Implicit. Corrupt/truncated deflate streams |
| `cat06_private_tags` | 14 | — | Valid/invalid private tags, command group in dataset, group 0xFFFF, stray delimiters, tag ordering violation, bulk private elements, shell/SQL/format-string injection payloads |
| `cat07_file_meta` | 14 | — | No preamble/DICM, 0xFF preamble, 127-byte off-by-one, DICM at wrong offsets, corrupt Group Length, SOP Class mismatch, invalid Transfer Syntax UID, group 0002 in dataset body |
| `cat08_string_encoding` | 16 | — | Charset/encoding mismatches, invalid UTF-8, null bytes, control chars, format strings, SSTI payloads, 1000-backslash VM, RTL override + zero-width chars |
| `cat09_logic_bombs` | 19 | — | SOP/Modality mismatch, duplicate tags, odd-length values, UID edge cases (64/65-char, dots, empty), Group Length=0, UID collision, dangling references |
| `cat10_cve_2026_3650` | 117 | CVE-2026-3650 | Non-standard VR in File Meta Info: single-element replacement (14 VRs × 6 tags), all-VRs-replaced, amplified lengths (64KB–1GB), repeated fake elements (10–1000), mixed valid/invalid, first-element corruption |
| `cat11_cve_2025_11266` | 10 | CVE-2025-11266 | GDCM OOB write: encapsulated PixelData fragment lengths 0xFFFFFFFF/0xFFFFFFFE/0x80000000, wrapping, bad BOT offsets, missing sequence delimiters |
| `cat12_cve_2024_47796` | 15 | CVE-2024-47796 | DCMTK nowindow OOB write: WindowCenter/WindowWidth = INT_MIN/INT_MAX/NaN/Inf/float overflow/UINT64_MAX with extreme BitsAllocated |
| `cat13_cve_microdicom` | 38 | CVE-2024-22100, CVE-2024-28877, CVE-2025-35975 | MicroDicom heap/stack: 256–65535 byte strings in PN/LO/SH/CS, pixel dim mismatches 65535×65535, 100 frames tiny buffer |
| `cat14_cve_2025_27578` | 6 | CVE-2025-27578 | OsiriX UAF: self-referencing SOP UIDs, shared SQ items, PerFrameFunctionalGroups count mismatches, 50 duplicate refs, triple UID reuse |
| `cat15_cve_2019_1010228` | 6 | CVE-2019-1010228 | DCMTK RLE decoder: OOB segment offsets, overlapping segments, expansion bombs, short data, 0/0xFFFFFFFF segments |
| `cat16_cve_dcmtk_null_pathtraversal` | 21 | CVE-2022-2121, CVE-2022-2119, CVE-2022-2120 | DCMTK NULL deref (12 required tags removed) + path traversal payloads (Unix/Windows/URL-encoded/null-byte) |
| `cat17_cve_libdicom_uaf` | 8 | CVE-2024-24793, CVE-2024-24794 | libdicom UAF: truncated File Meta (group length > actual), duplicate meta tags, missing SQ delimiters, premature Item Delimitation, zero-length meta |
| `cat18_cve_dcmtk_minmax_voi` | 14 | CVE-2024-52333, CVE-2024-28130 | DCMTK determineMinMax: BitsStored=0/17/33, HighBit=255, BitsStored>BitsAllocated. VOI LUT: string LUTDescriptor, empty LUTData, 65535-entry mismatch, Modality LUT with ASCII |
| `cat19_cve_dcmtk_ect_jpegls` | 9 | CVE-2024-27628, CVE-2025-2357 | EctEnhancedCT: frame/PFG mismatches (10000/0, 65535/1, 0/0), oversized SharedFunctionalGroups. JPEG-LS: zero components, NEAR=255, precision mismatch (16-bit/8-bit BA), truncated stream |
| `cat20_cve_dcmtk_dimse_segfault` | 5 | CVE-2024-34508, CVE-2024-34509 | DCMTK DIMSE segfault: undefined-length elements without delimiters, CommandGroupLength in dataset, 2-byte truncated dataset, mid-value truncation, cascading undefined-length |
| `cat21_cve_santesoft_oob` | 10 | CVE-2024-1453, CVE-2025-5307 | Santesoft OOB read: pixel buffer mismatches (1024², 4096², 32768×1), zero-byte PixelData, overlay data OOB, IconImageSequence 8192×8192 with 16-byte data |
| `cat22_cve_meddream_stack_overflow` | 74 | CVE-2025-3483, CVE-2025-3484, CVE-2025-3485 | MedDream PACS stack overflow: 8 target tags × 9 stack sizes (256–65535), combined all-tags-at-once at 4096/65535 |
| `cat23_cve_merge_toolkit` | 15 | CVE-2024-23912, CVE-2024-23913, CVE-2024-23914 | Merge Toolkit: element lengths exceeding file (64KB–4GB), odd-length violations, SQ item with huge length, format string payloads (%s, %n, %p, %08x, positional) |
| `cat24_cve_orthanc_osirix` | 9 | CVE-2023-33466, CVE-2025-31946 | Orthanc: JSON config polyglots in DICOM preamble (remote access, LuaScripts RCE, storage redirect), path traversal UIDs. OsiriX local UAF: circular SOP refs, DimensionOrganization mismatch, 20 private SQ stress test |

## CVE Reference Table

| CVE | Product | CWE | CVSS | Category |
|---|---|---|---|---|
| CVE-2026-3650 | GDCM 3.2.2 | CWE-401 (Memory Leak) | 7.5 HIGH | cat10 |
| CVE-2025-11266 | GDCM ≤ 3.0.24 | CWE-787 (OOB Write) | 6.6 | cat11 |
| CVE-2024-47796 | DCMTK 3.6.8 | CWE-787 (OOB Write) | 8.4 HIGH | cat12 |
| CVE-2024-22100 | MicroDicom ≤ 2023.3 | CWE-122 (Heap Overflow) | 7.8 HIGH | cat13 |
| CVE-2024-28877 | MicroDicom ≤ 2023.3 | CWE-121 (Stack Overflow) | 7.8 HIGH | cat13 |
| CVE-2025-35975 | MicroDicom ≤ 2025.1 | CWE-787 (OOB Write) | 8.8 HIGH | cat13 |
| CVE-2025-27578 | OsiriX MD ≤ 14.0.1 | CWE-416 (Use-After-Free) | 9.3 v4 CRITICAL | cat14 |
| CVE-2019-1010228 | DCMTK ≤ 3.6.3 | CWE-120 (Buffer Overflow) | — | cat15 |
| CVE-2022-2121 | DCMTK < 3.6.7 | CWE-476 (NULL Deref) | — | cat16 |
| CVE-2022-2119 | DCMTK < 3.6.7 | CWE-22 (Path Traversal) | — | cat16 |
| CVE-2022-2120 | DCMTK < 3.6.7 | CWE-22 (Path Traversal) | — | cat16 |
| CVE-2024-24793 | libdicom 1.0.5 | CWE-416 (Use-After-Free) | 8.1 HIGH | cat17 |
| CVE-2024-24794 | libdicom 1.0.5 | CWE-416 (Use-After-Free) | 8.1 HIGH | cat17 |
| CVE-2024-52333 | DCMTK 3.6.8 | CWE-787 (OOB Write) | 8.4 HIGH | cat18 |
| CVE-2024-28130 | DCMTK 3.6.8 | CWE-704 (Type Confusion) | 7.5 HIGH | cat18 |
| CVE-2024-27628 | DCMTK 3.6.8 | CWE-120 (Buffer Overflow) | — | cat19 |
| CVE-2025-2357 | DCMTK 3.6.9 | CWE-119 (Memory Corruption) | CRITICAL | cat19 |
| CVE-2024-34508 | DCMTK < 3.6.9 | CWE-476 (NULL Deref) | — | cat20 |
| CVE-2024-34509 | DCMTK < 3.6.9 | CWE-476 (NULL Deref) | — | cat20 |
| CVE-2024-1453 | Sante DICOM Viewer Pro ≤ 14.0.3 | CWE-125 (OOB Read) | 7.8 HIGH | cat21 |
| CVE-2025-5307 | Sante DICOM Viewer Pro ≤ 14.2.1 | CWE-125 (OOB Read) | 8.4 v4 HIGH | cat21 |
| CVE-2025-3483 | MedDream PACS < 7.3.5.860 | CWE-121 (Stack Overflow) | 9.8 CRITICAL | cat22 |
| CVE-2025-3484 | MedDream PACS < 7.3.5.860 | CWE-121 (Stack Overflow) | 9.8 CRITICAL | cat22 |
| CVE-2025-3485 | MedDream PACS < 7.3.5.860 | CWE-121 (Stack Overflow) | 9.8 CRITICAL | cat22 |
| CVE-2024-23912 | Merge DICOM Toolkit < 5.18 | CWE-125 (OOB Read) | 4.0 | cat23 |
| CVE-2024-23913 | Merge DICOM Toolkit < 5.18 | CWE-125 (OOB Read) | — | cat23 |
| CVE-2024-23914 | Merge DICOM Toolkit < 5.18 | CWE-134 (Format String) | — | cat23 |
| CVE-2023-33466 | Orthanc < 1.12.0 | CWE-22 (Path Traversal) | 8.8 HIGH | cat24 |
| CVE-2025-31946 | OsiriX MD ≤ 14.0.1 | CWE-416 (Use-After-Free) | 6.9 v4 | cat24 |

## Products Covered

| Product | CVEs | Categories |
|---|---|---|
| **OFFIS DCMTK** | 10 CVEs | cat12, cat15, cat16, cat18, cat19, cat20 |
| **Grassroots DICOM (GDCM)** | 2 CVEs | cat10, cat11 |
| **MicroDicom Viewer** | 3 CVEs | cat13 |
| **Pixmeo OsiriX MD** | 2 CVEs | cat14, cat24 |
| **libdicom (IDC)** | 2 CVEs | cat17 |
| **MedDream PACS** | 3 CVEs | cat22 |
| **Merative Merge DICOM Toolkit** | 3 CVEs | cat23 |
| **Orthanc** | 1 CVE | cat24 |
| **Santesoft Sante Viewer Pro** | 2 CVEs | cat21 |

## References

- [NVD — CVE-2026-3650](https://nvd.nist.gov/vuln/detail/CVE-2026-3650) | [CISA ICSMA-26-083-01](https://www.cisa.gov/news-events/ics-medical-advisories/icsma-26-083-01)
- [NVD — CVE-2025-11266](https://nvd.nist.gov/vuln/detail/CVE-2025-11266)
- [NVD — CVE-2024-47796](https://nvd.nist.gov/vuln/detail/CVE-2024-47796) | [TALOS-2024-2122](https://talosintelligence.com/vulnerability_reports/TALOS-2024-2122)
- [NVD — CVE-2024-22100](https://nvd.nist.gov/vuln/detail/CVE-2024-22100) | [CISA ICSMA-24-060-01](https://www.cisa.gov/news-events/ics-medical-advisories/icsma-24-060-01)
- [NVD — CVE-2024-28877](https://nvd.nist.gov/vuln/detail/CVE-2024-28877)
- [NVD — CVE-2025-35975](https://nvd.nist.gov/vuln/detail/CVE-2025-35975) | [CISA ICSMA-25-121-01](https://www.cisa.gov/news-events/ics-medical-advisories/icsma-25-121-01)
- [NVD — CVE-2025-27578](https://nvd.nist.gov/vuln/detail/CVE-2025-27578)
- [NVD — CVE-2019-1010228](https://nvd.nist.gov/vuln/detail/CVE-2019-1010228)
- [NVD — CVE-2022-2121](https://nvd.nist.gov/vuln/detail/CVE-2022-2121) | [CVE-2022-2119](https://nvd.nist.gov/vuln/detail/CVE-2022-2119) | [CVE-2022-2120](https://nvd.nist.gov/vuln/detail/CVE-2022-2120)
- [NVD — CVE-2024-24793](https://nvd.nist.gov/vuln/detail/CVE-2024-24793) | [CVE-2024-24794](https://nvd.nist.gov/vuln/detail/CVE-2024-24794)
- [NVD — CVE-2024-52333](https://nvd.nist.gov/vuln/detail/CVE-2024-52333) | [TALOS-2024-2121](https://talosintelligence.com/vulnerability_reports/TALOS-2024-2121)
- [NVD — CVE-2024-28130](https://nvd.nist.gov/vuln/detail/CVE-2024-28130) | [TALOS-2024-1957](https://talosintelligence.com/vulnerability_reports/TALOS-2024-1957)
- [NVD — CVE-2024-27628](https://nvd.nist.gov/vuln/detail/CVE-2024-27628)
- [NVD — CVE-2025-2357](https://nvd.nist.gov/vuln/detail/CVE-2025-2357)
- [NVD — CVE-2024-34508](https://nvd.nist.gov/vuln/detail/CVE-2024-34508) | [CVE-2024-34509](https://nvd.nist.gov/vuln/detail/CVE-2024-34509)
- [NVD — CVE-2024-1453](https://nvd.nist.gov/vuln/detail/CVE-2024-1453) | [CISA ICSMA-24-058-01](https://www.cisa.gov/news-events/ics-medical-advisories/icsma-24-058-01)
- [NVD — CVE-2025-5307](https://nvd.nist.gov/vuln/detail/CVE-2025-5307) | [CISA ICSMA-25-148-01](https://www.cisa.gov/news-events/ics-medical-advisories/icsma-25-148-01)
- [NVD — CVE-2025-3483](https://nvd.nist.gov/vuln/detail/CVE-2025-3483) | [ZDI-25-243](https://www.zerodayinitiative.com/advisories/ZDI-25-243/)
- [NVD — CVE-2024-23912](https://nvd.nist.gov/vuln/detail/CVE-2024-23912) | [Nozomi Networks Advisory](https://www.nozominetworks.com/blog/exploiting-healthcare-supply-chain-security-merge-dicom-toolkit)
- [NVD — CVE-2023-33466](https://nvd.nist.gov/vuln/detail/CVE-2023-33466) | [Shielder Blog](https://www.shielder.com/blog/2023/10/cve-2023-33466-exploiting-healthcare-servers-with-polyglot-files/)
- [NVD — CVE-2025-31946](https://nvd.nist.gov/vuln/detail/CVE-2025-31946)
- [TXOne: Uncovering New Vulnerabilities in PACS Servers and DICOM Viewers](https://www.txone.com/blog/uncovering-new-vulnerabilities-in-pacs-servers-and-dicom-viewers/)
