# DICOM C-STORE Fuzz Corpus

1,755 manifest-indexed test cases across 35 categories (~41 MB on disk).
Covers **35 CVEs** spanning 9 DICOM products/libraries.

A pre-built corpus of malformed DICOM files for security testing DICOM
implementations — designed to be delivered over the network via DIMSE C-STORE
(or, where noted, DICOMweb STOW-RS), targeting parsing vulnerabilities in PACS
servers, DICOM viewers, and medical imaging libraries.

Every test case is indexed in [`manifest.json`](manifest.json), which records
each case's file path (relative to this directory), description, target tag,
mutation, severity, and expected behavior. A known-good baseline lives in
[`baseline/`](baseline/).

## Corpus Summary

| Category | Cases | Target CVE(s) | What's in there |
|---|---|---|---|
| `cat01_tag_overflow` | 115 | - | Boundary, +1, 2x/10x/64KB/1MB overflows across 12 tags (PN, LO, SH, UI, CS). PN with 256 `^` separators, UID with 200 dot components, CS lowercase, invalid AS/DA/TM formats |
| `cat02_vr_mismatch` | 15 | - | UI-as-LO, US-as-UL, US-as-SS, DA-as-DS, PN-as-OB, OB-as-OW, CS-as-LO, LO-as-UN. Implicit VR cases with binary garbage in PN, 4-byte Rows, all-0xFF date |
| `cat03_sequence_nesting` | 12 | - | Depth 10/50/100 via pydicom, depth-500 as raw bytes. Wide SQ 1/100/1000 items. Undefined-length SQ, missing delimiters, stray delimiters, SQ containing PixelData, zero-length items |
| `cat04_pixel_data` | 29 | - | Buffer half/2x/10x/zero/1-byte vs declared dims. Zero Rows/Cols. BitsAllocated/Stored/HighBit inconsistencies. Encapsulated: empty BOT, zero-length fragment, 10K fragments. Photometric mismatch. Multi-frame NFrames=0/999999 |
| `cat05_transfer_syntax` | 3 | - | Meta declares Explicit but body is Implicit. Corrupt/truncated deflate streams |
| `cat06_private_tags` | 14 | - | Valid/invalid private tags, command group in dataset, group 0xFFFF, stray delimiters, tag ordering violation, bulk private elements, shell/SQL/format-string injection payloads |
| `cat07_file_meta` | 14 | - | No preamble/DICM, 0xFF preamble, 127-byte off-by-one, DICM at wrong offsets, corrupt Group Length, SOP Class mismatch, invalid Transfer Syntax UID, group 0002 in dataset body |
| `cat08_string_encoding` | 16 | - | Charset/encoding mismatches, invalid UTF-8, null bytes, control chars, format strings, SSTI payloads, 1000-backslash VM, RTL override + zero-width chars |
| `cat09_logic_bombs` | 19 | - | SOP/Modality mismatch, duplicate tags, odd-length values, UID edge cases (64/65-char, dots, empty), Group Length=0, UID collision, dangling references |
| `cat10_cve_2026_3650` | 117 | CVE-2026-3650 | Non-standard VR in File Meta Info: single-element replacement (14 VRs × 6 tags), all-VRs-replaced, amplified lengths (64KB-1GB), repeated fake elements (10-1000), mixed valid/invalid, first-element corruption |
| `cat11_cve_2025_11266` | 10 | CVE-2025-11266 | GDCM OOB write: encapsulated PixelData fragment lengths 0xFFFFFFFF/0xFFFFFFFE/0x80000000, wrapping, bad BOT offsets, missing sequence delimiters |
| `cat12_cve_2024_47796` | 15 | CVE-2024-47796 | DCMTK nowindow OOB write: WindowCenter/WindowWidth = INT_MIN/INT_MAX/NaN/Inf/float overflow/UINT64_MAX with extreme BitsAllocated |
| `cat13_cve_microdicom` | 38 | CVE-2024-22100, CVE-2024-28877, CVE-2025-35975 | MicroDicom heap/stack: 256-65535 byte strings in PN/LO/SH/CS, pixel dim mismatches 65535×65535, 100 frames tiny buffer |
| `cat14_cve_2025_27578` | 6 | CVE-2025-27578 | OsiriX UAF: self-referencing SOP UIDs, shared SQ items, PerFrameFunctionalGroups count mismatches, 50 duplicate refs, triple UID reuse |
| `cat15_cve_2019_1010228` | 6 | CVE-2019-1010228 | DCMTK RLE decoder: OOB segment offsets, overlapping segments, expansion bombs, short data, 0/0xFFFFFFFF segments |
| `cat16_cve_dcmtk_null_pathtraversal` | 21 | CVE-2022-2121, CVE-2022-2119, CVE-2022-2120 | DCMTK NULL deref (12 required tags removed) + path traversal payloads (Unix/Windows/URL-encoded/null-byte) |
| `cat17_cve_libdicom_uaf` | 8 | CVE-2024-24793, CVE-2024-24794 | libdicom UAF: truncated File Meta (group length > actual), duplicate meta tags, missing SQ delimiters, premature Item Delimitation, zero-length meta |
| `cat18_cve_dcmtk_minmax_voi` | 14 | CVE-2024-52333, CVE-2024-28130 | DCMTK determineMinMax: BitsStored=0/17/33, HighBit=255, BitsStored>BitsAllocated. VOI LUT: string LUTDescriptor, empty LUTData, 65535-entry mismatch, Modality LUT with ASCII |
| `cat19_cve_dcmtk_ect_jpegls` | 9 | CVE-2024-27628, CVE-2025-2357 | EctEnhancedCT: frame/PFG mismatches (10000/0, 65535/1, 0/0), oversized SharedFunctionalGroups. JPEG-LS: zero components, NEAR=255, precision mismatch (16-bit/8-bit BA), truncated stream |
| `cat20_cve_dcmtk_dimse_segfault` | 5 | CVE-2024-34508, CVE-2024-34509 | DCMTK DIMSE segfault: undefined-length elements without delimiters, CommandGroupLength in dataset, 2-byte truncated dataset, mid-value truncation, cascading undefined-length |
| `cat21_cve_santesoft_oob` | 10 | CVE-2024-1453, CVE-2025-5307 | Santesoft OOB read: pixel buffer mismatches (1024², 4096², 32768×1), zero-byte PixelData, overlay data OOB, IconImageSequence 8192×8192 with 16-byte data |
| `cat22_cve_meddream_stack_overflow` | 74 | CVE-2025-3483, CVE-2025-3484, CVE-2025-3485 | MedDream PACS stack overflow: 8 target tags × 9 stack sizes (256-65535), combined all-tags-at-once at 4096/65535 |
| `cat23_cve_merge_toolkit` | 15 | CVE-2024-23912, CVE-2024-23913, CVE-2024-23914 | Merge Toolkit: element lengths exceeding file (64KB-4GB), odd-length violations, SQ item with huge length, format string payloads (%s, %n, %p, %08x, positional) |
| `cat24_cve_orthanc_osirix` | 9 | CVE-2023-33466, CVE-2025-31946 | Orthanc: JSON config polyglots in DICOM preamble (remote access, LuaScripts RCE, storage redirect), path traversal UIDs. OsiriX local UAF: circular SOP refs, DimensionOrganization mismatch, 20 private SQ stress test |
| `cat25_cwe22_cstore_path_traversal` | 421 | - | CWE-22 storage-path traversal in UID/ID tags that form on-disk paths (SOPInstanceUID, StudyInstanceUID, SeriesInstanceUID, PatientID): Unix/Windows/UNC/URL-encoded/double-encoded/null-byte/absolute payloads, command-set-level source, Kubernetes service-account targeting |
| `cat26_cwe400_resource_exhaustion` | 57 | - | CWE-400/770 exhaustion: decompression/expansion bombs, oversized element lengths, deeply and widely populated datasets, sequence blowups, huge pixel/frame declarations |
| `cat27_vr_input_validation_bypass` | 285 | - | CWE-20 counterfeit numeric/identifier values (IS/DS/FL/FD/VM/UI): NaN/Inf/hex/sci-notation/overflow in IS and DS, malformed FL/FD, VM violations, non-conformant UIDs. RawDataElement passthrough confirmed on pydicom 3.0.2, GDCM 3.2.6, dicom-microscopy-viewer |
| `cat28_vr_datetime_pn_cs_bypass` | 166 | - | CWE-20 counterfeit DA/TM/DT (Feb-30, month-13, hour-24, bad TZ, NaN), PN structural injection (excess components/groups, CRLF+HL7, XSS, JNDI, null-byte hiding), CS/AE/AS/UR abuse (overlong, traversal, `javascript:`, SSRF, `file://`, `data:`) |
| `cat29_downstream_injection` | 90 | - | 15 payloads × 6 propagation-prone tags injecting into secondary contexts: HL7 v2 (field/segment/repetition/sub-component separators), SQL, XML/CDATA/XXE, FHIR/JSON, LDAP filters, CSV formula injection |
| `cat30_dicomweb_stow_ingestion` | 36 | - | DICOMweb STOW-RS: `dicom+json` model injection, XML/XXE breakout, BulkDataURI SSRF (cloud-metadata / `file://`), MIME confusion, and raw `.http` multipart bodies (boundary injection, CRLF header smuggle, nested multipart) |
| `cat31_encapsulated_codec_fuzzing` | 23 | - | Encapsulated codestreams routed to third-party decoders: JPEG 2000 (SIZ 4G×4G, truncated COD, missing EOC), JPEG-LS (SOF55 65535², precision=255), Baseline JPEG (SOF0 huge dims, 255 components), RLE (segment 0xFFFFFFFF, expansion bomb), fragmentation (lying BOT, 3000 fragments) |
| `cat32_cve_2026_dcmtk_orthanc` | 32 | CVE-2026-50003, CVE-2026-52868, CVE-2026-50254, CVE-2026-35505, CVE-2026-44628, CVE-2026-10528 | 2026 CVE refresh: DCMTK path traversal on storage-path tags, missing-free memory leaks (200/1000-item sequences, 500 private OB elements), wrong-VR type confusion (Rows/Columns/BitsAllocated/PixelData/NumberOfFrames/SamplesPerPixel), 400-deep undefined-length SQ nesting + ~4 GB declared element length; Orthanc heap corruption |
| `cat33_deid_bypass_phi_hiding` | 15 | - | PS3.15 de-identification bypass: synthetic `FAKEPHI` marker hidden in private elements (with/without creator), two-deep sequence items, VR UN/OB binary, uncommon identifying tags (PatientAddress, MilitaryRank, RegionOfResidence, TelephoneNumbers, ReligiousPreference), shadow copies, free-text descriptors |
| `cat34_dimse_command_set_fuzzing` | 21 | - | DIMSE command set (group 0000): command elements smuggled into the dataset body, command/File-Meta/dataset SOP-UID consistency (mismatch, spoofed IOD, empty/missing SOPInstanceUID), and raw `.cmd` command PDVs (bad CommandGroupLength, unknown CommandField, DataSetType lies, out-of-order/Explicit-VR command sets) |
| `cat35_sr_content_tree_fuzzing` | 15 | - | Structured Report content tree (0040,A730): 10/50/500-deep CONTAINER nesting, 1000/5000-wide trees, by-reference cycles and self-reference (0040,DB73), dangling references, malformed items (bad ValueType/RelationshipType, counterfeit NUM DS, TEXT injection, SCOORD GraphicData overflow), overlong coded concepts |

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
| CVE-2019-1010228 | DCMTK ≤ 3.6.3 | CWE-120 (Buffer Overflow) | - | cat15 |
| CVE-2022-2121 | DCMTK < 3.6.7 | CWE-476 (NULL Deref) | - | cat16 |
| CVE-2022-2119 | DCMTK < 3.6.7 | CWE-22 (Path Traversal) | - | cat16 |
| CVE-2022-2120 | DCMTK < 3.6.7 | CWE-22 (Path Traversal) | - | cat16 |
| CVE-2024-24793 | libdicom 1.0.5 | CWE-416 (Use-After-Free) | 8.1 HIGH | cat17 |
| CVE-2024-24794 | libdicom 1.0.5 | CWE-416 (Use-After-Free) | 8.1 HIGH | cat17 |
| CVE-2024-52333 | DCMTK 3.6.8 | CWE-787 (OOB Write) | 8.4 HIGH | cat18 |
| CVE-2024-28130 | DCMTK 3.6.8 | CWE-704 (Type Confusion) | 7.5 HIGH | cat18 |
| CVE-2024-27628 | DCMTK 3.6.8 | CWE-120 (Buffer Overflow) | - | cat19 |
| CVE-2025-2357 | DCMTK 3.6.9 | CWE-119 (Memory Corruption) | CRITICAL | cat19 |
| CVE-2024-34508 | DCMTK < 3.6.9 | CWE-476 (NULL Deref) | - | cat20 |
| CVE-2024-34509 | DCMTK < 3.6.9 | CWE-476 (NULL Deref) | - | cat20 |
| CVE-2024-1453 | Sante DICOM Viewer Pro ≤ 14.0.3 | CWE-125 (OOB Read) | 7.8 HIGH | cat21 |
| CVE-2025-5307 | Sante DICOM Viewer Pro ≤ 14.2.1 | CWE-125 (OOB Read) | 8.4 v4 HIGH | cat21 |
| CVE-2025-3483 | MedDream PACS < 7.3.5.860 | CWE-121 (Stack Overflow) | 9.8 CRITICAL | cat22 |
| CVE-2025-3484 | MedDream PACS < 7.3.5.860 | CWE-121 (Stack Overflow) | 9.8 CRITICAL | cat22 |
| CVE-2025-3485 | MedDream PACS < 7.3.5.860 | CWE-121 (Stack Overflow) | 9.8 CRITICAL | cat22 |
| CVE-2024-23912 | Merge DICOM Toolkit < 5.18 | CWE-125 (OOB Read) | 4.0 | cat23 |
| CVE-2024-23913 | Merge DICOM Toolkit < 5.18 | CWE-125 (OOB Read) | - | cat23 |
| CVE-2024-23914 | Merge DICOM Toolkit < 5.18 | CWE-134 (Format String) | - | cat23 |
| CVE-2023-33466 | Orthanc < 1.12.0 | CWE-22 (Path Traversal) | 8.8 HIGH | cat24 |
| CVE-2025-31946 | OsiriX MD ≤ 14.0.1 | CWE-416 (Use-After-Free) | 6.9 v4 | cat24 |
| CVE-2026-50003 | DCMTK | CWE-22 (Path Traversal) | - | cat32 |
| CVE-2026-52868 | DCMTK | CWE-22 (Path Traversal) | - | cat32 |
| CVE-2026-50254 | DCMTK | CWE-401 (Memory Leak) | - | cat32 |
| CVE-2026-35505 | DCMTK | CWE-401 (Memory Leak) | - | cat32 |
| CVE-2026-44628 | DCMTK | CWE-843 (Type Confusion) | - | cat32 |
| CVE-2026-10528 | Orthanc | CWE-121/119 (Buffer Overflow) | - | cat32 |

## Products Covered

| Product | CVEs | Categories |
|---|---|---|
| **OFFIS DCMTK** | 16 CVEs | cat12, cat15, cat16, cat18, cat19, cat20, cat32 |
| **Grassroots DICOM (GDCM)** | 2 CVEs | cat10, cat11 |
| **MicroDicom Viewer** | 3 CVEs | cat13 |
| **Pixmeo OsiriX MD** | 2 CVEs | cat14, cat24 |
| **libdicom (IDC)** | 2 CVEs | cat17 |
| **MedDream PACS** | 3 CVEs | cat22 |
| **Merative Merge DICOM Toolkit** | 3 CVEs | cat23 |
| **Orthanc** | 2 CVEs | cat24, cat32 |
| **Santesoft Sante Viewer Pro** | 2 CVEs | cat21 |

## Categories Beyond CVE Reproduction

The corpus also includes structural and standards-conformance categories not tied
to a single CVE:

| Category | Cases | Focus |
|---|---|---|
| `cat25_cwe22_cstore_path_traversal` | 421 | CWE-22 storage-path traversal (root-cause coverage) |
| `cat26_cwe400_resource_exhaustion` | 57 | CWE-400/770 resource exhaustion |
| `cat27_vr_input_validation_bypass` | 285 | CWE-20 VR validation bypass (IS/DS/FL/FD/VM/UI) |
| `cat28_vr_datetime_pn_cs_bypass` | 166 | CWE-20 counterfeit DA/TM/DT + PN + CS/AE/AS/UR |
| `cat29_downstream_injection` | 90 | CWE-74/89/90/611 downstream injection (HL7/FHIR/SQL/LDAP/XML/CSV) |
| `cat30_dicomweb_stow_ingestion` | 36 | CWE-611/918 DICOMweb STOW-RS ingestion and serialisation |
| `cat31_encapsulated_codec_fuzzing` | 23 | Encapsulated codec codestream fuzzing (J2K/JPEG-LS/JPEG/RLE) |
| `cat33_deid_bypass_phi_hiding` | 15 | CWE-359 PS3.15 de-identification bypass / PHI hiding |
| `cat34_dimse_command_set_fuzzing` | 21 | CWE-20 DIMSE command-set fuzzing and command/dataset consistency |
| `cat35_sr_content_tree_fuzzing` | 15 | CWE-674/835 Structured Report content-tree fuzzing |

`cat30` `.http` files and `cat34` `.cmd` files are not `.dcm` payloads: the
C-STORE fuzzer cannot send them. Drive `cat30` `.http` bodies against the STOW-RS
endpoint with curl, and replay `cat34` `.cmd` command groups with a
command-set-aware DUL sender.

## Contributing

New vulnerability categories, additional CVE coverage, and refreshed test cases
are welcome. Add a new `catNN_*/` directory of `.dcm` (or `.http`/`.cmd`) cases
and register each case in [`manifest.json`](manifest.json) so the corpus stays
fully indexed.

## References

- [NVD: CVE-2026-3650](https://nvd.nist.gov/vuln/detail/CVE-2026-3650) | [CISA ICSMA-26-083-01](https://www.cisa.gov/news-events/ics-medical-advisories/icsma-26-083-01)
- [NVD: CVE-2025-11266](https://nvd.nist.gov/vuln/detail/CVE-2025-11266)
- [NVD: CVE-2024-47796](https://nvd.nist.gov/vuln/detail/CVE-2024-47796) | [TALOS-2024-2122](https://talosintelligence.com/vulnerability_reports/TALOS-2024-2122)
- [NVD: CVE-2024-22100](https://nvd.nist.gov/vuln/detail/CVE-2024-22100) | [CISA ICSMA-24-060-01](https://www.cisa.gov/news-events/ics-medical-advisories/icsma-24-060-01)
- [NVD: CVE-2024-28877](https://nvd.nist.gov/vuln/detail/CVE-2024-28877)
- [NVD: CVE-2025-35975](https://nvd.nist.gov/vuln/detail/CVE-2025-35975) | [CISA ICSMA-25-121-01](https://www.cisa.gov/news-events/ics-medical-advisories/icsma-25-121-01)
- [NVD: CVE-2025-27578](https://nvd.nist.gov/vuln/detail/CVE-2025-27578)
- [NVD: CVE-2019-1010228](https://nvd.nist.gov/vuln/detail/CVE-2019-1010228)
- [NVD: CVE-2022-2121](https://nvd.nist.gov/vuln/detail/CVE-2022-2121) | [CVE-2022-2119](https://nvd.nist.gov/vuln/detail/CVE-2022-2119) | [CVE-2022-2120](https://nvd.nist.gov/vuln/detail/CVE-2022-2120)
- [NVD: CVE-2024-24793](https://nvd.nist.gov/vuln/detail/CVE-2024-24793) | [CVE-2024-24794](https://nvd.nist.gov/vuln/detail/CVE-2024-24794)
- [NVD: CVE-2024-52333](https://nvd.nist.gov/vuln/detail/CVE-2024-52333) | [TALOS-2024-2121](https://talosintelligence.com/vulnerability_reports/TALOS-2024-2121)
- [NVD: CVE-2024-28130](https://nvd.nist.gov/vuln/detail/CVE-2024-28130) | [TALOS-2024-1957](https://talosintelligence.com/vulnerability_reports/TALOS-2024-1957)
- [NVD: CVE-2024-27628](https://nvd.nist.gov/vuln/detail/CVE-2024-27628)
- [NVD: CVE-2025-2357](https://nvd.nist.gov/vuln/detail/CVE-2025-2357)
- [NVD: CVE-2024-34508](https://nvd.nist.gov/vuln/detail/CVE-2024-34508) | [CVE-2024-34509](https://nvd.nist.gov/vuln/detail/CVE-2024-34509)
- [NVD: CVE-2024-1453](https://nvd.nist.gov/vuln/detail/CVE-2024-1453) | [CISA ICSMA-24-058-01](https://www.cisa.gov/news-events/ics-medical-advisories/icsma-24-058-01)
- [NVD: CVE-2025-5307](https://nvd.nist.gov/vuln/detail/CVE-2025-5307) | [CISA ICSMA-25-148-01](https://www.cisa.gov/news-events/ics-medical-advisories/icsma-25-148-01)
- [NVD: CVE-2025-3483](https://nvd.nist.gov/vuln/detail/CVE-2025-3483) | [ZDI-25-243](https://www.zerodayinitiative.com/advisories/ZDI-25-243/)
- [NVD: CVE-2024-23912](https://nvd.nist.gov/vuln/detail/CVE-2024-23912) | [Nozomi Networks Advisory](https://www.nozominetworks.com/blog/exploiting-healthcare-supply-chain-security-merge-dicom-toolkit)
- [NVD: CVE-2023-33466](https://nvd.nist.gov/vuln/detail/CVE-2023-33466) | [Shielder Blog](https://www.shielder.com/blog/2023/10/cve-2023-33466-exploiting-healthcare-servers-with-polyglot-files/)
- [NVD: CVE-2025-31946](https://nvd.nist.gov/vuln/detail/CVE-2025-31946)
- [NVD: CVE-2026-50003](https://nvd.nist.gov/vuln/detail/CVE-2026-50003) | [CVE-2026-52868](https://nvd.nist.gov/vuln/detail/CVE-2026-52868) | [CVE-2026-50254](https://nvd.nist.gov/vuln/detail/CVE-2026-50254) | [CVE-2026-35505](https://nvd.nist.gov/vuln/detail/CVE-2026-35505) | [CVE-2026-44628](https://nvd.nist.gov/vuln/detail/CVE-2026-44628) | [CISA ICSMA-26-181-01](https://www.cisa.gov/news-events/ics-medical-advisories/icsma-26-181-01)
- [NVD: CVE-2026-10528](https://nvd.nist.gov/vuln/detail/CVE-2026-10528)
- [TXOne: Uncovering New Vulnerabilities in PACS Servers and DICOM Viewers](https://www.txone.com/blog/uncovering-new-vulnerabilities-in-pacs-servers-and-dicom-viewers/)

## Author

Paulino Calderon ([@calderpwn](https://x.com/calderpwn))
