# DICOM Fuzzing Toolkit

A comprehensive fuzzing corpus and toolset for security testing DICOM implementations. The project provides a pre-built corpus of malformed DICOM files to deliver them over the network via DIMSE C-STORE, targeting parsing vulnerabilities in PACS servers, DICOM viewers, and medical imaging libraries.

## Corpus Categories

**Protocol fuzzing (cat01-cat09):** Tag value overflow, VR type confusion, sequence nesting, pixel data corruption, transfer syntax abuse, private/unknown tags, file meta malformation, string encoding, and logic bombs.

**CVE-targeted (cat10-cat24):** Crafted test cases for specific vulnerabilities in GDCM, DCMTK, MicroDicom, OsiriX, libdicom, MedDream PACS, Merge DICOM Toolkit, Orthanc, and Santesoft Sante Viewer Pro. See [FUZZ_CORPUS_v3.md](FUZZ_CORPUS_v3.md) for the full CVE mapping.

## Contributing

New vulnerability categories, additional CVE coverage, and improvements to the generator or NSE scripts are welcome. The generator is designed to be extended — add a `gen_catNN()` function and wire it into the `ALL_CATS`, `CAT_FUNCS`, and `CAT_NAMES` registries.


## Author

Paulino Calderon ([@calderpwn](https://x.com/calderpwn))
