---
"@stll/skillguard": patch
"@stll/skillguard-core": patch
"@stll/skillguard-rules": patch
"@stll/skillguard-sarif": patch
---

Parse JavaScript and TypeScript with oxc-parser instead of the TypeScript compiler, report unparseable scripts as high-severity `JSA10` scan-integrity findings while still analyzing the program the parser recovered, and build declarations with the oxc generator.
