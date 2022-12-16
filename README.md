### Vulmatch: Binary-level Vulnerability Detection Through Signature

Vulmatch is an approach to match 1-day or N-day vulnerabilityes in query binary code. It works by firstly "learn" the vulnerable signature from training vulnerabilities. Then in the matching phase, the input is an unknown query binary without any debugging information and source code. In the training phase, for locate vulnerable instructions more accurately, Vulmatch utilize source code to guide locating vulnerable instructions in binary code.

Vulmatch contains four steps: 1. Data preparation. 2. Locating signature instructions. 3. Construct context-aware binary-level signatures. 4. Signature matching.

#### 1. Data preparation

###### 1.1 Prepare CVE informations of vulnerable projects. Record each CVE information and store them in the path like "/home/nuc/Downloads/vulnerable_projects/firmware/the_detailed_information_of_vulnerabilities.xlsx". 

###### 1.2 Prepare the source code of all the versions of the each project. 
Run ```python create_cve_folders.py``` to automatically create a folder for each CVE.
Run ```python find_bin_files_by_version.py``` to automatically extract source code files and binary files to each CVE folder just created.

###### 1.3 Add tags before each vulnerable function to inform the compiler not to inline the function.
Run ```python extract_sg/no_inline.py``` to automatically add tags in all source code versions. 

###### 1.4 Then compile all versions using the same optimization options.

#### 2. Locating signature instructions & 3. Construct context-aware binary-level signatures
Run ```python extract_sig/diff.py``` This will output source-code-level signatures in each CVE folder. 
Run ```python extract_sig/extract_insn_from_bin.py``` to output binary-code-level signatures in each CVE folder. Now the binary-code-level signatures in each CVE folder serves as the database.


#### 4. Signature matching
Run ```python extract_sig/match.py``` to detect similar vulnerabilities stored in the database.
