# rule format

capa uses a collection of rules to identify capabilities within a program.
These rules are easy to write, even for those new to reverse engineering.
By authoring rules, you can extend the capabilities that capa recognizes.
In some regards, capa rules are a mixture of the OpenIOC, Yara, and YAML formats.

Here's an example rule used by capa:

```yaml
rule:
  meta:
    name: hash data with CRC32
    namespace: data-manipulation/checksum/crc32
    author: moritz.raabe@fireeye.com
    scope: function
    examples:
      - 2D3EDC218A90F03089CC01715A9F047F:0x403CBD
      - 7D28CB106CB54876B2A5C111724A07CD:0x402350  # RtlComputeCrc32
  features:
    - or:
      - and:
        - mnemonic: shr
        - number: 0xEDB88320
        - number: 8
        - characteristic: nzxor
      - api: RtlComputeCrc32
```

This document defines the available structures and features that you can use as you write capa rules.
We'll start at the high level structure and then dig into the logic structures and features that capa supports.

### table of contents 
- [rule format](#rule-format)
  - [yaml](#yaml)
  - [meta block](#meta-block)
  - [features block](#features-block)
- [extracted features](#extracted-features)
  - [function features](#function-features)
    - [api](#api)
    - [number](#number)
    - [string](#string)
    - [bytes](#bytes)
    - [offset](#offset)
    - [mnemonic](#mnemonic)
    - [characteristic](#characteristic)
  - [file features](#file-features)
    - [string](#file-string)
    - [export](#export)
    - [import](#import)
    - [section](#section)
  - [counting](#counting)
  - [matching prior rule matches and namespaces](#matching-prior-rule-matches-and-namespaces)
  - [descriptions](#descriptions)


## yaml

Rules are YAML files that follow a certain schema.
You should be able to use any YAML editor/syntax highlighting to assist you.

Once you have a draft rule, you can use the [linter](https://github.com/fireeye/capa/blob/master/scripts/lint.py) 
 to check that your rule adheres to best practices.
Then, you should use the [formatter](https://github.com/fireeye/capa/blob/master/scripts/capafmt.py)
 to reformat the rule into a style that's consistent with all other capa rules.
This way, you don't have to worry about the width of indentation while you're focused on logic.
We run the linter and formatter in our Continuous Integration setup so that we can be sure all rules are consistent.

Within the YAML document, the top-level element is a dictionary named `rule`
 with two required children dictionaries:
`meta` and `features`.
There are no other children.

```yaml
rule:
  meta: ...
  features: ...
```

## meta block

The meta block contains metadata that identifies the rule, groups the technique, 
and provides references to additional documentation.
Here's an example:

```yaml
meta:
  name: packed with UPX
  namespace: anti-analysis/packer/upx
  author: william.ballenthin@fireeye.com
  description: the sample appears to be packed with UPX
  scope: file
  att&ck:
    - Defense Evasion::Obfuscated Files or Information [T1027.002]
  mbc:
      - Anti-Static Analysis::Software Packing
  examples:
    - CD2CBA9E6313E8DF2C1273593E649682
    - Practical Malware Analysis Lab 01-02.exe_:0x0401000
```


Here are the common fields:

  - `name` is required. This string should uniquely identify the rule. More details below.

  - `namespace` is required when a rule describes a technique, and helps us group rules into buckets. More details below.

  - `author` specifies the name or handle of the rule author.
  
  - `description` is optional text that describes the intent or interpretation of the rule.

  - `scope` indicates to which feature set this rule applies.
    Here are the legal values:
    - **`basic block`**: matches features within each basic block.
      This is used to achieve locality in rules (for example for parameters of a function).
    - **`function`** (default): match features within each function.
    - **`file`**: matches features across the whole file.
      
  - `att&ck` is an optional list of [ATT&CK framework](https://attack.mitre.org/) techniques that the rule implies, like 
`Discovery::Query Registry [T1012]` or `Persistence::Create or Modify System Process::Windows Service [T1543.003]`.
These tags are used to derive the ATT&CK mapping for the sample when the report gets rendered.

  - `mbc` is an optional list of [Malware Behavior Catalog](https://github.com/MBCProject/mbc-markdown) techniques that the rule implies,
like the ATT&CK list.

  - `maec/malware-category` is required when the rule describes a role, such as `dropper` or `backdoor`.

  - `maec/analysis-conclusion` is required when the rule describes a disposition, such as `benign` or `malicious`.

  - `examples` is a *required* list of references to samples that the rule should match.
The linter verifies that each rule correctly fires on each sample referenced in a rule's `examples` list.
These example files are stored in the [github.com/fireeye/capa-testfiles](https://github.com/fireeye/capa-testfiles) repository.

  - `references` lists related information found in a book, article, blog post, etc.

Other fields are not allowed, and the linter will complain about them.

### rule name

The `rule.meta.name` uniquely identifies a rule.
It can be referenced in other rules, so if you change a rule name, be sure to search for cross references.

By convention, the rule name should complete one of the following sentences:
  - "The program/function may..."
  - "The program was..."
  
When the rule describes a specific means to implement a techinque, this is typically specified by "via XYZ".
  
Therefore, these are good rule names:
  - (The function may) "**make an HTTP request via WinInet**"
  - (The function may) "**encrypt data using RC4 via WinCrypt**"
  - (The program was)  "**compiled by MSVC**"
  
...and, these are bad rule names:
  - "UPX"
  - "encryption with OpenSSL"

### rule namespace

The rule namespace helps us group related rules together.
You'll notice that the file system layout of the rule files matches the namespaces that they contain.
Furthermore, output from capa is ordered by namespace, so all `communication` matches render next to one another.

Namespaces are hierarchical, so the children of a namespace encodes its specific techniques.
In a few words each, the top level namespaces are:

  - [anti-analysis](https://github.com/fireeye/capa-rules/anti-analysis/) - packing, obfuscation, anti-X, etc.
  - [c2](https://github.com/fireeye/capa-rules/c2/) - commands that may be issued by a controller, such as interactive shell or file transfer
  - [collection](https://github.com/fireeye/capa-rules/collection/) - data that may be enumerated and collected for exfiltration
  - [communication](https://github.com/fireeye/capa-rules/communication/) - HTTP, TCP, etc.
  - [compiler](https://github.com/fireeye/capa-rules/compiler/) - detection of build environments, such as MSVC, Delphi, or AutoIT
  - [data-manipulation](https://github.com/fireeye/capa-rules/data-manipulation/) - encryption, hashing, etc.
  - [executable](https://github.com/fireeye/capa-rules/executable/) - characteristics of the executable, such as PE sections or debug info
  - [host-interaction](https://github.com/fireeye/capa-rules/host-interaction/) - access or manipulation of system resources, like processes or the Registry
  - [impact](https://github.com/fireeye/capa-rules/impact/) - end goal
  - [linking](https://github.com/fireeye/capa-rules/linking/) - detection of dependencies, such as OpenSSL or Zlib
  - [load-code](https://github.com/fireeye/capa-rules/load-code/) - runtime load and execution of code, such as embedded PE or shellcode
  - [persistence](https://github.com/fireeye/capa-rules/persistence/) - all sorts of ways to maintain access
  - [runtime](https://github.com/fireeye/capa-rules/runtime/) - detection of language runtimes, such as the .NET platform or Go
  - [targeting](https://github.com/fireeye/capa-rules/targeting/) - special handling of systems, such as ATM machines
  
We can easily add more top level namespaces as the need arises. 

All namespaces components should be nouns that describe the capability concept, except for possibly the last component.
For example, here's a namespace subtree that describes capabilities for interacting with system hardware:

```
host-interaction/hardware
host-interaction/hardware/storage
host-interaction/hardware/memory
host-interaction/hardware/cpu
host-interaction/hardware/mouse
host-interaction/hardware/keyboard
host-interaction/hardware/keyboard/layout
host-interaction/hardware/cdrom
```

When there are many common operations for a namespace, 
and many ways to implement each operation, 
then the final path component may be a verb that describes the operation.
For example, there are *many* ways to do multiple file operations on Windows, so the namespace subtree looks like:

```
rules/host-interaction/file-system
rules/host-interaction/file-system/create
rules/host-interaction/file-system/delete
rules/host-interaction/file-system/write
rules/host-interaction/file-system/copy
rules/host-interaction/file-system/exists
rules/host-interaction/file-system/read
rules/host-interaction/file-system/list
```

The depth of the namespace tree is not limited, but we've found that 3-4 components is typically sufficient.

## features block

This section declares logical statements about the features that must exist for the rule to match.

There are five structural expressions that may be nested:
  - `and` - all of the children expressions must match
  - `or` - match at least one of the children
  - `not` - match when the child expression does not
  - `N or more` - match at least `N` or more of the children
    - `optional` is an alias for `0 or more`, which is useful for documenting related features. See [write-file.yml](/rules/machine-access-control/file-manipulation/write-file.yml) for an example.

To add context to a statement, you can add *one* nested description entry in the form `- description: DESCRIPTION STRING`.
Check the [description section](#descriptions) for more details.

For example, consider the following rule:

```
      - and:
        - description: core of CRC-32 algorithm
        - mnemonic: shr
        - number: 0xEDB88320
        - number: 8
        - characteristic: nzxor
      - api: RtlComputeCrc32
```

For this to match, the function must:
  - contain an `shr` instruction, and
  - reference the immediate constant `0xEDB88320`, which some may recognize as related to the CRC32 checksum, and
  - reference the number `8`, and
  - have an unusual feature, in this case, contain a non-zeroing XOR instruction
If only one of these features is found in a function, the rule will not match.


# extracted features

## function features

capa extracts features from the disassembly of a function, such as which API functions are called.
The tool also reasons about the code structure to guess at function-level constructs.
These are the features supported at the function-scope:

  - [api](#api)
  - [number](#number)
  - [string](#string)
  - [bytes](#bytes)
  - [offset](#offset)
  - [mnemonic](#mnemonic)
  - [characteristic](#characteristic)

### api
A call to a named function, probably an import,
though possibly a local function (like `malloc`) extracted via function signature matching like FLIRT.

The parameter is a string describing the function name, specified like `module.functionname` or `functionname`.

Windows API functions that take string arguments come in two API versions. For example, `CreateProcessA` takes ANSI strings and `CreateProcessW` takes Unicode strings. capa extracts these API features both with and without the suffix character `A` or `W`. That means you can write a rule to match on both APIs using the base name. If you want to match a specific API version, you can include the suffix.

Example:

    api: kernel32.CreateFile  # matches both Ansi (CreateFileA) and Unicode (CreateFileW) versions
    api: CreateFile
    api: GetEnvironmentVariableW  # only matches on Unicode version


### number
A number used by the logic of the program.
This should not be a stack or structure offset.
For example, a crypto constant.

The parameter is a number; if prefixed with `0x` then in hex format, otherwise, decimal format.

If the number is only relevant for a particular architecture, then you can use one of the architecture flavors: `number/x32` or `number/x64`.

To help humans understand the meaning of a number, such that the constant `0x40` means `PAGE_EXECUTE_READWRITE`, you may provide a description alongside the definition.
Use the inline syntax (preferred) by ending the line with ` = DESCRIPTION STRING`.
Check the [description section](#descriptions) for more details.

Examples:

    number: 16
    number: 0x10
    number: 0x40 = PAGE_EXECUTE_READWRITE
    number/x32: 0x20 = number of bits

Note that capa treats all numbers as unsigned values. A negative number is not a valid feature value.
To match a negative number you may specify its two's complement representation. For example, `0xFFFFFFF0` (`-2`) in a 32-bit file.

### string
A string referenced by the logic of the program.
This is probably a pointer to an ASCII or Unicode string.
This could also be an obfuscated string, for example a stack string.

The parameter is a string describing the string.
This can be the verbatim value, or a regex matching the string.
Regexes should be surrounded with `/` characters. 
By default, capa uses case-sensitive matching and assumes leading and trailing wildcards.
To perform case-insensitive matching append an `i`. To anchor the regex at the start or end of a string, use `^` and/or `$`.

To add context to a string, use the two-line syntax `...description: DESCRIPTION STRING` shown below. The inline syntax is not supported here.
See the [description section](#descriptions) for more details.

Examples:

```
- string: Firefox 64.0
- string: This program cannot be run in DOS mode.
  description: MS-DOS stub message
- string: '{3E5FC7F9-9A51-4367-9063-A120244FBEC7}'
  description: CLSID_CMSTPLUA
- string: '/SELECT.*FROM.*WHERE/'
  description: SQL WHERE Clause
- string: /Hardware\\Description\\System\\CentralProcessor/i
```

Note that regex matching is expensive (`O(features)` rather than `O(1)`) so they should be used sparingly.

### bytes
A sequence of bytes referenced by the logic of the program. 
The provided sequence must match from the beginning of the referenced bytes and be no more than `0x100` bytes.
The parameter is a sequence of hexadecimal bytes.
To help humans understand the meaning of the bytes sequence, you may provide a description.
For this use the inline syntax by appending your ` = DESCRIPTION STRING`.
Check the [description section](#descriptions) for more details.

The example below illustrates byte matching given a COM CLSID pushed onto the stack prior to a call to `CoCreateInstance`.

Disassembly:

    push    offset iid_004118d4_IShellLinkA ; riid
    push    1               ; dwClsContext
    push    0               ; pUnkOuter
    push    offset clsid_004118c4_ShellLink ; rclsid
    call    ds:CoCreateInstance

Example rule elements:

    bytes: 01 14 02 00 00 00 00 00 C0 00 00 00 00 00 00 46 = CLSID_ShellLink
    bytes: EE 14 02 00 00 00 00 00 C0 00 00 00 00 00 00 46 = IID_IShellLink

### offset
A structure offset referenced by the logic of the program.
This should not be a stack offset.

The parameter is a number; if prefixed with `0x` then in hex format, otherwise, decimal format. Negative offsets are supported.
An offset can be followed by an optional description.

If the number is only relevant for a particular architecture, then you can use one of the architecture flavors: `number/x32` or `number/x64`.

Examples:

```yaml
offset: 0xC
offset: 0x14 = PEB.BeingDebugged
offset: -0x4
or:
  offset/x32: 0x68 = PEB.NtGlobalFlag
  offset/x64: 0xBC = PEB.NtGlobalFlag
```

### mnemonic

An instruction mnemonic found in the given function.

The parameter is a string containing the mnemonic.

Examples:

    mnemonic: xor
    mnemonic: shl
    
    
### characteristic

Characteristics are features that are extracted by the analysis engine.
They are one-off features that seem interesting to the authors.

For example, the `characteristic: nzxor` feature describes non-zeroing XOR instructions.
capa does not support instruction pattern matching,
 so a select set of interesting instructions are pulled out as characteristics.

| characteristic                             | scope                 | description |
|--------------------------------------------|-----------------------|-------------|
| `characteristic: embedded pe`        | file                  | (XOR encoded) embedded PE files. |
| `characteristic: loop`               | function              | Function contains a loop. |
| `characteristic: recursive call`     | function              | Function is recursive. |
| `characteristic: calls from`         | function              | There are unique calls from this function. Best used like: `count(characteristic(calls from)): 3 or more` |
| `characteristic: calls to`           | function              | There are unique calls to this function. Best used like: `count(characteristic(calls to)): 3 or more` |
| `characteristic: nzxor`              | basic block, function | Non-zeroing XOR instruction |
| `characteristic: peb access`         | basic block, function | Access to the process environment block (PEB), e.g. via fs:[30h], gs:[60h] |
| `characteristic: fs access`          | basic block, function | Access to memory via the `fs` segment. |
| `characteristic: gs access`          | basic block, function | Access to memory via the `gs` segment. |
| `characteristic: cross section flow` | basic block, function | Function contains a call/jump to a different section. This is commonly seen in unpacking stubs. |
| `characteristic: tight loop`         | basic block           | A tight loop where a basic block branches to itself. |
| `characteristic: indirect call`      | basic block, function | Indirect call instruction; for example, `call edx` or `call qword ptr [rsp+78h]`. |

## file features

capa extracts features from the file data.
File features stem from the file structure, i.e. PE structure or the raw file data.
These are the features supported at the file-scope:

  - [string](#file-string)
  - [export](#export)
  - [import](#import)
  - [section](#section)


### file string
An ASCII or UTF-16 LE string present in the file.

The parameter is a string describing the string.
This can be the verbatim value, or a regex matching the string.
Regexes should be surrounded with `/` characters. By default, capa uses case-sensitive matching.
To perform case-insensitive matching append an `i`.

Examples:

    string: Z:\Dev\dropper\dropper.pdb
    string: [ENTER]
    string: /.*VBox.*/
    string: /.*Software\Microsoft\Windows\CurrentVersion\Run.*/i

Note that regex matching is expensive (`O(features)` rather than `O(1)`) so they should be used sparingly.

### export

The name of a routine exported from a shared library.

Examples:

    export: InstallA

### import

The name of a routine imported from a shared library.

Examples:

    import: kernel32.WinExec
    import: WinExec           # wildcard module name
    import: kernel32.#22      # by ordinal

### section

The name of a section in a structured file.

Examples:

    section: .rsrc

## counting

Many rules will inspect the feature set for a select combination of features;
however, some rules may consider the number of times a feature was seen in a feature set.

These rules can be expressed like:

    count(characteristic(nzxor)): 2           # exactly match count==2
    count(characteristic(nzxor)): 2 or more   # at least two matches
    count(characteristic(nzxor)): 2 or fewer  # at most two matches
    count(characteristic(nzxor)): (2, 10)     # match any value in the range 2<=count<=10

    count(mnemonic(mov)): 3
    count(basic blocks): 4

`count` supports inline descriptions, except for [strings](#string), via the following syntax:

    count(number(2 = AF_INET/SOCK_DGRAM)): 2

## matching prior rule matches and namespaces

capa rules can specify logic for matching on other rule matches or namespaces.
This allows a rule author to refactor common capability patterns into their own reusable components.
You can specify a rule match expression like so:

    - and:
      - match: create process
      - match: host-interaction/file-system/write

Rules are uniquely identified by their `rule.meta.name` property;
this is the value that should appear on the right-hand side of the `match` expression.

capa will refuse to run if a rule dependency is not present during matching.
Similarly, you should ensure that you do not introduce circular dependencies among rules that match one another.

Common rule patterns, such as the various ways to implement "writes to a file", can be refactored into "library rules". 
These are rules with `rule.meta.lib: True`.
By default, library rules will not be output to the user as a rule match, 
but can be matched by other rules.
When no active rules depend on a library rule, these the library rules will not be evaluated - maintaining performance.

## descriptions

All features and statements support an optional description which helps with documenting rules and provides context in capa's output.

For all features except for [strings](#string), the description can be specified inline preceded by ` = `: ` = DESCRIPTION STRING`.
For example:

```
- number: 0x4550 = IMAGE_DOS_SIGNATURE (MZ)
```

The inline syntax is preferred.
For [strings](#string) or if the description is long or contains newlines, use the two-line syntax.
It uses the `description` tag in the following way: `description: DESCRIPTION STRING`.

For [statements](#features-block) you can add *one* nested description entry to the statement.

For example:

```
- or:
  - string: This program cannot be run in DOS mode.
    description: MS-DOS stub message
  - number: 0x4550
    description: IMAGE_DOS_SIGNATURE (MZ)
  - and:
    - description: documentation of this `and` statement
    - offset: 0x50 = IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage
    - offset: 0x34 = IMAGE_NT_HEADERS.OptionalHeader.ImageBase
  - and:
    - offset: 0x50 = IMAGE_NT_HEADERS64.OptionalHeader.SizeOfImage
    - offset: 0x30 = IMAGE_NT_HEADERS64.OptionalHeader.ImageBase
```
