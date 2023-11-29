# rule format

capa uses a collection of rules to identify capabilities within a program.
These rules are easy to write, even for those new to reverse engineering.
By authoring rules, you can extend the capabilities that capa recognizes.
In some regards, capa rules are a mixture of the OpenIOC, Yara, and YAML formats.

Here's an example rule used by capa:

```yaml
rule:
  meta:
    name: create TCP socket
    namespace: communication/socket/tcp
    authors:
      - william.ballenthin@mandiant.com
      - joakim@intezer.com
      - anushka.virgaonkar@mandiant.com
    scopes:
      static: basic block
      dynamic: call
    mbc:
      - Communication::Socket Communication::Create TCP Socket [C0001.011]
    examples:
      - Practical Malware Analysis Lab 01-01.dll_:0x10001010
  features:
    - or:
      - and:
        - number: 6 = IPPROTO_TCP
        - number: 1 = SOCK_STREAM
        - number: 2 = AF_INET
        - or:
          - api: ws2_32.socket
          - api: ws2_32.WSASocket
          - api: socket
      - property/read: System.Net.Sockets.TcpClient::Client
```

This document defines the available structures and features that you can use as you write capa rules.
We'll start at the high level structure and then dig into the logic structures and features that capa supports.

### table of contents 
- [rule format](#rule-format)
  - [yaml](#yaml)
  - [meta block](#meta-block)
    - [rule name](#rule-name)
    - [rule namespace](#rule-namespace)
    - [analysis flavors](#analysis-flavors)
  - [features block](#features-block)
- [extracted features](#extracted-features)
  - [static analysis scopes](#static-analysis-scopes)
    - [instruction features](#instruction-features)
    - [basic block features](#basic-block-features)
    - [function features](#function-features)
  - [dynamic analysis scopes](#dynamic-analysis-scopes)
    - [call features](#call-features)
    - [thread features](#thread-features)
    - [process features](#process-features)
  - [common scopes](#common-scopes)
    - [file features](#file-features)
    - [global features](#global-features)
  - [complete feature listing](#complete-feature-listing)
    - [characteristic](#characteristic)
    - [namespace](#namespace)
    - [class](#class)
    - [api](#api)
    - [property](#property)
    - [number](#number)
    - [string and substring](#string-and-substring)
    - [bytes](#bytes)
    - [offset](#offset)
    - [mnemonic](#mnemonic)
    - [operand](#operand)
    - [string and substring](#file-string-and-substring)
    - [export](#export)
    - [import](#import)
    - [section](#section)
    - [function-name](#function-name)
    - [namespace](#namespace)
    - [class](#class)
    - [os](#os)
    - [arch](#arch)
    - [format](#format)
  - [counting](#counting)
  - [matching prior rule matches and namespaces](#matching-prior-rule-matches-and-namespaces)
  - [descriptions](#descriptions)
  - [comments](#comments)

## yaml

Rules are YAML files that follow a certain schema.
You should be able to use any YAML editor/syntax highlighting to assist you.

Once you have a draft rule, you can use the [linter](https://github.com/mandiant/capa/blob/master/scripts/lint.py) 
 to check that your rule adheres to best practices.
Then, you should use the [formatter](https://github.com/mandiant/capa/blob/master/scripts/capafmt.py)
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
  authors:
    - william.ballenthin@mandiant.com
  description: the sample appears to be packed with UPX
  scopes: 
    static: file
    dynamic: file
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

  - `authors` is a list of names or handles of the rule authors.
  
  - `description` is optional text that describes the intent or interpretation of the rule.

  - `scopes` indicates which feature set the rule applies to, when analyzing static or dynamic analysis artifacts. There are two required sub fields: `static` and `dynamic`. Here are the legal values:
    - `scopes.static`:
      - **`instruction`**: matches features found at a single instruction.
        This is great to identify structure access or comparisons against magic constants.
      - **`basic block`**: matches features within each basic block.
        This is used to achieve close locality in rules (for example for parameters of a function).
      - **`function`**: match features within each function.
      - **`file`**: matches features across the whole file.
    - `scopes.dynamic`:
      - **`call`**: match features at each traced API call site, such as API name and argument values.
      - **`thread`**: match features within each thread, such as sequence of API names.
      - **`process`**: match features within each process.
      - **`file`**: matches features across the whole file, including from the executable file features *and* across the entire runtime trace.
      
  - `att&ck` is an optional list of [ATT&CK framework](https://attack.mitre.org/) techniques that the rule implies, like 
`Discovery::Query Registry [T1012]` or `Persistence::Create or Modify System Process::Windows Service [T1543.003]`.
These tags are used to derive the ATT&CK mapping for the sample when the report gets rendered.

  - `mbc` is an optional list of [Malware Behavior Catalog](https://github.com/MBCProject/mbc-markdown) techniques that the rule implies,
like the ATT&CK list.

  - `maec/malware-category` is required when the rule describes a role, such as `dropper` or `backdoor`.

  - `maec/malware-family` is required when the rule describes a malware family, such as `PlugX` or `Beacon`.
  
  - `maec/analysis-conclusion` is required when the rule describes a disposition, such as `benign` or `malicious`.

  - `examples` is a *required* list of references to samples that the rule should match.
The linter verifies that each rule correctly fires on each sample referenced in a rule's `examples` list.
These example files are stored in the [github.com/mandiant/capa-testfiles](https://github.com/mandiant/capa-testfiles) repository.
`function` and `basic block` scope rules must contain offsets to the respective match locations using the format `<sample name>:<function or basic block offset>`.

  - `references` A list of related information found in a book, article, blog post, etc.

Other fields are not allowed, and the linter will complain about them.

### rule name

The `rule.meta.name` uniquely identifies a rule.
It can be referenced in other rules, so if you change a rule name, be sure to search for cross references.

By convention, the rule name should complete one of the following sentences:
  - "The program/function may..."
  - "The program was..."

To focus rule names we try to omit articles (the/a/an).
For example, prefer `make HTTP request` over `make an HTTP request`.

When the rule describes a specific means to implement a technique, this is typically specified by "via XYZ".
For example, `make HTTP request via WinInet` or `make HTTP request via libcurl`.

When the rule describes a specific programming language or run time, this is typically specified by "in ABC".
  
Therefore, these are good rule names:
  - (The function may) "**make HTTP request via WinInet**"
  - (The function may) "**encrypt data using RC4 via WinCrypt**"
  - (The program was)  "**compiled by MSVC**"
  - (The program may)  "**capture screenshot in Go**"
  
...and, these are bad rule names:
  - "UPX"
  - "encryption with OpenSSL"

### rule namespace

The rule namespace helps us group related rules together.
You'll notice that the file system layout of the rule files matches the namespaces that they contain.
Furthermore, output from capa is ordered by namespace, so all `communication` matches render next to one another.

Namespaces are hierarchical, so the children of a namespace encodes its specific techniques.
In a few words each, the top level namespaces are:

  - [anti-analysis](https://github.com/mandiant/capa-rules/tree/master/anti-analysis/) - packing, obfuscation, anti-X, etc.
  - [collection](https://github.com/mandiant/capa-rules/tree/master/collection/) - data that may be enumerated and collected for exfiltration
  - [communication](https://github.com/mandiant/capa-rules/tree/master/communication/) - HTTP, TCP, command and control (C2) traffic, etc.
  - [compiler](https://github.com/mandiant/capa-rules/tree/master/compiler/) - detection of build environments, such as MSVC, Delphi, or AutoIT
  - [data-manipulation](https://github.com/mandiant/capa-rules/tree/master/data-manipulation/) - encryption, hashing, etc.
  - [executable](https://github.com/mandiant/capa-rules/tree/master/executable/) - characteristics of the executable, such as PE sections or debug info
  - [host-interaction](https://github.com/mandiant/capa-rules/tree/master/host-interaction/) - access or manipulation of system resources, like processes or the Registry
  - [impact](https://github.com/mandiant/capa-rules/tree/master/impact/) - end goal
  - [internal](https://github.com/mandiant/capa-rules/tree/master/internal/) - used internally by capa to guide analysis
  - [lib](https://github.com/mandiant/capa-rules/tree/master/lib/) - building blocks to create other rules
  - [linking](https://github.com/mandiant/capa-rules/tree/master/linking/) - detection of dependencies, such as OpenSSL or Zlib
  - [load-code](https://github.com/mandiant/capa-rules/tree/master/load-code/) - runtime load and execution of code, such as embedded PE or shellcode
  - [malware-family](https://github.com/mandiant/capa-rules/tree/master/malware-family/) - detection of malware families
  - [nursery](https://github.com/mandiant/capa-rules/tree/master/nursery/) - staging ground for rules that are not quite polished
  - [persistence](https://github.com/mandiant/capa-rules/tree/master/persistence/) - all sorts of ways to maintain access
  - [runtime](https://github.com/mandiant/capa-rules/tree/master/runtime/) - detection of language runtimes, such as the .NET platform or Go
  - [targeting](https://github.com/mandiant/capa-rules/tree/master/targeting/) - special handling of systems, such as ATM machines
  
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

### analysis flavors

capa analyzes capabilities found in both executable files and in API traces captured by sandboxes, such as CAPE.
We call these categories of analysis "flavors" and use "static analysis flavor" and "dynamic analysis flavor" to refer to them, respectively. Static analysis is great for reviewing the entire logic of a program and finding the interesting regions. Dynamic analysis via sandboxes helps bypass packing, which is very widespread in malware, and can better describe the actual runtime behavior of a program. We use the `meta.scopes.$flavor` key to specify how a rule interacts with a particular flavor.

When possible, we try to write capa rules that work in both static and dynamic analysis flavors.
For example, here's a rule that matches in both flavors:

```yml
rule:
  meta:
    name: create mutex
    namespace: host-interaction/mutex
    authors:
      - moritz.raabe@mandiant.com
      - michael.hunhoff@mandiant.com
    scopes:
      static: function
      dynamic: call
  features:
    - or:
      - api: kernel32.CreateMutex
      - api: kernel32.CreateMutexEx
      - api: System.Threading.Mutex::ctor
```

See how `create mutex` can be reasoned about both by inspecting the disassembly features (static analysis) as well as the runtime API trace (dynamic analysis)?

On the other hand, some behaviors are best described by rules that work in only one scope. 
Remember, its paramount that rules be human-readable, so avoid complicating logic for the sake of merging rules.
In this case, mark the excluded scope with `unsupported`, like in the following rule:

```yml
rule:
  meta:
    name: check for software breakpoints
    namespace: anti-analysis/anti-debugging/debugger-detection
    authors:
      - michael.hunhoff@mandiant.com
    scopes:
      static: function
      dynamic: unsupported  # requires mnemonic features
  features:
    - and:
      - or:
        - instruction:
          - mnemonic: cmp
          - number: 0xCC = INT3
      - match: contain loop
```

`check for software breakpoints` works great during disassembly analysis, where low-level instruction features can be matched, but doesn't work in dynamic scopes because these features aren't available. Hence, we mark the rule `scopes.dynamic: unsupported` so the rule won't be considered when processing sandbox traces.

As you'll see in the [extracted features](#extracted-features) section, capa matches features at various scopes, starting small (e.g., `instruction`) and growing large (e.g., `file`). In static analysis, scopes grow from `instruction`, to `basic block`, `function`, and then `file`. In dynamic analysis, scopes grow from `call`, to `thread`, `process`, and then to `file`.

When matching a sequence of API calls, the static scope is often `function` and the dynamic scope is `thread`. When matching a single API call with arguments, the static scope is usually `basic block` and the dynamic scope is `call`. One day we hope to support `call` scope directly in the static analysis flavor.


## features block

This section declares logical statements about the features that must exist for the rule to match.

There are five structural expressions that may be nested:
  - `and` - all of the children expressions must match
  - `or` - match at least one of the children
  - `not` - match when the child expression does not
  - `N or more` - match at least `N` or more of the children
    - `optional` is an alias for `0 or more`, which is useful for documenting related features. See [write-file.yml](/host-interaction/file-system/write/write-file.yml) for an example.

To add context to a statement, you can add *one* nested description entry in the form `- description: DESCRIPTION STRING`.
Check the [description section](#descriptions) for more details.

For example, consider the following rule:

```yaml
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

capa matches features at multiple scopes, starting small (e.g., `instruction`) and growing large (e.g., `file`). In static analysis, scopes grow from `instruction`, to `basic block`, `function`, and then `file`. In dynamic analysis, scopes grow from `call`, to `thread`, `process`, and then to `file`:

| static scope | best for...                                                                              |
|--------------|------------------------------------------------------------------------------------------|
| instruction  | specific combinations of mnemonics, operands, constants, etc. to find magic values       |
| basic block  | closely related instructions, such as structure access or function call arguments        |
| function     | collections of API calls, constants, etc. that suggest complete capabilities             |
| file         | high level conclusions, like encryptor, backdoor, or statically linked with some library |
| global       | the features available at every scope, like architecture or OS                           |

| dynamic scope | best for...                                                                              |
|---------------|------------------------------------------------------------------------------------------|
| call          | single API call and its arguments                                                        |
| thread        | sequence of related API calls                                                            |
| process       | combinations of other capabilities found within a (potentially multi-threaded) program   |
| file          | high level conclusions, like encryptor, backdoor, or statically linked with some library |
| global        | the features available at every scope, like architecture or OS                           |

In general, capa collects and merges the features from lower scopes into higher scopes;
for example, features extracted from individual instructions are merged into the function scope that contains the instructions.
This way, you can use the match results against instructions ("the constant X is for crypto algorithm Y") to recognize function-level capabilities ("crypto function Z").

| feature                           | static scope                                | dynamic scope                  |
|-----------------------------------|---------------------------------------------|--------------------------------|
| [api](#api)                       | instruction ↦ basic block ↦ function ↦ file | call ↦ thread ↦ process ↦ file |
| [string](#string-and-substring)   | instruction ↦ ...                           | call ↦ ...                     |
| [bytes](#bytes)                   | instruction ↦ ...                           | call ↦ ...                     |
| [number](#number)                 | instruction ↦ ...                           | call ↦ ...                     |
| [characteristic](#characteristic) | instruction ↦ ...                           | -                              |
| [mnemonic](#mnemonic)             | instruction ↦ ...                           | -                              |
| [operand](#operand)               | instruction ↦ ...                           | -                              |
| [offset](#offset)                 | instruction ↦ ...                           | -                              |
| [com](#com)                       | instruction ↦ ...                           | -                              |
| [namespace](#namespace)           | instruction ↦ ...                           | -                              |
| [class](#class)                   | instruction ↦ ...                           | -                              |
| [property](#property)             | instruction ↦ ...                           | -                              |
| [export](#export)                 | file                                        | file                           |
| [import](#import)                 | file                                        | file                           |
| [section](#section)               | file                                        | file                           |
| [function-name](#function-name)   | file                                        | -                              |
| [os](#os)                         | global                                      | global                         |
| [arch](#arch)                     | global                                      | global                         |
| [format](#format)                 | global                                      | global                         |

## static analysis scopes

### instruction features

Instruction features stem from individual instructions, such as mnemonics, string references, or function calls.
The following features are relevant at this scope and above:

  - [namespace](#namespace)
  - [class](#class)
  - [api](#api)
  - [property](#property)
  - [number](#number)
  - [string and substring](#string-and-substring)
  - [bytes](#bytes)
  - [com](#com)
  - [offset](#offset)
  - [mnemonic](#mnemonic)
  - [operand](#operand)

Also, the following [characteristics](#characteristic) are relevant at this scope and above:
  - `nzxor`
  - `peb access`
  - `fs access`
  - `gs access`
  - `cross section flow`
  - `indirect call`
  - `call $+5`
  - `unmanaged call`

### basic block features

Basic block features stem from combinations of features from the instruction scope that are found within the same basic block.

Also, the following [characteristics](#characteristic) are relevant at this scope and above:
  - `tight loop`
  - `stack string`

### function features

Function features stem from combinations of features from the instruction and basic block scopes that are found within the same function.

Also, the following [characteristics](#characteristic) are relevant at this scope and above:
  - `loop`
  - `recursive call`
  - `calls from`
  - `calls to`

## dynamic analysis scopes

### call features

Call features are collected from individual sandbox trace events, such as API calls.
They're typically useful for matching against the API name and arguments (strings or integer constants).

The following features are relevant at this scope and above:

  - [api](#api)
  - [number](#number)
  - [string and substring](#string-and-substring)
  - [bytes](#bytes)

### thread features

Thread features stem from combinations of features from the call scopes that are found within the same thread.
This is useful for matching a sequence of API calls, such as `OpenFile`/`ReadFile`/`CloseFile`.

There are no thread-specific features.

### process features

Process features are combinations of features from the thread scopes found within the same process.
This is useful for matching behaviors found across an entire program, even if its multi-threaded.

There are no process-specific features.

## common scopes

### file features

File features stem from the file structure, i.e. PE structure or the raw file data.

Also, all features found in all functions (static) or all processes (dynamic) are collected into the file scope.

The following features are supported at this scope:

  - [string and substring](#file-string-and-substring)
  - [export](#export)
  - [import](#import)
  - [section](#section)
  - [function-name](#function-name)
  - [namespace](#namespace)
  - [class](#class)

### global features

Global features are extracted at all scopes.
These are features that may be useful to both disassembly and file structure interpretation, such as the targeted OS or architecture.
The following features are supported at this scope:

  - [os](#os)
  - [arch](#arch)
  - [format](#format)

## complete feature listing

### characteristic

Characteristics are features that are extracted by the analysis engine.
They are one-off features that seem interesting to the authors.

For example, the `characteristic: nzxor` feature describes non-zeroing XOR instructions.

| characteristic                       | scope                              | description                                                                                               |
|--------------------------------------|------------------------------------|-----------------------------------------------------------------------------------------------------------|
| `characteristic: embedded pe`        | file                               | (XOR encoded) embedded PE files.                                                                          |
| `characteristic: forwarded export`   | file                               | PE file has a forwarded export.                                                                           |
| `characteristic: mixed mode`         | file                               | File contains both managed and unmanaged (native) code, often seen in .NET                                |
| `characteristic: loop`               | function                           | Function contains a loop.                                                                                 |
| `characteristic: recursive call`     | function                           | Function is recursive.                                                                                    |
| `characteristic: calls from`         | function                           | There are unique calls from this function. Best used like: `count(characteristic(calls from)): 3 or more` |
| `characteristic: calls to`           | function                           | There are unique calls to this function. Best used like: `count(characteristic(calls to)): 3 or more`     |
| `characteristic: tight loop`         | basic block, function              | A tight loop where a basic block branches to itself.                                                      |
| `characteristic: stack string`       | basic block, function              | There is a sequence of instructions that looks like stack string construction.                            |
| `characteristic: nzxor`              | instruction, basic block, function | Non-zeroing XOR instruction                                                                               |
| `characteristic: peb access`         | instruction, basic block, function | Access to the process environment block (PEB), e.g. via fs:[30h], gs:[60h]                                |
| `characteristic: fs access`          | instruction, basic block, function | Access to memory via the `fs` segment.                                                                    |
| `characteristic: gs access`          | instruction, basic block, function | Access to memory via the `gs` segment.                                                                    |
| `characteristic: cross section flow` | instruction, basic block, function | Function contains a call/jump to a different section. This is commonly seen in unpacking stubs.           |
| `characteristic: indirect call`      | instruction, basic block, function | Indirect call instruction; for example, `call edx` or `call qword ptr [rsp+78h]`.                         |
| `characteristic: call $+5`           | instruction, basic block, function | Call just past the current instruction.                                                                   |
| `characteristic: unmanaged call`     | instruction, basic block, function | Function contains a call from managed code to unmanaged (native) code, often seen in .NET                 |

### namespace
A named namespace used by the logic of the program.

The parameter is a string describing the namespace name, specified like `namespace` or `namespace.nestednamespace`.

Example:

    namespace: System.IO
    namespace: System.Net

### class
A named class used by the logic of the program. This must include the class's namespace if recoverable.

The parameter is a string describing the class, specified like `namespace.class` or `namespace.nestednamespace.class`.

Example:

    class: System.IO.File
    class: System.Net.WebResponse

Example rule: [create new application domain in .NET](../host-interaction/memory/create-new-application-domain-in-dotnet.yml)


### api
A call to a named function, probably an import,
though possibly a local function (like `malloc`) extracted via function signature matching like FLIRT.

The parameter is a string describing the function name, specified like  `functionname`, `module.functionname`, or `namespace.class::functioname`.

Since version 7 the module (DLL) name is not used during matching so only benefits the documentation.

Windows API functions that take string arguments come in two API versions. For example, `CreateProcessA` takes ANSI strings and `CreateProcessW` takes Unicode strings. capa extracts these API features both with and without the suffix character `A` or `W`. That means you can write a rule to match on both APIs using the base name. If you want to match a specific API version, you can include the suffix.

.NET classes and structures implement constructor (`.ctor`) and static constructor (`.cctor`) methods. capa extracts these constructor methods as `namespace.class::ctor` and `namespace.class::cctor`, respectively.

Example:

    api: kernel32.CreateFile  # the DLL name will be ignored during matching, but is good to include as documentation
    api: CreateFile  # matches both Ansi (CreateFileA) and Unicode (CreateFileW) versions
    api: GetEnvironmentVariableW  # only matches on Unicode version
    api: System.IO.File::Delete
    api: System.Net.WebResponse::GetResponseStream
    api: System.Threading.Mutex::ctor # match creation System.Threading.Mutex object

Example rule: [switch active desktop](../host-interaction/gui/switch-active-desktop.yml)

### property
A member of a class or structure used by the logic of a program. This must include the member's class and namespace if recoverable.

The parameter is a string describing the member, specificed like `namespace.class::member` or `namespace.nestednamespace.class::member`. You may also specify a `/read` accessor, if you intend a match to occur when the referenced property is read, or a `/write` accessor, if you intend a match to occur when the referenced property is written.

Example:

    property/read: System.Environment::OSVersion
    property/write: System.Net.WebRequest::Proxy

Example rule: [enumere GUI resources](../host-interaction/gui/enumerate-gui-resources.yml)

### number
A number used by the logic of the program.
This should not be a stack or structure offset.
For example, a crypto constant.

The parameter is a number; if prefixed with `0x` then in hex format, otherwise, decimal format.

To help humans understand the meaning of a number, such that the constant `0x40` means `PAGE_EXECUTE_READWRITE`, you may provide a description alongside the definition.
Use the inline syntax (preferred) by ending the line with ` = DESCRIPTION STRING`.
Check the [description section](#descriptions) for more details.

Examples:

    number: 16
    number: 0x10
    number: 0x40 = PAGE_EXECUTE_READWRITE

Note that capa treats all numbers as unsigned values. A negative number is not a valid feature value.
To match a negative number you may specify its two's complement representation. For example, `0xFFFFFFF0` (`-2`) in a 32-bit file.

If the number is only relevant on a particular architecture, don't hesitate to use a pattern like:

```yml
- and:
  - arch: i386
  - number: 4 = size of pointer
```

Example rule: [get disk size](../host-interaction/hardware/storage/get-disk-size.yml)

### string and substring
A string referenced by the logic of the program.
This is probably a pointer to an ASCII or Unicode string.
This could also be an obfuscated string, for example a stack string.

The parameter is a string describing the string.
This can be the verbatim value or a regex matching the string.

Verbatim values must be surrounded by double quotes and special characters must be escaped.

A special character is one of:
  - a backslash, which should be represented as `string: "\\"`
  - a newline or other non-space whitespace (e.g. tab, CR, LF, etc), which should be represented like `string: "\n"`
  - a double quote, which should be represented as `string: "\""`

capa only matches on the verbatim string, e.g. `"Mozilla"` does NOT match on `"User-Agent: Mozilla/5.0"`. 
To match verbatim substrings with leading/trailing wildcards, use a substring feature, e.g. `substring: "Mozilla"`.
For more complex patterns, use the regex syntax described below.

Regexes should be surrounded with `/` characters. 
By default, capa uses case-sensitive matching and assumes leading and trailing wildcards.
To perform case-insensitive matching append an `i`. To anchor the regex at the start or end of a string, use `^` and/or `$`.
As an example `/mozilla/i` matches on `"User-Agent: Mozilla/5.0"`.

To add context to a string, use the two-line syntax `...description: DESCRIPTION STRING` shown below. The inline syntax is not supported here.
See the [description section](#descriptions) for more details.

Examples:

```yaml
- string: "Firefox 64.0"
- string: "Hostname:\t\t\t%s\nIP address:\t\t\t%s\nOS version:\t\t\t%s\n"
- string: "This program cannot be run in DOS mode."
  description: MS-DOS stub message
- string: "{3E5FC7F9-9A51-4367-9063-A120244FBEC7}"
  description: CLSID_CMSTPLUA
- string: /SELECT.*FROM.*WHERE/
  description: SQL WHERE Clause
- string: /Hardware\\Description\\System\\CentralProcessor/i
- substring: "CurrentVersion"
```

Note that regex and substring matching is expensive (`O(features)` rather than `O(1)`) so they should be used sparingly.

Example rule: [identify ATM dispenser service provider](../targeting/automated-teller-machine/identify-atm-dispenser-service-provider.yml)

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

Example rule: [hash data using Whirlpool](../nursery/hash-data-using-whirlpool.yml)

### com
COM features represent Component Object Model (COM) interfaces and classes used in the program's logic. They help identify interactions with COM objects, methods, properties, and interfaces. The parameter is the name of the COM class or interface. This feature allows you to list human-readable names instead of the byte representations found in the program.

Examples:

```yaml
- com/class: InternetExplorer  # bytes: 01 DF 02 00 00 00 00 00 C0 00 00 00 00 00 00 46 = CLSID_InternetExplorer
- com/interface: IWebBrowser2  # bytes: 61 16 0C D3 AF CD D0 11 8A 3E 00 C0 4F C9 E2 6E = IID_IWebBrowser2
```

The rule parser translates com features to their `bytes` and `string` representation by fetching the GUIDs from an internal COM database.

Translated representation of the above rule:

```yaml
- or:
  - string : "0002DF01-0000-0000-C000-000000000046"
    description: CLSID_InternetExplorer as GUID string
  - bytes : 01 DF 02 00 00 00 00 00 C0 00 00 00 00 00 00 46 = CLSID_InternetExplorer as bytes
- or:
  - string: "D30C1661-CDAF-11D0-8A3E-00C04FC9E26E"
    description: IID_IWebBrowser2 as GUID string
  - bytes: 61 16 0C D3 AF CD D0 11 8A 3E 00 C0 4F C9 E2 6E = IID_IWebBrowser2 as bytes
```

Note: The automatically added descriptions help to maintain consistency and improve documentation.

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
```

If the offset is only relevant on a particular architecture (such as 32- or 64-bit Intel), don't hesitate to use a pattern like:

```yml
- and:
  - arch: i386
  - offset: 0xC = offset to linked list head
```

### mnemonic

An instruction mnemonic found in the given function.

The parameter is a string containing the mnemonic.

Examples:

    mnemonic: xor
    mnemonic: shl

Example rule: [check for trap flag exception](../anti-analysis/anti-debugging/debugger-detection/check-for-trap-flag-exception.yml)

### operand

Number and offset values for specific operand indices.
Use these features when you want to specify the flow of data from a source/destination, like move from a structure or compare against a constant.

Examples:

    operand[0].number: 0x10
    operand[1].offset: 0x2C

Example rule: [encrypt data using XTEA](../data-manipulation/encryption/xtea/encrypt-data-using-xtea.yml)


### file string and substring
An ASCII or UTF-16 LE string present in the file.

The parameter is a string describing the string.
This can be the verbatim value, a verbatim substring, or a regex matching the string and should use the same formatting used for
[string](#string) features.

Examples:

    string: "Z:\\Dev\\dropper\\dropper.pdb"
    string: "[ENTER]"
    string: /.*VBox.*/
    string: /.*Software\\Microsoft\Windows\\CurrentVersion\\Run.*/i
    substring: "CurrentVersion"

Note that regex and substring matching is expensive (`O(features)` rather than `O(1)`) so they should be used sparingly.

### export

The name of a routine exported from a shared library.

Examples:

    export: InstallA

To specify a [forwarded export](https://devblogs.microsoft.com/oldnewthing/20060719-24/?p=30473) use the format `<DLL path, lowercase>.<symbol name>`. Note that the path can be either implicit, relative, or absolute:

    export: "c:/windows/system32/version.GetFileVersionInfoA"
    export: "vresion.GetFileVersionInfoA"

Example rule: [act as password filter DLL](../persistence/authentication-process/act-as-password-filter-dll.yml)

### import

The name of a routine imported from a shared library. These can include DLL names that are checked during matching.

Examples:

    import: kernel32.WinExec
    import: WinExec           # wildcard module name
    import: kernel32.#22      # by ordinal
    import: System.IO.File::Exists

Example rule: [load NCR ATM library](../targeting/automated-teller-machine/ncr/load-ncr-atm-library.yml)

### function-name

The name of a recognized statically-linked library, such as recovered via FLIRT, or a name extracted from information contained in the file, such as .NET metadata.
This lets you write rules describing functionality from third party libraries, such as "encrypts data with AES via CryptoPP".

Examples:

    function-name: "?FillEncTable@Base@Rijndael@CryptoPP@@KAXXZ"
    function-name: Malware.Backdoor::Beacon

Example rule: [execute via .NET startup hook](../runtime/dotnet/execute-via-dotnet-startup-hook.yml)

### section

The name of a section in a structured file.

Examples:

    section: .rsrc


Example rule: [compiled with DMD](../compiler/d/compiled-with-dmd.yml)

### os

The name of the OS on which the sample runs. This is determined via heuristics applied to the file format (e.g. PE files are for Windows, header fields and notes sections in ELF files indicate Linux/*BSD/etc.).
This lets you group logic that should only be found on some platforms, such as Windows APIs are found only in Windows executables.

Examples:

```yml
- or:
  - and:
    description: Windows-specific APIs
    os: windows
    api: CreateFile

  - and:
    description: POSIX-specific APIs
    or:
      - os: linux
      - os: macos 
      - ...
    api: fopen
```

Valid OSes:
  - `windows`
  - `linux`
  - `macos`
  - `hpux`
  - `netbsd`
  - `hurd`
  - `86open`
  - `solaris`
  - `aix`
  - `irix`
  - `freebsd`
  - `tru64`
  - `modesto`
  - `openbsd`
  - `openvms`
  - `nsk`
  - `aros`
  - `fenixos`
  - `cloud`
  - `syllable`
  - `nacl`

Note: you can match any valid OS by not specifying an `os` feature or by using `any`, e.g. `- os: any`.

Example rule: [discover group policy via gpresult](../collection/group-policy/discover-group-policy-via-gpresult.yml)

### arch

The name of the CPU architecture on which the sample runs.
This lets you group logic that should only be found on some architectures, such as assembly instructions for Intel CPUs.

Valid architectures:
  - `i386` Intel 32-bit
  - `amd64` Intel 64-bit

Note: today capa only explicitly supports Intel architectures (`i386` and `amd64`). 
Therefore, most rules assume Intel instructions and mnemonics.
You don't have to explicitly include this condition in your rules:

```yml
- and:
  - mnem: lea
  - or:
    # this block is not necessary!
    - arch: i386
    - arch: amd64
```

However, this can be useful if you have groups of many architecture-specific offsets, such as:

```yml
- or:
  - and:
    - description: 32-bit structure fields
    - arch: i386
    - offset: 0x12
    - offset: 0x1C
    - offset: 0x20
  - and:
    - description: 64-bit structure fields
    - arch: amd64
    - offset: 0x28
    - offset: 0x30
    - offset: 0x40
```

This can be easier to understand than using many `offset/x32` or `offset/x64` features.

Example rule: [get process heap flags](../host-interaction/process/get-process-heap-flags.yml)

### format

The name of the file format.

Valid formats:
  - `pe`
  - `elf`
  - `dotnet`

Example rule: [access .NET resource](../executable/resource/access-dotnet-resource.yml)

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
```yaml
  - and:
      - match: create process
      - match: host-interaction/file-system/write
```
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

```yaml
- number: 0x5A4D = IMAGE_DOS_SIGNATURE (MZ)
```

The inline syntax is preferred.
For [strings](#string) or if the description is long or contains newlines, use the two-line syntax.
It uses the `description` tag in the following way: `description: DESCRIPTION STRING`.

For [statements](#features-block) you can add *one* nested description entry to the statement.

For example:

```yaml
- or:
  - string: "This program cannot be run in DOS mode."
    description: MS-DOS stub message
  - number: 0x5A4D
    description: IMAGE_DOS_SIGNATURE (MZ)
  - and:
    - description: documentation of this `and` statement
    - offset: 0x50 = IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage
    - offset: 0x34 = IMAGE_NT_HEADERS.OptionalHeader.ImageBase
  - and:
    - offset: 0x50 = IMAGE_NT_HEADERS64.OptionalHeader.SizeOfImage
    - offset: 0x30 = IMAGE_NT_HEADERS64.OptionalHeader.ImageBase
```

## comments

Capa rules support both inline/end-of-line and block comments

For example:

```yaml
features:
    # The constant words spell "expand 32-byte k" in ASCII (i.e. the 4 words are "expa", "nd 3", "2-by", and "te k")
    - or:
      - description: part of key setup
      - string: "expand 32-byte k = sigma"
      - string: "expand 16-byte k = tau"
      - string: "expand 32-byte kexpand 16-byte k"  # if sigma and tau are in contiguous memory, may result in concatenated string
      - and:
        - string: "expa"
        - string: "nd 3"
        - string: "2-by"
        - string: "te k"
      - and:
        - number: 0x61707865 = "apxe"
        - number: 0x3320646E = "3 dn"
        - number: 0x79622D32 = "yb-2"
        - number: 0x6B206574 = "k et"
```      
