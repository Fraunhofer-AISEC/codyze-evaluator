# Concepts and Operations

Concepts and operations serve as a representation of program semantics.
Operations are used to model a certain behavior of the program whereas concepts represent a high-level abstraction of some program behavior, arguments or anything else.
They mainly serve to simplify writing queries and to provide a more semantic view of the program.
Thus, they serve as a main entry-point for an analyst writing custom queries.
This document aims to provide a list of all concepts and operations that are available in the OpenStack Checker.

# Concepts

## EntryPoint
### Constructor: EntryPoint
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.declarations.FunctionDeclaration`

### Properties:

* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## DynamicLoading
### Constructor: DynamicLoading
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node`

### Properties:

* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## Memory
### Constructor: Memory
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node`
* `mode: de.fraunhofer.aisec.cpg.graph.concepts.memory.MemoryManagementMode`

### Properties:

* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## ConfigurationGroup
### Constructor: ConfigurationGroup
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node`
* `conf: de.fraunhofer.aisec.cpg.graph.concepts.config.Configuration`

### Properties:

* `conf: de.fraunhofer.aisec.cpg.graph.concepts.config.Configuration`
* `options: kotlin.collections.MutableList<de.fraunhofer.aisec.cpg.graph.concepts.config.ConfigurationOption>`
* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## Secret
### Constructor: Secret
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node`

### Properties:

* `keySize: kotlin.Int?`
* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## BlockStorage
### Constructor: BlockStorage
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node`

### Properties:

* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## OperatingSystemArchitecture
### Constructor: OperatingSystemArchitecture
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node`

### Properties:

* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## ConfigurationSource
### Constructor: ConfigurationSource
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node`

### Properties:

* `allOps: kotlin.collections.Set<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`
* `groups: kotlin.collections.MutableList<de.fraunhofer.aisec.cpg.graph.concepts.config.ConfigurationGroupSource>`
* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## ConfigurationOptionSource
### Constructor: ConfigurationOptionSource
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node`
* `group: de.fraunhofer.aisec.cpg.graph.concepts.config.ConfigurationGroupSource`

### Properties:

* `group: de.fraunhofer.aisec.cpg.graph.concepts.config.ConfigurationGroupSource`
* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## File
### Constructor: File
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node`
* `fileName: kotlin.String`

### Properties:

* `fileName: kotlin.String`
* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## Authentication
### Constructor: Authentication
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node`

### Properties:

* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## ConfigurationGroupSource
### Constructor: ConfigurationGroupSource
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node`

### Properties:

* `options: kotlin.collections.MutableList<de.fraunhofer.aisec.cpg.graph.concepts.config.ConfigurationOptionSource>`
* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## Configuration
### Constructor: Configuration
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node`

### Properties:

* `allOps: kotlin.collections.Set<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`
* `groups: kotlin.collections.MutableList<de.fraunhofer.aisec.cpg.graph.concepts.config.ConfigurationGroup>`
* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## HttpRequestHandler
### Constructor: HttpRequestHandler
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node`
* `basePath: kotlin.String`
* `endpoints: kotlin.collections.MutableList<de.fraunhofer.aisec.cpg.graph.concepts.http.HttpEndpoint>`

### Properties:

* `basePath: kotlin.String`
* `endpoints: kotlin.collections.MutableList<de.fraunhofer.aisec.cpg.graph.concepts.http.HttpEndpoint>`
* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## HttpClient
### Constructor: HttpClient
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node`
* `isTLS: kotlin.Boolean?` (optional)
* `authentication: de.fraunhofer.aisec.cpg.graph.concepts.auth.Authentication?` (optional)

### Properties:

* `authentication: de.fraunhofer.aisec.cpg.graph.concepts.auth.Authentication?`
* `isTLS: kotlin.Boolean?`
* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## ConfigurationOption
### Constructor: ConfigurationOption
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node`
* `group: de.fraunhofer.aisec.cpg.graph.concepts.config.ConfigurationGroup`
* `key: de.fraunhofer.aisec.cpg.graph.Node`
* `value: de.fraunhofer.aisec.cpg.graph.Node?` (optional)

### Properties:

* `group: de.fraunhofer.aisec.cpg.graph.concepts.config.ConfigurationGroup`
* `key: de.fraunhofer.aisec.cpg.graph.Node`
* `value: de.fraunhofer.aisec.cpg.graph.Node?`
* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## Cipher
### Constructor: Cipher
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node`

### Properties:

* `blockSize: kotlin.Int?`
* `cipherName: kotlin.String?`
* `keySize: kotlin.Int?`
* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## DiskEncryption
### Constructor: DiskEncryption
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node`

### Properties:

* `cipher: de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.Cipher?`
* `key: de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.Secret?`
* `target: de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.BlockStorage?`
* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## Log
### Constructor: Log
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node`

### Properties:

* `logName: kotlin.String?`
* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## LocalEntryPoint
### Constructor: LocalEntryPoint
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.declarations.FunctionDeclaration`
* `os: de.fraunhofer.aisec.cpg.graph.concepts.arch.OperatingSystemArchitecture`

### Properties:

* `os: de.fraunhofer.aisec.cpg.graph.concepts.arch.OperatingSystemArchitecture`
* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## RemoteEntryPoint
### Constructor: RemoteEntryPoint
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.declarations.FunctionDeclaration`

### Properties:

* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## POSIX
### Constructor: POSIX
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node`

### Properties:

* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## Agnostic
### Constructor: Agnostic
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node`

### Properties:

* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## Win32
### Constructor: Win32
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node`

### Properties:

* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## TokenBasedAuth
### Constructor: TokenBasedAuth
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node`
* `token: de.fraunhofer.aisec.cpg.graph.Node`

### Properties:

* `token: de.fraunhofer.aisec.cpg.graph.Node`
* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## LibraryEntryPoint
### Constructor: LibraryEntryPoint
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.declarations.FunctionDeclaration`
* `os: de.fraunhofer.aisec.cpg.graph.concepts.arch.OperatingSystemArchitecture`

### Properties:

* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`
* `os: de.fraunhofer.aisec.cpg.graph.concepts.arch.OperatingSystemArchitecture`

## PythonEntryPoint
### Constructor: PythonEntryPoint
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.declarations.FunctionDeclaration`
* `group: kotlin.String`
* `objectReference: kotlin.String`

### Properties:

* `group: kotlin.String`
* `objectReference: kotlin.String`
* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`
* `os: de.fraunhofer.aisec.cpg.graph.concepts.arch.OperatingSystemArchitecture`

## Main
### Constructor: Main
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.declarations.FunctionDeclaration`
* `os: de.fraunhofer.aisec.cpg.graph.concepts.arch.OperatingSystemArchitecture`

### Properties:

* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`
* `os: de.fraunhofer.aisec.cpg.graph.concepts.arch.OperatingSystemArchitecture`

## HttpEndpoint
### Constructor: HttpEndpoint
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.declarations.FunctionDeclaration`
* `httpMethod: de.fraunhofer.aisec.cpg.graph.concepts.http.HttpMethod`
* `path: kotlin.String`
* `arguments: kotlin.collections.List<de.fraunhofer.aisec.cpg.graph.Node>`
* `authentication: de.fraunhofer.aisec.cpg.graph.concepts.auth.Authentication?`

### Properties:

* `arguments: kotlin.collections.List<de.fraunhofer.aisec.cpg.graph.Node>`
* `authentication: de.fraunhofer.aisec.cpg.graph.concepts.auth.Authentication?`
* `httpMethod: de.fraunhofer.aisec.cpg.graph.concepts.http.HttpMethod`
* `path: kotlin.String`
* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## Darwin
### Constructor: Darwin
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node`

### Properties:

* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## JwtAuth
### Constructor: JwtAuth
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node`
* `jwt: de.fraunhofer.aisec.cpg.graph.Node`
* `payload: de.fraunhofer.aisec.cpg.graph.Node`

### Properties:

* `jwt: de.fraunhofer.aisec.cpg.graph.Node`
* `payload: de.fraunhofer.aisec.cpg.graph.Node`
* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`
* `token: de.fraunhofer.aisec.cpg.graph.Node`

# Operations

## EntryPoint
### Constructor: EntryPoint
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.declarations.FunctionDeclaration`

### Properties:

* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## DynamicLoading
### Constructor: DynamicLoading
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node`

### Properties:

* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## Memory
### Constructor: Memory
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node`
* `mode: de.fraunhofer.aisec.cpg.graph.concepts.memory.MemoryManagementMode`

### Properties:

* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## ConfigurationGroup
### Constructor: ConfigurationGroup
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node`
* `conf: de.fraunhofer.aisec.cpg.graph.concepts.config.Configuration`

### Properties:

* `conf: de.fraunhofer.aisec.cpg.graph.concepts.config.Configuration`
* `options: kotlin.collections.MutableList<de.fraunhofer.aisec.cpg.graph.concepts.config.ConfigurationOption>`
* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## Secret
### Constructor: Secret
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node`

### Properties:

* `keySize: kotlin.Int?`
* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## BlockStorage
### Constructor: BlockStorage
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node`

### Properties:

* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## OperatingSystemArchitecture
### Constructor: OperatingSystemArchitecture
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node`

### Properties:

* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## ConfigurationSource
### Constructor: ConfigurationSource
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node`

### Properties:

* `allOps: kotlin.collections.Set<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`
* `groups: kotlin.collections.MutableList<de.fraunhofer.aisec.cpg.graph.concepts.config.ConfigurationGroupSource>`
* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## ConfigurationOptionSource
### Constructor: ConfigurationOptionSource
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node`
* `group: de.fraunhofer.aisec.cpg.graph.concepts.config.ConfigurationGroupSource`

### Properties:

* `group: de.fraunhofer.aisec.cpg.graph.concepts.config.ConfigurationGroupSource`
* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## File
### Constructor: File
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node`
* `fileName: kotlin.String`

### Properties:

* `fileName: kotlin.String`
* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## Authentication
### Constructor: Authentication
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node`

### Properties:

* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## ConfigurationGroupSource
### Constructor: ConfigurationGroupSource
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node`

### Properties:

* `options: kotlin.collections.MutableList<de.fraunhofer.aisec.cpg.graph.concepts.config.ConfigurationOptionSource>`
* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## Configuration
### Constructor: Configuration
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node`

### Properties:

* `allOps: kotlin.collections.Set<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`
* `groups: kotlin.collections.MutableList<de.fraunhofer.aisec.cpg.graph.concepts.config.ConfigurationGroup>`
* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## HttpRequestHandler
### Constructor: HttpRequestHandler
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node`
* `basePath: kotlin.String`
* `endpoints: kotlin.collections.MutableList<de.fraunhofer.aisec.cpg.graph.concepts.http.HttpEndpoint>`

### Properties:

* `basePath: kotlin.String`
* `endpoints: kotlin.collections.MutableList<de.fraunhofer.aisec.cpg.graph.concepts.http.HttpEndpoint>`
* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## HttpClient
### Constructor: HttpClient
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node`
* `isTLS: kotlin.Boolean?` (optional)
* `authentication: de.fraunhofer.aisec.cpg.graph.concepts.auth.Authentication?` (optional)

### Properties:

* `authentication: de.fraunhofer.aisec.cpg.graph.concepts.auth.Authentication?`
* `isTLS: kotlin.Boolean?`
* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## ConfigurationOption
### Constructor: ConfigurationOption
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node`
* `group: de.fraunhofer.aisec.cpg.graph.concepts.config.ConfigurationGroup`
* `key: de.fraunhofer.aisec.cpg.graph.Node`
* `value: de.fraunhofer.aisec.cpg.graph.Node?` (optional)

### Properties:

* `group: de.fraunhofer.aisec.cpg.graph.concepts.config.ConfigurationGroup`
* `key: de.fraunhofer.aisec.cpg.graph.Node`
* `value: de.fraunhofer.aisec.cpg.graph.Node?`
* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## Cipher
### Constructor: Cipher
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node`

### Properties:

* `blockSize: kotlin.Int?`
* `cipherName: kotlin.String?`
* `keySize: kotlin.Int?`
* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## DiskEncryption
### Constructor: DiskEncryption
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node`

### Properties:

* `cipher: de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.Cipher?`
* `key: de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.Secret?`
* `target: de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.BlockStorage?`
* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## Log
### Constructor: Log
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node`

### Properties:

* `logName: kotlin.String?`
* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## LocalEntryPoint
### Constructor: LocalEntryPoint
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.declarations.FunctionDeclaration`
* `os: de.fraunhofer.aisec.cpg.graph.concepts.arch.OperatingSystemArchitecture`

### Properties:

* `os: de.fraunhofer.aisec.cpg.graph.concepts.arch.OperatingSystemArchitecture`
* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## RemoteEntryPoint
### Constructor: RemoteEntryPoint
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.declarations.FunctionDeclaration`

### Properties:

* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## POSIX
### Constructor: POSIX
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node`

### Properties:

* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## Agnostic
### Constructor: Agnostic
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node`

### Properties:

* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## Win32
### Constructor: Win32
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node`

### Properties:

* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## TokenBasedAuth
### Constructor: TokenBasedAuth
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node`
* `token: de.fraunhofer.aisec.cpg.graph.Node`

### Properties:

* `token: de.fraunhofer.aisec.cpg.graph.Node`
* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## LibraryEntryPoint
### Constructor: LibraryEntryPoint
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.declarations.FunctionDeclaration`
* `os: de.fraunhofer.aisec.cpg.graph.concepts.arch.OperatingSystemArchitecture`

### Properties:

* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`
* `os: de.fraunhofer.aisec.cpg.graph.concepts.arch.OperatingSystemArchitecture`

## PythonEntryPoint
### Constructor: PythonEntryPoint
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.declarations.FunctionDeclaration`
* `group: kotlin.String`
* `objectReference: kotlin.String`

### Properties:

* `group: kotlin.String`
* `objectReference: kotlin.String`
* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`
* `os: de.fraunhofer.aisec.cpg.graph.concepts.arch.OperatingSystemArchitecture`

## Main
### Constructor: Main
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.declarations.FunctionDeclaration`
* `os: de.fraunhofer.aisec.cpg.graph.concepts.arch.OperatingSystemArchitecture`

### Properties:

* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`
* `os: de.fraunhofer.aisec.cpg.graph.concepts.arch.OperatingSystemArchitecture`

## HttpEndpoint
### Constructor: HttpEndpoint
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.declarations.FunctionDeclaration`
* `httpMethod: de.fraunhofer.aisec.cpg.graph.concepts.http.HttpMethod`
* `path: kotlin.String`
* `arguments: kotlin.collections.List<de.fraunhofer.aisec.cpg.graph.Node>`
* `authentication: de.fraunhofer.aisec.cpg.graph.concepts.auth.Authentication?`

### Properties:

* `arguments: kotlin.collections.List<de.fraunhofer.aisec.cpg.graph.Node>`
* `authentication: de.fraunhofer.aisec.cpg.graph.concepts.auth.Authentication?`
* `httpMethod: de.fraunhofer.aisec.cpg.graph.concepts.http.HttpMethod`
* `path: kotlin.String`
* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## Darwin
### Constructor: Darwin
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node`

### Properties:

* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## JwtAuth
### Constructor: JwtAuth
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node`
* `jwt: de.fraunhofer.aisec.cpg.graph.Node`
* `payload: de.fraunhofer.aisec.cpg.graph.Node`

### Properties:

* `jwt: de.fraunhofer.aisec.cpg.graph.Node`
* `payload: de.fraunhofer.aisec.cpg.graph.Node`
* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`
* `token: de.fraunhofer.aisec.cpg.graph.Node`