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

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.declarations.FunctionDeclaration?`

### Properties:

* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## DynamicLoading
### Constructor: DynamicLoading
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node?` (optional)

### Properties:

* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## Memory
### Constructor: Memory
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node?` (optional)
* `mode: de.fraunhofer.aisec.cpg.graph.concepts.memory.MemoryManagementMode`

### Properties:

* `mode: de.fraunhofer.aisec.cpg.graph.concepts.memory.MemoryManagementMode`
* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## ConfigurationGroup
### Constructor: ConfigurationGroup
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node?` (optional)
* `conf: de.fraunhofer.aisec.cpg.graph.concepts.config.Configuration`

### Properties:

* `conf: de.fraunhofer.aisec.cpg.graph.concepts.config.Configuration`
* `options: kotlin.collections.MutableList<de.fraunhofer.aisec.cpg.graph.concepts.config.ConfigurationOption>`
* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## Secret
### Constructor: Secret
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node?` (optional)

### Properties:

* `keySize: kotlin.Int?`
* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## BlockStorage
### Constructor: BlockStorage
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node?` (optional)

### Properties:

* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## OperatingSystemArchitecture
### Constructor: OperatingSystemArchitecture
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node?`

### Properties:

* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## ConfigurationSource
### Constructor: ConfigurationSource
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node?` (optional)

### Properties:

* `allOps: kotlin.collections.Set<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`
* `groups: kotlin.collections.MutableList<de.fraunhofer.aisec.cpg.graph.concepts.config.ConfigurationGroupSource>`
* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## ConfigurationOptionSource
### Constructor: ConfigurationOptionSource
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node?` (optional)
* `group: de.fraunhofer.aisec.cpg.graph.concepts.config.ConfigurationGroupSource`

### Properties:

* `group: de.fraunhofer.aisec.cpg.graph.concepts.config.ConfigurationGroupSource`
* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## File
### Constructor: File
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node?` (optional)
* `fileName: kotlin.String`

### Properties:

* `fileName: kotlin.String`
* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## Authentication
### Constructor: Authentication
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node?`

### Properties:

* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## ConfigurationGroupSource
### Constructor: ConfigurationGroupSource
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node?` (optional)

### Properties:

* `options: kotlin.collections.MutableList<de.fraunhofer.aisec.cpg.graph.concepts.config.ConfigurationOptionSource>`
* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## Configuration
### Constructor: Configuration
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node?` (optional)

### Properties:

* `allOps: kotlin.collections.Set<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`
* `groups: kotlin.collections.MutableList<de.fraunhofer.aisec.cpg.graph.concepts.config.ConfigurationGroup>`
* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## HttpRequestHandler
### Constructor: HttpRequestHandler
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node?` (optional)
* `basePath: kotlin.String`
* `endpoints: kotlin.collections.MutableList<de.fraunhofer.aisec.cpg.graph.concepts.http.HttpEndpoint>`

### Properties:

* `basePath: kotlin.String`
* `endpoints: kotlin.collections.MutableList<de.fraunhofer.aisec.cpg.graph.concepts.http.HttpEndpoint>`
* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## HttpClient
### Constructor: HttpClient
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node?` (optional)
* `isTLS: kotlin.Boolean?` (optional)
* `authentication: de.fraunhofer.aisec.cpg.graph.concepts.auth.Authentication?` (optional)

### Properties:

* `authentication: de.fraunhofer.aisec.cpg.graph.concepts.auth.Authentication?`
* `isTLS: kotlin.Boolean?`
* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## ConfigurationOption
### Constructor: ConfigurationOption
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node?` (optional)
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

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node?` (optional)

### Properties:

* `blockSize: kotlin.Int?`
* `cipherName: kotlin.String?`
* `keySize: kotlin.Int?`
* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## DiskEncryption
### Constructor: DiskEncryption
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node?` (optional)

### Properties:

* `cipher: de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.Cipher?`
* `key: de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.Secret?`
* `target: de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.BlockStorage?`
* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## Log
### Constructor: Log
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node?` (optional)

### Properties:

* `logName: kotlin.String?`
* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## LocalEntryPoint
### Constructor: LocalEntryPoint
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.declarations.FunctionDeclaration?`
* `os: de.fraunhofer.aisec.cpg.graph.concepts.arch.OperatingSystemArchitecture`

### Properties:

* `os: de.fraunhofer.aisec.cpg.graph.concepts.arch.OperatingSystemArchitecture`
* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## RemoteEntryPoint
### Constructor: RemoteEntryPoint
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.declarations.FunctionDeclaration?`

### Properties:

* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## POSIX
### Constructor: POSIX
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node?` (optional)

### Properties:

* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## Agnostic
### Constructor: Agnostic
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node?` (optional)

### Properties:

* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## Win32
### Constructor: Win32
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node?` (optional)

### Properties:

* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## TokenBasedAuth
### Constructor: TokenBasedAuth
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node?` (optional)
* `token: de.fraunhofer.aisec.cpg.graph.Node`

### Properties:

* `token: de.fraunhofer.aisec.cpg.graph.Node`
* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## LibraryEntryPoint
### Constructor: LibraryEntryPoint
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.declarations.FunctionDeclaration?` (optional)
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

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.declarations.FunctionDeclaration?` (optional)
* `os: de.fraunhofer.aisec.cpg.graph.concepts.arch.OperatingSystemArchitecture`

### Properties:

* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`
* `os: de.fraunhofer.aisec.cpg.graph.concepts.arch.OperatingSystemArchitecture`

## HttpEndpoint
### Constructor: HttpEndpoint
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.declarations.FunctionDeclaration?` (optional)
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

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node?` (optional)

### Properties:

* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`

## JwtAuth
### Constructor: JwtAuth
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node?` (optional)
* `jwt: de.fraunhofer.aisec.cpg.graph.Node`
* `payload: de.fraunhofer.aisec.cpg.graph.Node`

### Properties:

* `jwt: de.fraunhofer.aisec.cpg.graph.Node`
* `payload: de.fraunhofer.aisec.cpg.graph.Node`
* `ops: kotlin.collections.MutableSet<de.fraunhofer.aisec.cpg.graph.concepts.Operation>`
* `token: de.fraunhofer.aisec.cpg.graph.Node`

# Operations
## DiskEncryptionOperation
### Constructor: DiskEncryptionOperation
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node?`
* `concept: de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.DiskEncryption`

### Properties:

* `concept: de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.DiskEncryption`

## HttpClientOperation
### Constructor: HttpClientOperation
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node?`
* `concept: de.fraunhofer.aisec.cpg.graph.concepts.Concept`

### Properties:

* `concept: de.fraunhofer.aisec.cpg.graph.concepts.Concept`

## LogGet
### Constructor: LogGet
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node?` (optional)
* `concept: de.fraunhofer.aisec.cpg.graph.concepts.logging.Log`

### Properties:

* `concept: de.fraunhofer.aisec.cpg.graph.concepts.logging.Log`

## HttpRequestHandlerOperation
### Constructor: HttpRequestHandlerOperation
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node?`
* `concept: de.fraunhofer.aisec.cpg.graph.concepts.Concept`

### Properties:

* `concept: de.fraunhofer.aisec.cpg.graph.concepts.Concept`

## MemoryOperation
### Constructor: MemoryOperation
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node?`
* `concept: de.fraunhofer.aisec.cpg.graph.concepts.Concept`

### Properties:

* `concept: de.fraunhofer.aisec.cpg.graph.concepts.Concept`

## BlockStorageOperation
### Constructor: BlockStorageOperation
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node`
* `concept: de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.BlockStorage`

### Properties:

* `concept: de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.BlockStorage`

## HttpEndpointOperation
### Constructor: HttpEndpointOperation
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node`
* `concept: de.fraunhofer.aisec.cpg.graph.concepts.Concept`

### Properties:

* `concept: de.fraunhofer.aisec.cpg.graph.concepts.Concept`

## LogWrite
### Constructor: LogWrite
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node?` (optional)
* `concept: de.fraunhofer.aisec.cpg.graph.concepts.logging.Log`
* `logLevel: de.fraunhofer.aisec.cpg.graph.concepts.logging.LogLevel`
* `logArguments: kotlin.collections.List<de.fraunhofer.aisec.cpg.graph.Node>`

### Properties:

* `concept: de.fraunhofer.aisec.cpg.graph.concepts.logging.Log`
* `logArguments: kotlin.collections.List<de.fraunhofer.aisec.cpg.graph.Node>`
* `logLevel: de.fraunhofer.aisec.cpg.graph.concepts.logging.LogLevel`

## SecretOperation
### Constructor: SecretOperation
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node?` (optional)
* `concept: de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.Secret`

### Properties:

* `concept: de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.Secret`

## AuthenticationOperation
### Constructor: AuthenticationOperation
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node?` (optional)
* `concept: de.fraunhofer.aisec.cpg.graph.concepts.auth.Authentication`

### Properties:

* `concept: de.fraunhofer.aisec.cpg.graph.concepts.Concept`

## FileOperation
### Constructor: FileOperation
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node?` (optional)
* `file: de.fraunhofer.aisec.cpg.graph.concepts.file.File`

### Properties:

* `file: de.fraunhofer.aisec.cpg.graph.concepts.file.File`
* `concept: de.fraunhofer.aisec.cpg.graph.concepts.Concept`

## CipherOperation
### Constructor: CipherOperation
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node?`
* `concept: de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.Cipher`

### Properties:

* `concept: de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.Cipher`

## ConfigurationOperation
### Constructor: ConfigurationOperation
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node?`
* `concept: de.fraunhofer.aisec.cpg.graph.concepts.Concept`

### Properties:

* `concept: de.fraunhofer.aisec.cpg.graph.concepts.Concept`

## CreateEncryptedDisk
### Constructor: CreateEncryptedDisk
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node?` (optional)
* `concept: de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.DiskEncryption`

### Properties:

* `concept: de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.DiskEncryption`

## UnlockEncryptedDisk
### Constructor: UnlockEncryptedDisk
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node?` (optional)
* `concept: de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.DiskEncryption`

### Properties:

* `concept: de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.DiskEncryption`

## HttpRequest
### Constructor: HttpRequest
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node?` (optional)
* `url: kotlin.String`
* `arguments: kotlin.collections.List<de.fraunhofer.aisec.cpg.graph.Node>`
* `httpMethod: de.fraunhofer.aisec.cpg.graph.concepts.http.HttpMethod`
* `concept: de.fraunhofer.aisec.cpg.graph.concepts.http.HttpClient`

### Properties:

* `arguments: kotlin.collections.List<de.fraunhofer.aisec.cpg.graph.Node>`
* `concept: de.fraunhofer.aisec.cpg.graph.concepts.http.HttpClient`
* `httpMethod: de.fraunhofer.aisec.cpg.graph.concepts.http.HttpMethod`
* `to: kotlin.collections.MutableList<de.fraunhofer.aisec.cpg.graph.concepts.http.HttpEndpoint>`
* `url: kotlin.String`

## RegisterHttpEndpoint
### Constructor: RegisterHttpEndpoint
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node?` (optional)
* `concept: de.fraunhofer.aisec.cpg.graph.concepts.Concept`
* `httpEndpoint: de.fraunhofer.aisec.cpg.graph.concepts.http.HttpEndpoint`

### Properties:

* `httpEndpoint: de.fraunhofer.aisec.cpg.graph.concepts.http.HttpEndpoint`
* `concept: de.fraunhofer.aisec.cpg.graph.concepts.Concept`

## DeAllocate
### Constructor: DeAllocate
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node?` (optional)
* `concept: de.fraunhofer.aisec.cpg.graph.concepts.Concept`
* `what: de.fraunhofer.aisec.cpg.graph.Node?`

### Properties:

* `what: de.fraunhofer.aisec.cpg.graph.Node?`
* `concept: de.fraunhofer.aisec.cpg.graph.concepts.Concept`

## DynamicLoadingOperation
### Constructor: DynamicLoadingOperation
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node?` (optional)
* `concept: de.fraunhofer.aisec.cpg.graph.concepts.Concept`
* `what: T?`
* `os: de.fraunhofer.aisec.cpg.graph.concepts.arch.OperatingSystemArchitecture?` (optional)

### Properties:

* `os: de.fraunhofer.aisec.cpg.graph.concepts.arch.OperatingSystemArchitecture?`
* `what: T?`
* `concept: de.fraunhofer.aisec.cpg.graph.concepts.Concept`

## Allocate
### Constructor: Allocate
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node?` (optional)
* `concept: de.fraunhofer.aisec.cpg.graph.concepts.Concept`
* `what: de.fraunhofer.aisec.cpg.graph.Node?`

### Properties:

* `what: de.fraunhofer.aisec.cpg.graph.Node?`
* `concept: de.fraunhofer.aisec.cpg.graph.concepts.Concept`

## CreateSecret
### Constructor: CreateSecret
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node?` (optional)
* `concept: de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.Secret`

### Properties:

* `concept: de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.Secret`

## GetSecret
### Constructor: GetSecret
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node?` (optional)
* `concept: de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.Secret`

### Properties:

* `concept: de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.Secret`

## Authenticate
### Constructor: Authenticate
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node?` (optional)
* `concept: de.fraunhofer.aisec.cpg.graph.concepts.auth.Authentication`
* `credential: de.fraunhofer.aisec.cpg.graph.Node`

### Properties:

* `credential: de.fraunhofer.aisec.cpg.graph.Node`
* `concept: de.fraunhofer.aisec.cpg.graph.concepts.Concept`

## ReadFile
### Constructor: ReadFile
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node?` (optional)
* `concept: de.fraunhofer.aisec.cpg.graph.concepts.file.File`

### Properties:

* `concept: de.fraunhofer.aisec.cpg.graph.concepts.Concept`
* `file: de.fraunhofer.aisec.cpg.graph.concepts.file.File`

## SetFileMask
### Constructor: SetFileMask
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node?` (optional)
* `concept: de.fraunhofer.aisec.cpg.graph.concepts.file.File`
* `mask: kotlin.Long`

### Properties:

* `mask: kotlin.Long`
* `concept: de.fraunhofer.aisec.cpg.graph.concepts.Concept`
* `file: de.fraunhofer.aisec.cpg.graph.concepts.file.File`

## WriteFile
### Constructor: WriteFile
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node?` (optional)
* `concept: de.fraunhofer.aisec.cpg.graph.concepts.file.File`
* `what: de.fraunhofer.aisec.cpg.graph.Node`

### Properties:

* `what: de.fraunhofer.aisec.cpg.graph.Node`
* `concept: de.fraunhofer.aisec.cpg.graph.concepts.Concept`
* `file: de.fraunhofer.aisec.cpg.graph.concepts.file.File`

## DeleteFile
### Constructor: DeleteFile
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node?` (optional)
* `concept: de.fraunhofer.aisec.cpg.graph.concepts.file.File`

### Properties:

* `concept: de.fraunhofer.aisec.cpg.graph.concepts.Concept`
* `file: de.fraunhofer.aisec.cpg.graph.concepts.file.File`

## SetFileFlags
### Constructor: SetFileFlags
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node?` (optional)
* `concept: de.fraunhofer.aisec.cpg.graph.concepts.file.File`
* `flags: kotlin.collections.Set<de.fraunhofer.aisec.cpg.graph.concepts.file.FileAccessModeFlags>`

### Properties:

* `flags: kotlin.collections.Set<de.fraunhofer.aisec.cpg.graph.concepts.file.FileAccessModeFlags>`
* `concept: de.fraunhofer.aisec.cpg.graph.concepts.Concept`
* `file: de.fraunhofer.aisec.cpg.graph.concepts.file.File`

## OpenFile
### Constructor: OpenFile
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node?` (optional)
* `concept: de.fraunhofer.aisec.cpg.graph.concepts.file.File`

### Properties:

* `concept: de.fraunhofer.aisec.cpg.graph.concepts.Concept`
* `file: de.fraunhofer.aisec.cpg.graph.concepts.file.File`

## CloseFile
### Constructor: CloseFile
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node?` (optional)
* `concept: de.fraunhofer.aisec.cpg.graph.concepts.file.File`

### Properties:

* `concept: de.fraunhofer.aisec.cpg.graph.concepts.Concept`
* `file: de.fraunhofer.aisec.cpg.graph.concepts.file.File`

## Encrypt
### Constructor: Encrypt
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node?` (optional)
* `concept: de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.Cipher`
* `key: de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.Secret`

### Properties:

* `key: de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.Secret`
* `concept: de.fraunhofer.aisec.cpg.graph.concepts.diskEncryption.Cipher`

## ProvideConfigurationOption
### Constructor: ProvideConfigurationOption
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node?` (optional)
* `source: de.fraunhofer.aisec.cpg.graph.concepts.config.ConfigurationOptionSource`
* `option: de.fraunhofer.aisec.cpg.graph.concepts.config.ConfigurationOption`
* `value: de.fraunhofer.aisec.cpg.graph.Node?`

### Properties:

* `option: de.fraunhofer.aisec.cpg.graph.concepts.config.ConfigurationOption`
* `source: de.fraunhofer.aisec.cpg.graph.concepts.config.ConfigurationOptionSource`
* `value: de.fraunhofer.aisec.cpg.graph.Node?`
* `concept: de.fraunhofer.aisec.cpg.graph.concepts.Concept`

## ProvideConfigurationGroup
### Constructor: ProvideConfigurationGroup
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node?` (optional)
* `source: de.fraunhofer.aisec.cpg.graph.concepts.config.ConfigurationGroupSource`
* `group: de.fraunhofer.aisec.cpg.graph.concepts.config.ConfigurationGroup`

### Properties:

* `group: de.fraunhofer.aisec.cpg.graph.concepts.config.ConfigurationGroup`
* `source: de.fraunhofer.aisec.cpg.graph.concepts.config.ConfigurationGroupSource`
* `concept: de.fraunhofer.aisec.cpg.graph.concepts.Concept`

## ProvideConfiguration
### Constructor: ProvideConfiguration
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node?` (optional)
* `source: de.fraunhofer.aisec.cpg.graph.concepts.config.ConfigurationSource`
* `conf: de.fraunhofer.aisec.cpg.graph.concepts.config.Configuration`

### Properties:

* `conf: de.fraunhofer.aisec.cpg.graph.concepts.config.Configuration`
* `source: de.fraunhofer.aisec.cpg.graph.concepts.config.ConfigurationSource`
* `concept: de.fraunhofer.aisec.cpg.graph.concepts.Concept`

## RegisterConfigurationGroup
### Constructor: RegisterConfigurationGroup
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node?` (optional)
* `group: de.fraunhofer.aisec.cpg.graph.concepts.config.ConfigurationGroup`

### Properties:

* `group: de.fraunhofer.aisec.cpg.graph.concepts.config.ConfigurationGroup`
* `concept: de.fraunhofer.aisec.cpg.graph.concepts.Concept`

## RegisterConfigurationOption
### Constructor: RegisterConfigurationOption
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node?` (optional)
* `option: de.fraunhofer.aisec.cpg.graph.concepts.config.ConfigurationOption`
* `defaultValue: de.fraunhofer.aisec.cpg.graph.Node?` (optional)

### Properties:

* `defaultValue: de.fraunhofer.aisec.cpg.graph.Node?`
* `option: de.fraunhofer.aisec.cpg.graph.concepts.config.ConfigurationOption`
* `concept: de.fraunhofer.aisec.cpg.graph.concepts.Concept`

## ReadConfigurationOption
### Constructor: ReadConfigurationOption
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node?` (optional)
* `option: de.fraunhofer.aisec.cpg.graph.concepts.config.ConfigurationOption`

### Properties:

* `option: de.fraunhofer.aisec.cpg.graph.concepts.config.ConfigurationOption`
* `concept: de.fraunhofer.aisec.cpg.graph.concepts.Concept`

## ReadConfigurationGroup
### Constructor: ReadConfigurationGroup
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node?` (optional)
* `group: de.fraunhofer.aisec.cpg.graph.concepts.config.ConfigurationGroup`

### Properties:

* `group: de.fraunhofer.aisec.cpg.graph.concepts.config.ConfigurationGroup`
* `concept: de.fraunhofer.aisec.cpg.graph.concepts.Concept`

## LoadConfiguration
### Constructor: LoadConfiguration
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node?` (optional)
* `conf: de.fraunhofer.aisec.cpg.graph.concepts.config.Configuration`
* `fileExpression: de.fraunhofer.aisec.cpg.graph.statements.expressions.Expression`

### Properties:

* `conf: de.fraunhofer.aisec.cpg.graph.concepts.config.Configuration`
* `fileExpression: de.fraunhofer.aisec.cpg.graph.statements.expressions.Expression`
* `concept: de.fraunhofer.aisec.cpg.graph.concepts.Concept`

## LoadSymbol
### Constructor: LoadSymbol
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node?` (optional)
* `concept: de.fraunhofer.aisec.cpg.graph.concepts.Concept`
* `what: T?`
* `loader: de.fraunhofer.aisec.cpg.graph.concepts.memory.LoadLibrary?`
* `os: de.fraunhofer.aisec.cpg.graph.concepts.arch.OperatingSystemArchitecture?`

### Properties:

* `loader: de.fraunhofer.aisec.cpg.graph.concepts.memory.LoadLibrary?`
* `concept: de.fraunhofer.aisec.cpg.graph.concepts.Concept`
* `os: de.fraunhofer.aisec.cpg.graph.concepts.arch.OperatingSystemArchitecture?`
* `what: T?`

## LoadLibrary
### Constructor: LoadLibrary
Arguments:

* `underlyingNode: de.fraunhofer.aisec.cpg.graph.Node?` (optional)
* `concept: de.fraunhofer.aisec.cpg.graph.concepts.Concept`
* `what: de.fraunhofer.aisec.cpg.graph.Component?`
* `entryPoints: kotlin.collections.List<de.fraunhofer.aisec.cpg.graph.concepts.flows.LibraryEntryPoint>` (optional)
* `os: de.fraunhofer.aisec.cpg.graph.concepts.arch.OperatingSystemArchitecture?`

### Properties:

* `entryPoints: kotlin.collections.List<de.fraunhofer.aisec.cpg.graph.concepts.flows.LibraryEntryPoint>`
* `concept: de.fraunhofer.aisec.cpg.graph.concepts.Concept`
* `os: de.fraunhofer.aisec.cpg.graph.concepts.arch.OperatingSystemArchitecture?`
* `what: de.fraunhofer.aisec.cpg.graph.Component?`