### Function: `FUN_14003e800` → Renamed: `integer_to_string`

**Address:** `0x14003e800`

**What it does:**
Converts an integer to a formatted string.

**Parameters:**
- `param_1`: Output string object
- `param_2`: Pointer to the integer to convert

**Used for:**
- Converting thread counts to strings for logging
- Formatting numeric values for output

**Why it matters:**
This is used to convert numeric values (like thread counts) to strings for logging messages.

### Function: `FUN_14003e3f0` → Renamed: `string_concat`

**Address:** `0x14003e3f0`

**What it does:**
Concatenates multiple strings together and returns the result.

**Parameters:**
- `param_1`: Output string object
- `param_2`: First string (literal)
- `param_3`: Second string object (the integer converted to string)
- `param_4`: Additional data

**How it works:**
1. Calculates the length of the first string
2. Ensures the destination has enough capacity
3. Copies the strings into the destination
4. Returns the concatenated result

### Logging and Cleanup Functions

| Original Name | New Name | Purpose |
|---------------|----------|---------|
| `FUN_1400427f0` | `log_info` | Log info message (level 2) |
| `FUN_1400371b0` | `cleanup_string` | Clean up string object |

**`log_info`:**
- Uses the global logger (`DAT_140102188`)
- Log level: 2 (info)
- Calls vtable function after logging

**`cleanup_string`:**
- Frees heap-allocated string buffers
- SSO threshold: 16 bytes
- Resets to empty state

**Why they matter:**
These functions handle logging and cleanup of temporary string objects.


### Function: `FUN_14007b6d0` → Renamed: `init_thread_pool`

**Address:** `0x14007b6d0`

**What it does:**
Initializes a thread pool/work queue for parallel encryption.

**Parameters:**
- `param_1`: Output thread pool structure
- `param_2`: Number of folder parser threads
- `param_3`: Number of encryption threads

**Structure:**

struct thread_pool {
    void* queue1; // Folder parser queue
    void* queue2; // Encryption worker queue
    CRITICAL_SECTION lock1; // Lock for queue1
    CRITICAL_SECTION lock2; // Lock for queue2
    int thread_count1; // Number of folder parsers
    int thread_count2; // Number of encryption workers
};



### Function: `FUN_140054d30` → Renamed: `init_work_queue`

**Address:** `0x140054d30`

**What it does:**
Initializes a work queue object for the thread pool.

**Parameters:**
- `param_1`: Output queue object
- `param_2`: Pointer to the number of worker threads

**Queue Object Structure:**
struct work_queue {
    void* data; // +0x00: Queue data (384 bytes)
    void* ref_count_obj; // +0x08: Reference-counted object
};


### Work Queue Functions

| Original Name | New Name | Purpose |
|---------------|----------|---------|
| `FUN_14004f3f0` | `copy_work_item` | Copy work item with ref counting |
| `FUN_14007b850` | `submit_work_to_queue` | Submit task to work queue |

**`copy_work_item`:**
- Increments reference count on the source
- Creates a copy of the work item

**`submit_work_to_queue`:**
- Acquires a lock on the queue
- Adds the work item
- Signals worker threads

**Why they matter:**
These functions implement the thread pool's task submission system for parallel encryption.


### Function: `FUN_1400434c0` → Renamed: `validate_path_and_log`

**Address:** `0x1400434c0`

**What it does:**
Validates a path and logs its type (local disk, network path, etc.).

**Parameters:**
- `param_1`: Output status code
- `param_2`: Path string to validate
- `param_3`: Unused flag

**Return Values:**
| Value | Meaning |
|-------|---------|
| `0` | Local disk (valid) |
| `0x100` | Network path |
| `0x101` | Invalid/unknown path |
| `1` | Not allowed disk |

**API calls:**
- `PathIsNetworkPathW`: Check if path is a network path
- `GetDriveTypeW`: Get drive type (fixed, removable, remote, etc.)

**Why it matters:**
This validates paths before encryption, ensuring the malware only encrypts valid local drives (or network drives if specified).


### Function: `FUN_140084180` → Renamed: `cleanup_crypto`

**Address:** `0x140084180`

**What it does:**
Cleans up a cryptographic context by freeing all allocated sub-objects.

**Parameters:**
- `param_1`: Pointer to the crypto context (56 bytes)

**What it frees:**

| Offset | Object | Cleanup Function |
|--------|--------|------------------|
| +0x18 | Cipher object | `FUN_14008a060` |
| +0x20 | Key object | `FUN_14008a0f0` |
| +0x28 | Hash context | `FUN_14008a850` |

**Why it matters:**
This is called during cleanup to prevent memory leaks and clear sensitive data.

### Function: `FUN_140055cd0` → Renamed: `string_append_char`

**Address:** `0x140055cd0`

**What it does:**
Appends a wide character (2 bytes) to a string, resizing if necessary.

**Parameters:**
- `param_1`: String object to modify
- `param_2`: Length to add (usually 1)
- `param_3`: Unused flag
- `param_4`: The character to append

**Growth Strategy:** 1.5x growth factor

### Function: `FUN_14003b2d0` → Renamed: `string_append_wstring`

**Address:** `0x14003b2d0`

**What it does:**
Appends a wide character string to a string object.

**Parameters:**
- `param_1`: String object to modify
- `param_2`: The wide string to append
- `param_3`: Length of the string to append

**Used for:**
Building the PowerShell command to clear event logs.

**Example:**
// Before: "-ep bypass -Command "
// After: "-ep bypass -Command Get-WinEvent -ListLog * | where { $_.RecordCount } | ForEach-Object -Process{ [System.Diagnostics.Eventing.Reader.EventLogSession]::Global Session.ClearLog($_.LogName) }"

This builds the PowerShell command that clears Windows event logs:
text

Get-WinEvent -ListLog * | where { $_.RecordCount } | ForEach-Object -Process{ [System.Diagnostics.Eventing.Reader.EventLogSession]::Global Session.ClearLog($_.LogName) }

What it does: Clears all Windows event logs.

ATT&CK Mapping: T1070 (Indicator Removal on Host)


### Function: `FUN_140054e50` → Renamed: `integer_to_string_alt`

**Address:** `0x140054e50`

**What it does:**
Converts a numeric value to a string (alternative implementation).

**Parameters:**
- `param_1`: Output string object
- `param_2`: Pointer to the numeric value to convert

**Used for:**
- Converting exit codes to strings for logging
- Formatting numeric values for output

**Why it matters:**
Similar to `integer_to_string` but uses a different conversion function.


### Function: `FUN_140039ec0` → Renamed: `log_error`

**Address:** `0x140039ec0`

**What it does:**
Logs an error message using the global logger.

**Parameters:**
- `param_1`: Unused (logger object)
- `param_2`: Error message to log

**Log Level:** 4 (Error)

**Example:**
log_error("ShellExecute failed: 5");


### Function: `FUN_14003fa40` → Renamed: `init_stringstream`

**Address:** `0x14003fa40`

**What it does:**
Initializes a `std::stringstream` object for string I/O operations.

**Parameters:**
- `param_1`: Stringstream object to initialize
- `param_2`: Flag (1 = full initialization)

**Stream Hierarchy:**
1. `std::basic_istream` (input)
2. `std::basic_ostream` (output)
3. `std::basic_iostream` (combined)
4. `std::basic_stringstream` (final)

**Why it matters:**
This is used for string formatting and parsing operations.


### Function: `FUN_14005ad40` → Renamed: `stringstream_write_value`

**Address:** `0x14005ad40`

**What it does:**
Writes a numeric value to a `std::stringstream` object.

**Parameters:**
- `param_1`: Stringstream object
- `param_2`: Value to write

**How it works:**
1. Checks the stream state
2. Writes the value using the stream's virtual functions
3. Checks for errors (failbit, badbit, eofbit)
4. Throws `ios_base::failure` on error

**Used for:**
- Formatting elapsed time for logging
- Converting numbers to strings for output

**Example:**
// Before: stringstream is empty
// After: stringstream contains "123456"


### Function: `FUN_140037430` → Renamed: `string_append`

**Address:** `0x140037430`

**What it does:**
Appends a byte string to a string object.

**Parameters:**
- `param_1`: String object to modify
- `param_2`: The string to append
- `param_3`: Length of the string to append

**SSO Threshold:** 16 bytes (0xf)

**Why it matters:**
This is a core string manipulation function used throughout the malware.

### Function: `FUN_140042830` → Renamed: `read_share_file`

**Address:** `0x140042830`

**What it does:**
Reads a file containing a list of network shares/paths and stores them in a vector.

**Parameters:**
- `param_1`: File path to read
- `param_2`: Output vector for the paths

**File Format:**
- One path per line
- Each path is a network share or directory to encrypt

**Why it matters:**
This is used when the `--share_file` argument is specified, allowing the malware to encrypt network shares.


### Function: `FUN_1400372d0` → Renamed: `string_init_from_cstr`

**Address:** `0x1400372d0`

**What it does:**
Creates a custom string object from a C-style string.

**Parameters:**
- `param_1`: Output string object
- `param_2`: Source C-style string

**Why it matters:**
Used to create error message strings.

### Function: `FUN_140055b30` → Renamed: `cleanup_vector_elements`

**Address:** `0x140055b30`

**What it does:**
Cleans up a range of vector elements by freeing their string data.

**Parameters:**
- `param_1`: Start of the vector range
- `param_2`: End of the vector range

**Element Structure (40 bytes):**
| Offset | Field |
|--------|-------|
| +0x00 | String buffer pointer |
| +0x08 | Additional data |
| +0x10 | String length |
| +0x18 | String capacity |
| +0x20 | Additional data |

**Why it matters:**
This is called during cleanup to free memory used by the drive information vector.

### Function: `FUN_14008e49c` → Renamed: `validate_pe_file`

**Address:** `0x14008e49c`

**What it does:**
Validates that the current module is a valid PE file and checks for a digital certificate.

**PE Checks Performed:**
1. Valid DOS header ("MZ")
2. Valid PE header ("PE\0\0")
3. x64 machine type (0x20b)
4. Subsystem version >= 15

**Return Value:**
- Low byte = 1 → Valid PE with certificate
- Low byte = 0 → Invalid PE or no certificate

**Why it matters:**
This is an anti-tampering check. If the PE file is modified (no certificate), the malware takes an obfuscated exit path.


ransomware_main
    │
    ├── Create log file (Log-YYYY-MM-DD-HH-MM-SS.txt)
    │
    ├── Process command-line arguments
    │   ├── --encryption_path → target directory
    │   ├── --share_file → network shares
    │   ├── --encryption_percent → file percentage
    │   ├── -localonly → local drives only
    │   ├── --exclude → exclude files/dirs
    │   └── -dellog → delete log
    │
    ├── enumerate_drives() → get all drives
    │
    ├── create_instance_mutex() → "akira", "arika"
    │
    ├── enumerate_blocked_processes() → process enumeration
    ├── terminate_specific_process() → terminate security tools
    │
    ├── GetSystemInfo() → CPU cores
    │   ├── If no CPU → log_error("No cpu available!")
    │   └── goto cleanup_and_exit
    │
    ├── init_encryption_key() → generate ChaCha20 key
    │
    ├── Calculate thread distribution
    │   ├── 30% for folder parsers
    │   ├── 10% for root folder parsers
    │   └── 60% for encryption
    │
    ├── init_thread_pool() → create worker threads
    ├── init_work_queue() → create work queue
    │
    ├── encryption_loop_entry
    │   ├── For each file/directory:
    │   │   ├── validate_path_and_log()
    │   │   ├── copy_work_item()
    │   │   └── submit_work_to_queue()
    │   │
    │   ├── If share_file → read_share_file()
    │   └── If error → log_error("Failed to read share files!")
    │
    ├── cleanup_worker_thread() → clean up threads
    ├── cleanup_crypto() → clear crypto context
    │
    ├── PowerShell event log clearing
    │   ├── string_append_char() → add quotes
    │   ├── string_append_wstring() → append command
    │   └── ShellExecuteW() → execute PowerShell
    │
    ├── init_stringstream() → create stringstream
    ├── stringstream_write_value() → write elapsed time
    ├── destroy_stringstream() → clean up
    │
    ├── cleanup_and_exit
    │   ├── cleanup_vector_elements() → free drive info
    │   ├── destroy_vector() → free vectors
    │   ├── destroy_tree() → free trees
    │   └── destroy_tree_set() → free sets
    │
    ├── Exit path
    │   ├── If normal → _cexit() → clean exit
    │   └── If error → obfuscation_dead_code → error exit
    │
    └── check_stack_cookie() → return

### Function: `FUN_14007eaf0` → Renamed: `wide_to_ansi`

**Address:** `0x14007eaf0`

**What it does:**
Converts a wide string (UTF-16) to a multi-byte (ANSI) string using `WideCharToMultiByte`.

**Parameters:**
- `param_1`: Output ANSI string object
- `param_2`: Input wide string object (UTF-16)
- `param_3`: Code page (0 = CP_ACP)

**Used for:**
- Converting wide strings to ANSI for logging
- Preparing strings for API calls that expect ANSI

**Why it matters:**
This is used throughout the malware to convert wide strings to ANSI format.


### Function: `FUN_140081d00` → Renamed: `init_critical_section`

**Address:** `0x140081d00`

**What it does:**
Initializes a critical section using Microsoft's Concurrency Runtime (`stl_critical_section_win7`).

**Parameters:**
- `param_1`: Pointer to the critical section object
- `param_2`: Initialization flag (usually 2)

**Structure:**
struct stl_critical_section {
    int flag; // +0x00: Init flag
    void* vftable; // +0x08: Virtual function table
    void* handle; // +0x10: Critical section handle
    int spin_count; // +0x48: Spin count (-1 = default)
    int lock_count; // +0x4c: Lock count
};

### Function: `FUN_1400820e8` → Renamed: `init_condition_variable`

**Address:** `0x1400820e8`

**What it does:**
Initializes a condition variable using the Concurrency Runtime (`stl_condition_variable_win7`).

**Parameters:**
- `param_1`: Pointer to the condition variable object

**Structure:**

struct stl_condition_variable {
    void* vftable; // +0x00: Virtual function table
    CONDITION_VARIABLE cv; // +0x08: Windows condition variable
};


### Function: `FUN_1400385f0` → Renamed: `init_critical_section`

**Address:** `0x1400385f0`

**What it does:**
Initializes a Windows critical section with error handling.

**Parameters:**
- `param_1`: Pointer to the `CRITICAL_SECTION` structure

**How it works:**
1. Calls `InitializeCriticalSection` (via `FUN_1400386b0`)
2. If initialization fails, logs an error and terminates

**Why it matters:**
This is used by the thread pool to create synchronization objects.

### Function: `FUN_14007a2d0` → Renamed: `init_asio_scheduler`

**Address:** `0x14007a2d0`

**What it does:**
Initializes the ASIO scheduler for the thread pool.

**Parameters:**
- `param_1`: Scheduler object (200 bytes)
- `param_2`: Critical section debug info
- `param_3`: Flags (thread count or mode)

**ASIO Scheduler Structure:**

struct asio_scheduler {
    void* vftable; // +0x00: ASIO scheduler vftable
    CRITICAL_SECTION cs; // +0x08: Critical section
    void* data; // +0x10: Internal data
    void* param3; // +0x18: param_3
    HANDLE shutdown_event; // +0x20: Manual-reset event
    HANDLE work_event; // +0x28: Auto-reset event
    void* thread_func; // +0x30: Worker thread function
};


### Function: `FUN_14007d200` → Renamed: `init_asio_typeinfo`

**Address:** `0x14007d200`

**What it does:**
Initializes a type descriptor for ASIO's RTTI system.

**Parameters:**
- `param_1`: Pointer to the type descriptor

**Why it matters:**
This confirms the malware uses the ASIO library for asynchronous operations.


### Function: `FUN_140079fc0` → Renamed: `create_service_already_exists`

**Address:** `0x140079fc0`

**What it does:**
Creates an `asio::service_already_exists` exception object.

**Exception Message:** `"Service already exists."`

**Exception Hierarchy:**

### Function: `FUN_140038a10` → Renamed: `create_worker_thread`

**Address:** `0x140038a10`

**What it does:**
Creates a single worker thread using `_beginthreadex`.

**Parameters:**
- `param_1`: Thread context structure
- `param_2`: Thread function wrapper

**How it works:**
1. Creates two event objects (entry and exit events)
2. Spawns a thread with entry point `LAB_140038ca0`
3. Waits for the thread to signal its entry event

**Events:**
- **Entry event**: Signals when the thread is running
- **Exit event**: Signals when the thread is exiting

**Why it matters:**
This is how the malware creates worker threads for parallel encryption.


### Function: `FUN_14007a030` → Renamed: `create_invalid_service_owner`

**Address:** `0x14007a030`

**What it does:**
Creates an `asio::invalid_service_owner` exception object.

**Exception Message:** `"Invalid service owner."`

**Exception Hierarchy:**

### Function: `FUN_140081b08` → Renamed: `acquire_lock`

**Address:** `0x140081b08`

**What it does:**
Acquires a recursive lock for the thread pool with thread tracking.

**Parameters:**
- `param_1`: Lock object
- `param_2`: Timeout or spin count (NULL = wait indefinitely)

**Lock Features:**
- **Recursive**: Same thread can acquire the lock multiple times
- **Thread tracking**: Stores the owning thread ID
- **Lock count**: Tracks recursion depth

**Why it matters:**
This is the synchronization mechanism used by the thread pool.

### Function: `FUN_14003a4a0` → Renamed: `allocate_work_item`

**Address:** `0x14003a4a0`

**What it does:**
Allocates memory for a work item with 16-byte alignment and thread-local caching.

**Parameters:**
- `param_1`: Size to allocate (0x120 = 288 bytes)

**Memory Strategy:**
1. Thread-local cache for fast allocation
2. 16-byte alignment (for SIMD instructions)
3. Fallback to `_aligned_malloc`

**Why it matters:**
This allocates memory for encryption work items.


### Function: `FUN_1400c4030` → Renamed: `init_work_item`

**Address:** `0x1400c4030`

**What it does:**
Initializes a work item structure with file path, string context, and flags.

**Parameters:**
- `param_1`: Flags
- `param_2`: Work item memory
- `param_3`: Output work item pointer
- `param_4`: Queue object
- `param_5`: File path string
- `param_6`: String context
- `param_7-10`: Flags and values

**Work Item Size:** 0x120 (288 bytes)

**Why it matters:**
This creates the encryption task that worker threads will process.

### Function: `FUN_14007bd00` → Renamed: `cleanup_work_item`

**Address:** `0x14007bd00`

**What it does:**
Cleans up a work item after it has been processed by a worker thread.

**Parameters:**
- `param_1`: Queue data
- `param_2`: Work item to clean up

**How it works:**
1. Removes the work item from the queue
2. Processes completion handlers
3. Cleans up resources
4. Handles reference counting

**Why it matters:**
This is called after a file encryption task is completed.




UndefinedFunction_140038ca0 --> worker_thread_entry

The ASIO scheduler worker function (called via *param_1 + 8) is where the actual file encryption happens. This is likely FUN_14007b1c0 or a similar function.

### ChaCha20 State Cleanup

| Original Name | New Name | Purpose |
|---------------|----------|---------|
| `FUN_14008a0f0` | `clean_chacha20_state` | Zero ChaCha20 state |
| `FUN_140088dd0` | `zero_16byte_block` | Zero 16-byte block |

**Purpose:**
Securely clears the ChaCha20 cipher state from memory to prevent key leakage.

**Structure:**

struct chacha20_state {
    uint32_t state[16]; // 16 x 4 bytes = 64 bytes
    uint32_t counter; // 4 bytes
    uint8_t buffer[64]; // 64 bytes
    // Total: ~132 bytes
};

### SHA-256 Key Derivation

| Original Name | New Name | Purpose |
|---------------|----------|---------|
| `FUN_14008a850` | `init_sha256_context` | Initialize SHA-256 context |
| `FUN_14008bb80` | `sha256_init_constants` | Set SHA-256 constants |

**SHA-256 Initial Values:**
H0 = 0x6a09e667
H1 = 0xbb67ae85
H2 = 0x3c6ef372
H3 = 0xa54ff53a
H4 = 0x510e527f
H5 = 0x9b05688c
H6 = 0x1f83d9ab
H7 = 0x5be0cd19


**Purpose:**
The malware uses SHA-256 to derive the ChaCha20 encryption key from timing entropy.

**ATT&CK Mapping:**
- T1486 (Data Encrypted for Impact): Key derivation
### Key Derivation Functions

| Original Name | New Name | Purpose |
|---------------|----------|---------|
| `FUN_14008b990` | `init_key_derivation` | Initialize key derivation |
| `FUN_14008a360` | `derive_key_multiround` | Multi-round key derivation |
| `FUN_14008b820` | `reset_key_context` | Reset key context |
| `FUN_14008b860` | `sha256_update_key` | SHA-256 update |
| `FUN_140089b20` | `check_hash_valid` | Check hash validity |
| `FUN_14008b9b0` | `der_parser_next` | ASN.1/DER parser |
| `FUN_14008a090` | `finalize_key_derivation` | Finalize key |

**Key Derivation Flow:**
1. Initialize context with key material
2. Parse DER-encoded key data
3. Update SHA-256 with key material
4. Finalize → ChaCha20 key

**ATT&CK Mapping:**
- T1486 (Data Encrypted for Impact): Key derivation
### Function: `FUN_140084360` → Renamed: `derive_key_from_time`

**Address:** `0x140084360`

**What it does:**
Derives a cryptographic key using timing entropy and SHA-256.

**How it works:**
1. Gets timing entropy from `QueryPerformanceCounter`
2. Converts the time to a string
3. Hashes the string with SHA-256
4. Stores the result in the crypto context

**Why it matters:**
This generates the ChaCha20 encryption key using time-based entropy.

**ATT&CK Mapping:**
- T1486 (Data Encrypted for Impact): Key derivation


asio_service_lookup()
    │
    ├── init_service_typeinfo()  ← Sets the type we're looking for
    │
    ├── EnterCriticalSection()
    │
    ├── Search through service list
    │   └── Compare type info of each service
    │
    ├── If found → return service
    │
    └── If not found → create new service


FUN_14007d1a0 --> This is the service object creation function. It allocates a 48-byte null_reactor service object and sets up its virtual function table.

open_directory_iterator
get_file_type
compare_paths
find_filename
get_file_extension
is_path_allowed
hash_string
wide_to_ansi_ex
wide_to_ansi
check_file_status
submit_encryption_task
advance_iterator
write_to_buffer
read_number_from_stream
delete_object
store_in_tls
cleanup_string_object

FUN_1400c13d0	process_directory_for_encryption	Main file processing loop

create_encryption_work_item
init_work_item
process_work_item
create_encryption_task

signal_worker_thread
destroy_encryption_task
link_task_to_queue
transfer_encryption_task
cleanup_work_item_string
setup_async_io
hash_path_to_filename
derive_file_key
get_string_buffer
copy_string
get_filename_from_path
copy_string_to
append_and_move
string_assign_move
create_completion_work
destroy_task_and_get_status
destroy_task
concat_strings
append_and_copy
release_ref_counted
cleanup_crypto
create_completion_handler
create_partial_completion_handler
create_spot_completion_handler
create_final_completion_handler
get_current_time_ns
ns_to_us
build_file_path
ansi_to_wide_ex
allocate_zero_buffer
error_code_to_string
append_file_path_to_message
cleanup_cryp_context
cleanup_hsh_context
unlock_file_for_encryption
process_file_encryption
init_encryption_task
chacha20_set_key
chacha20_set_nonce
chacha20_init
chacha20_generate_keystream
init_sha256_context
chacha20_encrypt

"The malware uses the mutex name akira (and arika) for single-instance enforcement. Encrypted files are renamed with the extension .akira (or .arika), confirming the ransomware's identity."

init_exclusion_list

ds "powershell.exe -Command \"Get-WmiObject Win32_Shadowcopy | Remove-WmiObject\""
