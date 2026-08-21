"""Parse .NET assemblies (P/Invoke imports, user strings, types, methods, BCL calls) using dnfile 0.18.0."""

import struct
from pathlib import Path
from typing import List, Dict, Any, Optional

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False

try:
    import dnfile
    from dnfile import dnPE
    from dnfile.enums import MetadataTables
    DNFILE_AVAILABLE = True
except (ImportError, ModuleNotFoundError, AttributeError, Exception) as e:
    DNFILE_AVAILABLE = False
    _DNFILE_ERROR = str(e)


class DotNetParser:
    """Parse .NET assemblies for P/Invoke imports, user strings, type/method names, and assembly metadata."""

    def __init__(self, file_path: Path, verbose: bool = False):
        """Initialize the parser.

        Args:
            file_path: Path to the .NET assembly to parse.
            verbose: Enable verbose progress logging.
        """
        self.file_path = file_path
        self.verbose = verbose
        self.errors: List[str] = []
        self.data: Optional[bytes] = None
        self.pe: Optional[dnPE] = None

    def parse(self) -> Dict[str, Any]:
        """Extract all .NET metadata.

        Returns:
            Dict with imports, strings, types, methods, bcl_calls,
            is_dotnet, assembly_name, and assembly_version.
        """
        result = {
            'imports': [],           # P/Invoke imports (DllImport)
            'strings': [],           # User strings from ldstr
            'types': [],             # Type/Class names
            'methods': [],           # Method names
            'bcl_calls': [],         # Fully-qualified BCL API calls (System.*, Microsoft.Win32.*, ...)
            'is_dotnet': False,
            'assembly_name': None,
            'assembly_version': None,
        }

        if not DNFILE_AVAILABLE:
            self.errors.append(f"dnfile not available")
            return result

        try:
            if self.file_path is None:
                self.errors.append("File path is None")
                return result

            file_path_str = str(self.file_path).replace('\x00', '')

            with open(file_path_str, 'rb') as f:
                self.data = f.read()

            if not self.data or len(self.data) < 64:
                self.errors.append("File is empty or too small")
                return result

            self.pe = dnfile.dnPE(file_path_str)

            if self.pe is None:
                self.errors.append("Failed to load .NET module with dnfile")
                return result

            if not hasattr(self.pe, 'net') or self.pe.net is None:
                self.errors.append("No .NET metadata found")
                return result

            result['is_dotnet'] = True

            # dnfile 0.18.0 keys mdtables.tables by numeric ECMA-335 table
            # ID (MetadataTables.Assembly.value), not by string name.
            try:
                if hasattr(self.pe.net, 'mdtables'):
                    mdtables = self.pe.net.mdtables
                    if MetadataTables.Assembly.value in mdtables.tables:
                        assembly_table = mdtables.tables[MetadataTables.Assembly.value]
                        if assembly_table and len(assembly_table.rows) > 0:
                            row = assembly_table.rows[0]
                            if hasattr(row, 'Name'):
                                result['assembly_name'] = row.Name.value if hasattr(row.Name, 'value') else str(row.Name)
                            if hasattr(row, 'Version'):
                                ver = row.Version
                                if ver:
                                    result['assembly_version'] = f"{ver.Major}.{ver.Minor}.{ver.Build}.{ver.Revision}"
            except Exception as e:
                self.errors.append(f"Error extracting assembly info: {e}")

            result['imports'] = self._extract_pinvoke_imports()
            result['strings'] = self._extract_user_strings()
            result['types'] = self._extract_types()
            result['methods'] = self._extract_methods()
            result['bcl_calls'] = self._extract_bcl_calls()

            self._log(f"Extracted {len(result['imports'])} P/Invoke imports, "
                     f"{len(result['strings'])} strings, "
                     f"{len(result['types'])} types, "
                     f"{len(result['methods'])} methods, "
                     f"{len(result['bcl_calls'])} BCL API calls")

        except OSError as e:
            self.errors.append(f"OS error parsing .NET: {e}")
            self._log(f"OS Error: {e}")
        except Exception as e:
            self.errors.append(f"Error parsing .NET: {e}")
            self._log(f"Error: {e}")

        return result

    def _extract_pinvoke_imports(self) -> List[Dict[str, Any]]:
        """Extract P/Invoke imports from the ImplMap table.

        row.ImportScope resolves directly to the ModuleRefRow via
        .row in this dnfile version -- no manual bit-masking needed.

        Returns:
            Deduplicated (dll, function) P/Invoke import entries.
        """
        imports = []
        seen = set()

        if self.pe is None or not hasattr(self.pe, 'net') or self.pe.net is None:
            return imports

        try:
            mdtables = self.pe.net.mdtables

            if MetadataTables.ImplMap.value not in mdtables.tables:
                return imports

            impl_map_table = mdtables.tables[MetadataTables.ImplMap.value]

            for row in impl_map_table.rows:
                if not hasattr(row, 'ImportScope') or row.ImportScope is None:
                    continue

                module_ref_row = row.ImportScope.row
                if module_ref_row is None or not hasattr(module_ref_row, 'Name') or not module_ref_row.Name:
                    continue
                dll_name = module_ref_row.Name.value if hasattr(module_ref_row.Name, 'value') else str(module_ref_row.Name)

                method_name = None
                if hasattr(row, 'ImportName'):
                    method_name = row.ImportName.value if hasattr(row.ImportName, 'value') else str(row.ImportName)

                if not method_name:
                    continue

                key = f"{dll_name}_{method_name}"
                if key in seen:
                    continue
                seen.add(key)

                imports.append({
                    'dll': dll_name,
                    'function': method_name,
                    'entry_point': method_name,
                    'calling_convention': None,
                    'set_last_error': False,
                    'char_set': None,
                    'source': 'pinvoke'
                })

        except Exception as e:
            self.errors.append(f"Error extracting P/Invoke imports: {e}")

        return imports

    def _extract_user_strings(self) -> List[str]:
        """Extract user strings from the #US heap.

        The heap (`pe.net.user_strings`) is offset-indexed, not
        iterable: each entry is an ECMA-335-compressed length prefix
        followed by that many bytes of UTF-16LE data, so walk it
        sequentially from offset 1 (offset 0 is a single null byte),
        using each entry's own reported size to find the next one.

        Returns:
            Up to 5000 deduplicated user strings, each at least 4 characters long.
        """
        strings = []
        seen = set()

        if self.pe is None or not hasattr(self.pe, 'net') or self.pe.net is None:
            return strings

        try:
            if not hasattr(self.pe.net, 'user_strings'):
                return strings

            heap = self.pe.net.user_strings
            heap_size = heap.sizeof()
            offset = 1

            while offset < heap_size and len(strings) < 5000:
                item = heap.get(offset)
                if item is None:
                    break

                consumed = item.item_size.raw_size + int(item.item_size)
                if consumed <= 0:
                    break  # malformed entry -- stop rather than loop forever

                if item.value and len(item.value) >= 4 and item.value not in seen:
                    seen.add(item.value)
                    strings.append(item.value)

                offset += consumed

        except Exception as e:
            self.errors.append(f"Error extracting user strings: {e}")

        return strings

    def _extract_types(self) -> List[Dict[str, Any]]:
        """Extract type/class names from the TypeDef table using dnfile 0.18.0's API.

        Returns:
            Deduplicated non-System.* type entries (name, full_name, namespace, flags).
        """
        types = []
        seen = set()

        if self.pe is None or not hasattr(self.pe, 'net') or self.pe.net is None:
            return types

        try:
            mdtables = self.pe.net.mdtables

            if MetadataTables.TypeDef.value in mdtables.tables:
                table = mdtables.tables[MetadataTables.TypeDef.value]
                for row in table.rows:
                    type_name = None
                    namespace = ""

                    if hasattr(row, 'TypeName') and row.TypeName:
                        type_name = row.TypeName.value if hasattr(row.TypeName, 'value') else str(row.TypeName)

                    if hasattr(row, 'TypeNamespace') and row.TypeNamespace:
                        namespace = row.TypeNamespace.value if hasattr(row.TypeNamespace, 'value') else str(row.TypeNamespace)

                    if type_name:
                        full_name = f"{namespace}.{type_name}" if namespace else type_name
                        if full_name.startswith("System."):
                            continue
                        if full_name not in seen:
                            seen.add(full_name)
                            types.append({
                                'name': type_name,
                                'full_name': full_name,
                                'namespace': namespace,
                                'is_public': True,
                                'is_enum': False,
                                'is_interface': False
                            })

        except Exception as e:
            self.errors.append(f"Error extracting types: {e}")

        return types

    def _extract_methods(self) -> List[Dict[str, Any]]:
        """Extract method names from the MethodDef table using dnfile 0.18.0's API.

        Returns:
            Deduplicated method entries, excluding property/event accessors (get_/set_/add_/remove_).
        """
        methods = []
        seen = set()

        if self.pe is None or not hasattr(self.pe, 'net') or self.pe.net is None:
            return methods

        try:
            mdtables = self.pe.net.mdtables

            if MetadataTables.MethodDef.value in mdtables.tables:
                table = mdtables.tables[MetadataTables.MethodDef.value]
                for row in table.rows:
                    if hasattr(row, 'Name') and row.Name:
                        name = row.Name.value if hasattr(row.Name, 'value') else str(row.Name)
                        if name:
                            # Property/event accessors, not real methods
                            if name.startswith("get_") or name.startswith("set_"):
                                continue
                            if name.startswith("add_") or name.startswith("remove_"):
                                continue

                            if name not in seen:
                                seen.add(name)
                                methods.append({
                                    'name': name,
                                    'full_name': name,
                                    'is_static': False,
                                    'is_public': True,
                                    'has_body': True
                                })

        except Exception as e:
            self.errors.append(f"Error extracting methods: {e}")

        return methods

    # BCL API call extraction: the extraction methods above only surface
    # NAMES (types, methods, P/Invoke imports), which a heavily obfuscated
    # sample can render meaningless. This walks method bodies for
    # call/callvirt/newobj instructions and resolves their token operands
    # to fully-qualified BCL API names -- the managed-code equivalent of
    # import-table mapping for native PE imports.
    #
    # dnfile 0.18.0 has no IL disassembler, so rather than writing a full
    # CIL opcode-length table to walk every instruction (real desync
    # risk), this scans for the 3 call opcodes as single bytes within the
    # method's own precisely-bounded code region (from its tiny/fat
    # header) and treats the next 4 bytes as a candidate token. A false
    # opcode-byte match is self-limiting: the following 4 bytes then also
    # have to decode to a valid table ID and an existing row.

    _CALL_OPCODES = (0x28, 0x6F, 0x73)  # call, callvirt, newobj
    _RESOLVABLE_TABLE_IDS = (0x0A, 0x2B)  # MemberRef, MethodSpec -- external refs; MethodDef (0x06) is a same-assembly call, not useful BCL evidence
    _MAX_METHOD_BODY_SIZE = 262144  # 256KB -- a method body this large is not real IL; skip rather than scan garbage
    _MAX_METHODS_SCANNED = 2000  # bound total work on pathologically large assemblies

    def _get_method_code_region(self, rva: int) -> tuple:
        """Parse a method's tiny/fat header.

        Args:
            rva: RVA of the method body (MethodDef row's Rva field).

        Returns:
            (code_start_rva, code_size), or (None, 0) if the header format is unrecognized.
        """
        header = self.pe.get_data(rva, 12)
        first_byte = header[0]
        fmt = first_byte & 0x03
        if fmt == 0x02:  # CorILMethod_TinyFormat
            return rva + 1, first_byte >> 2
        if fmt == 0x03:  # CorILMethod_FatFormat
            code_size = struct.unpack('<I', header[4:8])[0]
            return rva + 12, code_size
        return None, 0

    def _resolve_member_token(self, token: int) -> Optional[str]:
        """Resolve a MemberRef/MethodSpec token to a fully-qualified 'Namespace.Type::Member' name.

        Args:
            token: A 4-byte metadata token (table ID in the top byte, row index in the rest).

        Returns:
            The fully-qualified name, or None if the token isn't a resolvable external reference.
        """
        table_id = (token >> 24) & 0xFF
        row_index = token & 0xFFFFFF
        if table_id not in self._RESOLVABLE_TABLE_IDS:
            return None

        mdtables = self.pe.net.mdtables
        table = mdtables.tables.get(table_id)
        if table is None or row_index < 1 or row_index > len(table.rows):
            return None
        row = table.rows[row_index - 1]

        name_field = getattr(row, 'Name', None)
        if name_field is None:
            return None
        member_name = name_field.value if hasattr(name_field, 'value') else str(name_field)

        # MemberRef.Class is a coded index into TypeRef/TypeDef/TypeSpec/...
        # -- .row is the already-resolved parent row in this dnfile version.
        parent_name = ''
        class_field = getattr(row, 'Class', None)
        if class_field is not None:
            parent_row = getattr(class_field, 'row', None)
            type_name_field = getattr(parent_row, 'TypeName', None) if parent_row else None
            if type_name_field is not None:
                type_name = type_name_field.value if hasattr(type_name_field, 'value') else str(type_name_field)
                ns_field = getattr(parent_row, 'TypeNamespace', None)
                namespace = (ns_field.value if hasattr(ns_field, 'value') else str(ns_field)) if ns_field else ''
                parent_name = f"{namespace}.{type_name}" if namespace else type_name

        return f"{parent_name}::{member_name}" if parent_name else None  # bare names (no resolvable parent) aren't useful BCL evidence

    def _extract_bcl_calls(self) -> List[str]:
        """Scan every method body for call/callvirt/newobj targets.

        Returns:
            The deduplicated, sorted set of fully-qualified BCL API references.
        """
        calls: set = set()

        if self.pe is None or not hasattr(self.pe, 'net') or self.pe.net is None:
            return []

        try:
            mdtables = self.pe.net.mdtables
            if MetadataTables.MethodDef.value not in mdtables.tables:
                return []
            method_table = mdtables.tables[MetadataTables.MethodDef.value]

            scanned = 0
            for row in method_table.rows:
                if not row.Rva:
                    continue
                if scanned >= self._MAX_METHODS_SCANNED:
                    break
                scanned += 1

                try:
                    code_start, code_size = self._get_method_code_region(row.Rva)
                    if not code_start or code_size == 0 or code_size > self._MAX_METHOD_BODY_SIZE:
                        continue
                    code = self.pe.get_data(code_start, code_size)
                except Exception:
                    continue

                for i in range(len(code) - 4):
                    if code[i] not in self._CALL_OPCODES:
                        continue
                    token = struct.unpack('<I', code[i + 1:i + 5])[0]
                    resolved = self._resolve_member_token(token)
                    if resolved:
                        calls.add(resolved)

        except Exception as e:
            self.errors.append(f"Error extracting BCL calls: {e}")

        return sorted(calls)

    def get_pinvoke_imports(self) -> List[Dict[str, Any]]:
        """Get only P/Invoke imports."""
        result = self.parse()
        return result.get('imports', [])

    def get_strings(self) -> List[str]:
        """Get only user strings."""
        result = self.parse()
        return result.get('strings', [])

    def _log(self, message: str):
        if self.verbose:
            print(f"[*] DotNetParser: {message}")

    def get_errors(self) -> List[str]:
        return self.errors
