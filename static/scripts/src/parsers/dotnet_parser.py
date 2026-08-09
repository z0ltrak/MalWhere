"""
.NET parser for extracting metadata, strings, and P/Invoke imports.
Uses dnfile 0.18.0 (pure Python) for .NET PE parsing.
TFM 2025-2026 - Universidad Complutense de Madrid

Extracts:
- P/Invoke imports (DllImport attributes)
- User strings (ldstr instructions)
- Type/Class names
- Method names
- Assembly metadata

API Reference: https://pypi.org/project/dnfile/
"""

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
    DNFILE_AVAILABLE = True
except (ImportError, ModuleNotFoundError, AttributeError, Exception) as e:
    DNFILE_AVAILABLE = False
    _DNFILE_ERROR = str(e)


class DotNetParser:
    """
    Parse .NET assemblies using dnfile 0.18.0 to extract:
    - P/Invoke imports (DllImport attributes)
    - User strings from #US heap
    - Type/Class names from TypeDef table
    - Method names from MethodDef table
    - Assembly metadata
    """

    def __init__(self, file_path: Path, verbose: bool = False):
        self.file_path = file_path
        self.verbose = verbose
        self.errors: List[str] = []
        self.data: Optional[bytes] = None
        self.pe: Optional[dnPE] = None

    def parse(self) -> Dict[str, Any]:
        """Extract all .NET metadata."""
        result = {
            'imports': [],           # P/Invoke imports (DllImport)
            'strings': [],           # User strings from ldstr
            'types': [],             # Type/Class names
            'methods': [],           # Method names
            'is_dotnet': False,
            'assembly_name': None,
            'assembly_version': None,
        }

        if not DNFILE_AVAILABLE:
            self.errors.append(f"dnfile not available")
            return result

        try:
            # Read the file - ensure we handle the path correctly
            if self.file_path is None:
                self.errors.append("File path is None")
                return result

            # Convert to string and handle any null characters
            file_path_str = str(self.file_path)
            # Remove any null characters from the path
            file_path_str = file_path_str.replace('\x00', '')

            with open(file_path_str, 'rb') as f:
                self.data = f.read()

            if not self.data or len(self.data) < 64:
                self.errors.append("File is empty or too small")
                return result

            # Load with dnfile
            self.pe = dnfile.dnPE(file_path_str)

            if self.pe is None:
                self.errors.append("Failed to load .NET module with dnfile")
                return result

            # Check if it has .NET metadata
            if not hasattr(self.pe, 'net') or self.pe.net is None:
                self.errors.append("No .NET metadata found")
                return result

            result['is_dotnet'] = True

            # Extract assembly info from Assembly table
            try:
                if hasattr(self.pe.net, 'mdtables'):
                    mdtables = self.pe.net.mdtables
                    if 'Assembly' in mdtables.tables:
                        assembly_table = mdtables.tables['Assembly']
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

            # Extract P/Invoke imports from ImplMap table
            result['imports'] = self._extract_pinvoke_imports()

            # Extract user strings from #US heap
            result['strings'] = self._extract_user_strings()

            # Extract types from TypeDef table
            result['types'] = self._extract_types()

            # Extract methods from MethodDef table
            result['methods'] = self._extract_methods()

            self._log(f"Extracted {len(result['imports'])} P/Invoke imports, "
                     f"{len(result['strings'])} strings, "
                     f"{len(result['types'])} types, "
                     f"{len(result['methods'])} methods")

        except OSError as e:
            self.errors.append(f"OS error parsing .NET: {e}")
            self._log(f"OS Error: {e}")
        except Exception as e:
            self.errors.append(f"Error parsing .NET: {e}")
            self._log(f"Error: {e}")

        return result

    def _extract_pinvoke_imports(self) -> List[Dict[str, Any]]:
        """
        Extract P/Invoke imports from ImplMap table using dnfile 0.18.0 API.

        In dnfile 0.18.0, P/Invoke imports are found in:
        - ImplMap table: maps methods to imported DLLs
        - ModuleRef table: contains the DLL names
        """
        imports = []
        seen = set()

        if self.pe is None or not hasattr(self.pe, 'net') or self.pe.net is None:
            return imports

        try:
            mdtables = self.pe.net.mdtables

            # Check if we have the ImplMap table
            if 'ImplMap' not in mdtables.tables:
                return imports

            impl_map_table = mdtables.tables['ImplMap']
            module_ref_table = mdtables.tables.get('ModuleRef', None)

            if module_ref_table is None:
                return imports

            # Build a map of ModuleRef indices to names
            module_names = {}
            for idx, row in enumerate(module_ref_table.rows, 1):
                if hasattr(row, 'Name') and row.Name:
                    name = row.Name.value if hasattr(row.Name, 'value') else str(row.Name)
                    module_names[idx] = name

            # Iterate through ImplMap rows
            for row in impl_map_table.rows:
                # Get the DLL name from the ModuleRef
                if not hasattr(row, 'ImportScope') or not row.ImportScope:
                    continue

                # ImportScope is a coded index pointing to a ModuleRef
                # For ImplMap, the ImportScope is a ModuleRef
                # We need to extract the ModuleRef index from the coded index
                module_ref_idx = row.ImportScope & 0xFFFFFF

                if module_ref_idx in module_names:
                    dll_name = module_names[module_ref_idx]
                else:
                    continue

                # Get the method name from the ImplMap row
                method_name = None
                if hasattr(row, 'ImportName'):
                    method_name = row.ImportName.value if hasattr(row.ImportName, 'value') else str(row.ImportName)

                if not method_name:
                    continue

                # Skip duplicates
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

    # In _extract_user_strings method, change to:
    def _extract_user_strings(self) -> List[str]:
        """Extract user strings from #US heap using dnfile 0.18.0 API."""
        strings = []
        seen = set()

        if self.pe is None or not hasattr(self.pe, 'net') or self.pe.net is None:
            return strings

        try:
            # Access the #US heap directly
            if hasattr(self.pe.net, 'us'):
                us_heap = self.pe.net.us
                # In dnfile 0.18.0, us_heap is iterable
                for us_item in us_heap:
                    if us_item and hasattr(us_item, 'value') and us_item.value:
                        s = us_item.value
                        if len(s) >= 4 and s not in seen:
                            seen.add(s)
                            strings.append(s)

            # Limit to prevent explosion
            if len(strings) > 5000:
                strings = strings[:5000]

        except Exception as e:
            self.errors.append(f"Error extracting user strings: {e}")

        return strings

    def _extract_types(self) -> List[Dict[str, Any]]:
        """Extract type/class names from TypeDef table using dnfile 0.18.0 API."""
        types = []
        seen = set()

        if self.pe is None or not hasattr(self.pe, 'net') or self.pe.net is None:
            return types

        try:
            mdtables = self.pe.net.mdtables

            if 'TypeDef' in mdtables.tables:
                table = mdtables.tables['TypeDef']
                for row in table.rows:
                    # Get the type name and namespace
                    type_name = None
                    namespace = ""

                    if hasattr(row, 'TypeName') and row.TypeName:
                        type_name = row.TypeName.value if hasattr(row.TypeName, 'value') else str(row.TypeName)

                    if hasattr(row, 'TypeNamespace') and row.TypeNamespace:
                        namespace = row.TypeNamespace.value if hasattr(row.TypeNamespace, 'value') else str(row.TypeNamespace)

                    if type_name:
                        full_name = f"{namespace}.{type_name}" if namespace else type_name
                        # Skip system types
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
        """Extract method names from MethodDef table using dnfile 0.18.0 API."""
        methods = []
        seen = set()

        if self.pe is None or not hasattr(self.pe, 'net') or self.pe.net is None:
            return methods

        try:
            mdtables = self.pe.net.mdtables

            if 'MethodDef' in mdtables.tables:
                table = mdtables.tables['MethodDef']
                for row in table.rows:
                    if hasattr(row, 'Name') and row.Name:
                        name = row.Name.value if hasattr(row.Name, 'value') else str(row.Name)
                        if name:
                            # Skip property getters/setters
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
