from tree_sitter import Language, Parser, Node
import tree_sitter_javascript as tsjs

JS_LANGUAGE = Language(tsjs.language())


class JSExtractor:

    def __init__(self):
        self.parser = Parser(JS_LANGUAGE)

    # ── PUBLIC API ───────────────────────────────────────────
    # Same contract as the regex version: extract_all(source, filepath)
    # returns a flat list of finding dicts. Downstream (ConfigAnalyzer /
    # RuleEngine) reads library / method / parameter / value / line off
    # these dicts and is untouched by this rewrite.

    def extract_all(self, source_code, filepath):
        results = []
        results.extend(self.extract_bcrypt(source_code))
        results.extend(self.extract_jwt(source_code))
        results.extend(self.extract_axios(source_code))
        results.extend(self.extract_express(source_code))
        results.extend(self.extract_mongoose(source_code))
        results.extend(self.extract_lodash(source_code))
        return results

    def _parse(self, source_code):
        """Parse source and build the file-scoped symbol table. Each public
        extract_* method calls this itself so it can be invoked standalone
        (matching the original regex-based method signatures), not only
        through extract_all."""
        tree = self.parser.parse(bytes(source_code, "utf8"))
        root = tree.root_node
        symbols = self._build_symbol_table(root, source_code)
        aliases = self._build_import_aliases(root, source_code)
        return root, symbols, aliases

    # ── SYMBOL TABLE ─────────────────────────────────────────
    # Best-effort, file-scoped: tracks `const X = <literal>` / `let X = <literal>`
    # so an identifier argument (e.g. ROUNDS) can be resolved back to its
    # literal value. Does not attempt real scope resolution (shadowing,
    # blocks, reassignment) — that's out of scope for a security-default
    # scanner where the common case is a single module-level constant.

    def _build_symbol_table(self, root, source):
        symbols = {}

        def visit(node):
            if node.type == "variable_declarator":
                name_node = node.child_by_field_name("name")
                value_node = node.child_by_field_name("value")
                if name_node and value_node and name_node.type == "identifier":
                    literal = self._literal_value(value_node, source)
                    if literal is not _NOT_A_LITERAL:
                        symbols[self._text(name_node, source)] = literal
            for child in node.children:
                visit(child)

        visit(root)
        return symbols

    # ── IMPORT ALIASES ───────────────────────────────────────
    # Tracks how each required/imported module's exports are bound locally, e.g.:
    #   const { merge } = require('lodash')      -> aliases['merge'] = ('lodash', 'merge')
    #   const _ = require('lodash')              -> aliases['_']     = ('lodash', None)
    #   import { merge as mrg } from 'lodash'    -> aliases['mrg']   = ('lodash', 'merge')
    #   import cors from 'cors'                  -> aliases['cors']  = ('cors', 'default')
    # This lets extractors recognize a library's function whether it's called as
    # `lib.fn(...)`, `alias.fn(...)`, or a bare destructured `fn(...)`.

    def _build_import_aliases(self, root, source):
        aliases = {}

        def add(local_name, module, export_name):
            aliases[local_name] = (module, export_name)

        for node in self._walk(root):
            # const X = require('mod')  /  const { a, b: c } = require('mod')
            if node.type == "variable_declarator":
                name_node = node.child_by_field_name("name")
                value_node = node.child_by_field_name("value")
                if name_node is None or value_node is None:
                    continue
                require_mod = self._require_module_name(value_node, source)
                if require_mod is None:
                    continue
                if name_node.type == "identifier":
                    add(self._text(name_node, source), require_mod, None)
                elif name_node.type == "object_pattern":
                    for prop in name_node.children:
                        if prop.type == "shorthand_property_identifier_pattern":
                            local = self._text(prop, source)
                            add(local, require_mod, local)
                        elif prop.type == "pair_pattern":
                            key_node = prop.child_by_field_name("key")
                            val_node = prop.child_by_field_name("value")
                            if key_node is not None and val_node is not None:
                                exported = self._text(key_node, source).strip("'\"`")
                                local = self._text(val_node, source)
                                add(local, require_mod, exported)

            # import statements
            if node.type == "import_statement":
                source_node = None
                for child in node.children:
                    if child.type == "string":
                        source_node = child
                mod = self._text(source_node, source).strip("'\"`") if source_node else None
                if mod is None:
                    continue
                for child in node.children:
                    if child.type == "import_clause":
                        for sub in child.children:
                            if sub.type == "identifier":
                                add(self._text(sub, source), mod, "default")
                            elif sub.type == "named_imports":
                                for spec in sub.children:
                                    if spec.type == "import_specifier":
                                        name_n = spec.child_by_field_name("name")
                                        alias_n = spec.child_by_field_name("alias")
                                        if name_n is None:
                                            continue
                                        exported = self._text(name_n, source)
                                        local = self._text(alias_n, source) if alias_n else exported
                                        add(local, mod, exported)
                            elif sub.type == "namespace_import":
                                local = self._text(sub, source).replace("*", "").replace("as", "").strip()
                                add(local, mod, None)
        return aliases

    def _require_module_name(self, node, source):
        """If node is `require('mod')` (optionally chained, e.g. require('mod').default),
        return 'mod', else None."""
        target = node
        if target.type == "call_expression":
            fn = target.child_by_field_name("function")
            if fn is not None and fn.type == "identifier" and self._text(fn, source) == "require":
                args = self._call_args(target)
                if args and args[0].type == "string":
                    return self._text(args[0], source).strip("'\"`")
        return None

    def _resolves_to(self, name, module, aliases, export_name=None):
        """True if local `name` refers to `module` (optionally a specific export)
        via tracked import aliases, or matches the raw module/export name directly
        (covers the common case where no import tracking was needed, e.g. global `_`)."""
        if name in aliases:
            mod, exp = aliases[name]
            if mod != module:
                return False
            if export_name is None:
                return True
            return exp == export_name or exp is None
        return False

    def _literal_value(self, node, source):
        text = self._text(node, source)
        if node.type == "number":
            try:
                return int(text)
            except ValueError:
                try:
                    return float(text)
                except ValueError:
                    return _NOT_A_LITERAL
        if node.type == "string":
            return text.strip("'\"`")
        
        # Added 'boolean' to guarantee catching 'false' nodes
        if node.type in ("true", "false", "boolean"):
            return text  
            
        return _NOT_A_LITERAL

    def _resolve(self, node, source, symbols):
        """Resolve a node to a literal value, following one level of
        identifier -> const lookup if needed."""
        literal = self._literal_value(node, source)
        if literal is not _NOT_A_LITERAL:
            return literal
        if node.type == "identifier":
            name = self._text(node, source)
            if name in symbols:
                return symbols[name]
        return _NOT_A_LITERAL

    # ── HELPERS ──────────────────────────────────────────────

    def _text(self, node, source):
        # Tree-sitter offsets are BYTE indices, not char indices.
        # This prevents catastrophic misalignment if the JS file contains non-ASCII chars.
        if isinstance(source, str):
            return source.encode('utf8')[node.start_byte:node.end_byte].decode('utf8', errors='ignore')
        return source[node.start_byte:node.end_byte].decode('utf8', errors='ignore')

    def _line(self, node):
        return node.start_point[0] + 1

    def _walk(self, node):
        yield node
        for child in node.children:
            yield from self._walk(child)

    def _call_method_name(self, node, source):
        """If node is `obj.method(...)`, return 'method', else None."""
        if node.type != "call_expression":
            return None
        fn = node.child_by_field_name("function")
        if fn is None or fn.type != "member_expression":
            return None
        prop = fn.child_by_field_name("property")
        if prop is None or prop.type != "property_identifier":
            return None
        return self._text(prop, source)

    def _call_object_name(self, node, source):
        fn = node.child_by_field_name("function")
        obj = fn.child_by_field_name("object")
        return self._text(obj, source)

    def _call_bare_name(self, node, source):
        """If node is a bare `fn(...)` call (identifier, not member expression),
        return 'fn', else None."""
        if node.type != "call_expression":
            return None
        fn = node.child_by_field_name("function")
        if fn is None or fn.type != "identifier":
            return None
        return self._text(fn, source)

    def _call_args(self, node):
        args_node = node.child_by_field_name("arguments")
        if args_node is None:
            return []
        return [c for c in args_node.children if c.is_named]

    def _object_properties(self, obj_node, source):
        """Yield (key_text, value_node) for each property in an object literal."""
        if obj_node is None or obj_node.type != "object":
            return
        for child in obj_node.children:
            if child.type == "pair":
                key_node = child.child_by_field_name("key")
                value_node = child.child_by_field_name("value")
                if key_node is not None:
                    key_text = self._text(key_node, source).strip("'\"`")
                    yield key_text, value_node

    def _find_object_arg_containing(self, call_node, source, key_predicate):
        """For a call like foo({ ...key: val... }), return (key_text, value_node)
        of the first property matching key_predicate, searching all args
        (including one level of nesting, e.g. new https.Agent({ ... }) passed as a
        property value elsewhere is handled by callers walking the whole tree)."""
        for arg in self._call_args(call_node):
            target = arg
            if target.type != "object":
                continue
            for key_text, value_node in self._object_properties(target, source):
                if key_predicate(key_text):
                    return key_text, value_node
        return None, None

    # ── BCRYPT ───────────────────────────────────────────────
    # bcrypt.hashSync(password, rounds)  AND  bcrypt.hash(password, rounds, cb)

    def extract_bcrypt(self, source):
        root, symbols, aliases = self._parse(source)
        findings = []
        for node in self._walk(root):
            method = self._call_method_name(node, source)
            if method not in ("hashSync", "hash"):
                continue
            args = self._call_args(node)
            if len(args) < 2:
                continue
            rounds_node = args[1]
            # for bcrypt.hash(password, rounds, callback), rounds is still args[1];
            # guard against the case where args[1] is itself a callback (no rounds passed)
            value = self._resolve(rounds_node, source, symbols)
            if value is _NOT_A_LITERAL or not isinstance(value, (int, float)):
                continue
            findings.append({
                "library": "bcrypt",
                "method": method,
                "parameter": "rounds",
                "value": int(value),
                "line": self._line(rounds_node),
            })
        return findings

    # ── JWT ──────────────────────────────────────────────────
    # { algorithm: "none" } — anywhere as an object property, e.g. jwt.sign(payload, key, { algorithm: "none" })

    def extract_jwt(self, source):
        root, symbols, aliases = self._parse(source)
        findings = []
        for node in self._walk(root):
            if node.type != "pair":
                continue
            key_node = node.child_by_field_name("key")
            value_node = node.child_by_field_name("value")
            if key_node is None or value_node is None:
                continue
            key_text = self._text(key_node, source).strip("'\"`")
            if key_text != "algorithm":
                continue
            value = self._resolve(value_node, source, symbols)
            if isinstance(value, str) and value.lower() == "none":
                findings.append({
                    "library": "jwt",
                    "parameter": "algorithm",
                    "value": "none",
                    "line": self._line(value_node),
                })
        return findings

    # ── AXIOS ────────────────────────────────────────────────
    # { rejectUnauthorized: false } — anywhere as an object property, resolved
    # through the symbol table so `const INSECURE = false; ... rejectUnauthorized: INSECURE`
    # is also caught.

    def extract_axios(self, source):
        root, symbols, aliases = self._parse(source)
        findings = []
        for node in self._walk(root):
            if node.type != "pair":
                continue
            key_node = node.child_by_field_name("key")
            value_node = node.child_by_field_name("value")
            if key_node is None or value_node is None:
                continue
            key_text = self._text(key_node, source).strip("'\"`")
            if key_text != "rejectUnauthorized":
                continue
            value = self._resolve(value_node, source, symbols)
            if value == "false":
                findings.append({
                    "library": "axios",
                    "parameter": "rejectUnauthorized",
                    "value": "false",
                    "line": self._line(value_node),
                })
        return findings

    # ── EXPRESS ──────────────────────────────────────────────
    # cors({ origin: "*" }) — handles bare `cors(...)`, `require('cors')(...)`,
    # and any local alias of the cors module (e.g. `const corsMw = cors`).
    # Plus: express imported but helmet never mentioned.

    def extract_express(self, source):
        root, symbols, aliases = self._parse(source)
        findings = []

        # 1. CORS Configuration Check
        for node in self._walk(root):
            if node.type != "call_expression":
                continue
            fn = node.child_by_field_name("function")
            if fn is None:
                continue

            is_cors_call = False
            if fn.type == "identifier":
                name = self._text(fn, source)
                if name == "cors" or self._resolves_to(name, "cors", aliases, "default"):
                    is_cors_call = True
            elif fn.type == "call_expression":
                mod = self._require_module_name(fn, source)
                if mod == "cors":
                    is_cors_call = True

            if not is_cors_call:
                continue

            _, value_node = self._find_object_arg_containing(
                node, source, lambda k: k == "origin"
            )
            if value_node is not None:
                value = self._resolve(value_node, source, symbols)
                if value == "*":
                    findings.append({
                        "library": "express",
                        "parameter": "cors_origin",
                        "value": "*",
                        "line": self._line(value_node),
                    })

        # 2. Helmet Missing Check (Upgraded to use AST Imports)
        imports = self.extract_imports(source)
        if "express" in imports and "helmet" not in imports:
            findings.append({
                "library": "express",
                "parameter": "helmet",
                "value": "missing",
                "line": 1,
            })

        return findings

    # ── MONGOOSE ─────────────────────────────────────────────
    # strict: false  +  new mongoose.Schema({...}) missing required/validate

    def extract_mongoose(self, source):
        root, symbols, aliases = self._parse(source)
        findings = []

        for node in self._walk(root):
            if node.type != "pair":
                continue
            key_node = node.child_by_field_name("key")
            value_node = node.child_by_field_name("value")
            if key_node is None or value_node is None:
                continue
            key_text = self._text(key_node, source).strip("'\"`")
            if key_text == "strict" and self._resolve(value_node, source, symbols) == "false":
                findings.append({
                    "library": "mongoose",
                    "parameter": "strict",
                    "value": "false",
                    "line": self._line(value_node),
                })

        for node in self._walk(root):
            if node.type != "new_expression":
                continue
            ctor = node.child_by_field_name("constructor")
            if ctor is None:
                continue

            is_schema_ctor = False
            if ctor.type == "member_expression":
                obj = ctor.child_by_field_name("object")
                prop = ctor.child_by_field_name("property")
                if obj is not None and prop is not None:
                    if self._text(obj, source) == "mongoose" and self._text(prop, source) == "Schema":
                        is_schema_ctor = True
            elif ctor.type == "identifier":
                # e.g. const { Schema } = mongoose; new Schema({...})
                if self._text(ctor, source) == "Schema":
                    is_schema_ctor = True

            if not is_schema_ctor:
                continue

            args_node = node.child_by_field_name("arguments")
            schema_obj = None
            if args_node is not None:
                for c in args_node.children:
                    if c.type == "object":
                        schema_obj = c
                        break
            if schema_obj is None:
                continue

            if not self._schema_has_validation(schema_obj, source):
                findings.append({
                    "library": "mongoose",
                    "parameter": "validation",
                    "value": "missing",
                    "line": self._line(node),
                })

        return findings

    def _schema_has_validation(self, schema_obj, source):
        for key_text, value_node in self._object_properties(schema_obj, source):
            if key_text in ("required", "validate"):
                return True
            if value_node is not None and value_node.type == "object":
                for nested_key, _ in self._object_properties(value_node, source):
                    if nested_key in ("required", "validate"):
                        return True
        return False

    # ── LODASH ───────────────────────────────────────────────
    # (lodash|_).merge(..., req.*/body/params/query/user ...)  AND bare
    # `merge(...)` when `merge` was destructured from lodash.

    def extract_lodash(self, source):
        root, symbols, aliases = self._parse(source)
        findings = []
        tainted_hint = ("req.", "body", "params", "query", "user")

        for node in self._walk(root):
            if node.type != "call_expression":
                continue

            is_lodash_merge = False

            fn = node.child_by_field_name("function")
            if fn is None:
                continue

            if fn.type == "member_expression":
                obj = fn.child_by_field_name("object")
                prop = fn.child_by_field_name("property")
                if obj is not None and prop is not None and self._text(prop, source) == "merge":
                    obj_name = self._text(obj, source)
                    if obj_name in ("lodash", "_") or self._resolves_to(obj_name, "lodash", aliases):
                        is_lodash_merge = True
            elif fn.type == "identifier":
                name = self._text(fn, source)
                if self._resolves_to(name, "lodash", aliases, "merge") or self._resolves_to(name, "lodash.merge", aliases):
                    is_lodash_merge = True

            if not is_lodash_merge:
                continue

            args_node = node.child_by_field_name("arguments")
            if args_node is None:
                continue
            args_text = self._text(args_node, source).lower()
            if any(hint in args_text for hint in tainted_hint):
                findings.append({
                    "library": "lodash",
                    "parameter": "merge",
                    "value": "user_input",
                    "line": self._line(node),
                })

        return findings

    # ── IMPORTS (kept from original, unrelated to parsing engine choice) ──

    def extract_imports(self, source_code):
        tree = self.parser.parse(bytes(source_code, "utf8"))
        imports = []
        for node in self._walk(tree.root_node):
            if node.type == "call_expression":
                fn = node.child_by_field_name("function")
                if fn is not None and fn.type == "identifier" and self._text(fn, source_code) == "require":
                    args = self._call_args(node)
                    if args and args[0].type == "string":
                        imports.append(self._text(args[0], source_code).strip("'\"`"))
            if node.type == "import_statement":
                for child in node.children:
                    if child.type == "string":
                        imports.append(self._text(child, source_code).strip("'\"`"))
        return imports


class _NotALiteral:
    def __repr__(self):
        return "<NOT_A_LITERAL>"


_NOT_A_LITERAL = _NotALiteral()