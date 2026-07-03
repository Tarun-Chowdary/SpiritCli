from tree_sitter import Language, Parser
import tree_sitter_python as tspy

# Initialize the Python AST Parser
PY_LANGUAGE = Language(tspy.language())

class PythonExtractor:
    def __init__(self):
        self.parser = Parser(PY_LANGUAGE)

    def extract_all(self, source_code, filepath):
        results = []
        results.extend(self.extract_requests_ssl(source_code))
        return results

    def _text(self, node, source):
        # Using the same bulletproof byte-slicing logic we used for JS
        if isinstance(source, str):
            return source.encode('utf8')[node.start_byte:node.end_byte].decode('utf8', errors='ignore')
        return source[node.start_byte:node.end_byte].decode('utf8', errors='ignore')

    def extract_requests_ssl(self, source):
        """
        Catches: requests.get(..., verify=False) or requests.post(..., verify=False)
        """
        tree = self.parser.parse(bytes(source, "utf8"))
        findings = []

        def walk(node):
            # Look for keyword arguments in function calls
            if node.type == "keyword_argument":
                name_node = node.child_by_field_name("name")
                value_node = node.child_by_field_name("value")
                
                if name_node and value_node:
                    param_name = self._text(name_node, source)
                    param_value = self._text(value_node, source)

                    # If verify=False is passed
                    if param_name == "verify" and param_value == "False":
                        findings.append({
                            "library": "requests",
                            "parameter": "verify",
                            "value": False,
                            "line": node.start_point[0] + 1
                        })

            for child in node.children:
                walk(child)

        walk(tree.root_node)
        return findings