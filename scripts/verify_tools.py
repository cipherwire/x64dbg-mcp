import ast
import sys

with open('mcp_server/server.py', 'r', encoding='utf-8') as f:
    tree = ast.parse(f.read())

tools = []
for node in ast.walk(tree):
    if isinstance(node, ast.FunctionDef):
        for d in node.decorator_list:
            if isinstance(d, ast.Call) and getattr(d.func, 'attr', '') == 'tool':
                tools.append(node.name)
                break

print(f"Discovered {len(tools)} tools in server.py")
if len(tools) != 234:
    print(f"Expected 234 tools, found {len(tools)}")
    sys.exit(1)
print("Tool count assertion passed.")
