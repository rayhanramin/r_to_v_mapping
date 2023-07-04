import os
import sys
import re
import openpyxl
from pydriller import RepositoryMining
import jedi
import javalang
import clang.cindex
import esprima

# Set the desired recursion limit
sys.setrecursionlimit(10**6)

# Initialize Excel workbook and worksheet
workbook = openpyxl.Workbook()
worksheet = workbook.active
worksheet.append(['Language', 'Commit Hash', 'Modified File', 'Modified Function', 'Bug ID'])

# Define the repository path and URL
repo_path = 'd:\primary research\extract.py\kafka'
repo_url = 'https://github.com/apache/kafka'

# Define regex pattern for identifying Bug IDs in commit messages
bug_id_pattern = r'KAFKA-\d+'
#r'Bug\s+(\d+)'

# Define function to extract modified function names from Python code using Jedi
def extract_python_functions(code):
    functions = []
    script = jedi.Script(code)
    definitions = script.goto_definitions()
    for definition in definitions:
        if definition.type == 'function':
            functions.append(definition.name)
    return functions

# Define function to extract modified function names from Java code using javalang
def extract_java_functions(code):
    functions = []
    tree = javalang.parse.parse(code)
    for path, node in tree.filter(javalang.tree.MethodDeclaration):
        functions.append(node.name)
    return functions

# Define function to extract modified function names from C/C++ code using clang
def extract_cpp_functions(code):
    functions = []
    index = clang.cindex.Index.create()
    tu = index.parse("temp.cpp", args=['-std=c++11'], unsaved_files=[("temp.cpp", code)])
    for node in tu.cursor.walk_preorder():
        if node.kind == clang.cindex.CursorKind.FUNCTION_DECL:
            functions.append(node.spelling)
    return functions

# Define function to extract modified function names from JavaScript code using esprima
def extract_javascript_functions(code):
    functions = []
    ast = esprima.parseScript(code)
    for node in ast.body:
        if node.type == 'FunctionDeclaration':
            functions.append(node.id.name)
        elif node.type == 'FunctionExpression':
            if node.id:
                functions.append(node.id.name)
    return functions

# Iterate over the commits in the repository
for commit in RepositoryMining(repo_path, clone_url=repo_url).traverse_commits():
    try:
        commit_hash = commit.hash
        commit_message = commit.msg
        bug_ids = re.findall(bug_id_pattern, commit_message)
        
        # Proceed only if Bug IDs are found in the commit message
        if bug_ids:
            for modified_file in commit.modifications:
                file_path = modified_file.filename
                language = modified_file.language
                code = modified_file.source_code

                # Extract modified function names based on the language
                if language == 'Python':
                    functions = extract_python_functions(code)
                elif language == 'Java':
                    functions = extract_java_functions(code)
                elif language in ['C', 'C++']:
                    functions = extract_cpp_functions(code)
                elif language == 'JavaScript':
                    functions = extract_javascript_functions(code)

                # Write the extracted information to the Excel worksheet
                for function in functions:
                    for bug_id in bug_ids:
                        worksheet.append([language, commit_hash, file_path, function, bug_id])

    except Exception as e:
        # Code to handle the error
        print(f"An error occurred: {str(e)}")
        # Skip to the next iteration
        continue

# Save the Excel workbook
output_file = 'output.xlsx'
workbook.save(output_file)
print(f"Data saved to {output_file}")
