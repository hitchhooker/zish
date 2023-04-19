# zish
i interpreter bash into zig.


## Structures
zish/
├── build.zig
├── src/
│   ├── main.zig
│   ├── lexer.zig
│   ├── parser.zig
│   ├── ast.zig
│   ├── evaluator.zig
│   ├── utils.zig
│   └── error.zig
├── tests/
│   ├── test_runner.zig
│   ├── lexer_test.zig
│   ├── parser_test.zig
│   ├── evaluator_test.zig
│   └── test_data/
│       ├── test_script_1.zish
│       ├── test_script_2.zish
│       └── ...
├── examples/
│   ├── example_1.zish
│   ├── example_2.zish
│   └── ...
└── zig-cache/

build.zig: The build file for the Zig project.
src/: Contains the source code for the Zish interpreter.
main.zig: The entry point for the Zish interpreter application.
lexer.zig: Contains the lexer implementation to tokenize the input script.
parser.zig: Contains the parser implementation to create an abstract syntax tree (AST) from the tokens.
ast.zig: Contains the data structures for the abstract syntax tree (AST).
evaluator.zig: Contains the evaluator implementation to execute the code represented by the AST.
utils.zig: Contains utility functions and helpers for the project.
error.zig: Contains error handling and custom error types for the project.
tests/: Contains the test code for the Zish interpreter.
test_runner.zig: The entry point for running the test suite.
lexer_test.zig: Contains test cases for the lexer.
parser_test.zig: Contains test cases for the parser.
evaluator_test.zig: Contains test cases for the evaluator.
test_data/: Contains sample Zish script files for use in test cases.
examples/: Contains example Zish script files demonstrating various features of the language.
zig-cache/: Contains build artifacts and cache files generated by the Zig compiler.
