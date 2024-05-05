test!(top_mappings, "top", "-n", "10", "./fixtures/mappings.wasm");

test!(
    top_wee_alloc,
    "top",
    "-n",
    "10",
    "./fixtures/wee_alloc.wasm"
);

test!(
    top_retained_wee_alloc,
    "top",
    "-n",
    "10",
    "--retained",
    "./fixtures/wee_alloc.wasm"
);

test!(
    top_retained_mappings,
    "top",
    "-n",
    "10",
    "--retained",
    "./fixtures/mappings.wasm"
);

test!(
    top_2_json,
    "top",
    "./fixtures/wee_alloc.wasm",
    "-n",
    "2",
    "-f",
    "json"
);

test!(
    top_2_json_retained,
    "top",
    "./fixtures/wee_alloc.wasm",
    "--retained",
    "-n",
    "2",
    "-f",
    "json"
);

test!(
    top_2_csv,
    "top",
    "./fixtures/wee_alloc.wasm",
    "-n",
    "4",
    "-f",
    "csv"
);

test!(
    top_2_csv_retained,
    "top",
    "./fixtures/wee_alloc.wasm",
    "--retained",
    "-n",
    "4",
    "-f",
    "csv"
);

// This should not fail to open and write `whatever-output.txt`.
test!(
    output_to_file,
    "top",
    "./fixtures/wee_alloc.wasm",
    "-o",
    "whatever-output.txt"
);

// Regression test for https://github.com/rustwasm/twiggy/issues/151
test!(top_mono, "top", "./fixtures/mono.wasm", "-n", "10");

test!(
    top_memory_module,
    "top",
    "./fixtures/memory.wasm",
    "-n",
    "10"
);
