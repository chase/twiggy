use super::Parse;
use anyhow::anyhow;
use core::ops::Range;
use std::collections::HashMap;
use twiggy_ir::{self as ir, Id};
use wasmparser::{self, FromReader, HeapType, Operator, SectionLimited, ValType};

#[derive(Default)]
pub struct SectionIndices {
    type_: Option<usize>,
    code: Option<usize>,
    functions: Vec<Id>,
    tables: Vec<Id>,
    memories: Vec<Id>,
    globals: Vec<Id>,
}

struct IndexedSection<'a>(usize, wasmparser::Payload<'a>);

struct CodeSection<'a> {
    index: usize,
    reader: wasmparser::CodeSectionReader<'a>,
    byte_size: usize,
}

struct FunctionSection<'a> {
    index: usize,
    reader: wasmparser::FunctionSectionReader<'a>,
    byte_size: usize,
}

pub struct ModuleReader<'a> {
    data: &'a [u8],
    offset: usize,
    parser: wasmparser::Parser,
}

impl<'a> ModuleReader<'a> {
    pub fn new(data: &[u8]) -> ModuleReader {
        ModuleReader {
            data,
            offset: 0,
            parser: wasmparser::Parser::new(0),
        }
    }

    fn current_position(&self) -> usize {
        self.offset
    }

    fn eof(&self) -> bool {
        self.offset == self.data.len()
    }

    fn read(&mut self) -> anyhow::Result<wasmparser::Payload<'a>> {
        let (section, bytes_consumed) =
            match self.parser.parse(&self.data[self.offset..], self.eof())? {
                wasmparser::Chunk::NeedMoreData { .. } => {
                    return Err(anyhow!("wasm binary cannot be fully parsed"));
                }
                wasmparser::Chunk::Parsed { consumed, payload } => (payload, consumed),
            };
        self.offset += bytes_consumed;
        Ok(section)
    }

    fn new_code_section(
        &self,
        index: usize,
        start_offset: usize,
        byte_range: Range<usize>,
    ) -> anyhow::Result<CodeSection<'a>> {
        Ok(CodeSection {
            index,
            reader: wasmparser::CodeSectionReader::new(
                &self.data[byte_range.start..byte_range.end],
                byte_range.start,
            )?,
            byte_size: byte_range.end - start_offset,
        })
    }
}

impl<'a> Parse<'a> for ModuleReader<'a> {
    type ItemsExtra = ();

    fn parse_items(&mut self, items: &mut ir::ItemsBuilder, _extra: ()) -> anyhow::Result<()> {
        let mut sections: Vec<IndexedSection<'_>> = Vec::new();
        let mut code_section: Option<CodeSection<'_>> = None;
        let mut function_section: Option<FunctionSection<'_>> = None;
        let mut sizes: HashMap<usize, u32> = HashMap::new();

        // The function and code sections must be handled differently, so these
        // are not placed in the same `sections` array as the rest.
        let mut idx = 0;
        loop {
            let start = self.current_position();
            let at_eof = self.offset == self.data.len();
            if at_eof {
                break;
            }
            let (section, bytes_consumed) =
                match self.parser.parse(&self.data[self.offset..], at_eof)? {
                    wasmparser::Chunk::NeedMoreData { .. } => {
                        return Err(anyhow!("wasm binary cannot be fully parsed"));
                    }
                    wasmparser::Chunk::Parsed { consumed, payload } => (payload, consumed),
                };
            self.offset += bytes_consumed;
            let size = self.current_position() - start;
            let indexed_section = IndexedSection(idx, section);
            match indexed_section.1 {
                wasmparser::Payload::CodeSectionStart { range, .. } => {
                    code_section = Some(self.new_code_section(idx, start, range)?);
                }
                wasmparser::Payload::FunctionSection(reader) => {
                    function_section = Some(FunctionSection {
                        index: idx,
                        byte_size: reader.range().end - start,
                        reader,
                    });
                }
                wasmparser::Payload::CodeSectionEntry { .. } => {
                    // Ignore.
                }
                _ => sections.push(indexed_section),
            };
            sizes.insert(idx, size as u32);
            idx += 1;
        }

        // Before we actually parse any items prepare to parse a few sections
        // below, namely the code section. When parsing the code section we want
        // to try to assign human-readable names so we need the name section, if
        // present. Additionally we need to look at the number of imported
        // functions to handle the wasm function index space correctly.
        let names = parse_names_section(&sections)?;
        let imported_functions = count_imported_functions(&sections)?;

        // Next, we parse the function and code sections together, so that we
        // can collapse corresponding entries from the code and function
        // sections into a single representative IR item.
        match (function_section, code_section) {
            (Some(function_section), Some(code_section)) => (function_section, code_section)
                .parse_items(items, (imported_functions, &names.function_names))?,
            _ => Err(anyhow!("function or code section is missing",))?,
        };

        for IndexedSection(idx, section) in sections.into_iter() {
            let start = items.size_added();
            let name = get_section_name(&section);
            match section {
                wasmparser::Payload::CustomSection(reader) => {
                    CustomSectionReader {
                        name: reader.name(),
                        data: reader.data(),
                        data_offset: reader.data_offset(),
                    }
                    .parse_items(items, idx)?;
                }
                wasmparser::Payload::TypeSection(mut reader) => {
                    reader.parse_items(items, idx)?;
                }
                wasmparser::Payload::ImportSection(mut reader) => {
                    reader.parse_items(items, idx)?;
                }
                wasmparser::Payload::TableSection(mut reader) => {
                    reader.parse_items(items, idx)?;
                }
                wasmparser::Payload::MemorySection(mut reader) => {
                    reader.parse_items(items, idx)?;
                }
                wasmparser::Payload::GlobalSection(mut reader) => {
                    reader.parse_items(items, idx)?;
                }
                wasmparser::Payload::ExportSection(mut reader) => {
                    reader.parse_items(items, idx)?;
                }
                wasmparser::Payload::StartSection { func, range } => {
                    StartSection {
                        function_index: func,
                        _data: &self.data[range.start..range.end],
                    }
                    .parse_items(items, idx)?;
                }
                wasmparser::Payload::ElementSection(mut reader) => {
                    reader.parse_items(items, idx)?;
                }
                wasmparser::Payload::DataSection(mut reader) => {
                    reader.parse_items(items, (idx, &names.data_names))?;
                }
                wasmparser::Payload::CodeSectionStart { .. }
                | wasmparser::Payload::FunctionSection(_) => {
                    unreachable!("unexpected code or function section found");
                }
                wasmparser::Payload::Version { .. }
                | wasmparser::Payload::CodeSectionEntry { .. }
                | wasmparser::Payload::TagSection { .. }
                | wasmparser::Payload::InstanceSection { .. }
                | wasmparser::Payload::UnknownSection { .. }
                | wasmparser::Payload::End { .. }
                | wasmparser::Payload::ModuleSection { .. }
                | wasmparser::Payload::CoreTypeSection(_)
                | wasmparser::Payload::ComponentSection { .. }
                | wasmparser::Payload::ComponentInstanceSection(_)
                | wasmparser::Payload::ComponentAliasSection(_)
                | wasmparser::Payload::ComponentTypeSection(_)
                | wasmparser::Payload::ComponentCanonicalSection(_)
                | wasmparser::Payload::ComponentStartSection { .. }
                | wasmparser::Payload::ComponentImportSection(_)
                | wasmparser::Payload::ComponentExportSection(_)
                | wasmparser::Payload::DataCountSection { .. } => {}
            };
            let id = Id::section(idx);
            let added = items.size_added() - start;
            let size = sizes
                .get(&idx)
                .ok_or_else(|| anyhow!("Could not find section size"))?;
            assert!(added <= *size);
            items.add_root(ir::Item::new(id, name, size - added, ir::Misc::new()));
        }

        Ok(())
    }

    type EdgesExtra = ();

    fn parse_edges(&mut self, items: &mut ir::ItemsBuilder, _extra: ()) -> anyhow::Result<()> {
        let mut sections: Vec<IndexedSection<'_>> = Vec::new();
        let mut code_section: Option<CodeSection<'a>> = None;
        let mut function_section: Option<FunctionSection<'a>> = None;

        let mut idx = 0;
        while !self.eof() {
            let section = self.read()?;
            let start = self.current_position();
            match section {
                wasmparser::Payload::CodeSectionStart { range, .. } => {
                    code_section = Some(self.new_code_section(idx, start, range)?);
                }
                wasmparser::Payload::FunctionSection(reader) => {
                    function_section = Some(FunctionSection {
                        index: idx,
                        byte_size: reader.range().end - start,
                        reader,
                    });
                }
                _ => sections.push(IndexedSection(idx, section)),
            };
            idx += 1;
        }

        // Like above we do some preprocessing here before actually drawing all
        // the edges below. Here we primarily want to learn some properties of
        // the wasm module, such as what `Id` is mapped to all index spaces in
        // the wasm module. To handle that we build up all this data in
        // `SectionIndices` here as we parse all the various sections.
        let mut indices = SectionIndices::default();
        for IndexedSection(idx, section) in sections.iter() {
            match section {
                wasmparser::Payload::TypeSection(_reader) => {
                    indices.type_ = Some(*idx);
                }
                wasmparser::Payload::ImportSection(reader) => {
                    for (i, import) in reader.clone().into_iter().enumerate() {
                        let id = Id::entry(*idx, i);
                        match import?.ty {
                            wasmparser::TypeRef::Func(_) => {
                                indices.functions.push(id);
                            }
                            wasmparser::TypeRef::Table(_) => {
                                indices.tables.push(id);
                            }
                            wasmparser::TypeRef::Memory(_) => {
                                indices.memories.push(id);
                            }
                            wasmparser::TypeRef::Global(_) => {
                                indices.globals.push(id);
                            }
                            wasmparser::TypeRef::Tag(_) => {}
                        }
                    }
                }
                wasmparser::Payload::GlobalSection(reader) => {
                    for i in 0..reader.count() {
                        let id = Id::entry(*idx, i as usize);
                        indices.globals.push(id);
                    }
                }
                wasmparser::Payload::MemorySection(reader) => {
                    for i in 0..reader.count() {
                        let id = Id::entry(*idx, i as usize);
                        indices.memories.push(id);
                    }
                }
                wasmparser::Payload::TableSection(reader) => {
                    for i in 0..reader.count() {
                        let id = Id::entry(*idx, i as usize);
                        indices.tables.push(id);
                    }
                }
                wasmparser::Payload::CodeSectionStart { .. } => {
                    Err(anyhow!("unexpected code section"))?
                }
                wasmparser::Payload::FunctionSection(_reader) => {
                    Err(anyhow!("unexpected function section"))?
                }
                _ => {}
            }
        }
        if let (Some(function_section), Some(code_section)) =
            (function_section.as_ref(), code_section.as_ref())
        {
            indices.code = Some(code_section.index);
            for i in 0..function_section.reader.count() {
                let id = Id::entry(code_section.index, i as usize);
                indices.functions.push(id);
            }
        }

        match (function_section, code_section) {
            (Some(function_section), Some(code_section)) => {
                (function_section, code_section).parse_edges(items, &indices)?
            }
            _ => panic!("function or code section is missing"),
        };
        for IndexedSection(idx, section) in sections.into_iter() {
            match section {
                wasmparser::Payload::CustomSection(reader) => {
                    CustomSectionReader {
                        name: reader.name(),
                        data: reader.data(),
                        data_offset: reader.data_offset(),
                    }
                    .parse_edges(items, ())?;
                }
                wasmparser::Payload::TypeSection(mut reader) => {
                    reader.parse_edges(items, ())?;
                }
                wasmparser::Payload::ImportSection(mut reader) => {
                    reader.parse_edges(items, ())?;
                }
                wasmparser::Payload::TableSection(mut reader) => {
                    reader.parse_edges(items, ())?;
                }
                wasmparser::Payload::MemorySection(mut reader) => {
                    reader.parse_edges(items, ())?;
                }
                wasmparser::Payload::GlobalSection(mut reader) => {
                    reader.parse_edges(items, ())?;
                }
                wasmparser::Payload::ExportSection(mut reader) => {
                    reader.parse_edges(items, (&indices, idx))?;
                }
                wasmparser::Payload::StartSection { func, range } => {
                    StartSection {
                        function_index: func,
                        _data: &self.data[range.start..range.end],
                    }
                    .parse_edges(items, (&indices, idx))?;
                }
                wasmparser::Payload::ElementSection(mut reader) => {
                    reader.parse_edges(items, (&indices, idx))?;
                }
                wasmparser::Payload::DataSection(mut reader) => {
                    reader.parse_edges(items, ())?;
                }
                wasmparser::Payload::CodeSectionStart { .. }
                | wasmparser::Payload::FunctionSection { .. } => {
                    unreachable!("unexpected code or function section found");
                }
                wasmparser::Payload::Version { .. }
                | wasmparser::Payload::CodeSectionEntry { .. }
                | wasmparser::Payload::TagSection { .. }
                | wasmparser::Payload::InstanceSection { .. }
                | wasmparser::Payload::UnknownSection { .. }
                | wasmparser::Payload::End { .. }
                | wasmparser::Payload::ModuleSection { .. }
                | wasmparser::Payload::CoreTypeSection(_)
                | wasmparser::Payload::ComponentSection { .. }
                | wasmparser::Payload::ComponentInstanceSection(_)
                | wasmparser::Payload::ComponentAliasSection(_)
                | wasmparser::Payload::ComponentTypeSection(_)
                | wasmparser::Payload::ComponentCanonicalSection(_)
                | wasmparser::Payload::ComponentStartSection { .. }
                | wasmparser::Payload::ComponentImportSection(_)
                | wasmparser::Payload::ComponentExportSection(_)
                | wasmparser::Payload::DataCountSection { .. } => {}
            }
        }

        Ok(())
    }
}

fn get_code_section_name() -> String {
    "code section headers".to_string()
}

fn get_section_name(section: &wasmparser::Payload<'_>) -> String {
    match section {
        wasmparser::Payload::CustomSection(reader) => {
            format!("custom section '{}' headers", reader.name())
        }
        wasmparser::Payload::TypeSection(_) => "type section headers".to_string(),
        wasmparser::Payload::ImportSection(_) => "import section headers".to_string(),
        wasmparser::Payload::FunctionSection(_) => "function section headers".to_string(),
        wasmparser::Payload::TableSection(_) => "table section headers".to_string(),
        wasmparser::Payload::MemorySection(_) => "memory section headers".to_string(),
        wasmparser::Payload::GlobalSection(_) => "global section headers".to_string(),
        wasmparser::Payload::ExportSection(_) => "export section headers".to_string(),
        wasmparser::Payload::StartSection { .. } => "start section headers".to_string(),
        wasmparser::Payload::ElementSection(_) => "element section headers".to_string(),
        wasmparser::Payload::CodeSectionStart { .. } => get_code_section_name(),
        wasmparser::Payload::DataSection(_) => "data section headers".to_string(),
        wasmparser::Payload::DataCountSection { .. } => "data count section headers".to_string(),
        wasmparser::Payload::Version { .. } => "wasm magic bytes".to_string(),

        wasmparser::Payload::CodeSectionEntry { .. } => {
            panic!("unexpected CodeSectionEntry");
        }
        wasmparser::Payload::TagSection { .. }
        | wasmparser::Payload::InstanceSection { .. }
        | wasmparser::Payload::ModuleSection { .. }
        | wasmparser::Payload::ComponentSection { .. }
        | wasmparser::Payload::ComponentStartSection { .. }
        | wasmparser::Payload::UnknownSection { .. }
        | wasmparser::Payload::End { .. } => format!("{:?}", section),

        wasmparser::Payload::CoreTypeSection(_) => todo!(),
        wasmparser::Payload::ComponentInstanceSection(_) => todo!(),
        wasmparser::Payload::ComponentAliasSection(_) => todo!(),
        wasmparser::Payload::ComponentTypeSection(_) => todo!(),
        wasmparser::Payload::ComponentCanonicalSection(_) => todo!(),
        wasmparser::Payload::ComponentImportSection(_) => todo!(),
        wasmparser::Payload::ComponentExportSection(_) => todo!(),
    }
}

#[derive(Default)]
struct Names<'a> {
    function_names: HashMap<usize, &'a str>,
    data_names: HashMap<usize, &'a str>,
}

fn parse_names_section<'a>(indexed_sections: &[IndexedSection<'a>]) -> anyhow::Result<Names<'a>> {
    let mut names = Names::default();
    for IndexedSection(_, section) in indexed_sections.iter() {
        if let wasmparser::Payload::CustomSection(reader) = section {
            for subsection in
                wasmparser::NameSectionReader::new(reader.data(), reader.data_offset())
            {
                // We use a rather old version of wasmparser. This is a workaround
                // to skip new types of name subsections instead of aborting.
                let subsection = if let Ok(subsection) = subsection {
                    subsection
                } else {
                    continue;
                };
                match subsection {
                    wasmparser::Name::Function(f) => {
                        for naming in f {
                            if let Ok(naming) = naming {
                                names
                                    .function_names
                                    .insert(naming.index as usize, naming.name);
                            } else {
                                continue;
                            }
                        }
                    }
                    wasmparser::Name::Data(d) => {
                        for naming in d {
                            if let Ok(naming) = naming {
                                names.data_names.insert(naming.index as usize, naming.name);
                            } else {
                                continue;
                            }
                        }
                    }
                    _ => continue,
                };
            }
        }
    }
    Ok(names)
}

fn count_imported_functions(indexed_sections: &[IndexedSection<'_>]) -> anyhow::Result<usize> {
    let mut imported_functions = 0;
    for IndexedSection(_, section) in indexed_sections.iter() {
        if let wasmparser::Payload::ImportSection(reader) = section {
            for import in reader.clone() {
                if let wasmparser::TypeRef::Func(_) = import?.ty {
                    imported_functions += 1;
                }
            }
        }
    }
    Ok(imported_functions)
}

impl<'a> Parse<'a> for (FunctionSection<'a>, CodeSection<'a>) {
    type ItemsExtra = (usize, &'a HashMap<usize, &'a str>);

    fn parse_items(
        &mut self,
        items: &mut ir::ItemsBuilder,
        (imported_functions, names): Self::ItemsExtra,
    ) -> anyhow::Result<()> {
        let (func_section, code_section) = self;

        let func_section_index = func_section.index;
        let func_items: Vec<ir::Item> = iterate_with_size(&func_section.reader)
            .enumerate()
            .map(|(i, func)| {
                let (_func, size) = func?;
                let id = Id::entry(func_section_index, i);
                let name = format!("func[{}]", i);
                let item = ir::Item::new(id, name, size, ir::Misc::new());
                Ok(item)
            })
            .collect::<anyhow::Result<_>>()?;

        let code_section_index = code_section.index;
        let code_items: Vec<ir::Item> = iterate_with_size(&code_section.reader)
            .zip(func_items.into_iter())
            .enumerate()
            .map(|(i, (body, func))| {
                let (_body, size) = body?;
                let id = Id::entry(code_section_index, i);
                let name = names
                    .get(&(i + imported_functions))
                    .map_or_else(|| format!("code[{}]", i), |name| name.to_string());
                let code = ir::Code::new(&name);
                let item = ir::Item::new(id, name, size + func.size(), code);
                Ok(item)
            })
            .collect::<anyhow::Result<_>>()?;

        let start = items.size_added();
        let name = get_code_section_name();
        for item in code_items.into_iter() {
            items.add_item(item);
        }
        let id = Id::section(code_section.index);
        let added = items.size_added() - start;
        let code_section_size = code_section.byte_size as u32;
        let func_section_size = func_section.byte_size as u32;
        let size = code_section_size + func_section_size;

        assert!(added <= size);
        items.add_root(ir::Item::new(id, name, size - added, ir::Misc::new()));

        Ok(())
    }

    type EdgesExtra = &'a SectionIndices;

    fn parse_edges(
        &mut self,
        items: &mut ir::ItemsBuilder,
        indices: Self::EdgesExtra,
    ) -> anyhow::Result<()> {
        let (function_section, code_section) = self;

        type Edge = (ir::Id, ir::Id);

        let mut edges: Vec<Edge> = Vec::new();

        // Function section reader parsing.
        for (func_i, type_ref) in iterate_with_size(&function_section.reader).enumerate() {
            let (type_ref, _) = type_ref?;
            if let Some(type_idx) = indices.type_ {
                let type_id = Id::entry(type_idx, type_ref as usize);
                if let Some(code_idx) = indices.code {
                    let body_id = Id::entry(code_idx, func_i);
                    edges.push((body_id, type_id));
                }
            }
        }

        // Code section reader parsing.
        for (b_i, body) in iterate_with_size(&code_section.reader).enumerate() {
            let (body, _size) = body?;
            let body_id = Id::entry(code_section.index, b_i);

            let mut cache = None;
            for op in body.get_operators_reader()? {
                let prev = cache.take();
                match op? {
                    Operator::Call { function_index } => {
                        let f_id = indices.functions[function_index as usize];
                        edges.push((body_id, f_id));
                    }

                    // TODO: Rather than looking at indirect calls, need to look
                    // at where the vtables get initialized and/or vtable
                    // indices get pushed onto the stack.
                    Operator::CallIndirect { .. } => continue,

                    Operator::GlobalGet { global_index } | Operator::GlobalSet { global_index } => {
                        let g_id = indices.globals[global_index as usize];
                        edges.push((body_id, g_id));
                    }

                    Operator::I32Load { memarg }
                    | Operator::I32Load8S { memarg }
                    | Operator::I32Load8U { memarg }
                    | Operator::I32Load16S { memarg }
                    | Operator::I32Load16U { memarg }
                    | Operator::I64Load { memarg }
                    | Operator::I64Load8S { memarg }
                    | Operator::I64Load8U { memarg }
                    | Operator::I64Load16S { memarg }
                    | Operator::I64Load16U { memarg }
                    | Operator::I64Load32S { memarg }
                    | Operator::I64Load32U { memarg }
                    | Operator::F32Load { memarg }
                    | Operator::F64Load { memarg } => {
                        if let Some(Operator::I32Const { value }) = prev {
                            if let Some(data_id) = items.get_data(value as u64 + memarg.offset) {
                                edges.push((body_id, data_id));
                            }
                        }
                    }
                    other => cache = Some(other),
                }
            }
        }

        edges
            .into_iter()
            .for_each(|(from, to)| items.add_edge(from, to));

        Ok(())
    }
}

impl<'a> Parse<'a> for wasmparser::NameSectionReader<'a> {
    type ItemsExtra = usize;

    fn parse_items(&mut self, items: &mut ir::ItemsBuilder, idx: usize) -> anyhow::Result<()> {
        let mut i = 0;
        loop {
            let start = self.original_position();
            if let Some(section) = self.next() {
                let subsection = if let Ok(subsection) = section {
                    subsection
                } else {
                    continue;
                };
                let size = (self.original_position() - start) as u32;
                let name = match subsection {
                    wasmparser::Name::Module { .. } => "\"module name\" subsection",
                    wasmparser::Name::Function(_) => "\"function names\" subsection",
                    wasmparser::Name::Local(_) => "\"local names\" subsection",
                    wasmparser::Name::Unknown { .. } => "\"unknown name\" subsection",
                    wasmparser::Name::Label(_) => "\"label names\" subsection",
                    wasmparser::Name::Type(_) => "\"type names\" subsection",
                    wasmparser::Name::Table(_) => "\"table names\" subsection",
                    wasmparser::Name::Memory(_) => "\"memory names\" subsection",
                    wasmparser::Name::Global(_) => "\"global names\" subsection",
                    wasmparser::Name::Element(_) => "\"element names\" subsection",
                    wasmparser::Name::Data(_) => "\"data names\" subsection",
                    wasmparser::Name::Field(_) => "\"field names\" subsection",
                    wasmparser::Name::Tag(_) => "\"tag names\" subsection",
                };
                let id = Id::entry(idx, i);
                items.add_root(ir::Item::new(id, name, size, ir::DebugInfo::new()));
                i += 1;
            } else {
                break;
            }
        }

        Ok(())
    }

    type EdgesExtra = ();

    fn parse_edges(&mut self, _: &mut ir::ItemsBuilder, _: ()) -> anyhow::Result<()> {
        Ok(())
    }
}

struct CustomSectionReader<'a> {
    name: &'a str,
    data: &'a [u8],
    data_offset: usize,
}

impl<'a> Parse<'a> for CustomSectionReader<'a> {
    type ItemsExtra = usize;

    fn parse_items(&mut self, items: &mut ir::ItemsBuilder, idx: usize) -> anyhow::Result<()> {
        if self.name == "name" {
            wasmparser::NameSectionReader::new(self.data, self.data_offset)
                .parse_items(items, idx)?;
        } else {
            let size = self.data.len() as u32;
            let id = Id::entry(idx, 0);
            let name = format!("custom section '{}'", self.name);
            items.add_item(ir::Item::new(id, name, size, ir::Misc::new()));
        }
        Ok(())
    }

    type EdgesExtra = ();

    fn parse_edges(&mut self, _: &mut ir::ItemsBuilder, _: ()) -> anyhow::Result<()> {
        Ok(())
    }
}

impl<'a> Parse<'a> for wasmparser::TypeSectionReader<'a> {
    type ItemsExtra = usize;

    fn parse_items(&mut self, items: &mut ir::ItemsBuilder, idx: usize) -> anyhow::Result<()> {
        for (i, group) in iterate_with_size(self).enumerate() {
            let (group, size) = group?;
            let id = Id::entry(idx, i);
            let mut types = group.into_types();
            let ty = match (types.next(), types.next()) {
                (Some(ty), None) => ty,
                // TODO: handle GC types
                _ => continue,
            };
            if !ty.is_final || ty.supertype_idx.is_some() {
                // TODO: handle GC types
                continue;
            }
            let func = match ty.composite_type {
                wasmparser::CompositeType::Func(f) => f,
                // TODO: handle GC types
                _ => continue,
            };

            let mut name = format!("type[{}]: (", i);
            for (i, param) in func.params().iter().enumerate() {
                if i != 0 {
                    name.push_str(", ");
                }
                name.push_str(ty2str(*param));
            }
            name.push_str(") -> ");

            match func.results().len() {
                0 => name.push_str("nil"),
                1 => name.push_str(ty2str(func.results()[0])),
                _ => {
                    name.push('(');
                    for (i, result) in func.results().iter().enumerate() {
                        if i != 0 {
                            name.push_str(", ");
                        }
                        name.push_str(ty2str(*result));
                    }
                    name.push(')');
                }
            }

            items.add_item(ir::Item::new(id, name, size, ir::Misc::new()));
        }
        Ok(())
    }

    type EdgesExtra = ();

    fn parse_edges(&mut self, _: &mut ir::ItemsBuilder, _: ()) -> anyhow::Result<()> {
        Ok(())
    }
}

impl<'a> Parse<'a> for wasmparser::ImportSectionReader<'a> {
    type ItemsExtra = usize;

    fn parse_items(&mut self, items: &mut ir::ItemsBuilder, idx: usize) -> anyhow::Result<()> {
        for (i, imp) in iterate_with_size(self).enumerate() {
            let (imp, size) = imp?;
            let id = Id::entry(idx, i);
            let name = format!("import {}::{}", imp.module, imp.name);
            items.add_item(ir::Item::new(id, name, size, ir::Misc::new()));
        }
        Ok(())
    }

    type EdgesExtra = ();

    fn parse_edges(&mut self, _: &mut ir::ItemsBuilder, (): ()) -> anyhow::Result<()> {
        Ok(())
    }
}

impl<'a> Parse<'a> for wasmparser::TableSectionReader<'a> {
    type ItemsExtra = usize;

    fn parse_items(&mut self, items: &mut ir::ItemsBuilder, idx: usize) -> anyhow::Result<()> {
        for (i, entry) in iterate_with_size(self).enumerate() {
            let (_entry, size) = entry?;
            let id = Id::entry(idx, i);
            let name = format!("table[{}]", i);
            items.add_root(ir::Item::new(id, name, size, ir::Misc::new()));
        }
        Ok(())
    }

    type EdgesExtra = ();

    fn parse_edges(&mut self, _: &mut ir::ItemsBuilder, _: ()) -> anyhow::Result<()> {
        Ok(())
    }
}

impl<'a> Parse<'a> for wasmparser::MemorySectionReader<'a> {
    type ItemsExtra = usize;

    fn parse_items(&mut self, items: &mut ir::ItemsBuilder, idx: usize) -> anyhow::Result<()> {
        for (i, mem) in iterate_with_size(self).enumerate() {
            let (_mem, size) = mem?;
            let id = Id::entry(idx, i);
            let name = format!("memory[{}]", i);
            items.add_item(ir::Item::new(id, name, size, ir::Misc::new()));
        }
        Ok(())
    }

    type EdgesExtra = ();

    fn parse_edges(&mut self, _: &mut ir::ItemsBuilder, _: ()) -> anyhow::Result<()> {
        Ok(())
    }
}

impl<'a> Parse<'a> for wasmparser::GlobalSectionReader<'a> {
    type ItemsExtra = usize;

    fn parse_items(&mut self, items: &mut ir::ItemsBuilder, idx: usize) -> anyhow::Result<()> {
        for (i, g) in iterate_with_size(self).enumerate() {
            let (g, size) = g?;
            let id = Id::entry(idx, i);
            let name = format!("global[{}]", i);
            let ty = ty2str(g.ty.content_type).to_string();
            items.add_item(ir::Item::new(id, name, size, ir::Data::new(Some(ty))));
        }
        Ok(())
    }

    type EdgesExtra = ();

    fn parse_edges(&mut self, _: &mut ir::ItemsBuilder, _: ()) -> anyhow::Result<()> {
        Ok(())
    }
}

impl<'a> Parse<'a> for wasmparser::ExportSectionReader<'a> {
    type ItemsExtra = usize;

    fn parse_items(&mut self, items: &mut ir::ItemsBuilder, idx: usize) -> anyhow::Result<()> {
        for (i, exp) in iterate_with_size(self).enumerate() {
            let (exp, size) = exp?;
            let id = Id::entry(idx, i);
            let name = format!("export \"{}\"", exp.name);
            items.add_root(ir::Item::new(id, name, size, ir::Misc::new()));
        }
        Ok(())
    }

    type EdgesExtra = (&'a SectionIndices, usize);

    fn parse_edges(
        &mut self,
        items: &mut ir::ItemsBuilder,
        (indices, idx): Self::EdgesExtra,
    ) -> anyhow::Result<()> {
        for (i, exp) in iterate_with_size(self).enumerate() {
            let (exp, _) = exp?;
            let exp_id = Id::entry(idx, i);
            match exp.kind {
                wasmparser::ExternalKind::Func => {
                    items.add_edge(exp_id, indices.functions[exp.index as usize]);
                }
                wasmparser::ExternalKind::Table => {
                    items.add_edge(exp_id, indices.tables[exp.index as usize]);
                }
                wasmparser::ExternalKind::Memory => {
                    items.add_edge(exp_id, indices.memories[exp.index as usize]);
                }
                wasmparser::ExternalKind::Global => {
                    items.add_edge(exp_id, indices.globals[exp.index as usize]);
                }
                _ => {}
            }
        }

        Ok(())
    }
}

struct StartSection<'a> {
    function_index: u32,
    _data: &'a [u8], // We only need the size.
}

impl<'a> Parse<'a> for StartSection<'a> {
    type ItemsExtra = usize;

    fn parse_items(&mut self, _: &mut ir::ItemsBuilder, _: usize) -> anyhow::Result<()> {
        Ok(())
    }

    type EdgesExtra = (&'a SectionIndices, usize);

    fn parse_edges(
        &mut self,
        items: &mut ir::ItemsBuilder,
        (indices, idx): Self::EdgesExtra,
    ) -> anyhow::Result<()> {
        items.add_edge(
            Id::section(idx),
            indices.functions[self.function_index as usize],
        );
        Ok(())
    }
}

impl<'a> Parse<'a> for wasmparser::ElementSectionReader<'a> {
    type ItemsExtra = usize;

    fn parse_items(&mut self, items: &mut ir::ItemsBuilder, idx: usize) -> anyhow::Result<()> {
        for (i, elem) in iterate_with_size(self).enumerate() {
            let (_elem, size) = elem?;
            let id = Id::entry(idx, i);
            let name = format!("elem[{}]", i);
            items.add_item(ir::Item::new(id, name, size, ir::Misc::new()));
        }
        Ok(())
    }

    type EdgesExtra = (&'a SectionIndices, usize);

    fn parse_edges(
        &mut self,
        items: &mut ir::ItemsBuilder,
        (indices, idx): Self::EdgesExtra,
    ) -> anyhow::Result<()> {
        for (i, elem) in iterate_with_size(self).enumerate() {
            let (elem, _size) = elem?;
            let elem_id = Id::entry(idx, i);

            // TODO handle const expressions
            let section = match elem.items {
                wasmparser::ElementItems::Functions(f) => f,
                wasmparser::ElementItems::Expressions(_, _) => continue,
            };

            match elem.kind {
                wasmparser::ElementKind::Active { table_index, .. } => {
                    if let Some(table_index) = table_index {
                        items.add_edge(indices.tables[table_index as usize], elem_id);
                    }
                }
                wasmparser::ElementKind::Declared => {}
                wasmparser::ElementKind::Passive => {}
            }
            for func_idx in section {
                items.add_edge(elem_id, indices.functions[func_idx? as usize]);
            }
        }

        Ok(())
    }
}

impl<'a> Parse<'a> for wasmparser::DataSectionReader<'a> {
    type ItemsExtra = (usize, &'a HashMap<usize, &'a str>);

    fn parse_items(
        &mut self,
        items: &mut ir::ItemsBuilder,
        (idx, names): Self::ItemsExtra,
    ) -> anyhow::Result<()> {
        for (i, d) in iterate_with_size(self).enumerate() {
            let (d, size) = d?;
            let id = Id::entry(idx, i);
            let name = names.get(&i).map_or_else(
                || format!("data[{}]", i),
                |name| format!("data segment \"{}\"", name),
            );
            items.add_item(ir::Item::new(id, name, size, ir::Data::new(None)));

            // Get the constant address (if any) from the initialization
            // expression.
            if let wasmparser::DataKind::Active { offset_expr, .. } = d.kind {
                let mut iter = offset_expr.get_operators_reader();
                let offset = match iter.read()? {
                    Operator::I32Const { value } => Some(i64::from(value)),
                    Operator::I64Const { value } => Some(value),
                    _ => None,
                };

                if let Some(off) = offset {
                    let length = d.data.len(); // size of data
                    items.link_data(off, length, id);
                }
            }
        }
        Ok(())
    }

    type EdgesExtra = ();

    fn parse_edges(&mut self, _: &mut ir::ItemsBuilder, _: ()) -> anyhow::Result<()> {
        Ok(())
    }
}

/// An iterator that returns items along with the difference to the next offset.
pub struct SectionLimitedIntoIterWithOffsetDiff<'a, T> {
    iter: wasmparser::SectionLimitedIntoIter<'a, T>,
}

impl<'a, T> Iterator for SectionLimitedIntoIterWithOffsetDiff<'a, T>
where
    T: FromReader<'a>,
{
    type Item = anyhow::Result<(T, u32)>;

    fn next(&mut self) -> Option<Self::Item> {
        let current_pos = self.iter.original_position();
        self.iter.next().map(|result| {
            let next_pos = self.iter.original_position();
            let offset_diff = if next_pos > current_pos {
                next_pos - current_pos
            } else {
                0 // Handle potential underflow if next_pos is not greater
            };
            result
                .map(|item| (item, offset_diff as u32))
                .map_err(anyhow::Error::new)
        })
    }
}

fn iterate_with_size<'a, S>(
    s: &'a SectionLimited<'a, S>,
) -> impl Iterator<Item = anyhow::Result<(S, u32)>> + 'a
where
    S: FromReader<'a>,
{
    SectionLimitedIntoIterWithOffsetDiff {
        iter: s.clone().into_iter(),
    }
}

fn ty2str(t: ValType) -> &'static str {
    match t {
        ValType::I32 => "i32",
        ValType::I64 => "i64",
        ValType::F32 => "f32",
        ValType::F64 => "f64",
        ValType::V128 => "v128",
        ValType::Ref(r) => match (r.is_nullable(), r.heap_type()) {
            (true, HeapType::Any) => "anyref",
            (false, HeapType::Any) => "(ref any)",
            (true, HeapType::None) => "nullref",
            (false, HeapType::None) => "(ref none)",
            (true, HeapType::NoExtern) => "nullexternref",
            (false, HeapType::NoExtern) => "(ref noextern)",
            (true, HeapType::NoFunc) => "nullfuncref",
            (false, HeapType::NoFunc) => "(ref nofunc)",
            (true, HeapType::Eq) => "eqref",
            (false, HeapType::Eq) => "(ref eq)",
            (true, HeapType::Struct) => "structref",
            (false, HeapType::Struct) => "(ref struct)",
            (true, HeapType::Array) => "arrayref",
            (false, HeapType::Array) => "(ref array)",
            (true, HeapType::I31) => "i31ref",
            (false, HeapType::I31) => "(ref i31)",
            (true, HeapType::Extern) => "externref",
            (false, HeapType::Extern) => "(ref extern)",
            (true, HeapType::Func) => "funcref",
            (false, HeapType::Func) => "(ref func)",
            (true, HeapType::Exn) => "exnref",
            (false, HeapType::Exn) => "(ref exn)",
            (true, HeapType::NoExn) => "nullexnref",
            (false, HeapType::NoExn) => "(ref noexn)",
            (true, HeapType::Concrete(_)) => "(ref null #)",
            (false, HeapType::Concrete(_)) => "(ref #)",
        },
    }
}
