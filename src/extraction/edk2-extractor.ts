import * as path from 'path';
import { Edge, ExtractionError, ExtractionResult, Node, UnresolvedReference } from '../types';
import { generateNodeId } from './tree-sitter-helpers';

/**
 * Edk2Extractor — parses EDK2 / UEFI firmware descriptor files.
 *
 * EDK2 describes a firmware module across INI-style files that a tree-sitter
 * grammar can't usefully parse (there is no INI grammar in tree-sitter-wasms):
 *
 *   - `.inf`  Module definition: BASE_NAME, ENTRY_POINT/CONSTRUCTOR/UNLOAD,
 *            [Sources]/[Packages]/[LibraryClasses]/[Guids]/[Protocols]/[Ppis]/
 *            [Pcd]/[Depex]. The build wires an INF to its `.c` implementation
 *            and to the DEC packages / library classes / PCDs / GUIDs it uses.
 *   - `.dec`  Package declaration: PACKAGE_NAME, [Guids]/[Protocols]/[Ppis]
 *            (`gXxx = {…}`), [LibraryClasses] (`Class|header.h`), [Pcds*]
 *            (`TokenSpaceGuid.PcdName|Value|Type|Token`).
 *   - `.dsc`  Platform build: [LibraryClasses] `Class|Impl.inf`,
 *            [Components] `Path.inf { … }`, [Pcds*] `TokenSpace.PcdName|Value`.
 *   - `.fdf`  Flash layout: `INF Path/Module.inf` lines inside FV sections.
 *   - `.uni`  Localization strings: `#string STR_X #language en "…"`.
 *   - `.vfr`  HII form definitions: `formset title = STRING_TOKEN(STR_X) …`.
 *
 * The extractor emits a `file` node per file plus `module` (INF/DEC/DSC/formset)
 * and `constant` (GUID/Protocol/PPI/PCD/class/UNI-token) child nodes, each
 * linked to its file with a `contains` edge. Cross-file links are emitted as
 * unresolved references and resolved later by the edk2 framework resolver
 * (`src/resolution/frameworks/edk2.ts`): INF→DEC `imports`, INF→C
 * ENTRY_POINT→function `references`, C `PcdGet*`/`gEfiXxx…Guid`→DEC `references`.
 *
 * Non-EDK2 `.inf` (Windows driver INF) lacks `[Defines]`/`LIBRARY_CLASS` and
 * returns just a file node — MyBatis's non-mapper-XML fallback precedent.
 */
export class Edk2Extractor {
  private filePath: string;
  private source: string; // CRLF-normalized
  private ext: string;
  private nodes: Node[] = [];
  private edges: Edge[] = [];
  private unresolvedReferences: UnresolvedReference[] = [];
  private errors: ExtractionError[] = [];
  private fileNodeId = '';
  private now = Date.now();

  constructor(filePath: string, source: string) {
    this.filePath = filePath;
    this.source = source.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
    this.ext = path.extname(filePath).toLowerCase();
  }

  extract(): ExtractionResult {
    const start = Date.now();
    this.fileNodeId = generateNodeId(this.filePath, 'file', this.filePath, 1);

    try {
      switch (this.ext) {
        case '.inf':
          this.parseInf();
          break;
        case '.dec':
          this.parseDec();
          break;
        case '.dsc':
          this.parseDsc();
          break;
        case '.fdf':
          this.parseFdf();
          break;
        case '.uni':
          this.parseUni();
          break;
        case '.vfr':
          this.parseVfr();
          break;
        case '.inc':
          // EDK2 !include fragment (`*.dsc.inc` / `*.fdf.inc` / `*.inf.inc`) —
          // section-less descriptor content spliced into a host file.
          this.parseFragment();
          break;
        default:
          break;
      }
    } catch (err) {
      this.errors.push({
        message: `Edk2Extractor failed: ${
          err instanceof Error ? err.message : String(err)
        }`,
        filePath: this.filePath,
        severity: 'warning',
      });
    }

    // Every file always gets a file node, even on a parse miss / non-EDK2 inf,
    // so the watcher tracks it.
    const hasFileNode = this.nodes.some((n) => n.id === this.fileNodeId);
    if (!hasFileNode) this.nodes.push(this.createFileNode());

    return {
      nodes: this.nodes,
      edges: this.edges,
      unresolvedReferences: this.unresolvedReferences,
      errors: this.errors,
      durationMs: Date.now() - start,
    };
  }

  private createFileNode(): Node {
    return {
      id: this.fileNodeId,
      kind: 'file',
      name: path.basename(this.filePath),
      qualifiedName: this.filePath,
      filePath: this.filePath,
      language: 'edk2',
      startLine: 1,
      endLine: 1,
      startColumn: 0,
      endColumn: 0,
      updatedAt: this.now,
    };
  }

  /** Add a child node + a file→child `contains` edge. */
  private addNode(node: Node): void {
    this.nodes.push(node);
    this.edges.push({
      kind: 'contains',
      source: this.fileNodeId,
      target: node.id,
      line: node.startLine,
    });
  }

  private dirOf(): string {
    const d = path.dirname(this.filePath);
    return d === '.' ? '' : d;
  }

  /** Resolve a path listed relative to this file's directory to project-relative
   * forward-slash form. */
  private rel(p: string): string {
    const joined = this.dirOf() ? path.posix.join(this.dirOf(), p) : p;
    return joined.replace(/\\/g, '/');
  }

  /** Expand `$(NAME)` build macros in a path (INF/DSC [Defines] `DEFINE NAME =
   * value` lines). `MODULE_NAME` is defined by the build system as BASE_NAME
   * (INF only). Unknown macros stay verbatim — the resolver's fileExists gate
   * drops them. */
  private expandMacros(
    p: string,
    macros: Map<string, string>,
    defines?: Map<string, string>
  ): string {
    const moduleName = defines?.get('BASE_NAME');
    return p.replace(/\$\(([A-Za-z0-9_]+)\)/g, (whole, name: string) => {
      if (name === 'MODULE_NAME' && moduleName) return moduleName;
      const v = macros.get(name);
      return v !== undefined ? v : whole;
    });
  }

  private emitRef(
    fromNodeId: string,
    referenceName: string,
    referenceKind: UnresolvedReference['referenceKind'],
    line: number,
    candidates?: string[]
  ): void {
    this.unresolvedReferences.push({
      fromNodeId,
      referenceName,
      referenceKind,
      line,
      column: 0,
      filePath: this.filePath,
      language: 'edk2',
      candidates,
    });
  }

  // --------------------------------------------------------------------------
  // INI-family section splitter (INF/DEC/DSC): `[a,b.ARCH]` headers, `#`
  // full-line comments + `##` inline annotations, `!` preprocessor skipped.
  // --------------------------------------------------------------------------
  private static splitSections(
    source: string
  ): { name: string; lines: { text: string; line: number }[] }[] {
    const sections: {
      name: string;
      lines: { text: string; line: number }[];
    }[] = [];
    const all = source.split('\n');
    let current: { name: string; lines: { text: string; line: number }[] }[] = [];
    for (let i = 0; i < all.length; i++) {
      const raw = all[i]!;
      const line = i + 1;
      const trimmed = raw.trim();
      if (trimmed === '') {
        continue;
      }
      if (trimmed.startsWith('!')) {
        // EDK2 build preprocessor (!include / !if / !endif) — skip, but parse
        // the content of both branches (over-linking is harmless).
        continue;
      }
      if (/^\s*#/.test(raw)) {
        // `#` or `##` comment line.
        continue;
      }
      const hdr = trimmed.match(/^\[([^\]]+)\]$/);
      if (hdr) {
        // EDK2 sections carry arch/modifier segments: `[LibraryClasses.common.PEIM]`,
        // `[Depex.common.DXE_DRIVER]`, `[PcdsFixedAtBuild.X64]`. Strip ALL
        // dotted segments (the old one-shot strip left `LibraryClasses.common`
        // unmatched); comma lists (`[Sources.Ia32, Sources.X64]`) split first.
        // Section names are case-insensitive per the EDK2 spec (build tools
        // accept `[defines]`/`[depex]` — real GoogleTest-mock INFs use them) —
        // normalize to lowercase once, here, so every consumer compares
        // lowercase.
        const bases = hdr[1]!
          .toLowerCase()
          .split(',')
          .map((t) => t.trim().replace(/\.[A-Za-z0-9_]+/g, ''))
          .filter((t) => t.length > 0);
        current = bases.map((b) => ({ name: b, lines: [] }));
        if (sections.length === 0) {
          // Pre-section content is the file header docblock — ignore.
        }
        for (const s of current) sections.push(s);
        continue;
      }
      if (current.length === 0) {
        continue; // pre-section content
      }
      // Strip inline ` ## annotation` (## …) or ` # …`.
      const text = raw.replace(/\s##.*$/, '').replace(/\s#\s.*$/, '').trim();
      if (text === '') continue;
      for (const s of current) s.lines.push({ text, line });
    }
    return sections;
  }

  // --------------------------------------------------------------------------
  // INF
  // --------------------------------------------------------------------------
  private parseInf(): void {
    const sections = Edk2Extractor.splitSections(this.source);
    const defines = new Map<string, string>();
    const macros = new Map<string, string>(); // `DEFINE NAME = value` build macros
    const sources: string[] = []; // project-relative .c/.cc source paths
    const sourceFiles: { rel: string; line: number }[] = []; // every [Sources] entry
    let moduleUni: { value: string; line: number } | null = null;
    let moduleLine = 1;

    for (const sec of sections) {
      if (sec.name === 'defines') {
        for (const { text, line } of sec.lines) {
          // `DEFINE OPENSSL_PATH = openssl` — build-time macro used in
          // [Sources] paths (`$(OPENSSL_PATH)/crypto/…`). The build expands
          // these; the extractor records them so source paths resolve to the
          // real files (vendored-source modules list hundreds of them).
          const dm = text.match(/^DEFINE\s+([A-Za-z0-9_]+)\s*=\s*(.*)$/i);
          if (dm && dm[2]!.trim()) {
            macros.set(dm[1]!, dm[2]!.trim());
            continue;
          }
          const m = text.match(/^([A-Za-z0-9_]+)\s*=\s*(.*)$/);
          if (m) {
            // Defines keys are case-insensitive per the EDK2 spec (build tools
            // accept `base_name`); normalize so BASE_NAME/MODULE_UNI_FILE etc.
            // lookups work regardless of spelling.
            const key = m[1]!.toUpperCase();
            defines.set(key, m[2]!.trim());
            if (key === 'MODULE_UNI_FILE' && m[2]!.trim()) {
              moduleUni = { value: m[2]!.trim(), line };
            }
          }
        }
      } else if (sec.name === 'sources') {
        for (const { text, line } of sec.lines) {
          // `foo.nasm| INTEL` — a toolcode attached without a separating space.
          const sp = text.split(/\s+/)[0]!.replace(/\|.*$/, '').trim();
          if (/\.(c|cc|cpp)$/i.test(sp)) sources.push(this.rel(this.expandMacros(sp, macros, defines)));
          // .vfr included: INFs list their HII form file in [Sources]
          // (NetworkPkg Ip4Dxe → Ip4Config2.vfr) — the formset module must
          // hang off the driver module.
          if (/\.(c|cc|cpp|asm|nasm|nasmb|s|asl|aslc|h|uni|vfr)$/i.test(sp)) {
            sourceFiles.push({ rel: this.rel(this.expandMacros(sp, macros, defines)), line });
          }
        }
      }
    }

    const baseName = defines.get('BASE_NAME');
    const libraryClass = defines.get('LIBRARY_CLASS');
    // Content gate: a real EDK2 INF has [Defines] with BASE_NAME and/or
    // LIBRARY_CLASS. Windows driver INFs have neither → file node only.
    if (!baseName && !libraryClass) {
      return;
    }

    // Module node.
    const moduleName = baseName || libraryClass!;
    moduleLine = this.findDefinesLine('BASE_NAME') || this.findDefinesLine('LIBRARY_CLASS') || 1;
    const moduleNodeId = generateNodeId(this.filePath, 'module', moduleName, moduleLine);
    const dir = this.dirOf();
    this.addNode({
      id: moduleNodeId,
      kind: 'module',
      name: moduleName,
      qualifiedName: dir ? `${dir}::${moduleName}` : moduleName,
      filePath: this.filePath,
      language: 'edk2',
      startLine: moduleLine,
      endLine: moduleLine,
      startColumn: 0,
      endColumn: 0,
      signature: libraryClass ? `LIBRARY_CLASS = ${libraryClass}` : defines.get('MODULE_TYPE'),
      updatedAt: this.now,
    });

    const from = moduleNodeId;

    for (const sec of sections) {
      switch (sec.name) {
        case 'packages': {
          for (const { text, line } of sec.lines) {
            const p = text.split(/\s+/)[0]!;
            if (p.endsWith('.dec')) this.emitRef(from, p, 'imports', line);
          }
          break;
        }
        case 'libraryclasses': {
          for (const { text, line } of sec.lines) {
            const cls = text.split(/\s+/)[0]!;
            if (cls) this.emitRef(from, cls, 'imports', line);
          }
          break;
        }
        case 'guids':
        case 'protocols':
        case 'ppis': {
          for (const { text, line } of sec.lines) {
            const m = text.match(/^(g[A-Za-z0-9_]+)/);
            if (m) this.emitRef(from, m[1]!, 'references', line);
          }
          break;
        }
        case 'pcd':
        case 'fixedpcd':
        case 'pcdsfixedatbuild':
        case 'pcdspatchableinmodule':
        case 'pcdsdynamic':
        case 'pcdsdynamicex':
        case 'featurepcd': {
          for (const { text, line } of sec.lines) {
            const token = text.split('|')[0]!.trim();
            const mm = token.match(/^([A-Za-z0-9_]+)\.([A-Za-z0-9_]+)$/);
            if (mm) {
              const pcdName = mm[2]!;
              this.emitRef(from, pcdName, 'references', line, [token]);
            } else if (/^[A-Za-z0-9_]+$/.test(token)) {
              this.emitRef(from, token, 'references', line, [token]);
            }
          }
          break;
        }
        case 'depex': {
          for (const { text, line } of sec.lines) {
            const toks = text
              .split(/\s+AND\s+|\s+/i)
              .map((t) => t.trim())
              .filter((t) => /^g[A-Za-z0-9_]+$/.test(t));
            for (const t of toks) this.emitRef(from, t, 'references', line);
          }
          break;
        }
        default:
          break;
      }
    }

    // Module → every [Sources] file (C + assembly). The C entries also scope
    // the ENTRY_POINT lookup below; assembly entries have no function nodes so
    // this import is their only module hook.
    for (const { rel, line } of sourceFiles) {
      this.emitRef(from, rel, 'imports', line);
    }
    // Module → its HII strings file (MODULE_UNI_FILE, 593 INFs in the corpus).
    if (moduleUni) this.emitRef(from, this.rel(moduleUni.value), 'imports', moduleUni.line);

    // ENTRY_POINT / UNLOAD_IMAGE / CONSTRUCTOR / DESTRUCTOR → C function
    // (candidates = the module's [Sources] .c paths so the resolver scopes the
    // function lookup). DESTRUCTOR is in the EDK2 INF spec and used by 82 INFs
    // in the reference corpus (SmmLockBox, DxeDebugPrintErrorLevelLib, …).
    for (const key of ['ENTRY_POINT', 'UNLOAD_IMAGE', 'CONSTRUCTOR', 'DESTRUCTOR']) {
      const v = defines.get(key);
      if (v && /^[A-Za-z_][A-Za-z0-9_]*$/.test(v)) {
        const defLine = this.findDefinesLine(key) || moduleLine;
        this.emitRef(from, v, 'references', defLine, sources.length ? sources : undefined);
      }
    }
  }

  /** Find the 1-indexed line of a `KEY =` in [Defines] (for node startLine). */
  private findDefinesLine(key: string): number | undefined {
    const re = new RegExp(`^\\s*${key}\\s*=`, 'im');
    const m = this.source.match(re);
    if (!m || m.index === undefined) return undefined;
    return this.source.slice(0, m.index).split('\n').length;
  }

  // --------------------------------------------------------------------------
  // DEC
  // --------------------------------------------------------------------------
  private parseDec(): void {
    const sections = Edk2Extractor.splitSections(this.source);
    const defines = new Map<string, string>();
    let pkgUni: { value: string; line: number } | null = null;
    for (const sec of sections) {
      if (sec.name !== 'defines') continue;
      for (const { text, line } of sec.lines) {
        const m = text.match(/^([A-Za-z0-9_]+)\s*=\s*(.*)$/);
        if (m) {
          const key = m[1]!.toUpperCase();
          defines.set(key, m[2]!.trim());
          if (key === 'PACKAGE_UNI_FILE' && m[2]!.trim()) {
            pkgUni = { value: m[2]!.trim(), line };
          }
        }
      }
    }
    const pkg = defines.get('PACKAGE_NAME');
    if (!pkg) return; // not a real DEC

    const moduleLine = this.findDefinesLine('PACKAGE_NAME') || 1;
    const dir = this.dirOf();
    const decBase = path.basename(this.filePath, '.dec');
    const moduleNodeId = generateNodeId(this.filePath, 'module', pkg, moduleLine);
    this.addNode({
      id: moduleNodeId,
      kind: 'module',
      name: pkg,
      qualifiedName: dir ? `${dir}::${pkg}` : pkg,
      filePath: this.filePath,
      language: 'edk2',
      startLine: moduleLine,
      endLine: moduleLine,
      startColumn: 0,
      endColumn: 0,
      updatedAt: this.now,
    });

    // Package → its HII strings file (PACKAGE_UNI_FILE, 13 DECs in the corpus).
    if (pkgUni) this.emitRef(moduleNodeId, this.rel(pkgUni.value), 'imports', pkgUni.line);

    for (const sec of sections) {
      if (sec.name === 'libraryclasses') {
        for (const { text, line } of sec.lines) {
          const left = text.split('|')[0]!.trim();
          if (/^[A-Za-z0-9_]+$/.test(left)) {
            this.addNode({
              id: generateNodeId(this.filePath, 'constant', left, line),
              kind: 'constant',
              name: left,
              qualifiedName: `${decBase}::${left}`,
              filePath: this.filePath,
              language: 'edk2',
              startLine: line,
              endLine: line,
              startColumn: 0,
              endColumn: 0,
              updatedAt: this.now,
            });
          }
        }
      } else if (sec.name === 'guids' || sec.name === 'protocols' || sec.name === 'ppis') {
        for (const { text, line } of sec.lines) {
          const m = text.match(/^(g[A-Za-z0-9_]+)/);
          if (m) {
            this.addNode({
              id: generateNodeId(this.filePath, 'constant', m[1]!, line),
              kind: 'constant',
              name: m[1]!,
              qualifiedName: `${decBase}::${m[1]}`,
              filePath: this.filePath,
              language: 'edk2',
              startLine: line,
              endLine: line,
              startColumn: 0,
              endColumn: 0,
              updatedAt: this.now,
            });
          }
        }
      } else if (sec.name.startsWith('pcds') || sec.name === 'fixedpcd') {
        for (const { text, line } of sec.lines) {
          // TokenSpaceGuid.PcdName|Value|Type|Token
          const m = text.match(/^([A-Za-z0-9_]+)\.([A-Za-z0-9_]+)\s*\|/);
          if (m) {
            const tokenSpace = m[1]!;
            const pcdName = m[2]!;
            this.addNode({
              id: generateNodeId(this.filePath, 'constant', pcdName, line),
              kind: 'constant',
              name: pcdName,
              qualifiedName: `${tokenSpace}.${pcdName}`,
              filePath: this.filePath,
              language: 'edk2',
              startLine: line,
              endLine: line,
              startColumn: 0,
              endColumn: 0,
              updatedAt: this.now,
            });
          }
        }
      }
    }
  }

  // --------------------------------------------------------------------------
  // DSC
  // --------------------------------------------------------------------------
  private parseDsc(): void {
    const sections = Edk2Extractor.splitSections(this.source);
    const defines = new Map<string, string>();
    const macros = new Map<string, string>(); // [Defines] `DEFINE NAME = value`
    let flashDef: { value: string; line: number } | null = null;
    for (const sec of sections) {
      if (sec.name !== 'defines') continue;
      for (const { text, line } of sec.lines) {
        // `DEFINE FSP_PACKAGE = QemuFspPkg` — platform macros used in
        // [Components]/[LibraryClasses] paths (`$(FSP_PACKAGE)/X.inf`) and
        // `!include` lines. The build expands them; without expansion the
        // component refs can't resolve (and a hardcoded macro table in the
        // resolver would expand to the WRONG package when the platform
        // overrides the default — QemuFspPkg.dsc does exactly that).
        const dm = text.match(/^DEFINE\s+([A-Za-z0-9_]+)\s*=\s*(.*)$/i);
        if (dm && dm[2]!.trim()) {
          macros.set(dm[1]!, dm[2]!.trim());
          continue;
        }
        const m = text.match(/^([A-Za-z0-9_]+)\s*=\s*(.*)$/);
        if (m) {
          const key = m[1]!.toUpperCase();
          defines.set(key, m[2]!.trim());
          if (key === 'FLASH_DEFINITION' && m[2]!.trim().endsWith('.fdf')) {
            flashDef = { value: m[2]!.trim(), line };
          }
        }
      }
    }
    const platform = defines.get('PLATFORM_NAME');
    if (!platform) return; // not a real DSC

    const moduleLine = this.findDefinesLine('PLATFORM_NAME') || 1;
    const dir = this.dirOf();
    const moduleNodeId = generateNodeId(this.filePath, 'module', platform, moduleLine);
    this.addNode({
      id: moduleNodeId,
      kind: 'module',
      name: platform,
      qualifiedName: dir ? `${dir}::${platform}` : platform,
      filePath: this.filePath,
      language: 'edk2',
      startLine: moduleLine,
      endLine: moduleLine,
      startColumn: 0,
      endColumn: 0,
      updatedAt: this.now,
    });
    const from = moduleNodeId;

    for (const sec of sections) {
      switch (sec.name) {
        case 'packages': {
          for (const { text, line } of sec.lines) {
            const p = text.split(/\s+/)[0]!;
            if (p.endsWith('.dec')) this.emitRef(from, p, 'imports', line);
          }
          break;
        }
        case 'libraryclasses': {
          for (const { text, line } of sec.lines) {
            // Class|Path.inf — link to the implementation INF file.
            const after = text.split('|')[1];
            if (after) {
              const impl = this.expandMacros(after.trim(), macros);
              if (impl.endsWith('.inf')) this.emitRef(from, impl, 'imports', line);
            }
          }
          break;
        }
        case 'components': {
          // Path.inf optionally followed by `{ … }` override block containing
          // `<LibraryClasses>` / `<Pcds*>` pseudo-sections — component-scoped
          // library instances and PCD assignments (real: 378 `<LibraryClasses>`
          // in the tianocore corpus).
          let inBlock = false;
          let blockSection: string | null = null;
          for (const { text, line } of sec.lines) {
            if (inBlock) {
              if (/^}\s*$/.test(text)) {
                inBlock = false;
                blockSection = null;
                continue;
              }
              const hdr = text.match(/^<([^>]+)>$/);
              if (hdr) {
                // `<LibraryClasses.common>` / `<PcdsFixedAtBuild.X64>` —
                // lowercase for the same case-insensitivity as section names.
                blockSection = hdr[1]!
                  .toLowerCase()
                  .replace(/\.[A-Za-z0-9_]+$/, '');
                continue;
              }
              if (blockSection === 'libraryclasses') {
                const lc = text.match(/^([A-Za-z0-9_]+)\s*\|\s*(\S+\.inf)/);
                if (lc) {
                  this.emitRef(from, this.expandMacros(lc[2]!, macros), 'imports', line);
                  continue;
                }
              } else if (blockSection && blockSection.startsWith('pcds')) {
                const pcd = text.match(/^([A-Za-z0-9_]+)\.([A-Za-z0-9_]+)\s*\|/);
                if (pcd) {
                  this.emitRef(from, pcd[2]!, 'references', line, [pcd[1]! + '.' + pcd[2]!]);
                  continue;
                }
              }
              continue; // <Defines>/<BuildOptions>/bare lines → no link target
            }
            const m = text.match(/^(\S+\.inf)/);
            if (m) {
              this.emitRef(from, this.expandMacros(m[1]!, macros), 'imports', line);
              if (text.includes('{')) inBlock = true;
            }
          }
          break;
        }
        default:
          if (sec.name.startsWith('pcds')) {
            for (const { text, line } of sec.lines) {
              const token = text.split('|')[0]!.trim();
              const mm = token.match(/^([A-Za-z0-9_]+)\.([A-Za-z0-9_]+)$/);
              if (mm) this.emitRef(from, mm[2]!, 'references', line, [token]);
            }
          }
          break;
      }
    }

    // `!include` lines — splitSections' `!` skip drops them, so scan raw lines.
    const rawLines = this.source.split('\n');
    for (let i = 0; i < rawLines.length; i++) {
      const inc = rawLines[i]!.match(/^\s*!include\s+(\S+)/);
      if (inc) this.emitRef(from, this.expandMacros(inc[1]!, macros), 'imports', i + 1);
    }
    // The platform's flash layout file — the DSC→FDF link that makes
    // dead-FDF detection possible (an FDF with no incoming edges is unused).
    if (flashDef) this.emitRef(from, this.expandMacros(flashDef.value, macros), 'imports', flashDef.line);
  }

  // --------------------------------------------------------------------------
  // FDF: scan every `INF [RuleOverride=…] Path.inf` line (FV sections).
  // --------------------------------------------------------------------------
  private parseFdf(): void {
    const lines = this.source.split('\n');
    // Top-level `DEFINE NAME = value` statements (FD sizes, but also paths
    // used in `INF $(NAME)/…` lines on other platforms).
    const macros = new Map<string, string>();
    for (const l of lines) {
      const dm = l.match(/^\s*DEFINE\s+([A-Za-z0-9_]+)\s*=\s*(.*)$/i);
      if (dm && dm[2]!.trim()) macros.set(dm[1]!, dm[2]!.trim());
    }
    // `INF [RuleOverride=…] [FILE_GUID = <guid>] path.inf` — both modifiers
    // may appear before the module path (OvmfPkgX64.fdf overrides module
    // FILE_GUIDs this way: `INF FILE_GUID = $(UP_CPU_PEI_GUID)
    // UefiCpuPkg/CpuMpPei/CpuMpPei.inf`).
    const re = /^\s*INF\s+(?:(?:RuleOverride|FILE_GUID)\s*=\s*\S+\s+)*(\S+\.inf)\s*$/i;
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i]!;
      const inc = line.match(/^\s*!include\s+(\S+)/);
      if (inc) {
        this.emitRef(this.fileNodeId, this.expandMacros(inc[1]!, macros), 'imports', i + 1);
        continue;
      }
      const m = line.match(re);
      if (m) this.emitRef(this.fileNodeId, this.expandMacros(m[1]!, macros), 'imports', i + 1);
    }
  }

  // --------------------------------------------------------------------------
  // Fragments (`*.dsc.inc` / `*.fdf.inc` / `*.inf.inc`): section-less content
  // spliced into a host file's section context via `!include`. No section
  // headers required — scan every line for the four linkage patterns. Pure
  // build-flag fragments (e.g. NetworkBuildOptions.dsc.inc) match none and
  // degrade to a file node only.
  // --------------------------------------------------------------------------
  private parseFragment(): void {
    const lines = this.source.split('\n');
    const includeRe = /^\s*!include\s+(\S+)/;
    const libClassRe = /^([A-Za-z0-9_]+)\s*\|\s*(\S+\.inf)/;
    const pcdRe = /^\s*(?:([A-Za-z0-9_]+)\.)?(Pcd[A-Za-z0-9_]+)\s*\|/;
    const infRe = /^\s*INF\s+(?:(?:RuleOverride|FILE_GUID)\s*=\s*\S+\s+)*(\S+\.inf)\s*$/i;
    for (let i = 0; i < lines.length; i++) {
      const text = lines[i]!.trim();
      const line = i + 1;
      const inc = text.match(includeRe);
      if (inc) {
        this.emitRef(this.fileNodeId, inc[1]!, 'imports', line);
        continue;
      }
      if (text === '' || text.startsWith('#') || text.startsWith('//') || text.startsWith('!')) {
        // `!if/!endif` etc. are skipped — both branches are scanned regardless
        // (over-linking is harmless, splitSections precedent).
        continue;
      }
      const lc = text.match(libClassRe);
      if (lc) {
        this.emitRef(this.fileNodeId, lc[2]!, 'imports', line);
        continue;
      }
      const pcd = text.match(pcdRe);
      if (pcd) {
        const full = pcd[1] ? pcd[1]! + '.' + pcd[2]! : pcd[2]!;
        this.emitRef(this.fileNodeId, pcd[2]!, 'references', line, [full]);
        continue;
      }
      const inf = text.match(infRe);
      if (inf) {
        this.emitRef(this.fileNodeId, inf[1]!, 'imports', line);
      }
    }
  }

  // --------------------------------------------------------------------------
  // UNI: `#string TOKEN #language LANG "value"`
  // --------------------------------------------------------------------------
  private parseUni(): void {
    // Strip `//` line comments.
    const lines = this.source.split('\n');
    const seen = new Set<string>();
    // `#string STR_X` may split across lines: `#string STR_X` / `#language
    // en-US` / `"value"` (the *Extra.uni family — 254 tokens in the corpus).
    let pending: { token: string; line: number; lang: boolean } | null = null;
    const emit = (token: string, value: string, line: number) => {
      if (seen.has(token)) return;
      seen.add(token);
      this.addNode({
        id: generateNodeId(this.filePath, 'constant', token, line),
        kind: 'constant',
        name: token,
        qualifiedName: `${this.filePath}::${token}`,
        filePath: this.filePath,
        language: 'edk2',
        startLine: line,
        endLine: line,
        startColumn: 0,
        endColumn: 0,
        docstring: value,
        updatedAt: this.now,
      });
    };
    for (let i = 0; i < lines.length; i++) {
      const raw = lines[i]!;
      if (raw.trim().startsWith('//')) continue;
      // `#include "SharedStrings.uni"` — UNI files splice shared string
      // tokens from other UNI files (SmbiosMiscDxeStrings.uni pattern).
      const inc = raw.match(/^\s*#include\s+["<]([^">]+)[">]/);
      if (inc) {
        this.emitRef(this.fileNodeId, this.rel(inc[1]!), 'imports', i + 1);
        continue;
      }
      // Combined form: `#string STR_X #language en-US "value"`.
      const m = raw.match(/^\s*#string\s+([A-Za-z0-9_]+)\s+#language\s+\S+\s+"(.*)"\s*$/);
      if (m) {
        emit(m[1]!, m[2]!, i + 1);
        pending = null;
        continue;
      }
      // Split form part 1: `#string STR_X`.
      const s = raw.match(/^\s*#string\s+([A-Za-z0-9_]+)\s*$/);
      if (s) {
        pending = { token: s[1]!, line: i + 1, lang: false };
        continue;
      }
      if (!pending) continue;
      // Split form part 2: `#language en-US "value"` (one line)…
      const l = raw.match(/^\s*#language\s+\S+\s+"(.*)"\s*$/);
      if (l) {
        emit(pending.token, l[1]!, pending.line);
        pending = null;
        continue;
      }
      // …or `#language en-US` alone, value on the NEXT line.
      if (!pending.lang && /^\s*#language\s+\S+\s*$/.test(raw)) {
        pending.lang = true;
        continue;
      }
      if (pending.lang) {
        const v = raw.match(/^\s*"(.*)"\s*$/);
        if (v) {
          emit(pending.token, v[1]!, pending.line);
          pending = null;
        }
      }
    }
  }

  // --------------------------------------------------------------------------
  // VFR: formset + STRING_TOKEN refs (link to UNI strings)
  // --------------------------------------------------------------------------
  private parseVfr(): void {
    // Strip /* */ block comments and // line comments.
    const stripped = this.source
      .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' '))
      .replace(/\/\/[^\n]*/g, (m) => ' '.repeat(m.length));

    // `#include "X.vfr"` — VFR files share forms/structures across drivers
    // (NetworkPkg Ip4Config2.vfr pattern).
    const incRe = /^\s*#include\s+["<]([^">]+)[">]/gm;
    let incM: RegExpExecArray | null;
    while ((incM = incRe.exec(this.source)) !== null) {
      const incLine = this.source.slice(0, incM.index).split('\n').length;
      this.emitRef(this.fileNodeId, this.rel(incM[1]!), 'imports', incLine);
    }

    // formset module node — name from the formset title STRING_TOKEN, else file.
    let formsetName: string | null = null;
    let formsetLine = 1;
    const formsetOpen = stripped.match(/^\s*formset\b/im);
    if (formsetOpen && formsetOpen.index !== undefined) {
      formsetLine = stripped.slice(0, formsetOpen.index).split('\n').length;
      const blockEnd = Edk2Extractor.findBlockEnd(stripped, formsetOpen.index);
      const block = stripped.slice(formsetOpen.index, blockEnd);
      const title = block.match(/title\s*=\s*STRING_TOKEN\s*\(\s*([A-Za-z0-9_]+)\s*\)/i);
      if (title) formsetName = title[1]!;
    }
    if (!formsetName) formsetName = path.basename(this.filePath, '.vfr');
    const formsetId = generateNodeId(this.filePath, 'module', formsetName, formsetLine);
    const dir = this.dirOf();
    this.addNode({
      id: formsetId,
      kind: 'module',
      name: formsetName,
      qualifiedName: dir ? `${dir}::${formsetName}` : formsetName,
      filePath: this.filePath,
      language: 'edk2',
      startLine: formsetLine,
      endLine: formsetLine,
      startColumn: 0,
      endColumn: 0,
      updatedAt: this.now,
    });

    // All STRING_TOKEN(STR_X) → references to UNI constants (dedup).
    const re = /STRING_TOKEN\s*\(\s*([A-Za-z0-9_]+)\s*\)/g;
    const seen = new Set<string>();
    let m: RegExpExecArray | null;
    while ((m = re.exec(stripped)) !== null) {
      const tok = m[1]!;
      if (seen.has(tok)) continue;
      seen.add(tok);
      const line = stripped.slice(0, m.index).split('\n').length;
      this.emitRef(formsetId, tok, 'references', line);
    }
  }

  /** Find the `endformset;` / matching close for a `formset` opener at `idx`. */
  private static findBlockEnd(source: string, idx: number): number {
    const rest = source.slice(idx);
    const end = rest.search(/\n\s*endformset\s*;/i);
    if (end === -1) return source.length;
    return idx + end;
  }
}