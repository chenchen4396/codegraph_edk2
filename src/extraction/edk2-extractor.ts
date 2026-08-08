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
        const bases = hdr[1]!
          .split(',')
          .map((t) => t.trim().replace(/\.[A-Za-z0-9_]+$/, '')) // strip .ARCH
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
    const sources: string[] = []; // project-relative .c/.cc source paths
    let moduleLine = 1;

    for (const sec of sections) {
      if (sec.name === 'Defines') {
        for (const { text } of sec.lines) {
          const m = text.match(/^([A-Za-z0-9_]+)\s*=\s*(.*)$/);
          if (m) defines.set(m[1]!, m[2]!.trim());
        }
      } else if (sec.name === 'Sources') {
        for (const { text } of sec.lines) {
          const sp = text.split(/\s+/)[0]!;
          if (/\.(c|cc|cpp)$/i.test(sp)) sources.push(this.rel(sp));
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
        case 'Packages': {
          for (const { text, line } of sec.lines) {
            const p = text.split(/\s+/)[0]!;
            if (p.endsWith('.dec')) this.emitRef(from, p, 'imports', line);
          }
          break;
        }
        case 'LibraryClasses': {
          for (const { text, line } of sec.lines) {
            const cls = text.split(/\s+/)[0]!;
            if (cls) this.emitRef(from, cls, 'imports', line);
          }
          break;
        }
        case 'Guids':
        case 'Protocols':
        case 'Ppis': {
          for (const { text, line } of sec.lines) {
            const m = text.match(/^(g[A-Za-z0-9_]+)/);
            if (m) this.emitRef(from, m[1]!, 'references', line);
          }
          break;
        }
        case 'Pcd':
        case 'PcdsFixedAtBuild':
        case 'PcdsPatchableInModule':
        case 'PcdsDynamic':
        case 'PcdsDynamicEx':
        case 'FeaturePcd': {
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
        case 'Depex': {
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

    // ENTRY_POINT / UNLOAD_IMAGE / CONSTRUCTOR → C function (candidates = the
    // module's [Sources] .c paths so the resolver scopes the function lookup).
    for (const key of ['ENTRY_POINT', 'UNLOAD_IMAGE', 'CONSTRUCTOR']) {
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
    for (const sec of sections) {
      if (sec.name !== 'Defines') continue;
      for (const { text } of sec.lines) {
        const m = text.match(/^([A-Za-z0-9_]+)\s*=\s*(.*)$/);
        if (m) defines.set(m[1]!, m[2]!.trim());
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

    for (const sec of sections) {
      if (sec.name === 'LibraryClasses') {
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
      } else if (sec.name === 'Guids' || sec.name === 'Protocols' || sec.name === 'Ppis') {
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
      } else if (sec.name.startsWith('Pcds')) {
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
    for (const sec of sections) {
      if (sec.name !== 'Defines') continue;
      for (const { text } of sec.lines) {
        const m = text.match(/^([A-Za-z0-9_]+)\s*=\s*(.*)$/);
        if (m) defines.set(m[1]!, m[2]!.trim());
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
        case 'Packages': {
          for (const { text, line } of sec.lines) {
            const p = text.split(/\s+/)[0]!;
            if (p.endsWith('.dec')) this.emitRef(from, p, 'imports', line);
          }
          break;
        }
        case 'LibraryClasses': {
          for (const { text, line } of sec.lines) {
            // Class|Path.inf — link to the implementation INF file.
            const after = text.split('|')[1];
            if (after) {
              const impl = after.trim();
              if (impl.endsWith('.inf')) this.emitRef(from, impl, 'imports', line);
            }
          }
          break;
        }
        case 'Components': {
          // Path.inf optionally followed by `{ … }` override block. `}` closes.
          for (const { text, line } of sec.lines) {
            const m = text.match(/^(\S+\.inf)/);
            if (m) this.emitRef(from, m[1]!, 'imports', line);
          }
          break;
        }
        default:
          if (sec.name.startsWith('Pcds')) {
            for (const { text, line } of sec.lines) {
              const token = text.split('|')[0]!.trim();
              const mm = token.match(/^([A-Za-z0-9_]+)\.([A-Za-z0-9_]+)$/);
              if (mm) this.emitRef(from, mm[2]!, 'references', line, [token]);
            }
          }
          break;
      }
    }
  }

  // --------------------------------------------------------------------------
  // FDF: scan every `INF [RuleOverride=…] Path.inf` line (FV sections).
  // --------------------------------------------------------------------------
  private parseFdf(): void {
    const lines = this.source.split('\n');
    const re = /^\s*INF\s+(?:RuleOverride=\S+\s+)?(\S+\.inf)\s*$/i;
    for (let i = 0; i < lines.length; i++) {
      const m = lines[i]!.match(re);
      if (m) this.emitRef(this.fileNodeId, m[1]!, 'imports', i + 1);
    }
  }

  // --------------------------------------------------------------------------
  // UNI: `#string TOKEN #language LANG "value"`
  // --------------------------------------------------------------------------
  private parseUni(): void {
    // Strip `//` line comments.
    const lines = this.source.split('\n');
    const re = /^\s*#string\s+([A-Za-z0-9_]+)\s+#language\s+\S+\s+"(.*)"\s*$/;
    const seen = new Set<string>();
    for (let i = 0; i < lines.length; i++) {
      const raw = lines[i]!;
      if (raw.trim().startsWith('//')) continue;
      const m = raw.match(re);
      if (m) {
        const token = m[1]!;
        const value = m[2]!;
        if (seen.has(token)) continue;
        seen.add(token);
        this.addNode({
          id: generateNodeId(this.filePath, 'constant', token, i + 1),
          kind: 'constant',
          name: token,
          qualifiedName: `${this.filePath}::${token}`,
          filePath: this.filePath,
          language: 'edk2',
          startLine: i + 1,
          endLine: i + 1,
          startColumn: 0,
          endColumn: 0,
          docstring: value,
          updatedAt: this.now,
        });
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