/**
 * ACPI Source Language extractor (.asl).
 *
 * `.asl` files define ACPI tables: a top-level `DefinitionBlock ("X.aml",
 * "SIGNATURE", …)` containing `Scope` / `Device` / `Method` / `Name` nodes.
 * The build compiles them to AML with IASL; INFs list the `.asl` in
 * `[Sources]` (or an `[Acpi]`-style section), so the INF module's imports
 * edge lands on this file's file node.
 *
 * Emission model (mirrors Edk2Extractor's shape):
 *   - file node (always);
 *   - one `module` node per DefinitionBlock, named by the table signature
 *     (`DSDT`/`SSDT`/…), qualifiedName `<filePath>::<signature>`, with the
 *     AML filename in `signature`;
 *   - `constant` nodes per top-level-ish `Device (…)` / `Method (…)` entry —
 *     the table's declared devices and control methods (e.g. `NVDR`,
 *     `_PIC`). `Name (…)` is skipped (hundreds of `_HID`/`_STR` noise with
 *     no query value).
 *
 * No cross-file references are emitted (ASL has no import syntax) — linkage
 * comes from the INF `[Sources]` imports and from the file being queryable.
 */

import * as path from 'path';
import { Edge, ExtractionResult, Node } from '../types';
import { generateNodeId } from './tree-sitter-helpers';

export class AslExtractor {
  private readonly source: string;
  private readonly ext: string;
  private readonly fileNodeId: string;
  private readonly now = Date.now();
  private readonly nodes: Node[] = [];
  private readonly edges: Edge[] = [];
  private readonly errors: ExtractionResult['errors'] = [];

  constructor(
    private readonly filePath: string,
    source: string
  ) {
    this.source = source.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
    this.ext = path.extname(filePath).toLowerCase();
    this.fileNodeId = generateNodeId(filePath, 'file', filePath, 1);
  }

  extract(): ExtractionResult {
    const start = Date.now();
    try {
      if (this.ext === '.asl') this.parseDefinitionBlock();
    } catch (err) {
      this.errors.push({
        message: `AslExtractor failed: ${err instanceof Error ? err.message : String(err)}`,
        filePath: this.filePath,
        severity: 'warning',
      });
    }

    if (!this.nodes.some((n) => n.id === this.fileNodeId)) {
      this.nodes.push(this.createFileNode());
    }

    return {
      nodes: this.nodes,
      edges: this.edges,
      unresolvedReferences: [],
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
      language: 'asl',
      startLine: 1,
      endLine: 1,
      startColumn: 0,
      endColumn: 0,
      updatedAt: this.now,
    };
  }

  private addNode(node: Node): void {
    this.nodes.push(node);
    this.edges.push({
      kind: 'contains',
      source: this.fileNodeId,
      target: node.id,
      line: node.startLine,
    });
  }

  /** Parse a DefinitionBlock and its Device/Method entries. */
  private parseDefinitionBlock(): void {
    const lines = this.source.split('\n');

    // DefinitionBlock ("RamDisk.aml", "SSDT", 2, "INTEL ", "RamDisk ", 0x1000)
    // — the opener spans multiple lines, so match over the whole source.
    let blockLine = 0;
    let amlFile = '';
    let signature = '';
    const block = this.source.match(
      /DefinitionBlock\s*\(\s*"([^"]+\.aml)"\s*,\s*"([A-Za-z0-9]+)"/
    );
    if (block && block.index !== undefined) {
      blockLine = this.source.slice(0, block.index).split('\n').length;
      amlFile = block[1]!;
      signature = block[2]!;
    }
    if (!signature) return; // not a real ASL file — file node only

    const dir = this.dirOf();
    this.addNode({
      id: generateNodeId(this.filePath, 'module', signature, blockLine),
      kind: 'module',
      name: signature,
      qualifiedName: dir ? `${dir}::${signature}` : signature,
      filePath: this.filePath,
      language: 'asl',
      startLine: blockLine,
      endLine: blockLine,
      startColumn: 0,
      endColumn: 0,
      signature: `DefinitionBlock ${amlFile}`,
      updatedAt: this.now,
    });

    // Device (NVDR) / Method (_PIC, 1, NotSerialized) — declared table entries.
    const seen = new Set<string>();
    for (let i = 0; i < lines.length; i++) {
      const m = lines[i]!.match(/^\s*(?:Device|Method)\s*\(\s*([A-Za-z0-9_]+)/);
      if (!m) continue;
      const name = m[1]!;
      const key = `${name}@${i + 1}`;
      if (seen.has(key)) continue;
      seen.add(key);
      this.addNode({
        id: generateNodeId(this.filePath, 'constant', name, i + 1),
        kind: 'constant',
        name,
        qualifiedName: `${this.filePath}::${name}`,
        filePath: this.filePath,
        language: 'asl',
        startLine: i + 1,
        endLine: i + 1,
        startColumn: 0,
        endColumn: 0,
        updatedAt: this.now,
      });
    }
  }

  private dirOf(): string {
    const d = path.dirname(this.filePath);
    return d === '.' ? '' : d;
  }
}
