/**
 * EDK2 / UEFI Framework Resolver
 *
 * Bridges EDK2 descriptor files (INF/DSC/FDF/DEC/UNI/VFR, parsed by
 * {@link Edk2Extractor}) and the UEFI C sources so the graph answers the
 * questions firmware work needs:
 *
 *   - Which C function is an INF's ENTRY_POINT/UNLOAD/CONSTRUCTOR? (INF → C)
 *   - Which DEC declares the `gEfiXxxProtocolGuid` / PPI a C file or INF
 *     consumes, and which INF produces it? (C/INF → DEC)
 *   - Which PCD does a `PcdGet32`/`FixedPcdGet*` call site read, and where is
 *     it declared (DEC) / overridden (DSC)? (C/DSC → DEC)
 *   - Which library class does an INF consume, and which INF implements it for
 *     a given platform (DSC [LibraryClasses] `Class|Impl.inf`)? (INF → DEC, DSC → INF)
 *   - Which modules enter a firmware volume (FDF `INF …`)? (FDF → INF)
 *
 * Two emission sources feed `resolve()`:
 *   - Edk2Extractor emits descriptor-side unresolved references (INF/DSC/FDF
 *     `imports`/`references`) with `language: 'edk2'`.
 *   - This resolver's `extract()` scans `.c`/`.h` content for PCD-getter and
 *     GUID-usage calls and emits synthetic `references` refs with
 *     `language: 'c'`, keyed by the C file's file node.
 *
 * `resolve()` only ever returns `references`/`imports` edges. It deliberately
 * does NOT touch `calls` refs, so a `PcdGet32(…)` call's real function edge to
 * `PcdLib` (resolved by normal name/import matching) is never shadowed: the
 * synthetic `references` ref names the PCD, a separate edge to the DEC
 * declaration. Returning `confidence >= 0.9` short-circuits resolution
 * (`resolveOne` Strategy 1), and `gateFrameworkLanguage` preserves the
 * cross-language `c → edk2` and `edk2 → edk2` edges (EDK2 isn't a known
 * language family, so `crossesKnownFamily` is false — config↔code bridges
 * survive, per the gate's documented intent).
 */

import * as path from 'path';
import type {
  FrameworkResolver,
  UnresolvedRef,
  ResolvedRef,
  ResolutionContext,
  FrameworkExtractionResult,
} from '../types';

const PCD_USAGE_RE =
  /\b(?:Pcd|FixedPcd|PatchPcd)(?:Get|Set)(?:8|16|32|64|Ptr)?S?\s*\(\s*(?:&\s*)?(?:([A-Za-z0-9_]+)PkgTokenSpaceGuid\s*\.)?\s*(Pcd[A-Za-z0-9_]+)\b/g;

const GUID_USAGE_RE = /\b(g(?:Efi|Edkii)[A-Za-z0-9_]*(?:ProtocolGuid|PpiGuid|Guid))\b/g;

const DESCRIPTOR_EXT = /\.(dec|inf|dsc|fdf)$/i;
const SOURCE_EXT = /\.(c|cc|cpp)$/i;

export const edk2Resolver: FrameworkResolver = {
  name: 'edk2',
  languages: ['edk2', 'c'],

  detect(context: ResolutionContext): boolean {
    return context.getAllFiles().some((f) => f.endsWith('.dec'));
  },

  // Path-shaped descriptor imports (e.g. `MdePkg/MdePkg.dec`) name a FILE, not
  // a declared symbol — opt them through the name-exists pre-filter so they
  // reach resolve() at all (terraform's `claimsReference` for scoped refs).
  claimsReference(name: string): boolean {
    return DESCRIPTOR_EXT.test(name);
  },

  resolve(ref: UnresolvedRef, context: ResolutionContext): ResolvedRef | null {
    if (ref.referenceKind !== 'references' && ref.referenceKind !== 'imports') return null;

    const name = ref.referenceName;

    // ENTRY_POINT / UNLOAD_IMAGE / CONSTRUCTOR → C function. The Edk2Extractor
    // carries the module's [Sources] .c paths in `candidates` so the lookup is
    // scoped to the module's own directory (avoids same-named functions in
    // sibling modules — a real EDK2 hazard, e.g. multiple `InitializeDriver`).
    if (ref.candidates?.some((c) => SOURCE_EXT.test(c))) {
      for (const cand of ref.candidates) {
        if (!SOURCE_EXT.test(cand)) continue;
        const inFile = context.getNodesInFile(cand);
        for (const n of inFile) {
          if (n.kind === 'function' && n.name === name) {
            return { original: ref, targetNodeId: n.id, confidence: 0.95, resolvedBy: 'framework' };
          }
        }
      }
      // Fall back to the global function index only when unambiguous.
      const fns = context.getNodesByName(name).filter((n) => n.kind === 'function');
      if (fns.length === 1) {
        return { original: ref, targetNodeId: fns[0]!.id, confidence: 0.85, resolvedBy: 'framework' };
      }
      return null;
    }

    // Path-shaped imports → the target descriptor file's module/file node.
    if (DESCRIPTOR_EXT.test(name)) {
      if (!context.fileExists(name)) return null;
      const inFile = context.getNodesInFile(name);
      const target = inFile.find((n) => n.kind === 'module') ?? inFile.find((n) => n.kind === 'file');
      if (target) {
        return { original: ref, targetNodeId: target.id, confidence: 0.9, resolvedBy: 'framework' };
      }
      return null;
    }

    // PCD: prefer the token-space-qualified name (DEC stores qualifiedName as
    // `TokenSpaceGuid.PcdName`), then fall back to the simple name.
    const qualified = ref.candidates?.find((c) => c.includes('.'));
    if (qualified) {
      const qhits = context.getNodesByQualifiedName(qualified).filter(
        (n) => n.kind === 'constant' && n.language === 'edk2'
      );
      if (qhits.length > 0) {
        return { original: ref, targetNodeId: qhits[0]!.id, confidence: 0.9, resolvedBy: 'framework' };
      }
    }

    // GUID / PCD / library-class by simple name → DEC constant.
    const hits = context
      .getNodesByName(name)
      .filter((n) => n.kind === 'constant' && n.language === 'edk2');
    if (hits.length > 0) {
      return { original: ref, targetNodeId: hits[0]!.id, confidence: 0.9, resolvedBy: 'framework' };
    }

    return null;
  },

  extract(filePath: string, content: string): FrameworkExtractionResult {
    // Only UEFI C / headers carry PCD getters and GUID usage. Non-C files are
    // handled by Edk2Extractor; return empty here so we never duplicate its
    // descriptor-side nodes/refs.
    const ext = path.extname(filePath).toLowerCase();
    if (ext !== '.c' && ext !== '.cc' && ext !== '.cpp' && ext !== '.h') {
      return { nodes: [], references: [] };
    }
    // Cheap gate: skip headers/sources with no EDK2 token at all (avoids
    // minting refs for thousands of plain-C files in a mixed tree).
    if (
      content.indexOf('Pcd') === -1 &&
      content.indexOf('gEfi') === -1 &&
      content.indexOf('gEdkii') === -1
    ) {
      return { nodes: [], references: [] };
    }

    // The C file's file node (matches TreeSitterExtractor's `file:<path>` id —
    // generateNodeId would produce a different hash and the ref would be
    // dropped by the store's insertedIds filter).
    const fromNodeId = `file:${filePath}`;
    const references: UnresolvedRef[] = [];
    const seen = new Set<string>();

    const lineCol = (offset: number): { line: number; column: number } => {
      let line = 1;
      let col = 0;
      for (let i = 0; i < offset && i < content.length; i++) {
        if (content.charCodeAt(i) === 0x0a /* \n */) {
          line++;
          col = 0;
        } else {
          col++;
        }
      }
      return { line, column: col };
    };

    const emit = (referenceName: string, candidates: string[] | undefined, offset: number) => {
      const key = candidates?.[0] ? `${candidates[0]}` : referenceName;
      if (seen.has(key)) return;
      seen.add(key);
      const { line, column } = lineCol(offset);
      references.push({
        fromNodeId,
        referenceName,
        referenceKind: 'references',
        line,
        column,
        filePath,
        language: 'c',
        candidates,
      });
    };

    // PCD getters/setters: `PcdGet32(PcdFoo)`, `FixedPcdGet64(PcdFoo)`,
    // `PcdSet32S(gEfiMdePkgTokenSpaceGuid.PcdFoo, …)`, `PatchPcdGetPtr(…)`.
    let m: RegExpExecArray | null;
    PCD_USAGE_RE.lastIndex = 0;
    while ((m = PCD_USAGE_RE.exec(content)) !== null) {
      const tokenSpace = m[1]; // e.g. gEfiMdePkg (without the TokenSpaceGuid suffix)
      const pcdName = m[2]!;
      const full = tokenSpace
        ? `${tokenSpace}PkgTokenSpaceGuid.${pcdName}`
        : pcdName;
      emit(pcdName, full === pcdName ? undefined : [full], m.index);
    }

    // GUID / Protocol / PPI usage: `gEfiArpProtocolGuid`, `gEfiDxeIplPpiGuid`.
    GUID_USAGE_RE.lastIndex = 0;
    while ((m = GUID_USAGE_RE.exec(content)) !== null) {
      emit(m[1]!, undefined, m.index);
    }

    return { nodes: [], references };
  },
};