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
  /\b(?:Pcd|FixedPcd|PatchPcd)(?:Get|Set)(?:Ex)?(?:8|16|32|64|Ptr|Size|Bool)?S?\s*\(\s*(?:&\s*)?(?:([A-Za-z0-9_]+)PkgTokenSpaceGuid\s*\.)?\s*(Pcd[A-Za-z0-9_]+)\b/g;

const GUID_USAGE_RE = /\b(g(?:Efi|Edkii)[A-Za-z0-9_]*(?:ProtocolGuid|PpiGuid|Guid))\b/g;

// HII string-token usage: `STRING_TOKEN (STR_X)` in C — the token is declared
// as a constant in a `.uni` file (same simple-name contract as PCD/GUID).
const STRING_TOKEN_RE = /\bSTRING_TOKEN\s*\(\s*([A-Za-z0-9_]+)\s*\)/g;

const DESCRIPTOR_EXT = /\.(dec|inf|dsc|fdf|uni)(?:\.inc)?$/i;
const SOURCE_EXT = /\.(c|cc|cpp)$/i;

/**
 * Per-project map of `#include <...>` name → indexed `<pkg>/Include/...`
 * header paths, built lazily from the file nodes on first C-include resolve.
 * EDK2 packages declare their `[Includes]` dirs (MdePkg: `Include`), so a
 * header `Uefi.h` lives at `MdePkg/Include/Uefi.h` — root-relative lookups
 * miss it. One pass over the file nodes per project, then O(1) per ref.
 */
const includeIndex = new WeakMap<ResolutionContext, Map<string, string[]>>();
function buildIncludeIndex(context: ResolutionContext): Map<string, string[]> {
  const index = new Map<string, string[]>();
  for (const n of context.getNodesByKind('file')) {
    // BaseTools/Source/C/Include vendored build-tool headers shadow the MdePkg
    // canon for names like `Protocol/DevicePath.h` — never let them win.
    if (n.filePath.startsWith('BaseTools/')) continue;
    const m = /\/Include\/(.+)$/.exec(n.filePath);
    if (m) {
      const arr = index.get(m[1]!);
      if (arr) arr.push(n.filePath);
      else index.set(m[1]!, [n.filePath]);
    }
  }
  return index;
}

export const edk2Resolver: FrameworkResolver = {
  name: 'edk2',
  languages: ['edk2', 'c'],

  detect(context: ResolutionContext): boolean {
    return context.getAllFiles().some((f) => f.endsWith('.dec'));
  },

  // Path-shaped descriptor imports (`MdePkg/MdePkg.dec`, `Rules.fdf.inc`) name
  // a FILE, not a declared symbol — opt them through the name-exists
  // pre-filter so they reach resolve() at all (terraform's `claimsReference`
  // for scoped refs). Also C `#include <...>` targets (`Uefi.h`,
  // `Protocol/Arp.h`): their native import refs die in the pre-filter today.
  claimsReference(name: string): boolean {
    return DESCRIPTOR_EXT.test(name) || name.includes('/') || name.endsWith('.h');
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

    // Path-shaped imports → the target descriptor file's module/file node
    // (descriptor paths, `!include` fragments, and C `#include <...>` targets).
    // Angle-bracket headers resolve against EDK2's default layout
    // (`Include/<name>` — MdePkg/NetworkPkg/MdeModulePkg all declare a single
    // `[Includes]` dir); quoted includes resolve via the normal import resolver
    // (root-relative fileExists fails here → null → no duplicate edge).
    if (DESCRIPTOR_EXT.test(name) || name.includes('/') || name.endsWith('.h')) {
      // `$(FSP_PACKAGE)/…` / `$(PLATFORM_PACKAGE)/…` workspace macros (DSC
      // components, FDF INF lines) — expand the two EDK2-known ones.
      const expanded = name.replace(
        /^\$\((FSP_PACKAGE|PLATFORM_PACKAGE)\)\//,
        (_, k: string) => (k === 'FSP_PACKAGE' ? 'IntelFsp2Pkg/' : 'PrmPkg/')
      );
      let cand = context.fileExists(expanded) ? expanded : null;
      if (!cand && name.endsWith('.h')) {
        // `<pkg>/Include/<name>` layout fallback (see buildIncludeIndex).
        let index = includeIndex.get(context);
        if (!index) {
          index = buildIncludeIndex(context);
          includeIndex.set(context, index);
        }
        const hits = index.get(name);
        if (hits && hits.length > 0) {
          // Prefer the candidate from the including file's own package
          // (ShellPkg code must get ShellPkg's header, not MdeModulePkg's).
          const refPkg = ref.filePath?.split('/')[0];
          cand = (refPkg && hits.find((h) => h.startsWith(refPkg + '/'))) ?? hits[0]!;
        }
      }
      if (!cand) return null;
      const inFile = context.getNodesInFile(cand);
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

    // GUID / PCD / library-class by simple name → DEC constant. STRING_TOKEN
    // names (STR_MODULE_ABSTRACT etc.) are declared in every module's own
    // .uni — prefer the constant in the referencing file's directory before
    // falling back to the first declaration.
    const hits = context
      .getNodesByName(name)
      .filter((n) => n.kind === 'constant' && n.language === 'edk2');
    if (hits.length > 0) {
      const refDir = ref.filePath ? path.dirname(ref.filePath) : '';
      const local = refDir
        ? hits.find((n) => path.dirname(n.filePath) === refDir)
        : undefined;
      const target = local ?? hits[0]!;
      return { original: ref, targetNodeId: target.id, confidence: 0.9, resolvedBy: 'framework' };
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
      content.indexOf('gEdkii') === -1 &&
      content.indexOf('STRING_TOKEN') === -1
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

    // HII string tokens: `STRING_TOKEN (STR_CAP_ARCH)` → the `.uni` constant.
    STRING_TOKEN_RE.lastIndex = 0;
    while ((m = STRING_TOKEN_RE.exec(content)) !== null) {
      emit(m[1]!, undefined, m.index);
    }

    return { nodes: [], references };
  },
};