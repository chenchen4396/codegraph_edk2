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
  RefusedRef,
  ResolutionContext,
  FrameworkExtractionResult,
} from '../types';

// FeaturePcdGet/FeaturePcdSet are the BOOLEAN feature-PCD accessors (NetworkPkg
// gates, e.g. `FeaturePcdGet(PcdNetworkIp4Protocol)`); the leading `\b` keeps
// them from being shadowed by the `Pcd` alternative inside `FeaturePcd`.
// The token-space group covers ALL spellings: `gEfiMdePkgTokenSpaceGuid.PcdX`
// (dotted), `gEmbeddedTokenSpaceGuid.PcdX` (no `Pkg` infix — Arm/Embedded),
// and `PcdGetEx (&gEfiMdePkgTokenSpaceGuid, PcdX)` (pointer form).
// PCD C-names need NOT start with `Pcd` (Arm platform PCDs:
// `FixedPcdGet32 (PL011UartClkInHz)`); accept any uppercase-led identifier —
// lowercase-led identifiers are call-site variables, not PCDs.
const PCD_USAGE_RE =
  /\b(?:Pcd|FixedPcd|PatchPcd|FeaturePcd)(?:Get|Set)(?:Ex)?(?:8|16|32|64|Ptr|Size|Bool)?S?\s*\(\s*(?:(?:&\s*)?([A-Za-z0-9_]+)TokenSpaceGuid\s*[.,]\s*)?((?:Pcd[A-Za-z0-9_]+|[A-Z][A-Za-z0-9_]*))\b/g;

// GUID / PPI / protocol usage candidates: any `g<Cap>…` identifier. The
// SHAPE is only a candidate gate — authority is the DEC declaration set:
// resolve() admits names declared in a DEC [Guids]/[Protocols]/[Ppis]
// section and refuses the rest (gBS/gRT globals, doc-comment mentions,
// undeclared spellings), so no suffix convention (Guid/ProtocolGuid/Ppi,
// versioned Guid_31, or none at all — gEfiRngAlgorithmArmRndr) is ever
// needed and no naming-convention drift can drop a real edge. `{4,}` keeps
// the 2-3 char service-table globals (gBS, gRT, gST, gDS, gPS) from even
// becoming candidates.
const GUID_USAGE_RE = /\b(g[A-Z][A-Za-z0-9_]{3,})\b/g;

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
  const add = (key: string, filePath: string) => {
    const arr = index.get(key);
    if (arr) arr.push(filePath);
    else index.set(key, [filePath]);
  };
  const allFiles = new Set<string>();
  for (const n of context.getNodesByKind('file')) {
    // BaseTools/Source/C/Include vendored build-tool headers shadow the MdePkg
    // canon for names like `Protocol/DevicePath.h` — never let them win. Path
    // segments (not prefix): nested-EDK2 layouts put BaseTools under
    // `<repo>/edk2/BaseTools/…`.
    if (n.filePath.split('/').includes('BaseTools')) continue;
    allFiles.add(n.filePath);
    const m = /\/Include\/(.+)$/.exec(n.filePath);
    if (m) add(m[1]!, n.filePath);
  }
  // DEC `[Includes]` declarations are the authoritative include dirs — a
  // package may declare dirs OUTSIDE the default `Include/` layout
  // (SecurityPkg's libspdm, MdePkg's MipiSysTLib, …). Parse each DEC's
  // `[Includes…]` section and map every indexed file under a declared dir by
  // its dir-relative name. Declared dirs are package-relative (relative to
  // the DEC file's own directory).
  const decDirs = new Set<string>();
  for (const n of context.getNodesByKind('module')) {
    if (n.language !== 'edk2' || !n.filePath.toLowerCase().endsWith('.dec')) continue;
    const content = context.readFile(n.filePath);
    if (!content) continue;
    const decDir = path.posix.dirname(n.filePath);
    let inIncludes = false;
    for (const raw of content.split('\n')) {
      const line = raw.trim();
      if (/^\[[^\]]+\]$/.test(line)) {
        inIncludes = /^\[includes/i.test(line);
        continue;
      }
      if (!inIncludes || line === '' || line.startsWith('#')) continue;
      const dir = line.split(/\s+/)[0]!.trim();
      if (dir && !dir.startsWith('!')) {
        decDirs.add(decDir === '.' ? dir : path.posix.join(decDir, dir));
      }
    }
  }
  if (decDirs.size > 0) {
    const dirs = [...decDirs].sort((a, b) => b.length - a.length); // longest first
    for (const filePath of allFiles) {
      for (const dir of dirs) {
        if (filePath.startsWith(dir + '/')) {
          add(filePath.slice(dir.length + 1), filePath);
          break;
        }
      }
    }
  }
  return index;
}

/**
 * Per-project DECLARED-name sets, built lazily from the indexed nodes:
 * which GUID/Protocol/PPI names are declared in DEC sections, which PCD
 * names in DEC [Pcds*], which string tokens in UNI files. Authority for
 * C-side synthetic refs: a candidate name that is NOT declared is refused
 * (dropped), whatever its shape; a declared name resolves regardless of
 * shape (gEfiRngAlgorithmArmRndr has no Guid suffix at all).
 */
interface DeclaredSets {
  /** DEC [Guids]/[Protocols]/[Ppis] entry names (`gXxx`) */
  guids: Set<string>;
  /** DEC [Pcds*] PCD names (simple name, e.g. `PcdDebugPropertyMask`) */
  pcds: Set<string>;
  /** UNI `#string` tokens */
  strings: Set<string>;
}
const declaredSets = new WeakMap<ResolutionContext, DeclaredSets>();
function buildDeclaredSets(context: ResolutionContext): DeclaredSets {
  const sets: DeclaredSets = { guids: new Set(), pcds: new Set(), strings: new Set() };
  for (const n of context.getNodesByKind('constant')) {
    if (n.language !== 'edk2') continue;
    if (n.filePath.toLowerCase().endsWith('.uni')) {
      sets.strings.add(n.name);
    } else if (n.filePath.toLowerCase().endsWith('.dec')) {
      // PCD constants carry the qualified `TokenSpace.PcdName`; GUID/
      // Protocol/PPI constants are bare `gXxx` names (DEC parser requires
      // the g prefix). Library-class constants have neither shape.
      if (n.name.startsWith('g')) sets.guids.add(n.name);
      else if (n.qualifiedName.includes('.')) sets.pcds.add(n.name);
    }
  }
  return sets;
}

export const edk2Resolver: FrameworkResolver = {
  name: 'edk2',
  // `cpp` included: UEFI C++ sources (.cpp/.cc — GoogleTest hosts,
  // NetworkPkg/RedfishPkg/EmulatorPkg) carry the same PCD/GUID/STRING_TOKEN
  // usage and must get synthetic refs too. Safe for non-EDK2 C++ projects:
  // detect() requires a `.dec`, and extract()'s cheap gate short-circuits.
  languages: ['edk2', 'c', 'cpp'],

  detect(context: ResolutionContext): boolean {
    return context.getAllFiles().some((f) => f.toLowerCase().endsWith('.dec'));
  },

  // Path-shaped descriptor imports (`MdePkg/MdePkg.dec`, `Rules.fdf.inc`) name
  // a FILE, not a declared symbol — opt them through the name-exists
  // pre-filter so they reach resolve() at all (terraform's `claimsReference`
  // for scoped refs). Also C `#include <...>` targets (`Uefi.h`,
  // `Protocol/Arp.h`): their native import refs die in the pre-filter today.
  claimsReference(name: string): boolean {
    return (
      DESCRIPTOR_EXT.test(name) ||
      name.includes('/') ||
      name.endsWith('.h') ||
      // Wide GUID-candidate shape: pre-filter would drop undeclared gXxx
      // names (no node exists) before resolve() can refuse them.
      /^g[A-Z][A-Za-z0-9_]{3,}$/.test(name)
    );
  },

  resolve(ref: UnresolvedRef, context: ResolutionContext): ResolvedRef | RefusedRef | null {
    if (ref.referenceKind !== 'references' && ref.referenceKind !== 'imports') return null;

    const name = ref.referenceName;
    const refused = (reason: string): RefusedRef => ({ original: ref, refused: true, reason });

    // C-side synthetic refs (emitted by this resolver's extract(), keyed by
    // the FILE node id) are DECLARATION-GOVERNED: extract() uses broad
    // candidate shapes, and only names declared in the authoritative EDK2
    // sections (DEC [Guids]/[Protocols]/[Ppis]/[Pcds*], UNI `#string`) are
    // real — everything else (gBS/gRT globals, doc mentions, undeclared
    // spellings, non-PCD accessor args) is refused and dropped, whatever its
    // shape. Shape conventions (Guid/ProtocolGuid suffixes) are never
    // required: gEfiRngAlgorithmArmRndr resolves because it is DEC-declared.
    if (
      ref.language === 'c' &&
      ref.referenceKind === 'references' &&
      ref.fromNodeId === `file:${ref.filePath}`
    ) {
      let sets = declaredSets.get(context);
      if (!sets) {
        sets = buildDeclaredSets(context);
        declaredSets.set(context, sets);
      }
      if (ref.candidates && ref.candidates.length > 0) {
        // PCD accessor argument (`PcdGet32 (PcdX)`, `FixedPcdGet32 (PL011…)`)
        // — AutoGen generates it from DEC declarations, so it must be one.
        if (!sets.pcds.has(name)) {
          return refused(`PCD '${name}' is not declared in any DEC [Pcds*] section`);
        }
      } else if (/^g[A-Z][A-Za-z0-9_]{3,}$/.test(name)) {
        if (!sets.guids.has(name)) {
          return refused(`GUID '${name}' is not declared in any DEC [Guids]/[Protocols]/[Ppis] section`);
        }
      } else if (/^STR_[A-Za-z0-9_]+$/.test(name)) {
        if (!sets.strings.has(name)) {
          return refused(`string token '${name}' is not declared in any .uni file`);
        }
      } else {
        return null; // not an EDK2 candidate shape — other strategies own it
      }
    }

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
      // `$(WORKSPACE)/…` / `$(EDK_TOOLS_PATH)/…` — workspace-level EDK2 build
      // macros, universal across platforms: WORKSPACE is the project root,
      // EDK_TOOLS_PATH the BaseTools tree. (Vendor macros like
      // `$(FSP_PACKAGE)` are platform-DEFINE'd and expanded extractor-side
      // from the file's own [Defines]; a hardcoded mapping here would point
      // at the wrong package on any platform that overrides them.)
      const expanded = name
        .replace(/^\$\(WORKSPACE\)\//, '')
        .replace(/^\$\(EDK_TOOLS_PATH\)\//, 'BaseTools/');
      let cand = context.fileExists(expanded) ? expanded : null;
      if (!cand) {
        // EDK2 build tools resolve `!include` paths relative to the including
        // file's directory FIRST, then the workspace root (MetaFileParser:
        // PathClass(IncludedFile, self.MetaFile.Dir) → gWorkspace). Descriptor
        // refs are emitted workspace-relative; try the including-file-relative
        // spelling when the workspace-relative one misses.
        const refDir = ref.filePath ? path.dirname(ref.filePath) : '';
        const joined = refDir ? path.posix.join(refDir, expanded) : '';
        if (joined && context.fileExists(joined)) cand = joined;
      }
      if (!cand) {
        // `<pkg>/Include/<name>` layout fallback (see buildIncludeIndex) —
        // for C headers AND assembly/ASL include targets (`Register/….h`,
        // `AArch64.h`, `CommonMacros.inc`): EDK2 builds pass `-I` include dirs
        // (MdePkg/Include, …), so an include name is relative to any declared
        // include dir, not necessarily the including file. Map miss → O(1).
        let index = includeIndex.get(context);
        if (!index) {
          index = buildIncludeIndex(context);
          includeIndex.set(context, index);
        }
        const hits = index.get(expanded);
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
    // falling back to the first declaration. For package-level constants
    // (GUIDs), prefer a declaration in the referencing file's own package
    // (a vendor fork may redeclare a GUID in its own DEC).
    const hits = context
      .getNodesByName(name)
      .filter((n) => n.kind === 'constant' && n.language === 'edk2');
    if (hits.length > 0) {
      const refDir = ref.filePath ? path.dirname(ref.filePath) : '';
      const refPkg = ref.filePath?.split('/')[0];
      const local = refDir
        ? hits.find((n) => path.dirname(n.filePath) === refDir)
        : undefined;
      const samePkg =
        refPkg && !local
          ? hits.find((n) => n.filePath.startsWith(refPkg + '/'))
          : undefined;
      const target = local ?? samePkg ?? hits[0]!;
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
    // minting refs for thousands of plain-C files in a mixed tree). Must
    // cover the widened GUID pattern too — a file mentioning only a vendor
    // GUID (gZeroGuid, gAcpiTableHobGuid…) has no `gEfi`/`gEdkii` token.
    // Full-content scan: a token past the first 64KB must not be missed.
    if (
      content.indexOf('Pcd') === -1 &&
      content.indexOf('gEfi') === -1 &&
      content.indexOf('gEdkii') === -1 &&
      content.indexOf('STRING_TOKEN') === -1 &&
      !/g[A-Z][A-Za-z0-9_]{3,}\b/.test(content)
    ) {
      return { nodes: [], references: [] };
    }

    // The C file's file node (matches TreeSitterExtractor's `file:<path>` id —
    // generateNodeId would produce a different hash and the ref would be
    // dropped by the store's insertedIds filter).
    const fromNodeId = `file:${filePath}`;
    const references: UnresolvedRef[] = [];
    const seen = new Set<string>();

    // Line/column from a byte offset: one scan builds the line-start index,
    // then binary search — O(log n) per ref instead of O(offset).
    const lineStarts: number[] = [0];
    for (let i = 0; i < content.length; i++) {
      if (content.charCodeAt(i) === 0x0a /* \n */) lineStarts.push(i + 1);
    }
    const lineCol = (offset: number): { line: number; column: number } => {
      let lo = 0;
      let hi = lineStarts.length - 1;
      while (lo < hi) {
        const mid = (lo + hi + 1) >> 1;
        if (lineStarts[mid]! <= offset) lo = mid;
        else hi = mid - 1;
      }
      return { line: lo + 1, column: offset - lineStarts[lo]! };
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
      const tokenSpace = m[1]; // e.g. gEfiMdePkg, gEmbedded
      const pcdName = m[2]!;
      const full = tokenSpace
        ? `${tokenSpace}TokenSpaceGuid.${pcdName}`
        : pcdName;
      // Always carry the candidate (simple or qualified): resolve() gates
      // synthetic refs on the DEC PCD declaration set, and the candidates
      // field is what marks this ref as a PCD-accessor usage.
      emit(pcdName, [full], m.index);
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