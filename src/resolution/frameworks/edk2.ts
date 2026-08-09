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
 * `resolve()` returns `references`/`imports` edges plus library-CALL bridges
 * (C call → library instance function via the [LibraryClasses]→DSC→[Sources]
 * declaration chain). A call name that exists only in library instances is
 * REFUSED (row deleted) when the caller module declares none of the providing
 * classes — plain same-name resolution would mint an edge the build could
 * never link. Instance-level ambiguity (multi-platform DSC mappings,
 * module-type-partitioned sections, !if branches) keeps the row instead and
 * falls through to ordinary resolution. The synthetic PCD/GUID/STRING_TOKEN
 * `references` refs name the PCD/constant, never shadowing the ordinary
 * function edge for the accessor call itself (e.g. `LibPcdGet32` falls back
 * to normal name resolution when its instances are ambiguous).
 * Returning `confidence >= 0.9` short-circuits resolution
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

/**
 * LIBRARY-CALL BRIDGE — the EDK2 link model is declaration-driven end to end:
 *
 *   module C calls Foo()
 *     └─ module INF [LibraryClasses] declares class C (Foo's library class)
 *        └─ platform DSC [LibraryClasses] `C|Impl.inf` — or the unique INF
 *           whose LIBRARY_CLASS = C when no DSC / no mapping (per-component
 *           `<LibraryClasses>` overrides refine the instance per module)
 *           └─ instance INF [Sources] defines Foo → the edge
 *
 * C sources have no import statement for library functions (the build links
 * them); plain cross-module name matching therefore misses almost every
 * library call (115k+ unresolved calls on the tianocore corpus). This index
 * maps function names → declaring library instance, keyed by the caller's
 * declared classes, and admits only unambiguous (caller-declared class +
 * single matching instance) calls at confidence 0.9.
 */
interface LibCallTarget {
  nodeId: string;
  className: string;
  infPath: string;
}
interface LibraryIndex {
  /** C file → owning module INF + the classes its [LibraryClasses] declares */
  fileModules: Map<string, { moduleInf: string; classes: Set<string> }>;
  /** module INF → function names defined in its [Sources] (module-local wins) */
  moduleFunctions: Map<string, Set<string>>;
  /** class → DSC top-level [LibraryClasses] instance INFs (authoritative) */
  defaultInstances: Map<string, string[]>;
  /** class → LIBRARY_CLASS-declared instance INFs (fallback when no DSC map) */
  libClassInstances: Map<string, string[]>;
  /** module INF → class → per-component override instance INF */
  overrides: Map<string, Map<string, string>>;
  /** function name → declaring library-instance targets */
  fns: Map<string, LibCallTarget[]>;
}
const libraryIndex = new WeakMap<ResolutionContext, LibraryIndex>();

/** Parse an INF's [Defines]/[LibraryClasses]/[Sources] with section tracking. */
function parseInfLight(
  content: string
): { libraryClass: string[]; classes: string[]; sources: string[] } {
  let section = '';
  const classes: string[] = [];
  const sources: string[] = [];
  const libraryClass: string[] = [];
  const defines = new Map<string, string>();
  for (const raw of content.split('\n')) {
    const line = raw.trim();
    const hdr = line.match(/^\[([^\]]+)\]/);
    if (hdr) {
      section = hdr[1]!.toLowerCase().split(',')[0]!.replace(/\.[A-Za-z0-9_]+/g, '');
      continue;
    }
    if (line === '' || line.startsWith('!') || line.startsWith('#')) continue;
    if (section === 'defines') {
      const def = line.match(/^DEFINE\s+([A-Za-z0-9_]+)\s*=\s*(.*)$/i);
      if (def) defines.set(def[1]!, def[2]!.trim());
      const lc = line.match(/^LIBRARY_CLASS\s*=\s*([A-Za-z0-9_]+)/i);
      if (lc) libraryClass.push(lc[1]!);
    } else if (section === 'libraryclasses') {
      const cls = line.split(/\s+/)[0]!;
      if (cls) classes.push(cls);
    } else if (section === 'sources') {
      // `$(NAME)` macros come from [Defines] DEFINE rows (OpenSSL-style
      // autogenerated listings); resolve iteratively against previously seen
      // definitions (a DEFINE may itself reference an earlier one).
      let sp = line.split(/\s+/)[0]!.replace(/\|.*$/, '').trim();
      for (let i = 0; i < 10 && sp.includes('$('); i++) {
        const m = sp.match(/\$\(([A-Za-z0-9_]+)\)/);
        if (!m) break;
        const v = defines.get(m[1]!);
        if (v === undefined) break;
        sp = sp.replace(`$(${m[1]})`, v);
      }
      if (/\.(c|cc|cpp)$/i.test(sp)) sources.push(sp);
    }
  }
  return { libraryClass, classes, sources };
}

/**
 * Inline `!include` file rows into a DSC/INF listing. EDK2 platform DSC
 * files routinely split their [LibraryClasses] into `!include` fragments
 * (e.g. NetworkPkg/NetworkLibs.dsc.inc), and those rows ARE the authoritative
 * Class|Impl.inf mappings — skipping them loses the platform's instance
 * choice. Included rows keep their position, so the caller's section
 * tracking (incl. a [LibraryClasses] header inside the fragment) applies.
 * Depth-capped against recursive includes.
 */
function expandIncludeLines(content: string, filePath: string, readFile: (p: string) => string | null, depth = 0): string {
  if (depth > 5) return content;
  const rel = (p: string): string => {
    const dir = filePath.includes('/') ? filePath.slice(0, filePath.lastIndexOf('/')) : '';
    return path.posix.normalize(dir ? `${dir}/${p}` : p).replace(/\\/g, '/');
  };
  const out: string[] = [];
  for (const raw of content.split('\n')) {
    const inc = raw.trim().match(/^!include\s+(\S+)/i);
    if (inc) {
      // EDK2 `!include` paths resolve against the WORKSPACE ROOT, not the
      // including file's directory (`!include NetworkPkg/NetworkLibs.dsc.inc`
      // from OvmfPkg/OvmfPkgX64.dsc). Try the root-relative form first, then
      // the file-relative form for odd layouts.
      const incPath = rel(inc[1]!);
      const incContent = readFile(inc[1]!) ?? readFile(incPath);
      if (incContent) out.push(expandIncludeLines(incContent, inc[1]!, readFile, depth + 1));
      continue;
    }
    out.push(raw);
  }
  return out.join('\n');
}

function buildLibraryIndex(context: ResolutionContext): LibraryIndex {
  const idx: LibraryIndex = {
    fileModules: new Map(),
    moduleFunctions: new Map(),
    defaultInstances: new Map(),
    libClassInstances: new Map(),
    overrides: new Map(),
    fns: new Map(),
  };
  const rel = (infPath: string, p: string): string => {
    const dir = infPath.includes('/') ? infPath.slice(0, infPath.lastIndexOf('/')) : '';
    return path.posix.normalize(dir ? `${dir}/${p}` : p).replace(/\\/g, '/');
  };
  const readExpanded = (p: string): string | null => {
    const c = context.readFile(p);
    return c === null ? null : expandIncludeLines(c, p, (q) => context.readFile(q));
  };
  const addInstance = (map: Map<string, string[]>, cls: string, inf: string) => {
    const arr = map.get(cls);
    if (arr) {
      if (!arr.includes(inf)) arr.push(inf);
    } else map.set(cls, [inf]);
  };

  // Pass 1: INF modules → per-file class declarations + LIBRARY_CLASS instances.
  for (const n of context.getNodesByKind('module')) {
    if (n.language !== 'edk2' || !n.filePath.toLowerCase().endsWith('.inf')) continue;
    const content = readExpanded(n.filePath);
    if (!content) continue;
    const info = parseInfLight(content);
    const modFns = idx.moduleFunctions.get(n.filePath) ?? new Set<string>();
    for (const src of info.sources) {
      const file = rel(n.filePath, src);
      const entry = idx.fileModules.get(file) ?? { moduleInf: n.filePath, classes: new Set<string>() };
      for (const cls of info.classes) entry.classes.add(cls);
      idx.fileModules.set(file, entry);
      for (const fnNode of context.getNodesInFile(file)) {
        if (fnNode.kind === 'function') modFns.add(fnNode.name);
      }
    }
    if (modFns.size > 0) idx.moduleFunctions.set(n.filePath, modFns);
    for (const cls of info.libraryClass) addInstance(idx.libClassInstances, cls, n.filePath);
  }
  // Pass 2: DSC — top-level [LibraryClasses] rows set the authoritative
  // default instance; `<LibraryClasses>` rows inside a [Components] block
  // override per module.
  for (const n of context.getNodesByKind('module')) {
    if (n.language !== 'edk2' || !n.filePath.toLowerCase().endsWith('.dsc')) continue;
    const content = readExpanded(n.filePath);
    if (!content) continue;
    let section = '';
    let inBlock = false;
    let blockSection: string | null = null;
    let currentComponent = '';
    for (const raw of content.split('\n')) {
      const line = raw.trim();
      const hdr = line.match(/^\[([^\]]+)\]/);
      if (hdr) {
        section = hdr[1]!.toLowerCase().split(',')[0]!.replace(/\.[A-Za-z0-9_]+/g, '');
        inBlock = false;
        blockSection = null;
        continue;
      }
      if (line === '' || line.startsWith('#') || line.startsWith('!')) continue;
      if (inBlock) {
        if (line === '}') {
          inBlock = false;
          blockSection = null;
          currentComponent = '';
          continue;
        }
        const inner = line.match(/^<([^>]+)>$/);
        if (inner) {
          blockSection = inner[1]!.toLowerCase().replace(/\.[A-Za-z0-9_]+/g, '');
          continue;
        }
        if (blockSection === 'libraryclasses') {
          const m = line.match(/^([A-Za-z0-9_]+)\s*\|\s*(\S+\.inf)/);
          if (m && currentComponent) {
            let ov = idx.overrides.get(currentComponent);
            if (!ov) {
              ov = new Map();
              idx.overrides.set(currentComponent, ov);
            }
            ov.set(m[1]!, m[2]!);
          }
        }
        continue;
      }
      if (section === 'libraryclasses') {
        const m = line.match(/^([A-Za-z0-9_]+)\s*\|\s*(\S+\.inf)/);
        if (m) addInstance(idx.defaultInstances, m[1]!, m[2]!);
      } else if (section === 'components') {
        const inf = line.match(/^(\S+\.inf)/);
        if (inf) {
          currentComponent = inf[1]!;
          if (line.includes('{')) inBlock = true;
        } else if (line === '{') {
          inBlock = true;
        }
      }
    }
  }
  // Pass 3: instance [Sources] functions — every candidate instance (DSC
  // defaults, LIBRARY_CLASS fallbacks, per-module overrides).
  const instanceInfs = new Set<string>();
  for (const list of idx.defaultInstances.values()) for (const i of list) instanceInfs.add(i);
  for (const list of idx.libClassInstances.values()) for (const i of list) instanceInfs.add(i);
  for (const m of idx.overrides.values()) for (const i of m.values()) instanceInfs.add(i);
  const seen = new Set<string>();
  for (const infPath of instanceInfs) {
    const content = context.readFile(infPath);
    if (!content) continue;
    const info = parseInfLight(content);
    if (info.libraryClass.length === 0) continue;
    // First declared class is the canonical one; arch-split instances
    // (BaseLib's [Sources.Ia32] + [Sources.X64]) define the same function in
    // several files — dedup per (instance, function name), keep the first
    // definition: any one of them is the instance's implementation.
    for (const src of info.sources) {
      const file = rel(infPath, src);
      for (const fn of context.getNodesInFile(file)) {
        if (fn.kind !== 'function') continue;
        const key = `${infPath}\u0000${fn.name}`;
        if (seen.has(key)) continue;
        seen.add(key);
        const arr = idx.fns.get(fn.name) ?? [];
        arr.push({ nodeId: fn.id, className: info.libraryClass[0]!, infPath });
        idx.fns.set(fn.name, arr);
      }
    }
  }
  return idx;
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
    const name = ref.referenceName;
    const refused = (reason: string): RefusedRef => ({ original: ref, refused: true, reason });

    // LIBRARY-CALL BRIDGE (calls from C): the module's INF [LibraryClasses]
    // declares the class, the DSC (or unique LIBRARY_CLASS) picks the
    // instance, the instance's [Sources] defines the function. Confidence
    // 0.9 short-circuits after the caller's declared-class check and an
    // unambiguous single instance. A call name that only exists in library
    // instances, from a module that did NOT declare the class, is refused:
    // plain same-name resolution would otherwise mint a WRONG edge to the
    // instance (the build would not link it). A module that defines the name
    // itself wins (module-local functions shadow library names).
    if (
      (ref.referenceKind === 'calls' && (ref.language === 'c' || ref.language === 'cpp') && ref.filePath)
    ) {
      let lIdx = libraryIndex.get(context);
      if (!lIdx) {
        lIdx = buildLibraryIndex(context);
        libraryIndex.set(context, lIdx);
      }
      const targets = lIdx.fns.get(name);
      if (targets && targets.length > 0) {
        const caller = lIdx.fileModules.get(ref.filePath);
        if (!caller) return null; // not module code (BaseTools etc.) — normal resolution
        if (lIdx.moduleFunctions.get(caller.moduleInf)?.has(name)) return null; // module-local definition wins
        // Effective instance for the caller's module: per-module override
        // first, then the DSC top-level default, then the unique
        // LIBRARY_CLASS fallback (DSC is authoritative when present).
        const effectiveInstance = (cls: string): string | null => {
          const ov = lIdx.overrides.get(caller.moduleInf)?.get(cls);
          if (ov) return ov;
          const dsc = lIdx.defaultInstances.get(cls);
          if (dsc && dsc.length > 0) return dsc.length === 1 ? dsc[0]! : null;
          const lc = lIdx.libClassInstances.get(cls);
          return lc && lc.length === 1 ? lc[0]! : null;
        };
        const cands = targets.filter(
          (t) => caller.classes.has(t.className) && effectiveInstance(t.className) === t.infPath
        );
        if (cands.length === 1) {
          return { original: ref, targetNodeId: cands[0]!.nodeId, confidence: 0.9, resolvedBy: 'framework' };
        }
        // Refuse ONLY when the caller declares none of the providing classes
        // (the name lives exclusively in library instances, so the build
        // could never link this call and same-name resolution would mint a
        // wrong edge). Instance-level ambiguity — multi-platform DSC
        // mappings, module-type-partitioned [LibraryClasses.common.*]
        // sections, !if branches, or an unknown per-module override — keeps
        // the row and falls through to ordinary resolution.
        const provided = new Set(targets.map((t) => t.className));
        if (![...caller.classes].some((c) => provided.has(c))) {
          return refused(
            `library call '${name}': caller module declares none of the providing classes ` +
              `(${[...provided].join(', ')}); the build could not link it`
          );
        }
        return null;
      }
    }

    if (ref.referenceKind !== 'references' && ref.referenceKind !== 'imports') return null;

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
      } else {
        // Any non-g candidate is a STRING_TOKEN use — UEFI HII does not
        // constrain token names (the corpus declares TPM_*, CONF_*, TCG_*,
        // DISC_* … 169 non-STR_ tokens); the .uni declaration set is the
        // authority, not a prefix convention.
        if (!sets.strings.has(name)) {
          return refused(`string token '${name}' is not declared in any .uni file`);
        }
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