import { describe, it, expect } from 'vitest';
import { edk2Resolver } from '../src/resolution/frameworks/edk2';
import type { UnresolvedRef } from '../src/resolution/types';
import type { Node } from '../src/types';
import { generateNodeId } from '../src/extraction/tree-sitter-helpers';

// Unit-level: a hand-rolled ResolutionContext holding the graph the edk2
// resolver queries. Mirrors the NestJS resolver test in frameworks.test.ts.

interface FakeContext extends Record<string, unknown> {
  getNodesInFile: (fp: string) => Node[];
  getNodesByName: (name: string) => Node[];
  getNodesByQualifiedName: (q: string) => Node[];
  getNodesByKind: (k: Node['kind']) => Node[];
  fileExists: (fp: string) => boolean;
  readFile: (fp: string) => string | null;
  getProjectRoot: () => string;
  getAllFiles: () => string[];
  getNodesByLowerName: (name: string) => Node[];
  getImportMappings: (fp: string, lang: string) => unknown[];
}

function mkConstant(
  name: string,
  qualifiedName: string,
  filePath: string,
  startLine: number,
  language: 'edk2' = 'edk2'
): Node {
  return {
    id: generateNodeId(filePath, 'constant', name, startLine),
    kind: 'constant',
    name,
    qualifiedName,
    filePath,
    language,
    startLine,
    endLine: startLine,
    startColumn: 0,
    endColumn: 0,
    updatedAt: Date.now(),
  };
}

function mkModuleNode(filePath: string, startLine: number, name: string): Node {
  return {
    id: generateNodeId(filePath, 'module', name, startLine),
    kind: 'module',
    name,
    qualifiedName: `${filePath}::${name}`,
    filePath,
    language: 'edk2',
    startLine,
    endLine: startLine,
    startColumn: 0,
    endColumn: 0,
    updatedAt: Date.now(),
  };
}

function mkFunction(filePath: string, startLine: number, name: string): Node {
  return {
    id: generateNodeId(filePath, 'function', name, startLine),
    kind: 'function',
    name,
    qualifiedName: `${filePath}::${name}`,
    filePath,
    language: 'c',
    startLine,
    endLine: startLine,
    startColumn: 0,
    endColumn: 0,
    updatedAt: Date.now(),
  };
}

function baseContext(): FakeContext {
  return {
    getNodesInFile: () => [],
    getNodesByName: () => [],
    getNodesByQualifiedName: () => [],
    getNodesByKind: () => [],
    fileExists: () => false,
    readFile: () => null,
    getProjectRoot: () => '/test',
    getAllFiles: () => [],
    getNodesByLowerName: () => [],
    getImportMappings: () => [],
  };
}

describe('edk2Resolver.detect', () => {
  it('detects an EDK2 project when a .dec exists', () => {
    const ctx = { ...baseContext(), getAllFiles: () => ['MdePkg/MdePkg.dec'] };
    expect(edk2Resolver.detect(ctx as never)).toBe(true);
  });

  it('returns false when no .dec exists', () => {
    const ctx = { ...baseContext(), getAllFiles: () => ['pkg/foo.c'] };
    expect(edk2Resolver.detect(ctx as never)).toBe(false);
  });
});

describe('edk2Resolver.resolve', () => {
  const guid = mkConstant(
    'gEfiArpProtocolGuid',
    'MdePkg::gEfiArpProtocolGuid',
    'MdePkg/MdePkg.dec',
    120
  );
  const pcd = mkConstant(
    'PcdNetworkIp4Protocol',
    'gEfiNetworkPkgTokenSpaceGuid.PcdNetworkIp4Protocol',
    'NetworkPkg/NetworkPkg.dec',
    200
  );
  const decModule = mkModuleNode('MdePkg/MdePkg.dec', 3, 'MdePkg');

  it('resolves a C-side GUID usage to the DEC constant (cross-language c→edk2)', () => {
    const ctx = {
      ...baseContext(),
      getNodesByName: (n: string) => (n === 'gEfiArpProtocolGuid' ? [guid] : []),
    };
    const ref: UnresolvedRef = {
      fromNodeId: generateNodeId('test/App.c', 'file', 'test/App.c', 1),
      referenceName: 'gEfiArpProtocolGuid',
      referenceKind: 'references',
      line: 10,
      column: 5,
      filePath: 'test/App.c',
      language: 'c',
    };
    const result = edk2Resolver.resolve(ref, ctx as never);
    expect(result?.targetNodeId).toBe(guid.id);
    expect(result?.resolvedBy).toBe('framework');
    expect(result?.confidence).toBeGreaterThanOrEqual(0.9);
  });

  it('resolves a C-side PCD usage to the DEC PCD via token-space qualified name', () => {
    const ctx = {
      ...baseContext(),
      getNodesByQualifiedName: (q: string) =>
        q === 'gEfiNetworkPkgTokenSpaceGuid.PcdNetworkIp4Protocol' ? [pcd] : [],
      getNodesByName: () => [],
    };
    const ref: UnresolvedRef = {
      fromNodeId: generateNodeId('test/App.c', 'file', 'test/App.c', 1),
      referenceName: 'PcdNetworkIp4Protocol',
      referenceKind: 'references',
      line: 20,
      column: 0,
      filePath: 'test/App.c',
      language: 'c',
      candidates: ['gEfiNetworkPkgTokenSpaceGuid.PcdNetworkIp4Protocol'],
    };
    const result = edk2Resolver.resolve(ref, ctx as never);
    expect(result?.targetNodeId).toBe(pcd.id);
    expect(result?.resolvedBy).toBe('framework');
  });

  it('resolves an INF import to the DEC module node', () => {
    const ctx = {
      ...baseContext(),
      fileExists: (p: string) => p === 'MdePkg/MdePkg.dec',
      getNodesInFile: (p: string) => (p === 'MdePkg/MdePkg.dec' ? [decModule] : []),
    };
    const ref: UnresolvedRef = {
      fromNodeId: generateNodeId('NetworkPkg/ArpDxe/ArpDxe.inf', 'module', 'ArpDxe', 3),
      referenceName: 'MdePkg/MdePkg.dec',
      referenceKind: 'imports',
      line: 18,
      column: 0,
      filePath: 'NetworkPkg/ArpDxe/ArpDxe.inf',
      language: 'edk2',
    };
    const result = edk2Resolver.resolve(ref, ctx as never);
    expect(result?.targetNodeId).toBe(decModule.id);
    expect(result?.resolvedBy).toBe('framework');
  });

  it('resolves an INF ENTRY_POINT to the C function via Sources candidates', () => {
    const fn = mkFunction('NetworkPkg/ArpDxe/ArpMain.c', 25, 'ArpDriverEntryPoint');
    const ctx = {
      ...baseContext(),
      getNodesInFile: (p: string) =>
        p === 'NetworkPkg/ArpDxe/ArpMain.c' ? [fn] : [],
      getNodesByName: () => [],
    };
    const ref: UnresolvedRef = {
      fromNodeId: generateNodeId('NetworkPkg/ArpDxe/ArpDxe.inf', 'module', 'ArpDxe', 3),
      referenceName: 'ArpDriverEntryPoint',
      referenceKind: 'references',
      line: 7,
      column: 0,
      filePath: 'NetworkPkg/ArpDxe/ArpDxe.inf',
      language: 'edk2',
      candidates: ['NetworkPkg/ArpDxe/ArpMain.c', 'NetworkPkg/ArpDxe/ArpImpl.c'],
    };
    const result = edk2Resolver.resolve(ref, ctx as never);
    expect(result?.targetNodeId).toBe(fn.id);
    expect(result?.confidence).toBeGreaterThanOrEqual(0.95);
  });

  it('returns null for a non-references/imports ref (does not shadow calls)', () => {
    const ctx = baseContext();
    const ref: UnresolvedRef = {
      fromNodeId: 'x',
      referenceName: 'PcdGet32',
      referenceKind: 'calls',
      line: 1,
      column: 0,
      filePath: 'test/App.c',
      language: 'c',
    };
    expect(edk2Resolver.resolve(ref, ctx as never)).toBeNull();
  });
});

describe('edk2Resolver.extract — C-side ref synthesis', () => {
  it('synthesizes a PCD reference for PcdGet32(PcdFoo) with token-space candidate', () => {
    const src = `#include <Uefi.h>
VOID F(VOID) {
  UINT32 v = PcdGet32(gEfiMdePkgTokenSpaceGuid.PcdDebugPropertyMask);
}`;
    const { references } = edk2Resolver.extract!('MdePkg/Foo.c', src)!;
    const refs = references.filter((r) => r.referenceKind === 'references');
    const pcd = refs.find((r) => r.referenceName === 'PcdDebugPropertyMask');
    expect(pcd).toBeDefined();
    expect(pcd!.candidates).toContain('gEfiMdePkgTokenSpaceGuid.PcdDebugPropertyMask');
    expect(pcd!.language).toBe('c');
    expect(pcd!.filePath).toBe('MdePkg/Foo.c');
  });

  it('synthesizes a GUID reference for gEfiXxxProtocolGuid usage', () => {
    const src = `#include <Uefi.h>
EFI_STATUS F(VOID) { extern void gEfiArpProtocolGuid_SEEN; return 0; }
/* also: gEfiArpProtocolGuid */`;
    const { references } = edk2Resolver.extract!('MdePkg/Foo.c', src)!;
    const guid = references.find((r) => r.referenceName === 'gEfiArpProtocolGuid');
    expect(guid).toBeDefined();
    expect(guid!.referenceKind).toBe('references');
  });

  it('dedups repeated PCD/GUID usages to one ref per name', () => {
    const src = `#include <Uefi.h>
VOID F(VOID) {
  PcdGet32(gEfiXPkgTokenSpaceGuid.PcdA);
  PcdGet32(gEfiXPkgTokenSpaceGuid.PcdA);
  gEfiFooProtocolGuid; gEfiFooProtocolGuid;
}`;
    const { references } = edk2Resolver.extract!('MdePkg/Foo.c', src)!;
    const pcdA = references.filter((r) => r.referenceName === 'PcdA');
    const foo = references.filter((r) => r.referenceName === 'gEfiFooProtocolGuid');
    expect(pcdA).toHaveLength(1);
    expect(foo).toHaveLength(1);
  });

  it('returns empty for a .inf / non-C file', () => {
    const { references, nodes } = edk2Resolver.extract!(
      'MdePkg/MdePkg.dec',
      '[Guids]\ngFoo={0x1}'
    )!;
    expect(references).toHaveLength(0);
    expect(nodes).toHaveLength(0);
  });

  it('returns empty for a .c with no PCD/GUID usage', () => {
    const { references } = edk2Resolver.extract!('MdePkg/Plain.c', 'int add(int a, int b){return a+b;}')!;
    expect(references).toHaveLength(0);
  });
});
describe('edk2Resolver.claimsReference', () => {
  it('claims path-shaped descriptor refs, fragments, and C headers', () => {
    expect(edk2Resolver.claimsReference('MdePkg/MdePkg.dec')).toBe(true);
    expect(edk2Resolver.claimsReference('NetworkPkg/NetworkLibs.dsc.inc')).toBe(true);
    expect(edk2Resolver.claimsReference('OvmfPkg/ArmVirtRules.fdf.inc')).toBe(true);
    expect(edk2Resolver.claimsReference('Protocol/Arp.h')).toBe(true);
    expect(edk2Resolver.claimsReference('Uefi.h')).toBe(true);
    // symbol-shaped names pass the pre-filter natively (no claim needed);
    // wide GUID-candidate shapes ARE claimed so the resolver's
    // declaration-set gate can refuse undeclared ones (they'd otherwise die
    // at the pre-filter before the framework ever sees them).
    expect(edk2Resolver.claimsReference('PcdDebugPropertyMask')).toBe(false);
    expect(edk2Resolver.claimsReference('gEfiArpProtocolGuid')).toBe(true);
    expect(edk2Resolver.claimsReference('gBS')).toBe(false); // 2-char service globals never candidates
  });
});

describe('edk2Resolver — C include resolution', () => {
  it('resolves angle-bracket headers via the <pkg>/Include/ layout fallback', () => {
    const header = mkConstant('Arp.h', 'MdePkg/Include/Protocol/Arp.h', 'MdePkg/Include/Protocol/Arp.h', 1);
    header.kind = 'file';
    const ctx = {
      ...baseContext(),
      fileExists: () => false,
      getNodesByKind: (k: string) => (k === 'file' ? [header] : []),
      getNodesInFile: (p: string) => (p === 'MdePkg/Include/Protocol/Arp.h' ? [header] : []),
    };
    const ref: UnresolvedRef = {
      fromNodeId: 'file:test/App.c',
      referenceName: 'Protocol/Arp.h',
      referenceKind: 'imports',
      line: 1,
      column: 10,
      filePath: 'test/App.c',
      language: 'c',
    };
    const result = edk2Resolver.resolve(ref, ctx as never);
    expect(result?.targetNodeId).toBe(header.id);
    expect(result?.resolvedBy).toBe('framework');
    expect(result?.confidence).toBeGreaterThanOrEqual(0.9);
  });

  it('resolves a bare header name (Uefi.h) via the include index', () => {
    const header = mkConstant('Uefi.h', 'MdePkg/Include/Uefi.h', 'MdePkg/Include/Uefi.h', 1);
    header.kind = 'file';
    const ctx = {
      ...baseContext(),
      fileExists: () => false,
      getNodesByKind: (k: string) => (k === 'file' ? [header] : []),
      getNodesInFile: (p: string) => (p === 'MdePkg/Include/Uefi.h' ? [header] : []),
    };
    const ref: UnresolvedRef = {
      fromNodeId: 'file:test/App.c',
      referenceName: 'Uefi.h',
      referenceKind: 'imports',
      line: 1,
      column: 10,
      filePath: 'test/App.c',
      language: 'c',
    };
    const result = edk2Resolver.resolve(ref, ctx as never);
    expect(result?.targetNodeId).toBe(header.id);
  });

  it('returns null for a header with no Include/ match (normal resolver takes over)', () => {
    const ref: UnresolvedRef = {
      fromNodeId: 'file:test/App.c',
      referenceName: 'CapsuleService.h',
      referenceKind: 'imports',
      line: 2,
      column: 0,
      filePath: 'test/App.c',
      language: 'c',
    };
    expect(edk2Resolver.resolve(ref, baseContext() as never)).toBeNull();
  });
});

describe('edk2Resolver — PCD Bool/Size variants', () => {
  it('extracts PcdGetBool and FixedPcdGetSize refs from C content', () => {
    const src = `VOID f (VOID) {
  BOOLEAN a = PcdGetBool (PcdIPv4PXESupport);
  UINTN   b = FixedPcdGetSize (PcdDebugPrintErrorLevel);
  PcdSetBoolS (gEfiNetworkPkgTokenSpaceGuid.PcdIPv6PXESupport, TRUE);
}
`;
    const out = edk2Resolver.extract('Pkg/Drv/Drv.c', src);
    const names = out.references.map((r) => r.referenceName);
    expect(names).toContain('PcdIPv4PXESupport');
    expect(names).toContain('PcdDebugPrintErrorLevel');
    expect(names).toContain('PcdIPv6PXESupport');
    const ts = out.references.find((r) => r.referenceName === 'PcdIPv6PXESupport');
    expect(ts?.candidates).toContain('gEfiNetworkPkgTokenSpaceGuid.PcdIPv6PXESupport');
    expect(out.references.every((r) => r.referenceKind === 'references')).toBe(true);
  });
});

describe('edk2Resolver — STRING_TOKEN (HII string usage)', () => {
  it('extracts STRING_TOKEN refs from C content', () => {
    const src = `EFI_STRING s = HiiGetString (hii, STRING_TOKEN (STR_LI_DUMP_NAME), NULL);
if (Token == STRING_TOKEN (STR_GOP_DUMP_MAIN)) {}
`;
    const out = edk2Resolver.extract('Pkg/Drv/Drv.c', src);
    const names = out.references.map((r) => r.referenceName);
    expect(names).toContain('STR_LI_DUMP_NAME');
    expect(names).toContain('STR_GOP_DUMP_MAIN');
    expect(out.references.every((r) => r.referenceKind === 'references')).toBe(true);
  });

  it('resolves a STRING_TOKEN ref to the UNI constant by simple name', () => {
    const uniTok = mkConstant(
      'STR_LI_DUMP_NAME',
      'Pkg/Drv/DrvStrings.uni::STR_LI_DUMP_NAME',
      'Pkg/Drv/DrvStrings.uni',
      30
    );
    const ctx = {
      ...baseContext(),
      getNodesByName: (n: string) => (n === 'STR_LI_DUMP_NAME' ? [uniTok] : []),
      getNodesByKind: (k: string) => (k === 'constant' ? [uniTok] : []),
    };
    const ref: UnresolvedRef = {
      fromNodeId: 'file:Pkg/Drv/Drv.c',
      referenceName: 'STR_LI_DUMP_NAME',
      referenceKind: 'references',
      line: 10,
      column: 30,
      filePath: 'Pkg/Drv/Drv.c',
      language: 'c',
    };
    const result = edk2Resolver.resolve(ref, ctx as never);
    expect(result?.targetNodeId).toBe(uniTok.id);
    expect(result?.resolvedBy).toBe('framework');
    expect(result?.confidence).toBeGreaterThanOrEqual(0.9);
  });
});

describe('edk2Resolver — Round 3 audit fixes', () => {
  it('prefers the same-package header over the first indexed candidate', () => {
    const shellHdr = mkConstant('PlatformBootManager.h', 'ShellPkg/Include/Library/PlatformBootManager.h', 'ShellPkg/Include/Library/PlatformBootManager.h', 1);
    const mdeHdr = mkConstant('PlatformBootManager.h', 'MdeModulePkg/Include/Library/PlatformBootManager.h', 'MdeModulePkg/Include/Library/PlatformBootManager.h', 1);
    shellHdr.kind = 'file';
    mdeHdr.kind = 'file';
    const ctx = {
      ...baseContext(),
      fileExists: () => false,
      getNodesByKind: (k: string) => (k === 'file' ? [mdeHdr, shellHdr] : []),
      getNodesInFile: (p: string) =>
        p === 'ShellPkg/Include/Library/PlatformBootManager.h' ? [shellHdr] : p === 'MdeModulePkg/Include/Library/PlatformBootManager.h' ? [mdeHdr] : [],
    };
    const ref: UnresolvedRef = {
      fromNodeId: 'file:ShellPkg/Library/UefiBootManagerLib/InternalBm.c',
      referenceName: 'Library/PlatformBootManager.h',
      referenceKind: 'imports',
      line: 1,
      column: 10,
      filePath: 'ShellPkg/Library/UefiBootManagerLib/InternalBm.c',
      language: 'c',
    };
    const result = edk2Resolver.resolve(ref, ctx as never);
    expect(result?.targetNodeId).toBe(shellHdr.id);
  });

  it('excludes BaseTools vendored headers from the include index', () => {
    const btHdr = mkConstant('DevicePath.h', 'BaseTools/Source/C/Include/Protocol/DevicePath.h', 'BaseTools/Source/C/Include/Protocol/DevicePath.h', 1);
    const mdeHdr = mkConstant('DevicePath.h', 'MdePkg/Include/Protocol/DevicePath.h', 'MdePkg/Include/Protocol/DevicePath.h', 1);
    btHdr.kind = 'file';
    mdeHdr.kind = 'file';
    const ctx = {
      ...baseContext(),
      fileExists: () => false,
      getNodesByKind: (k: string) => (k === 'file' ? [btHdr, mdeHdr] : []),
      getNodesInFile: (p: string) => (p === 'MdePkg/Include/Protocol/DevicePath.h' ? [mdeHdr] : []),
    };
    const ref: UnresolvedRef = {
      fromNodeId: 'file:ShellPkg/Shell.c',
      referenceName: 'Protocol/DevicePath.h',
      referenceKind: 'imports',
      line: 1,
      column: 10,
      filePath: 'ShellPkg/Shell.c',
      language: 'c',
    };
    const result = edk2Resolver.resolve(ref, ctx as never);
    expect(result?.targetNodeId).toBe(mdeHdr.id);
  });

  it('prefers the same-directory UNI constant for STRING_TOKEN refs', () => {
    const local = mkConstant('STR_MODULE_ABSTRACT', 'Pkg/Drv/Drv.uni::STR_MODULE_ABSTRACT', 'Pkg/Drv/Drv.uni', 3);
    const other = mkConstant('STR_MODULE_ABSTRACT', 'Pkg/Other/Other.uni::STR_MODULE_ABSTRACT', 'Pkg/Other/Other.uni', 3);
    const ctx = {
      ...baseContext(),
      getNodesByName: (n: string) => (n === 'STR_MODULE_ABSTRACT' ? [other, local] : []),
      getNodesByKind: (k: string) => (k === 'constant' ? [local, other] : []),
    };
    const ref: UnresolvedRef = {
      fromNodeId: 'file:Pkg/Drv/Drv.c',
      referenceName: 'STR_MODULE_ABSTRACT',
      referenceKind: 'references',
      line: 5,
      column: 20,
      filePath: 'Pkg/Drv/Drv.c',
      language: 'c',
    };
    const result = edk2Resolver.resolve(ref, ctx as never);
    expect(result?.targetNodeId).toBe(local.id);
  });

  it('expands $(WORKSPACE)/ and $(EDK_TOOLS_PATH)/ macro paths before resolving', () => {
    // WORKSPACE is the project root; EDK_TOOLS_PATH the BaseTools tree — the
    // only macro expansions that are platform-invariant (vendor macros like
    // FSP_PACKAGE are DEFINE'd per-platform and expanded extractor-side).
    const target = mkModuleNode('MdeModulePkg/Core/X.inf', 1, 'X');
    const ctx = {
      ...baseContext(),
      fileExists: (p: string) => p === 'MdeModulePkg/Core/X.inf' || p === 'BaseTools/Source/C/X.inf',
      getNodesInFile: (p: string) =>
        p === 'MdeModulePkg/Core/X.inf' || p === 'BaseTools/Source/C/X.inf' ? [target] : [],
    };
    const refWs: UnresolvedRef = {
      fromNodeId: 'file:Test.dsc',
      referenceName: '$(WORKSPACE)/MdeModulePkg/Core/X.inf',
      referenceKind: 'imports',
      line: 1,
      column: 0,
      filePath: 'Test.dsc',
      language: 'edk2',
    };
    expect(edk2Resolver.resolve(refWs, ctx as never)?.targetNodeId).toBe(target.id);
    const refEtp: UnresolvedRef = {
      fromNodeId: 'file:Test.dsc',
      referenceName: '$(EDK_TOOLS_PATH)/Source/C/X.inf',
      referenceKind: 'imports',
      line: 1,
      column: 0,
      filePath: 'Test.dsc',
      language: 'edk2',
    };
    expect(edk2Resolver.resolve(refEtp, ctx as never)?.targetNodeId).toBe(target.id);
  });

  it('does NOT expand vendor macros ($(FSP_PACKAGE)) with a hardcoded package', () => {
    // A platform that overrides `DEFINE FSP_PACKAGE = <its own package>` must
    // not be linked to IntelFsp2Pkg — the resolver has no business knowing
    // vendor defaults. The ref stays verbatim and dies on fileExists.
    const ctx = {
      ...baseContext(),
      fileExists: (p: string) => p === 'IntelFsp2Pkg/Core/X.inf',
      getNodesInFile: (p: string) => (p === 'IntelFsp2Pkg/Core/X.inf' ? [mkModuleNode('IntelFsp2Pkg/Core/X.inf', 1, 'X')] : []),
    };
    const ref: UnresolvedRef = {
      fromNodeId: 'file:Platform.dsc',
      referenceName: '$(FSP_PACKAGE)/Core/X.inf',
      referenceKind: 'imports',
      line: 1,
      column: 0,
      filePath: 'Platform.dsc',
      language: 'edk2',
    };
    expect(edk2Resolver.resolve(ref, ctx as never)).toBeNull();
  });

  it('resolves headers under DEC-declared [Includes] dirs outside the default layout', () => {
    // SecurityPkg's libspdm style: `[Includes] = Library/SpdmLib/libspdm/include`
    // — the `/Include/` path heuristic can't see it, the DEC declaration can.
    const header = mkModuleNode('SecurityPkg/Library/SpdmLib/libspdm/include/library/spdm_lib_config.h', 1, 'spdm_lib_config');
    header.kind = 'file' as Node['kind'];
    const dec = mkModuleNode('SecurityPkg/SecurityPkg.dec', 1, 'SecurityPkg');
    const ctx = {
      ...baseContext(),
      getNodesByKind: (k: string) => {
        if (k === 'file') return [header];
        if (k === 'module') return [dec];
        return [];
      },
      getNodesInFile: (p: string) => (p === header.filePath ? [header] : []),
      readFile: (p: string) => (p === 'SecurityPkg/SecurityPkg.dec'
        ? '[Defines]\n  PACKAGE_NAME = SecurityPkg\n\n[Includes]\n  Include\n  Library/SpdmLib/libspdm/include\n'
        : null),
    };
    const ref: UnresolvedRef = {
      fromNodeId: 'file:SecurityPkg/Drv.c',
      referenceName: 'library/spdm_lib_config.h',
      referenceKind: 'imports',
      line: 1,
      column: 10,
      filePath: 'SecurityPkg/Drv.c',
      language: 'c',
    };
    const result = edk2Resolver.resolve(ref, ctx as never);
    expect(result?.targetNodeId).toBe(header.id);
  });
});

describe('edk2Resolver — Round 4: EDK2-architecture audit fixes', () => {
  it('synthesizes a FeaturePcdGet reference (BOOLEAN feature PCD)', () => {
    // `FeaturePcdGet(PcdNetworkIp4Protocol)` gates network features; the
    // accessor must not be shadowed by the `Pcd` alternative inside it.
    const src = `#include <Uefi.h>
EFI_STATUS F (VOID) {
  if (FeaturePcdGet (PcdNetworkIp4Protocol)) {
    return EFI_SUCCESS;
  }
  return EFI_UNSUPPORTED;
}`;
    const { references } = edk2Resolver.extract!('NetworkPkg/Foo.c', src)!;
    const pcd = references.find((r) => r.referenceName === 'PcdNetworkIp4Protocol');
    expect(pcd).toBeDefined();
    expect(pcd!.referenceKind).toBe('references');
  });

  it('synthesizes a vendor-GUID reference (non-gEfi/gEdkii prefix)', () => {
    // gAcpiTableHobGuid, gZeroGuid, gAmiXxxProtocolGuid … are declared in DEC
    // [Guids] but were invisible to the gEfi|gEdkii-only usage regex.
    const src = `#include <PiDxe.h>
EFI_GUID *GetHob (VOID) {
  return GetFirstGuidHob (&gAcpiTableHobGuid);
}`;
    const { references } = edk2Resolver.extract!('MdeModulePkg/Foo.c', src)!;
    const guid = references.find((r) => r.referenceName === 'gAcpiTableHobGuid');
    expect(guid).toBeDefined();
    expect(guid!.referenceKind).toBe('references');
  });

  it('resolves a vendor-GUID ref to its DEC constant by simple name', () => {
    const guid = mkConstant('gAcpiTableHobGuid', 'MdeModulePkg/MdeModulePkg.dec::gAcpiTableHobGuid', 'MdeModulePkg/MdeModulePkg.dec', 12);
    const ctx = {
      ...baseContext(),
      getNodesByName: (n: string) => (n === 'gAcpiTableHobGuid' ? [guid] : []),
      getNodesByKind: (k: string) => (k === 'constant' ? [guid] : []),
    };
    const ref: UnresolvedRef = {
      fromNodeId: 'file:MdeModulePkg/Foo.c',
      referenceName: 'gAcpiTableHobGuid',
      referenceKind: 'references',
      line: 3,
      column: 30,
      filePath: 'MdeModulePkg/Foo.c',
      language: 'c',
    };
    const result = edk2Resolver.resolve(ref, ctx as never);
    expect(result?.targetNodeId).toBe(guid.id);
    expect(result?.confidence).toBeGreaterThanOrEqual(0.9);
  });

  it('passes the widened cheap gate for vendor-GUID-only files', () => {
    // A file whose only EDK2 token is a vendor GUID (no Pcd/gEfi/gEdkii/
    // STRING_TOKEN) must still be scanned.
    const src = `#include <PiDxe.h>
EFI_GUID *G (VOID) { return &gZeroGuid; }`;
    const { references } = edk2Resolver.extract!('MdeModulePkg/Zero.c', src)!;
    expect(references.map((r) => r.referenceName)).toContain('gZeroGuid');
  });

  it('synthesizes a PcdGetEx reference in the pointer form (&TokenSpaceGuid, Pcd)', () => {
    // `PcdGetEx (&gEfiMdePkgTokenSpaceGuid, PcdDebugPrintErrorLevel)` — the
    // token-space GUID passed by pointer, comma-separated (PcdLib API shape).
    const src = `#include <Uefi.h>
UINTN F (VOID) {
  return PcdGetEx (&gEfiMdePkgTokenSpaceGuid, PcdDebugPrintErrorLevel);
}`;
    const { references } = edk2Resolver.extract!('MdeModulePkg/Foo.c', src)!;
    const pcd = references.find((r) => r.referenceName === 'PcdDebugPrintErrorLevel');
    expect(pcd).toBeDefined();
    expect(pcd!.candidates).toContain('gEfiMdePkgTokenSpaceGuid.PcdDebugPrintErrorLevel');
  });
});

describe('edk2Resolver.extract — round-9 widened synthesis', () => {
  it('synthesizes PCD refs for non-Pcd-prefixed names (Arm PL011 shape)', () => {
    const src = `#include <Uefi.h>
UINTN F(VOID) { return FixedPcdGet32 (PL011UartClkInHz); }`;
    const { references } = edk2Resolver.extract!('ArmVirtPkg/Flash.c', src)!;
    const ref = references.find((r) => r.referenceName === 'PL011UartClkInHz');
    expect(ref).toBeDefined();
    expect(ref!.referenceKind).toBe('references');
  });

  it('accepts token spaces without the Pkg infix (gEmbeddedTokenSpaceGuid)', () => {
    const src = `#include <Uefi.h>
UINT32 F(VOID) { return PcdGet32 (gEmbeddedTokenSpaceGuid.PcdFdtDeviceTree); }`;
    const { references } = edk2Resolver.extract!('EmbeddedPkg/F.c', src)!;
    const ref = references.find((r) => r.referenceName === 'PcdFdtDeviceTree');
    expect(ref).toBeDefined();
    expect(ref!.candidates).toContain('gEmbeddedTokenSpaceGuid.PcdFdtDeviceTree');
  });

  it('synthesizes GUID refs without Guid suffix and version-suffixed GUIDs', () => {
    const src = `#include <Uefi.h>
EFI_STATUS F(VOID) {
  extern EFI_GUID gEfiMmEndOfPeiProtocol;
  extern EFI_GUID gEfiNetworkInterfaceIdentifierProtocolGuid_31;
  return 0;
}`;
    const { references } = edk2Resolver.extract!('StandaloneMmPkg/Core.c', src)!;
    expect(references.some((r) => r.referenceName === 'gEfiMmEndOfPeiProtocol')).toBe(true);
    expect(references.some((r) => r.referenceName === 'gEfiNetworkInterfaceIdentifierProtocolGuid_31')).toBe(true);
    // NOT the variable-declaration suffix (`_SEEN` is not a GUID version)
    expect(references.some((r) => r.referenceName === 'gEfiArpProtocolGuid_SEEN')).toBe(false);
  });

  it('synthesizes PCD/GUID refs from .cpp sources (UEFI C++ hosts)', () => {
    const src = `#include <Uefi.h>
TEST_F(Foo, Bar) {
  UINT32 v = PcdGet8 (PcdDebugPropertyMask);
}`;
    const { references } = edk2Resolver.extract!('UnitTestFrameworkPkg/Sample.cpp', src)!;
    expect(references.some((r) => r.referenceName === 'PcdDebugPropertyMask')).toBe(true);
  });

  it('does not mint refs for lowercase-led identifiers inside PCD accessors', () => {
    const src = `#include <Uefi.h>
UINT32 F(VOID) { UINT32 x = 0; return PcdGet32 (x); }`;
    const { references } = edk2Resolver.extract!('MdePkg/F.c', src)!;
    expect(references.some((r) => r.referenceName === 'x')).toBe(false);
  });
});

describe('edk2Resolver — declaration-set governance (RefusedRef)', () => {
  const mkGuidConst = (name: string, file: string) => {
    const c = mkConstant(name, `${file}::${name}`, file, 1);
    return c;
  };

  it('refuses a synthetic GUID ref not declared in any DEC section', () => {
    const guid = mkGuidConst('gEfiArpProtocolGuid', 'MdePkg/MdePkg.dec');
    const ctx = {
      ...baseContext(),
      getNodesByName: (n: string) => (n === 'gEfiArpProtocolGuid' ? [guid] : []),
      getNodesByKind: (k: string) => (k === 'constant' ? [guid] : []),
    };
    const ref: UnresolvedRef = {
      fromNodeId: 'file:MdePkg/Foo.c',
      referenceName: 'gUndeclaredSomethingGuid',
      referenceKind: 'references',
      line: 3,
      column: 10,
      filePath: 'MdePkg/Foo.c',
      language: 'c',
    };
    const result = edk2Resolver.resolve(ref, ctx as never);
    expect(result).not.toBeNull();
    expect('refused' in (result as object)).toBe(true);
  });

  it('resolves a declared GUID with NO Guid suffix (gEfiRngAlgorithmArmRndr shape)', () => {
    const guid = mkGuidConst('gEfiRngAlgorithmArmRndr', 'MdePkg/MdePkg.dec');
    const ctx = {
      ...baseContext(),
      getNodesByName: (n: string) => (n === 'gEfiRngAlgorithmArmRndr' ? [guid] : []),
      getNodesByKind: (k: string) => (k === 'constant' ? [guid] : []),
    };
    const ref: UnresolvedRef = {
      fromNodeId: 'file:MdePkg/Rng.c',
      referenceName: 'gEfiRngAlgorithmArmRndr',
      referenceKind: 'references',
      line: 3,
      column: 10,
      filePath: 'MdePkg/Rng.c',
      language: 'c',
    };
    const result = edk2Resolver.resolve(ref, ctx as never);
    expect(result?.targetNodeId).toBe(guid.id);
  });

  it('refuses a PCD usage whose name is not DEC-declared', () => {
    const pcd = mkConstant('PcdDebugPropertyMask', 'gEfiMdePkgTokenSpaceGuid.PcdDebugPropertyMask', 'MdePkg/MdePkg.dec', 1);
    const ctx = {
      ...baseContext(),
      getNodesByName: (n: string) => (n === 'PcdDebugPropertyMask' ? [pcd] : []),
      getNodesByKind: (k: string) => (k === 'constant' ? [pcd] : []),
    };
    const ref: UnresolvedRef = {
      fromNodeId: 'file:MdePkg/Foo.c',
      referenceName: 'PcdNotDeclaredAnywhere',
      referenceKind: 'references',
      line: 3,
      column: 10,
      filePath: 'MdePkg/Foo.c',
      language: 'c',
      candidates: ['PcdNotDeclaredAnywhere'],
    };
    const result = edk2Resolver.resolve(ref, ctx as never);
    expect('refused' in (result as object)).toBe(true);
  });

  it('leaves non-synthetic refs alone (symbol-node fromNodeId)', () => {
    const ctx = { ...baseContext(), getNodesByKind: () => [] };
    const ref: UnresolvedRef = {
      fromNodeId: 'func:abc123', // a real symbol node, not file:path
      referenceName: 'gEfiArpProtocolGuid',
      referenceKind: 'references',
      line: 3,
      column: 10,
      filePath: 'MdePkg/Foo.c',
      language: 'c',
    };
    expect(edk2Resolver.resolve(ref, ctx as never)).toBeNull();
  });
});

describe('edk2Resolver — non-STR_ string tokens (declaration-driven)', () => {
  it('resolves a TPM_ token to its UNI declaration (no STR_ prefix required)', () => {
    const tok = mkConstant('TPM_DEVICE_ERROR', 'SecurityPkg/Tpm.uni::TPM_DEVICE_ERROR', 'SecurityPkg/Tpm.uni', 5);
    const ctx = {
      ...baseContext(),
      getNodesByName: (n: string) => (n === 'TPM_DEVICE_ERROR' ? [tok] : []),
      getNodesByKind: (k: string) => (k === 'constant' ? [tok] : []),
    };
    const ref: UnresolvedRef = {
      fromNodeId: 'file:SecurityPkg/Tpm.c',
      referenceName: 'TPM_DEVICE_ERROR',
      referenceKind: 'references',
      line: 3,
      column: 10,
      filePath: 'SecurityPkg/Tpm.c',
      language: 'c',
    };
    const result = edk2Resolver.resolve(ref, ctx as never);
    expect(result?.targetNodeId).toBe(tok.id);
  });

  it('refuses an undeclared non-STR_ token', () => {
    const ctx = { ...baseContext(), getNodesByKind: () => [] };
    const ref: UnresolvedRef = {
      fromNodeId: 'file:X.c',
      referenceName: 'TPM_NOT_DECLARED',
      referenceKind: 'references',
      line: 3,
      column: 10,
      filePath: 'X.c',
      language: 'c',
    };
    const result = edk2Resolver.resolve(ref, ctx as never);
    expect('refused' in (result as object)).toBe(true);
  });
});

describe('edk2Resolver — library-call bridge (unit)', () => {
  const INF_LIB = '[Defines]\n  BASE_NAME = TestLib\n  LIBRARY_CLASS = TestLib\n  MODULE_TYPE = BASE\n\n[Sources]\n  TestLib.c\n';
  const INF_DRV = '[Defines]\n  BASE_NAME = Drv\n  MODULE_TYPE = DXE_DRIVER\n\n[Sources]\n  Drv.c\n\n[LibraryClasses]\n  TestLib\n';
  const DSC = '[Defines]\n  PLATFORM_NAME = TestPkg\n\n[LibraryClasses]\n  TestLib|TestPkg/Library/TestLib/TestLib.inf\n';

  function libCtx() {
    const fn = mkConstant('FetchValue', 'FetchValue', 'TestPkg/Library/TestLib/TestLib.c', 3);
    fn.kind = 'function';
    const libMod = { ...mkConstant('TestLib', 'TestPkg/Library/TestLib/TestLib.inf::TestLib', 'TestPkg/Library/TestLib/TestLib.inf', 1), kind: 'module' as const };
    const drvMod = { ...mkConstant('Drv', 'TestPkg/Drv/Drv.inf::Drv', 'TestPkg/Drv/Drv.inf', 1), kind: 'module' as const };
    const otherMod = { ...mkConstant('Other', 'TestPkg/Other/Other.inf::Other', 'TestPkg/Other/Other.inf', 1), kind: 'module' as const };
    const dscMod = { ...mkConstant('TestPkg', 'TestPkg/TestPkg.dsc::TestPkg', 'TestPkg/TestPkg.dsc', 1), kind: 'module' as const };
    return {
      ...baseContext(),
      getNodesByKind: (k: string) => (k === 'module' ? [libMod, drvMod, otherMod, dscMod] : []),
      getNodesInFile: (p: string) =>
        p === 'TestPkg/Library/TestLib/TestLib.c' ? [fn] : p === 'TestPkg/Drv/Drv.c' ? [mkConstant('Get', 'Get', p, 3)] : p === 'TestPkg/Other/Other.c' ? [mkConstant('Get2', 'Get2', p, 3)] : [],
      readFile: (p: string) => {
        if (p === 'TestPkg/Library/TestLib/TestLib.inf') return INF_LIB;
        if (p === 'TestPkg/Drv/Drv.inf') return INF_DRV;
        if (p === 'TestPkg/Other/Other.inf') return '[Defines]\n  BASE_NAME = Other\n  MODULE_TYPE = DXE_DRIVER\n\n[Sources]\n  Other.c\n';
        if (p === 'TestPkg/TestPkg.dsc') return DSC;
        return null;
      },
      getNodesByName: (n: string) => (n === 'FetchValue' ? [fn] : []),
    };
  }

  it('resolves a library call to the DSC-selected instance function', () => {
    const ctx = libCtx();
    const fn = ctx.getNodesInFile('TestPkg/Library/TestLib/TestLib.c')[0]!;
    const ref: UnresolvedRef = {
      fromNodeId: 'function:caller1',
      referenceName: 'FetchValue',
      referenceKind: 'calls',
      line: 4,
      column: 12,
      filePath: 'TestPkg/Drv/Drv.c',
      language: 'c',
    };
    const result = edk2Resolver.resolve(ref, ctx as never);
    expect(result).not.toBeNull();
    expect(result!.targetNodeId).toBe(fn.id);
    expect(result!.confidence).toBeGreaterThanOrEqual(0.9);
  });

  it('refuses a call to a library-only name from a module that never declared the class', () => {
    const ctx = libCtx();
    const ref: UnresolvedRef = {
      fromNodeId: 'function:caller2',
      referenceName: 'FetchValue',
      referenceKind: 'calls',
      line: 4,
      column: 12,
      filePath: 'TestPkg/Other/Other.c', // no [LibraryClasses] TestLib
      language: 'c',
    };
    const result = edk2Resolver.resolve(ref, ctx as never);
    expect(result).not.toBeNull();
    expect('refused' in (result as object)).toBe(true);
  });

  it('returns null for non-library calls (no index hit)', () => {
    const ctx = libCtx();
    const ref: UnresolvedRef = {
      fromNodeId: 'function:caller3',
      referenceName: 'LocalFunction',
      referenceKind: 'calls',
      line: 4,
      column: 12,
      filePath: 'TestPkg/Drv/Drv.c',
      language: 'c',
    };
    expect(edk2Resolver.resolve(ref, ctx as never)).toBeNull();
  });

  it('keeps the row (null) when the DSC maps the class to multiple instances', () => {
    const ctx = libCtx();
    const baseRead = ctx.readFile.bind(ctx);
    (ctx as unknown as { readFile: (p: string) => string | null }).readFile = (p: string) => {
      if (p === 'TestPkg/TestPkg.dsc') {
        return '[Defines]\n  PLATFORM_NAME = TestPkg\n\n[LibraryClasses]\n  TestLib|TestPkg/Library/TestLib/TestLib.inf\n  TestLib|TestPkg/Library/TestLib/TestLib2.inf\n';
      }
      if (p === 'TestPkg/Library/TestLib/TestLib2.inf') return '[Defines]\n  BASE_NAME = TestLib2\n  LIBRARY_CLASS = TestLib\n  MODULE_TYPE = BASE\n\n[Sources]\n  TestLib2.c\n';
      return baseRead(p);
    };
    const ref: UnresolvedRef = {
      fromNodeId: 'function:caller4',
      referenceName: 'FetchValue',
      referenceKind: 'calls',
      line: 4,
      column: 12,
      filePath: 'TestPkg/Drv/Drv.c',
      language: 'c',
    };
    const result = edk2Resolver.resolve(ref, ctx as never);
    // ambiguous effective instance → null (row survives for normal resolution)
    expect(result).toBeNull();
  });

  it('resolves through an arch-split instance (same name, multiple [Sources] files)', () => {
    const ctx = libCtx();
    const fn2 = mkConstant('FetchValue', 'FetchValue', 'TestPkg/Library/TestLib/TestLibArch.c', 3);
    fn2.kind = 'function';
    const baseGetInFile = ctx.getNodesInFile.bind(ctx);
    const baseRead = ctx.readFile.bind(ctx);
    (ctx as unknown as { getNodesInFile: (p: string) => unknown[] }).getNodesInFile = (p: string) =>
      p === 'TestPkg/Library/TestLib/TestLib.c' || p === 'TestPkg/Library/TestLib/TestLibArch.c'
        ? [p === 'TestPkg/Library/TestLib/TestLib.c' ? baseGetInFile(p)[0]! : fn2]
        : p === 'TestPkg/Drv/Drv.c'
          ? [mkConstant('Get', 'Get', p, 3)]
          : [];
    (ctx as unknown as { readFile: (p: string) => string | null }).readFile = (p: string) => {
      if (p === 'TestPkg/Library/TestLib/TestLib.inf') {
        return '[Defines]\n  BASE_NAME = TestLib\n  LIBRARY_CLASS = TestLib\n  MODULE_TYPE = BASE\n\n[Sources]\n  TestLib.c\n  TestLibArch.c\n';
      }
      return baseRead(p);
    };
    const ref: UnresolvedRef = {
      fromNodeId: 'function:caller5',
      referenceName: 'FetchValue',
      referenceKind: 'calls',
      line: 4,
      column: 12,
      filePath: 'TestPkg/Drv/Drv.c',
      language: 'c',
    };
    const result = edk2Resolver.resolve(ref, ctx as never);
    // both files define FetchValue under the SAME (class, instance) — dedup
    // must yield exactly one candidate and a 0.9 edge
    expect(result).not.toBeNull();
    expect(result!.confidence).toBeGreaterThanOrEqual(0.9);
  });

  it('honors DSC !include fragments for the instance mapping', () => {
    const ctx = libCtx();
    const baseRead = ctx.readFile.bind(ctx);
    (ctx as unknown as { readFile: (p: string) => string | null }).readFile = (p: string) => {
      if (p === 'TestPkg/TestPkg.dsc') {
        return '[Defines]\n  PLATFORM_NAME = TestPkg\n\n[LibraryClasses]\n  !include TestPkg/Library.map.inc\n';
      }
      if (p === 'TestPkg/Library.map.inc') {
        return '  TestLib|TestPkg/Library/TestLib/TestLib.inf\n';
      }
      return baseRead(p);
    };
    const ref: UnresolvedRef = {
      fromNodeId: 'function:caller6',
      referenceName: 'FetchValue',
      referenceKind: 'calls',
      line: 4,
      column: 12,
      filePath: 'TestPkg/Drv/Drv.c',
      language: 'c',
    };
    const result = edk2Resolver.resolve(ref, ctx as never);
    expect(result).not.toBeNull();
    expect(result!.confidence).toBeGreaterThanOrEqual(0.9);
  });

  it('expands $(DEFINE) macros in instance [Sources] paths', () => {
    const ctx = libCtx();
    const baseRead = ctx.readFile.bind(ctx);
    const baseGetInFile = ctx.getNodesInFile.bind(ctx);
    (ctx as unknown as { readFile: (p: string) => string | null }).readFile = (p: string) => {
      if (p === 'TestPkg/Library/TestLib/TestLib.inf') {
        return '[Defines]\n  BASE_NAME = TestLib\n  LIBRARY_CLASS = TestLib\n  MODULE_TYPE = BASE\n  DEFINE SRC_DIR = src\n\n[Sources]\n  $(SRC_DIR)/TestLib.c\n';
      }
      return baseRead(p);
    };
    (ctx as unknown as { getNodesInFile: (p: string) => unknown[] }).getNodesInFile = (p: string) =>
      p === 'TestPkg/Library/TestLib/src/TestLib.c' ? baseGetInFile('TestPkg/Library/TestLib/TestLib.c') : baseGetInFile(p);
    const ref: UnresolvedRef = {
      fromNodeId: 'function:caller7',
      referenceName: 'FetchValue',
      referenceKind: 'calls',
      line: 4,
      column: 12,
      filePath: 'TestPkg/Drv/Drv.c',
      language: 'c',
    };
    const result = edk2Resolver.resolve(ref, ctx as never);
    expect(result).not.toBeNull();
    expect(result!.confidence).toBeGreaterThanOrEqual(0.9);
  });
});
