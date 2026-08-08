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
    // symbol-shaped names are NOT claimed — they pass the pre-filter natively
    expect(edk2Resolver.claimsReference('PcdDebugPropertyMask')).toBe(false);
    expect(edk2Resolver.claimsReference('gEfiArpProtocolGuid')).toBe(false);
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

  it('expands $(FSP_PACKAGE)/… macro paths before resolving', () => {
    const target = mkModuleNode('IntelFsp2Pkg/Core/X.inf', 1, 'X');
    const ctx = {
      ...baseContext(),
      fileExists: (p: string) => p === 'IntelFsp2Pkg/Core/X.inf',
      getNodesInFile: (p: string) => (p === 'IntelFsp2Pkg/Core/X.inf' ? [target] : []),
    };
    const ref: UnresolvedRef = {
      fromNodeId: 'file:Test.dsc',
      referenceName: '$(FSP_PACKAGE)/Core/X.inf',
      referenceKind: 'imports',
      line: 1,
      column: 0,
      filePath: 'Test.dsc',
      language: 'edk2',
    };
    const result = edk2Resolver.resolve(ref, ctx as never);
    expect(result?.targetNodeId).toBe(target.id);
  });
});
