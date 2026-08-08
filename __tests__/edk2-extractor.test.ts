import { describe, it, expect } from 'vitest';
import { extractFromSource } from '../src/extraction/tree-sitter';
import { detectLanguage } from '../src/extraction/grammars';

// Edk2Extractor — custom (no tree-sitter grammar) extraction of EDK2 / UEFI
// descriptor files. Each extension asserts: a file node + module/constant
// children with `contains` edges, plus the cross-file unresolved references
// the edk2 framework resolver later turns into INF→DEC/C→DEC edges.

const INF_FIXTURE = `## @file
#  ArpDxe module.
##
[Defines]
  INF_VERSION    = 0x00010005
  BASE_NAME      = ArpDxe
  FILE_GUID      = 529D3F93-E8E9-4e73-B1E1-BDF6A9D50113
  MODULE_TYPE    = UEFI_DRIVER
  ENTRY_POINT    = ArpDriverEntryPoint
  UNLOAD_IMAGE   = NetLibDefaultUnload

[Sources]
  ArpMain.c
  ArpImpl.c
  ArpDriver.c

[Packages]
  MdePkg/MdePkg.dec
  NetworkPkg/NetworkPkg.dec

[LibraryClasses]
  UefiLib
  DebugLib
  NetLib

[Protocols]
  gEfiArpServiceBindingProtocolGuid           ## BY_START
  gEfiArpProtocolGuid                          ## BY_START
  gEfiManagedNetworkProtocolGuid              ## TO_START

[Pcd]
  gEfiNetworkPkgTokenSpaceGuid.PcdNetworkIp4Protocol|FALSE|BOOLEAN|0x1

[Depex]
  gEfiArpServiceBindingProtocolGuid
`;

const DEC_FIXTURE = `## @file
#  NetworkPkg.dec
##
[Defines]
  PACKAGE_NAME  = NetworkPkg
  PACKAGE_GUID  = 947988BE-8D5C-471a-893D-AD181C46BEBB

[LibraryClasses]
  NetLib|Include/Library/NetLib.h
  DpcLib|Include/Library/DpcLib.h

[Guids]
  gEfiNetworkPkgTokenSpaceGuid = { 0x40e064b2, 0x0ae0, 0x48b1, { 0xa0, 0x7d }}
  gIp6ConfigNvDataGuid         = { 0x2eea107, 0x98db, 0x400e, { 0x98, 0x30 }}

[PcdsFixedAtBuild]
  gEfiNetworkPkgTokenSpaceGuid.PcdNetworkIp4Protocol|FALSE|BOOLEAN|0x1
  gEfiNetworkPkgTokenSpaceGuid.PcdNetworkIp6Protocol|FALSE|BOOLEAN|0x2
`;

const DSC_FIXTURE = `## @file
#  Platform DSC.
##
[Defines]
  PLATFORM_NAME    = Emu
  PLATFORM_GUID     = 1d2b3c4-d5e6-7
  BUILD_TARGETS     = DEBUG|RELEASE|NOOPT

[LibraryClasses]
  NetLib|NetworkPkg/Library/DxeNetLib/DxeNetLib.inf

[PcdsFixedAtBuild]
  gEfiNetworkPkgTokenSpaceGuid.PcdNetworkIp4Protocol|FALSE

[Components]
  NetworkPkg/ArpDxe/ArpDxe.inf
  EmulatorPkg/BootManagerMenuDxe/BootManagerMenuDxe.inf
`;

const FDF_FIXTURE = `#
#  Example FDF.
#
[Defines]
[FD.CLOUDHV_EFI]
BaseAddress = 0x00000000|gArmTokenSpaceGuid.PcdFdBaseAddress

[FV.FvMain]
  INF MdeModulePkg/Core/Dxe/DxeMain.inf
  INF MdeModulePkg/Universal/PCD/Dxe/Pcd.inf
`;

const UNI_FIXTURE = `// /** @file
//  BootManagerMenuDxe.
// **/
#string STR_MODULE_ABSTRACT #language en-US "Boot Manager Menu"
#string STR_MODULE_DESCRIPTION #language en-US "This module provides the Boot Manager UI."
`;

const VFR_FIXTURE = `/** @file
  Vfr file for BootManagerMenu.
**/
#include "BootManagerMenuNvData.h"
formset
  guid = BOOT_MANAGER_FORMSET_GUID,
  title = STRING_TOKEN(STR_BOOT_MANAGER_FORM_TITLE),
  help = STRING_TOKEN(STR_BOOT_MANAGER_HELP),
  classguid = EFI_HII_PLATFORM_SETUP_FORMSET_GUID,

  form formid = FORMID_MAIN_FORM,
    title = STRING_TOKEN(STR_BOOT_DEVICE_FORM_TITLE);
    subtitle text = STRING_TOKEN(STR_NULL);
  endform;
endformset;
`;

const WINDOWS_INF = `[Version]
Signature   = "$WINDOWS NT$"
Class       = Net
Provider    = %Vendor%
[Strings]
Vendor = "Acme"

[SourceDisksFiles]
acme.sys = 1
`;

const CRLF = (s: string): string => s.replace(/\n/g, '\r\n');

describe('Edk2Extractor — INF', () => {
  it('emits file + module + contains edges and cross-file refs', () => {
    const result = extractFromSource('NetworkPkg/ArpDxe/ArpDxe.inf', CRLF(INF_FIXTURE), 'edk2');
    const fileNode = result.nodes.find((n) => n.kind === 'file');
    expect(fileNode).toBeDefined();
    const module = result.nodes.find((n) => n.kind === 'module' && n.name === 'ArpDxe');
    expect(module).toBeDefined();
    expect(module!.qualifiedName).toBe('NetworkPkg/ArpDxe' + '::' + 'ArpDxe');

    const contains = result.edges.filter(
      (e) => e.kind === 'contains' && e.source === fileNode!.id && e.target === module!.id
    );
    expect(contains).toHaveLength(1);

    const refNames = result.unresolvedReferences.map((r) => r.referenceName);
    // [Packages]
    expect(refNames).toContain('MdePkg/MdePkg.dec');
    expect(refNames).toContain('NetworkPkg/NetworkPkg.dec');
    // [LibraryClasses] (imports)
    expect(refNames).toContain('UefiLib');
    expect(refNames).toContain('NetLib');
    // [Protocols] (references)
    expect(refNames).toContain('gEfiArpServiceBindingProtocolGuid');
    expect(refNames).toContain('gEfiArpProtocolGuid');
    // [Pcd] (references + candidates with token space)
    const pcdRef = result.unresolvedReferences.find(
      (r) => r.referenceName === 'PcdNetworkIp4Protocol'
    );
    expect(pcdRef).toBeDefined();
    expect(pcdRef!.candidates).toContain('gEfiNetworkPkgTokenSpaceGuid.PcdNetworkIp4Protocol');
    // ENTRY_POINT → C function (candidates list the module's .c Source paths)
    const epRef = result.unresolvedReferences.find(
      (r) => r.referenceName === 'ArpDriverEntryPoint'
    );
    expect(epRef).toBeDefined();
    expect(epRef!.candidates).toContain('NetworkPkg/ArpDxe/ArpMain.c');
    // UNLOAD_IMAGE also emits
    const unloadRef = result.unresolvedReferences.find(
      (r) => r.referenceName === 'NetLibDefaultUnload'
    );
    expect(unloadRef).toBeDefined();

    // imports vs references kinds
    const packages = result.unresolvedReferences.find(
      (r) => r.referenceName === 'MdePkg/MdePkg.dec'
    )!;
    expect(packages.referenceKind).toBe('imports');
    const proto = result.unresolvedReferences.find(
      (r) => r.referenceName === 'gEfiArpProtocolGuid'
    )!;
    expect(proto.referenceKind).toBe('references');
  });

  it('skips non-EDK2 Windows driver INF (no BASE_NAME/LIBRARY_CLASS)', () => {
    const result = extractFromSource('acme.inf', WINDOWS_INF, 'edk2');
    expect(result.nodes).toHaveLength(1);
    expect(result.nodes[0]!.kind).toBe('file');
    expect(result.unresolvedReferences).toHaveLength(0);
  });
});

describe('Edk2Extractor — DEC', () => {
  it('emits a module (PACKAGE_NAME) + declared constants', () => {
    const result = extractFromSource('NetworkPkg/NetworkPkg.dec', CRLF(DEC_FIXTURE), 'edk2');
    const pkg = result.nodes.find((n) => n.kind === 'module' && n.name === 'NetworkPkg');
    expect(pkg).toBeDefined();
    // [LibraryClasses] → constant
    const libClass = result.nodes.find(
      (n) => n.kind === 'constant' && n.name === 'NetLib'
    );
    expect(libClass).toBeDefined();
    // [Guids] → constant
    const guid = result.nodes.find(
      (n) => n.kind === 'constant' && n.name === 'gEfiNetworkPkgTokenSpaceGuid'
    );
    expect(guid).toBeDefined();
    // [PcdsFixedAtBuild] → constant with qualifiedName TokenSpace.PcdName
    const pcd = result.nodes.find(
      (n) => n.kind === 'constant' && n.name === 'PcdNetworkIp4Protocol'
    );
    expect(pcd).toBeDefined();
    expect(pcd!.qualifiedName).toBe('gEfiNetworkPkgTokenSpaceGuid.PcdNetworkIp4Protocol');
    // second PCD proves we read more than one entry
    const pcd2 = result.nodes.find(
      (n) => n.kind === 'constant' && n.name === 'PcdNetworkIp6Protocol'
    );
    expect(pcd2).toBeDefined();
  });

  it('skips a non-DEC file (no PACKAGE_NAME)', () => {
    const result = extractFromSource(
      'MdePkg/MdePkg.notdec',
      '[Guids]\n gFooGuid = {0x1}',
      'edk2'
    );
    expect(result.nodes).toHaveLength(1);
    expect(result.nodes[0]!.kind).toBe('file');
  });
});

describe('Edk2Extractor — DSC', () => {
  it('emits a module (PLATFORM_NAME) + component/library imports', () => {
    const result = extractFromSource('EmulatorPkg/EmuPkg.dsc', CRLF(DSC_FIXTURE), 'edk2');
    const platform = result.nodes.find((n) => n.kind === 'module' && n.name === 'Emu');
    expect(platform).toBeDefined();

    const refNames = result.unresolvedReferences.map((r) => r.referenceName);
    // LibraryClasses Class|Impl.inf
    expect(refNames).toContain('NetworkPkg/Library/DxeNetLib/DxeNetLib.inf');
    // Components
    expect(refNames).toContain('NetworkPkg/ArpDxe/ArpDxe.inf');
    expect(refNames).toContain(
      'EmulatorPkg/BootManagerMenuDxe/BootManagerMenuDxe.inf'
    );
    // PcdsFixedAtBuild references
    const pcdRef = result.unresolvedReferences.find(
      (r) => r.referenceName === 'PcdNetworkIp4Protocol'
    );
    expect(pcdRef).toBeDefined();
    expect(pcdRef!.candidates).toContain('gEfiNetworkPkgTokenSpaceGuid.PcdNetworkIp4Protocol');
  });
});

describe('Edk2Extractor — FDF', () => {
  it('emits INF imports from FV sections', () => {
    const result = extractFromSource('ArmVirt/cloudHv.fdf', CRLF(FDF_FIXTURE), 'edk2');
    expect(result.nodes).toHaveLength(1);
    const refNames = result.unresolvedReferences.map((r) => r.referenceName);
    expect(refNames).toContain('MdeModulePkg/Core/Dxe/DxeMain.inf');
    expect(refNames).toContain('MdeModulePkg/Universal/PCD/Dxe/Pcd.inf');
    expect(result.unresolvedReferences[0]!.referenceKind).toBe('imports');
  });
});

describe('Edk2Extractor — UNI', () => {
  it('emits a constant node per #string TOKEN (multi-locale dedup)', () => {
    const result = extractFromSource(
      'NetworkPkg/ArpDxe/ArpDxe.uni',
      CRLF(UNI_FIXTURE),
      'edk2'
    );
    const tokens = result.nodes.filter((n) => n.kind === 'constant');
    expect(tokens).toHaveLength(2);
    const names = tokens.map((n) => n.name);
    expect(names).toContain('STR_MODULE_ABSTRACT');
    expect(names).toContain('STR_MODULE_DESCRIPTION');
    expect(result.nodes.find((n) => n.kind === 'file')).toBeDefined();
  });
});

describe('Edk2Extractor — VFR', () => {
  it('emits a formset module + STRING_TOKEN references', () => {
    const result = extractFromSource(
      'EmulatorPkg/BootManagerMenuDxe/BootManagerMenu.vfr',
      CRLF(VFR_FIXTURE),
      'edk2'
    );
    const formset = result.nodes.find((n) => n.kind === 'module');
    expect(formset).toBeDefined();
    expect(formset!.name).toBe('STR_BOOT_MANAGER_FORM_TITLE');

    const strRefs = result.unresolvedReferences.map((r) => r.referenceName);
    expect(strRefs).toContain('STR_BOOT_MANAGER_FORM_TITLE');
    expect(strRefs).toContain('STR_BOOT_MANAGER_HELP');
    expect(strRefs).toContain('STR_BOOT_DEVICE_FORM_TITLE');
    expect(strRefs).toContain('STR_NULL');
    result.unresolvedReferences.forEach((r) => {
      expect(r.referenceKind).toBe('references');
    });
  });
});
describe('Edk2Extractor — .inc fragments', () => {
  it('routes *.dsc.inc / *.fdf.inc through detectLanguage to edk2', () => {
    expect(detectLanguage('NetworkPkg/NetworkLibs.dsc.inc')).toBe('edk2');
    expect(detectLanguage('OvmfPkg/ArmVirtRules.fdf.inc')).toBe('edk2');
    expect(detectLanguage('NetworkPkg/Network.fdf.inc')).toBe('edk2');
    // plain .inc stays out of the edk2 path (php include / asm fragments)
    expect(detectLanguage('OvmfPkg/Include/TdxCommondefs.inc')).not.toBe('edk2');
  });

  it('parses section-less dsc.inc content (!include + lib instance + PCD)', () => {
    const src = `## @file
# Network DSC include.
##
!include NetworkPkg/NetworkDefines.dsc.inc

  DpcLib|NetworkPkg/Library/DxeDpcLib/DxeDpcLib.inf
  gEfiNetworkPkgTokenSpaceGuid.PcdIPv4PXESupport|0x01
`;
    const result = extractFromSource('NetworkPkg/NetworkLibs.dsc.inc', CRLF(src), 'edk2');
    const names = result.unresolvedReferences.map((r) => r.referenceName);
    expect(names).toContain('NetworkPkg/NetworkDefines.dsc.inc');
    expect(names).toContain('NetworkPkg/Library/DxeDpcLib/DxeDpcLib.inf');
    const pcd = result.unresolvedReferences.find((r) => r.referenceName === 'PcdIPv4PXESupport');
    expect(pcd).toBeDefined();
    expect(pcd!.candidates).toContain('gEfiNetworkPkgTokenSpaceGuid.PcdIPv4PXESupport');
    expect(pcd!.referenceKind).toBe('references');
    // fragments have no identity — file node only
    expect(result.nodes).toHaveLength(1);
    expect(result.nodes[0]!.kind).toBe('file');
  });

  it('parses fdf.inc INF lines and !include', () => {
    const src = `!include OvmfPkg/Include/Fdf/ShellDxe.fdf.inc
  INF NetworkPkg/DpcDxe/DpcDxe.inf
`;
    const result = extractFromSource('NetworkPkg/Network.fdf.inc', CRLF(src), 'edk2');
    const names = result.unresolvedReferences.map((r) => r.referenceName);
    expect(names).toContain('OvmfPkg/Include/Fdf/ShellDxe.fdf.inc');
    expect(names).toContain('NetworkPkg/DpcDxe/DpcDxe.inf');
    expect(result.unresolvedReferences.every((r) => r.referenceKind === 'imports')).toBe(true);
  });

  it('degrades a pure build-flag fragment to a file node only', () => {
    const src = `!if $(NETWORK_ISCSI_ENABLE) == TRUE
  MSFT:*_*_*_CC_FLAGS = /D ENABLE_MD5_DEPRECATED_INTERFACES
  GCC:*_*_*_CC_FLAGS = -D ENABLE_MD5_DEPRECATED_INTERFACES
!endif
`;
    const result = extractFromSource('NetworkPkg/NetworkBuildOptions.dsc.inc', CRLF(src), 'edk2');
    expect(result.nodes).toHaveLength(1);
    expect(result.nodes[0]!.kind).toBe('file');
    expect(result.unresolvedReferences).toHaveLength(0);
  });
});

describe('Edk2Extractor — DSC !include / FLASH_DEFINITION / component blocks', () => {
  it('emits the FLASH_DEFINITION FDF as an imports ref', () => {
    const src = `[Defines]
  PLATFORM_NAME      = Ovmf
  FLASH_DEFINITION   = OvmfPkg/OvmfPkgX64.fdf

[Components]
  OvmfPkg/PlatformDxe/PlatformDxe.inf
`;
    const result = extractFromSource('OvmfPkg/OvmfPkgX64.dsc', CRLF(src), 'edk2');
    const flash = result.unresolvedReferences.find(
      (r) => r.referenceName === 'OvmfPkg/OvmfPkgX64.fdf'
    );
    expect(flash).toBeDefined();
    expect(flash!.referenceKind).toBe('imports');
  });

  it('emits !include refs from a DSC via the raw-line scan', () => {
    const src = `[Defines]
  PLATFORM_NAME = Ovmf
!include OvmfPkg/OvmfPkgDefines.dsc.inc

[Components]
  NetworkPkg/ArpDxe/ArpDxe.inf
`;
    const result = extractFromSource('OvmfPkg/OvmfPkgX64.dsc', CRLF(src), 'edk2');
    const names = result.unresolvedReferences.map((r) => r.referenceName);
    expect(names).toContain('OvmfPkg/OvmfPkgDefines.dsc.inc');
  });

  it('parses [Components] override blocks (LibraryClasses + Pcds)', () => {
    const src = `[Defines]
  PLATFORM_NAME = Ovmf

[Components]
  UefiCpuPkg/CpuDxe/CpuDxe.inf {
    <LibraryClasses>
      MpInitLib|UefiCpuPkg/Library/MpInitLib/DxeMpInitLib.inf
      NULL|OvmfPkg/Library/MpInitLibDepLib/DxeMpInitLibMpDepLib.inf
    <PcdsFixedAtBuild>
      gEfiMdeModulePkgTokenSpaceGuid.PcdDxeNxMemoryProtectionPolicy|0x1
  }
  NetworkPkg/ArpDxe/ArpDxe.inf
`;
    const result = extractFromSource('OvmfPkg/OvmfPkgX64.dsc', CRLF(src), 'edk2');
    const names = result.unresolvedReferences.map((r) => r.referenceName);
    expect(names).toContain('UefiCpuPkg/CpuDxe/CpuDxe.inf');
    expect(names).toContain('UefiCpuPkg/Library/MpInitLib/DxeMpInitLib.inf');
    expect(names).toContain('OvmfPkg/Library/MpInitLibDepLib/DxeMpInitLibMpDepLib.inf');
    expect(names).toContain('NetworkPkg/ArpDxe/ArpDxe.inf');
    const pcd = result.unresolvedReferences.find(
      (r) => r.referenceName === 'PcdDxeNxMemoryProtectionPolicy'
    );
    expect(pcd).toBeDefined();
    expect(pcd!.candidates).toContain('gEfiMdeModulePkgTokenSpaceGuid.PcdDxeNxMemoryProtectionPolicy');
  });
});

describe('Edk2Extractor — INF [Sources] imports', () => {
  it('emits imports to every [Sources] entry (C + assembly)', () => {
    const src = `[Defines]
  BASE_NAME    = ResetVector
  MODULE_TYPE  = SEC

[Sources]
  ResetVector.nasm
  Main.c
`;
    const result = extractFromSource('OvmfPkg/ResetVector/ResetVector.inf', CRLF(src), 'edk2');
    const names = result.unresolvedReferences.map((r) => r.referenceName);
    expect(names).toContain('OvmfPkg/ResetVector/ResetVector.nasm');
    expect(names).toContain('OvmfPkg/ResetVector/Main.c');
    expect(result.unresolvedReferences.every((r) => r.referenceKind === 'imports')).toBe(true);
  });
});
