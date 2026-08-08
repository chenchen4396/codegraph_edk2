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

  it('emits INF imports for lines with FILE_GUID = and RuleOverride = modifiers', () => {
    // OvmfPkgX64.fdf overrides module GUIDs: `INF FILE_GUID = $(UP_CPU_PEI_GUID)
    // UefiCpuPkg/CpuMpPei/CpuMpPei.inf` — the modifiers must not swallow the
    // module path.
    const src = `[FV.FVMAIN_COMPACT]
  INF FILE_GUID = $(UP_CPU_PEI_GUID) UefiCpuPkg/CpuMpPei/CpuMpPei.inf
  INF RuleOverride = USE_OLD_VER UefiCpuPkg/CpuDxe/CpuDxe.inf
  INF RuleOverride = X RuleOverride = Y UefiCpuPkg/CpuDxe/CpuDxe.inf
  INF FmpDevicePkg/FmpDxe/FmpDxe.inf
`;
    const result = extractFromSource('OvmfPkg/OvmfPkgX64.fdf', CRLF(src), 'edk2');
    const refNames = result.unresolvedReferences.map((r) => r.referenceName);
    expect(refNames).toContain('UefiCpuPkg/CpuMpPei/CpuMpPei.inf');
    expect(refNames).toContain('UefiCpuPkg/CpuDxe/CpuDxe.inf');
    expect(refNames).toContain('FmpDevicePkg/FmpDxe/FmpDxe.inf');
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
    // STRING_TOKEN refs are `references`; the `#include "…NvData.h"` line is
    // an `imports` to the included file.
    result.unresolvedReferences.forEach((r) => {
      if (r.referenceName.endsWith('BootManagerMenuNvData.h')) {
        expect(r.referenceKind).toBe('imports');
      } else {
        expect(r.referenceKind).toBe('references');
      }
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

describe('Edk2Extractor — ASL / aslc / nasm.inc routing', () => {
  it('routes .asl → asl, .aslc → c, .nasm.inc → assembly via detectLanguage', () => {
    expect(detectLanguage('OvmfPkg/Bhyve/AcpiTables/Dsdt.asl')).toBe('asl');
    expect(detectLanguage('OvmfPkg/Bhyve/AcpiTables/Facp.aslc')).toBe('c');
    expect(detectLanguage('OvmfPkg/ResetVector/X64/PageTables64.nasm.inc')).toBe('assembly');
    expect(detectLanguage('NetworkPkg/NetworkLibs.dsc.inc')).toBe('edk2');
    // ASL Include fragments (.asi) are spliced into .asl via
    // Include ("X.asi") / #include "X.asi" (ManageabilityPkg BmcSsdt pattern).
    expect(detectLanguage('ManageabilityPkg/Universal/IpmiBmcAcpi/BmcSsdt/IpmiOprRegions.asi')).toBe('asl');
  });

  it('emits Include ("X.asi") and #include "X.asi" imports from ASL', () => {
    const src = `/** @file
  BMC SSDT.
**/
#include "IpmiOprRegions.asi"
DefinitionBlock (
  "BmcSsdt.aml",
  "SSDT",
  2,
  "INTEL ",
  "BMC",
  0x00000001
) {
  Include ("CommonOprRegions.asi")
}
`;
    const result = extractFromSource(
      'ManageabilityPkg/Universal/IpmiBmcAcpi/BmcSsdt/BmcSsdt.asl',
      src,
      'asl'
    );
    const names = result.unresolvedReferences.map((r) => r.referenceName);
    expect(names).toContain('ManageabilityPkg/Universal/IpmiBmcAcpi/BmcSsdt/IpmiOprRegions.asi');
    expect(names).toContain('ManageabilityPkg/Universal/IpmiBmcAcpi/BmcSsdt/CommonOprRegions.asi');
    expect(result.unresolvedReferences.every((r) => r.referenceKind === 'imports')).toBe(true);
  });

  it('parses a DefinitionBlock into a module node + Device/Method constants', () => {
    const src = `/** @file
  DSDT for the RAM disk root device.
**/
DefinitionBlock (
  "RamDisk.aml",
  "SSDT",
  2,
  "INTEL ",
  "RamDisk ",
  0x1000
  )
{
  Scope (\\_SB)
  {
    Device (NVDR)
    {
      Name (_HID, "ACPI0012")
      Name (_STR, Unicode ("NVDIMM Root Device"))
    }
    Method (_PIC, 1, NotSerialized)
    {
    }
  }
}
`;
    const result = extractFromSource('MdeModulePkg/Universal/Disk/RamDiskDxe/RamDisk.asl', CRLF(src), 'asl');
    // file node
    expect(result.nodes.some((n) => n.kind === 'file' && n.language === 'asl')).toBe(true);
    // DefinitionBlock → module named by signature
    const block = result.nodes.find((n) => n.kind === 'module' && n.name === 'SSDT');
    expect(block).toBeDefined();
    expect(block!.language).toBe('asl');
    expect(block!.signature).toBe('DefinitionBlock RamDisk.aml');
    // Device/Method → constants
    const dev = result.nodes.find((n) => n.kind === 'constant' && n.name === 'NVDR');
    expect(dev).toBeDefined();
    expect(dev!.language).toBe('asl');
    const method = result.nodes.find((n) => n.kind === 'constant' && n.name === '_PIC');
    expect(method).toBeDefined();
    // Name (_HID…) is skipped (noise)
    expect(result.nodes.some((n) => n.name === '_HID')).toBe(false);
    // contains edges from file node: module + NVDR + _PIC
    const fileNode = result.nodes.find((n) => n.kind === 'file')!;
    const contains = result.edges.filter((e) => e.kind === 'contains' && e.source === fileNode.id);
    expect(contains).toHaveLength(3);
  });

  it('degrades a non-ASL file to a file node only', () => {
    const result = extractFromSource('x.asl', '// just a comment\n', 'asl');
    expect(result.nodes).toHaveLength(1);
    expect(result.nodes[0]!.kind).toBe('file');
  });

  it('emits [Sources] imports for .asl/.aslc entries', () => {
    const src = `[Defines]
  BASE_NAME    = AcpiTables
  MODULE_TYPE  = DXE_DRIVER

[Sources]
  Dsdt.asl
  Facp.aslc
  Main.c
`;
    const result = extractFromSource('OvmfPkg/Bhyve/AcpiTables/AcpiTables.inf', CRLF(src), 'edk2');
    const names = result.unresolvedReferences.map((r) => r.referenceName);
    expect(names).toContain('OvmfPkg/Bhyve/AcpiTables/Dsdt.asl');
    expect(names).toContain('OvmfPkg/Bhyve/AcpiTables/Facp.aslc');
    expect(names).toContain('OvmfPkg/Bhyve/AcpiTables/Main.c');
  });
});

describe('Edk2Extractor — Round 3 audit fixes', () => {
  it('handles multi-dot section headers ([LibraryClasses.common.PEIM])', () => {
    const src = `[Defines]
  PLATFORM_NAME = Test

[LibraryClasses.common.PEIM]
  DebugLib|MdePkg/Library/BaseDebugLibNull/BaseDebugLibNull.inf

[Components]
  FooPkg/Foo.inf
`;
    const result = extractFromSource('Test.dsc', CRLF(src), 'edk2');
    const names = result.unresolvedReferences.map((r) => r.referenceName);
    expect(names).toContain('MdePkg/Library/BaseDebugLibNull/BaseDebugLibNull.inf');
  });

  it('emits DEC constants from [LibraryClasses.common.Private] sections', () => {
    const src = `[Defines]
  PACKAGE_NAME = CryptoPkg

[LibraryClasses.common.Private]
  OpensslLib|Library/OpensslLib/OpensslLib.inf
`;
    const result = extractFromSource('CryptoPkg/CryptoPkg.dec', CRLF(src), 'edk2');
    expect(result.nodes.some((n) => n.kind === 'constant' && n.name === 'OpensslLib')).toBe(true);
  });

  it('emits [Depex.common.X] refs', () => {
    const src = `[Defines]
  BASE_NAME = Foo
  MODULE_TYPE = DXE_RUNTIME_DRIVER

[Depex.common.DXE_RUNTIME_DRIVER]
  gEfiCpuArchProtocolGuid
`;
    const result = extractFromSource('Foo.inf', CRLF(src), 'edk2');
    const names = result.unresolvedReferences.map((r) => r.referenceName);
    expect(names).toContain('gEfiCpuArchProtocolGuid');
  });

  it('emits MODULE_UNI_FILE and PACKAGE_UNI_FILE imports', () => {
    const inf = `[Defines]
  BASE_NAME      = ArpDxe
  MODULE_TYPE    = UEFI_DRIVER
  MODULE_UNI_FILE = ArpDxe.uni

[Sources]
  ArpMain.c
`;
    const infResult = extractFromSource('NetworkPkg/ArpDxe/ArpDxe.inf', CRLF(inf), 'edk2');
    const infNames = infResult.unresolvedReferences.map((r) => r.referenceName);
    expect(infNames).toContain('NetworkPkg/ArpDxe/ArpDxe.uni');

    const dec = `[Defines]
  PACKAGE_NAME     = NetworkPkg
  PACKAGE_UNI_FILE = NetworkPkg.uni
`;
    const decResult = extractFromSource('NetworkPkg/NetworkPkg.dec', CRLF(dec), 'edk2');
    const decNames = decResult.unresolvedReferences.map((r) => r.referenceName);
    expect(decNames).toContain('NetworkPkg/NetworkPkg.uni');
  });

  it('parses the split UNI #language form (#string X / #language en-US "v")', () => {
    const src = `#string STR_PROPERTIES_ABSTRACT
#language en-US "Disk Info"

#string STR_DISK_MAIN
#language en-US "Disk"
`;
    const result = extractFromSource('FatPkg/FatPei/FatPeiExtra.uni', CRLF(src), 'edk2');
    const tokens = result.nodes
      .filter((n) => n.kind === 'constant')
      .map((n) => n.name);
    expect(tokens).toContain('STR_PROPERTIES_ABSTRACT');
    expect(tokens).toContain('STR_DISK_MAIN');
    const disk = result.nodes.find((n) => n.name === 'STR_DISK_MAIN');
    expect(disk!.docstring).toBe('Disk');
  });

  it('handles [Sources] .h/.uni/.nasmb entries and attached toolcode (nasm|)', () => {
    const src = `[Defines]
  BASE_NAME    = BaseCpuLib
  MODULE_TYPE  = BASE

[Sources]
  Ia32/CpuSleep.nasm| INTEL
  CpuLib.h
  BaseCpuLib.uni
  ResetVec.nasmb
`;
    const result = extractFromSource('MdePkg/Library/BaseCpuLib/BaseCpuLib.inf', CRLF(src), 'edk2');
    const names = result.unresolvedReferences.map((r) => r.referenceName);
    expect(names).toContain('MdePkg/Library/BaseCpuLib/Ia32/CpuSleep.nasm');
    expect(names).toContain('MdePkg/Library/BaseCpuLib/CpuLib.h');
    expect(names).toContain('MdePkg/Library/BaseCpuLib/BaseCpuLib.uni');
    expect(names).toContain('MdePkg/Library/BaseCpuLib/ResetVec.nasmb');
  });
});

describe('Edk2Extractor — 3-line UNI split form', () => {
  it('parses #string X / #language en-US / "value" across three lines', () => {
    const src = `// /** @file
//  FatPei Localized Strings
// **/

#string STR_PROPERTIES_MODULE_NAME
#language en-US
"FAT File System Lite PEI Module"

#string STR_PROPERTIES_MODULE_ABSTRACT
#language en-US
"FAT PEI module"
`;
    const result = extractFromSource('FatPkg/FatPei/FatPeiExtra.uni', CRLF(src), 'edk2');
    const names = result.nodes.filter((n) => n.kind === 'constant').map((n) => n.name);
    expect(names).toContain('STR_PROPERTIES_MODULE_NAME');
    expect(names).toContain('STR_PROPERTIES_MODULE_ABSTRACT');
    const mod = result.nodes.find((n) => n.name === 'STR_PROPERTIES_MODULE_NAME');
    expect(mod!.docstring).toBe('FAT File System Lite PEI Module');
    expect(mod!.startLine).toBe(5); // the #string line, not the value line
  });
});

describe('Edk2Extractor — Round 4: EDK2-architecture audit fixes', () => {
  it('accepts lowercase section names ([defines]/[sources]/[depex]/[FixedPcd])', () => {
    // EDK2 section names are case-insensitive; GoogleTest-mock INFs (and the
    // real MockTpmMeasurementLib.inf) use all-lowercase headers.
    const src = `[defines]
  INF_VERSION = 0x00010015
  BASE_NAME   = MockTpmMeasurementlib
  MODULE_TYPE = HOST_APPLICATION
  LIBRARY_CLASS = TpmMeasurementlib
  CONSTRUCTOR = MockLibConstructor
  DESTRUCTOR  = MockLibDestructor

[sources]
  MockTpmMeasurementLib.cpp

[packages]
  MdePkg/MdePkg.dec

[libraryclasses]
  GoogleTestLib

[depex]
  gEfiOtherGuid

[FixedPcd]
  gEfiMdeModulePkgTokenSpaceGuid.PcdFixedThing
`;
    const result = extractFromSource(
      'MdeModulePkg/Test/Mock/Library/GoogleTest/MockTpmMeasurementLib/MockTpmMeasurementLib.inf',
      CRLF(src),
      'edk2'
    );
    const module = result.nodes.find((n) => n.kind === 'module');
    expect(module).toBeDefined();
    expect(module!.name).toBe('MockTpmMeasurementlib');
    const names = result.unresolvedReferences.map((r) => r.referenceName);
    expect(names).toContain('GoogleTestLib'); // lowercase [libraryclasses]
    expect(names).toContain(
      'MdeModulePkg/Test/Mock/Library/GoogleTest/MockTpmMeasurementLib/MockTpmMeasurementLib.cpp'
    );
    // [depex] + [FixedPcd] (lowercase and legacy names) both emit references
    // (PCD refs carry the token-space-qualified name as the candidate).
    expect(names).toContain('gEfiOtherGuid');
    expect(names).toContain('PcdFixedThing');
    // CONSTRUCTOR + DESTRUCTOR → function refs (82 corpus INFs use
    // DESTRUCTOR — SmmLockBox, DxeDebugPrintErrorLevelLib, …).
    expect(names).toContain('MockLibConstructor');
    expect(names).toContain('MockLibDestructor');
    const fixedPcd = result.unresolvedReferences.find((r) => r.referenceName === 'PcdFixedThing');
    expect(fixedPcd!.candidates).toContain('gEfiMdeModulePkgTokenSpaceGuid.PcdFixedThing');
  });

  it('expands [Defines] DEFINE macros in [Sources] paths', () => {
    // TcgTpmPkg/Library/TpmLib/TpmLib.inf pattern: 200+ vendored sources are
    // listed as `$(TPM_LIB_PATH)/command/…`; the macro is DEFINE'd in the
    // same INF. Without expansion the module loses its source links.
    const src = `[Defines]
  INF_VERSION  = 0x00010005
  BASE_NAME    = TpmLib
  MODULE_TYPE  = BASE
  LIBRARY_CLASS = TpmLib

  DEFINE TPM_LIB_PATH            =  TPM/TPMCmd/tpm/src
  DEFINE TPM_CONF_PATH           =  TPM/TPMCmd/TpmConfiguration

[Sources]
  TpmLib.c
  $(TPM_LIB_PATH)/command/Startup/Startup.c
  $(TPM_LIB_PATH)/command/Startup/Shutdown.c
  $(TPM_CONF_PATH)/TpmVendorCommandHandlers/Vendor_TCG_Test.c
  $(UNKNOWN_MACRO)/mystery.c
`;
    const result = extractFromSource('TcgTpmPkg/Library/TpmLib/TpmLib.inf', CRLF(src), 'edk2');
    const names = result.unresolvedReferences.map((r) => r.referenceName);
    expect(names).toContain(
      'TcgTpmPkg/Library/TpmLib/TPM/TPMCmd/tpm/src/command/Startup/Startup.c'
    );
    expect(names).toContain(
      'TcgTpmPkg/Library/TpmLib/TPM/TPMCmd/TpmConfiguration/TpmVendorCommandHandlers/Vendor_TCG_Test.c'
    );
    // Unknown macros stay verbatim (the resolver's fileExists gate drops them).
    expect(names).toContain('TcgTpmPkg/Library/TpmLib/$(UNKNOWN_MACRO)/mystery.c');
  });

  it('expands the built-in $(MODULE_NAME) macro (build defines it as BASE_NAME)', () => {
    const src = `[Defines]
  BASE_NAME   = VarCheckPcdLib
  MODULE_TYPE = BASE

[Sources]
  $(MODULE_NAME).c
`;
    const result = extractFromSource('MdeModulePkg/Library/VarCheckPcdLib/VarCheckPcdLib.inf', CRLF(src), 'edk2');
    const names = result.unresolvedReferences.map((r) => r.referenceName);
    expect(names).toContain('MdeModulePkg/Library/VarCheckPcdLib/VarCheckPcdLib.c');
  });

  it('emits UNI #include imports (shared string files)', () => {
    const src = `/** @file
  Strings.
**/

#string STR_MISC_BIOS_VERSION  #language en-US "1.0"

#include "SmbiosMiscDxeCommonStrings.uni"
`;
    const result = extractFromSource(
      'ArmPkg/Universal/Smbios/SmbiosMiscDxe/SmbiosMiscDxeStrings.uni',
      CRLF(src),
      'edk2'
    );
    const names = result.unresolvedReferences.map((r) => r.referenceName);
    expect(names).toContain(
      'ArmPkg/Universal/Smbios/SmbiosMiscDxe/SmbiosMiscDxeCommonStrings.uni'
    );
    const inc = result.unresolvedReferences.find((r) => r.referenceName.endsWith('SmbiosMiscDxeCommonStrings.uni'));
    expect(inc!.referenceKind).toBe('imports');
  });

  it('emits imports for .vfr entries in INF [Sources] (HII forms)', () => {
    // NetworkPkg Ip4Dxe pattern: the driver's form file is listed in
    // [Sources]; the VFR formset module must hang off the driver module.
    const src = `[Defines]
  BASE_NAME   = Ip4Dxe
  MODULE_TYPE = UEFI_DRIVER

[Sources]
  Ip4Driver.c
  Ip4Config2.vfr
`;
    const result = extractFromSource('NetworkPkg/Ip4Dxe/Ip4Dxe.inf', CRLF(src), 'edk2');
    const names = result.unresolvedReferences.map((r) => r.referenceName);
    expect(names).toContain('NetworkPkg/Ip4Dxe/Ip4Config2.vfr');
  });

  it('expands DSC [Defines] DEFINE macros in component/library paths', () => {
    // IntelFsp2Pkg/Tools/Tests/QemuFspPkg.dsc pattern: `DEFINE FSP_PACKAGE =
    // QemuFspPkg` with `$(FSP_PACKAGE)/…` component paths — a hardcoded
    // resolver-side macro table would expand to the WRONG package here.
    const src = `[Defines]
  PLATFORM_NAME = QemuFspPkg
  DEFINE FSP_PACKAGE = QemuFspPkg

[LibraryClasses]
  FspSecPlatformLib|$(FSP_PACKAGE)/Library/PlatformSecLib/Vtf0PlatformSecTLib.inf

[Components]
  $(FSP_PACKAGE)/FspHeader/FspHeader.inf
`;
    const result = extractFromSource('IntelFsp2Pkg/Tools/Tests/QemuFspPkg.dsc', CRLF(src), 'edk2');
    const names = result.unresolvedReferences.map((r) => r.referenceName);
    expect(names).toContain('QemuFspPkg/FspHeader/FspHeader.inf');
    expect(names).toContain('QemuFspPkg/Library/PlatformSecLib/Vtf0PlatformSecTLib.inf');
    expect(names.some((n) => n.includes('IntelFsp2Pkg/FspHeader'))).toBe(false);
  });

  it('expands FDF DEFINE macros in INF lines and !include lines', () => {
    const src = `DEFINE PLATFORM_MODULES = OvmfPkg/Platform
[FV.PEIFV]
  INF $(PLATFORM_MODULES)/PeiMain.inf
  !include $(PLATFORM_MODULES)/Extra.fdf.inc
`;
    const result = extractFromSource('OvmfPkg/Test.fdf', CRLF(src), 'edk2');
    const names = result.unresolvedReferences.map((r) => r.referenceName);
    expect(names).toContain('OvmfPkg/Platform/PeiMain.inf');
    expect(names).toContain('OvmfPkg/Platform/Extra.fdf.inc');
  });
});

describe('Edk2Extractor — Round 4b: lowercase DSC', () => {
  it('accepts lowercase DSC sections and <LibraryClasses> override blocks', () => {
    const src = `[defines]
  PLATFORM_NAME = QemuTest
  FLASH_DEFINITION = QemuTest.fdf

[libraryclasses]
  UefiLib|MdePkg/Library/UefiLib/UefiLib.inf

[components]
  MdeModulePkg/Universal/HelloWorld/HelloWorld.inf {
    <LibraryClasses>
      PrintLib|MdePkg/Library/BasePrintLib/BasePrintLib.inf
    <PcdsFixedAtBuild>
      gEfiMdePkgTokenSpaceGuid.PcdDebugPrintErrorLevel|0x80000000
  }
`;
    const result = extractFromSource('OvmfPkg/QemuTest.dsc', CRLF(src), 'edk2');
    const names = result.unresolvedReferences.map((r) => r.referenceName);
    expect(names).toContain('MdePkg/Library/UefiLib/UefiLib.inf');
    expect(names).toContain('MdeModulePkg/Universal/HelloWorld/HelloWorld.inf');
    expect(names).toContain('MdePkg/Library/BasePrintLib/BasePrintLib.inf');
    const pcd = result.unresolvedReferences.find(
      (r) => r.referenceName === 'PcdDebugPrintErrorLevel'
    );
    expect(pcd).toBeDefined();
  });
});
