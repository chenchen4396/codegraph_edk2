import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { CodeGraph } from '../src';
import { initGrammars, loadAllGrammars } from '../src/extraction/grammars';

beforeAll(async () => {
  await initGrammars();
  await loadAllGrammars();
});

const INF = `## @file
# ArpDxe
##
[Defines]
  INF_VERSION    = 0x00010005
  BASE_NAME      = ArpDxe
  MODULE_TYPE    = UEFI_DRIVER
  ENTRY_POINT    = ArpDriverEntryPoint
  UNLOAD_IMAGE   = NetLibDefaultUnload

[Sources]
  ArpMain.c

[Packages]
  MdePkg/MdePkg.dec
  NetworkPkg/NetworkPkg.dec

[LibraryClasses]
  UefiLib
  DebugLib

[Protocols]
  gEfiArpProtocolGuid                           ## BY_START

[Pcd]
  gEfiNetworkPkgTokenSpaceGuid.PcdNetworkIp4Protocol|FALSE|BOOLEAN|0x1

[Depex]
  gEfiArpServiceBindingProtocolGuid
`;

const C = `#include <Uefi.h>
#include <Library/PcdLib.h>
#include <Library/DebugLib.h>

EFI_STATUS EFIAPI ArpDriverEntryPoint(IN EFI_HANDLE ImageHandle) {
  UINT32 v = PcdGet32(PcdDebugPropertyMask);
  if (FeaturePcdGet(PcdNetworkIp4Protocol)) {
    DEBUG((DEBUG_ERROR, "Arp loaded\\n"));
  }
  extern void gEfiArpProtocolGuid_SEEN;
  return EFI_SUCCESS;
}
`;

const NET_DEC = `## @file
# NetworkPkg.dec
##
[Defines]
  PACKAGE_NAME  = NetworkPkg

[Guids]
  gEfiNetworkPkgTokenSpaceGuid = { 0x40e064b2 }

[Protocols]
  gEfiArpProtocolGuid = { 0x6fa9e9d1 }

[PcdsFixedAtBuild]
  gEfiNetworkPkgTokenSpaceGuid.PcdNetworkIp4Protocol|FALSE|BOOLEAN|0x1
`;

const MDE_DEC = `## @file
# MdePkg.dec
##
[Defines]
  PACKAGE_NAME  = MdePkg

[PcdsFixedAtBuild]
  gEfiMdePkgTokenSpaceGuid.PcdDebugPropertyMask|0x0f|UINT8|0x0d
`;

describe('EDK2 full index + linkage', () => {
  let dir: string;
  let cg: CodeGraph;

  beforeAll(async () => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'edk2-idx-'));
    fs.mkdirSync(path.join(dir, 'NetworkPkg/ArpDxe'), { recursive: true });
    fs.mkdirSync(path.join(dir, 'MdePkg'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'NetworkPkg/ArpDxe/ArpDxe.inf'), INF.replace(/\n/g, '\r\n'));
    fs.writeFileSync(path.join(dir, 'NetworkPkg/ArpDxe/ArpMain.c'), C);
    fs.writeFileSync(path.join(dir, 'NetworkPkg/NetworkPkg.dec'), NET_DEC.replace(/\n/g, '\r\n'));
    fs.writeFileSync(path.join(dir, 'MdePkg/MdePkg.dec'), MDE_DEC.replace(/\n/g, '\r\n'));

    cg = await CodeGraph.init(dir, { index: false });
    await cg.indexAll();
  });

  afterAll(() => {
    cg?.destroy();
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  });

  it('indexes edk2 files', () => {
    const stats = cg.getStats();
    expect(stats.nodeCount).toBeGreaterThan(0);
  });

  it('has ArpDxe INF module node', () => {
    const module = cg.queries.getNodesByName('ArpDxe').find((n) => n.kind === 'module' && n.language === 'edk2');
    expect(module).toBeDefined();
  });

  it('has gEfiArpProtocolGuid DEC constant', () => {
    const constant = cg.queries.getNodesByName('gEfiArpProtocolGuid').find((n) => n.kind === 'constant' && n.language === 'edk2');
    expect(constant).toBeDefined();
  });

  it('has PcdDebugPropertyMask PCD constant', () => {
    const constant = cg.queries.getNodesByName('PcdDebugPropertyMask').find((n) => n.kind === 'constant' && n.language === 'edk2');
    expect(constant).toBeDefined();
  });

  it('resolved INF→DEC imports edge', () => {
    const infModule = cg.queries.getNodesByName('ArpDxe').find((n) => n.kind === 'module');
    const mdeModule = cg.queries.getNodesByName('MdePkg').find((n) => n.kind === 'module' && n.language === 'edk2');
    if (infModule && mdeModule) {
      const edges = cg.queries.getOutgoingEdges(infModule.id);
      const importEdge = edges.find((e) => e.kind === 'imports' && e.target === mdeModule.id);
      expect(importEdge).toBeDefined();
    }
  });

  it('resolved C→DEC PCD references (PcdGet32→PcdDebugPropertyMask)', () => {
    const pcdNode = cg.queries.getNodesByName('PcdDebugPropertyMask').find((n) => n.kind === 'constant' && n.language === 'edk2');
    expect(pcdNode).toBeDefined();
    if (pcdNode) {
      const edges = cg.queries.getIncomingEdges(pcdNode.id);
      const refEdge = edges.find((e) => e.kind === 'references');
      expect(refEdge).toBeDefined();
    }
  });

  it('resolved C→DEC GUID reference (gEfiArpProtocolGuid)', () => {
    const guidNode = cg.queries.getNodesByName('gEfiArpProtocolGuid').find((n) => n.kind === 'constant' && n.language === 'edk2');
    expect(guidNode).toBeDefined();
    if (guidNode) {
      const edges = cg.queries.getIncomingEdges(guidNode.id);
      const refEdge = edges.find((e) => e.kind === 'references');
      expect(refEdge).toBeDefined();
    }
  });

  it('resolved INF ENTRY_POINT → C function', () => {
    const fn = cg.queries.getNodesByName('ArpDriverEntryPoint').find((n) => n.kind === 'function');
    expect(fn).toBeDefined();
    const infModule = cg.queries.getNodesByName('ArpDxe').find((n) => n.kind === 'module');
    expect(infModule).toBeDefined();
    if (fn && infModule) {
      const edges = cg.queries.getOutgoingEdges(infModule.id);
      const entryEdge = edges.find((e) => e.kind === 'references' && e.target === fn.id);
      expect(entryEdge).toBeDefined();
    }
  });
});

describe('EDK2 round-2: fragments, FLASH_DEFINITION, C headers, assembly', () => {
  let dir: string;
  let cg: CodeGraph;

  beforeAll(async () => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'edk2-r2-'));
    // descriptor fragment + nested include chain
    fs.mkdirSync(path.join(dir, 'Platform'), { recursive: true });
    fs.writeFileSync(
      path.join(dir, 'Platform/NetworkLibs.dsc.inc'),
      '!include Platform/MoreLibs.dsc.inc\nDpcLib|NetworkPkg/Library/DxeDpcLib/DxeDpcLib.inf\n'.replace(/\n/g, '\r\n')
    );
    fs.writeFileSync(
      path.join(dir, 'Platform/MoreLibs.dsc.inc'),
      'DebugLib|MdePkg/Library/BaseDebugLibNull/BaseDebugLibNull.inf\n'
    );
    // platform DSC (FLASH_DEFINITION + !include) and its FDF
    fs.writeFileSync(
      path.join(dir, 'Platform/Platform.dsc'),
      '[Defines]\n  PLATFORM_NAME      = TestPlatform\n  FLASH_DEFINITION   = Platform/Platform.fdf\n  !include Platform/NetworkLibs.dsc.inc\n\n[Components]\n  Platform/Drv.inf\n'.replace(/\n/g, '\r\n')
    );
    fs.writeFileSync(path.join(dir, 'Platform/Platform.fdf'), '[FV.FvMain]\n  INF Platform/Drv.inf\n');
    fs.writeFileSync(path.join(dir, 'Platform/Drv.inf'), '[Defines]\n  BASE_NAME = Drv\n  MODULE_TYPE = DXE_DRIVER\n\n[Sources]\n  Drv.c\n');
    fs.writeFileSync(path.join(dir, 'Platform/Drv.c'), '#include <Protocol/Arp.h>\n\nEFI_STATUS EFIAPI Dummy (VOID) { return 0; }\n');
    // C include target under the default EDK2 layout
    fs.mkdirSync(path.join(dir, 'Include/Protocol'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'Include/Protocol/Arp.h'), 'typedef struct _EFI_ARP_PROTOCOL EFI_ARP_PROTOCOL;\n');
    // assembly source + its INF
    fs.writeFileSync(path.join(dir, 'CommonMacros.nasm.inc'), '%define FIXED_VECTOR 0x10\n');
    fs.writeFileSync(path.join(dir, 'ResetVec.nasm'), 'BITS 64\n%include "CommonMacros.nasm.inc"\n');
    fs.writeFileSync(path.join(dir, 'ResetVec.inf'), '[Defines]\n  BASE_NAME = ResetVec\n  MODULE_TYPE = SEC\n\n[Sources]\n  ResetVec.nasm\n'.replace(/\n/g, '\r\n'));
    // GNU-as ARM style: `#include "AsmMacroIoLib.inc"` (no % prefix)
    fs.writeFileSync(path.join(dir, 'AsmMacroIoLib.inc'), 'MACRO\n  MyMacro\nENDM\n');
    fs.writeFileSync(path.join(dir, 'ArmBoot.S'), '#include "AsmMacroIoLib.inc"\n.section .text\n');
    fs.writeFileSync(path.join(dir, 'ArmBoot.inf'), '[Defines]\n  BASE_NAME = ArmBoot\n  MODULE_TYPE = SEC\n\n[Sources]\n  ArmBoot.S\n'.replace(/\n/g, '\r\n'));

    cg = await CodeGraph.init(dir, { index: false });
    await cg.indexAll();
  });

  afterAll(() => {
    cg?.destroy();
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  });

  it('resolved DSC FLASH_DEFINITION → FDF file edge', () => {
    const dscModule = cg.queries.getNodesByName('TestPlatform').find((n) => n.kind === 'module');
    const fdf = cg.queries.getNodesByFile('Platform/Platform.fdf').find((n) => n.kind === 'file');
    expect(dscModule).toBeDefined();
    expect(fdf).toBeDefined();
    if (dscModule && fdf) {
      const edges = cg.queries.getOutgoingEdges(dscModule.id);
      expect(edges.some((e) => e.kind === 'imports' && e.target === fdf.id)).toBe(true);
    }
  });

  it('resolved DSC !include → fragment file edge', () => {
    const dscModule = cg.queries.getNodesByName('TestPlatform').find((n) => n.kind === 'module');
    const frag = cg.queries.getNodesByFile('Platform/NetworkLibs.dsc.inc').find((n) => n.kind === 'file');
    expect(frag).toBeDefined();
    if (dscModule && frag) {
      const edges = cg.queries.getOutgoingEdges(dscModule.id);
      expect(edges.some((e) => e.kind === 'imports' && e.target === frag.id)).toBe(true);
    }
  });

  it('resolved fragment !include chain (NetworkLibs → MoreLibs)', () => {
    const frag = cg.queries.getNodesByFile('Platform/NetworkLibs.dsc.inc').find((n) => n.kind === 'file');
    const more = cg.queries.getNodesByFile('Platform/MoreLibs.dsc.inc').find((n) => n.kind === 'file');
    expect(frag).toBeDefined();
    expect(more).toBeDefined();
    if (frag && more) {
      const edges = cg.queries.getOutgoingEdges(frag.id);
      expect(edges.some((e) => e.kind === 'imports' && e.target === more.id)).toBe(true);
    }
  });

  it('resolved C #include <Protocol/Arp.h> → Include/Protocol/Arp.h', () => {
    const header = cg.queries.getNodesByFile('Include/Protocol/Arp.h').find((n) => n.kind === 'file');
    expect(header).toBeDefined();
    if (header) {
      const edges = cg.queries.getIncomingEdges(header.id);
      expect(edges.some((e) => e.kind === 'imports')).toBe(true);
    }
  });

  it('indexed assembly source as an assembly file node linked from its INF', () => {
    const asm = cg.queries.getNodesByFile('ResetVec.nasm').find((n) => n.kind === 'file');
    expect(asm).toBeDefined();
    expect(asm!.language).toBe('assembly');
    const module = cg.queries.getNodesByName('ResetVec').find((n) => n.kind === 'module');
    expect(module).toBeDefined();
    if (module && asm) {
      const edges = cg.queries.getOutgoingEdges(module.id);
      expect(edges.some((e) => e.kind === 'imports' && e.target === asm.id)).toBe(true);
    }
  });

  it('resolved NASM %include → fragment file edge', () => {
    const asm = cg.queries.getNodesByFile('ResetVec.nasm').find((n) => n.kind === 'file');
    const inc = cg.queries.getNodesByFile('CommonMacros.nasm.inc').find((n) => n.kind === 'file');
    expect(asm).toBeDefined();
    expect(inc).toBeDefined();
    if (asm && inc) {
      const edges = cg.queries.getOutgoingEdges(asm.id);
      expect(edges.some((e) => e.kind === 'imports' && e.target === inc.id)).toBe(true);
    }
  });

  it('resolved GNU-as #include in .S → fragment file edge', () => {
    // ARM/RISC-V EDK2 assembly uses C-preprocessor `#include "AsmMacroIoLib.inc"`
    // — the assembly branch must link it like NASM's %include.
    const asm = cg.queries.getNodesByFile('ArmBoot.S').find((n) => n.kind === 'file');
    const inc = cg.queries.getNodesByFile('AsmMacroIoLib.inc').find((n) => n.kind === 'file');
    expect(asm).toBeDefined();
    expect(inc).toBeDefined();
    if (asm && inc) {
      const edges = cg.queries.getOutgoingEdges(asm.id);
      expect(edges.some((e) => e.kind === 'imports' && e.target === inc.id)).toBe(true);
    }
  });
});

describe('EDK2 ASL: asl/aslc sources + nasm.inc routing', () => {
  let dir: string;
  let cg: CodeGraph;

  beforeAll(async () => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'edk2-asl-'));
    fs.mkdirSync(path.join(dir, 'Pkg/AcpiTables'), { recursive: true });
    fs.writeFileSync(
      path.join(dir, 'Pkg/AcpiTables/AcpiTables.inf'),
      '[Defines]\n  BASE_NAME = AcpiTables\n  MODULE_TYPE = DXE_DRIVER\n\n[Sources]\n  Dsdt.asl\n  Facs.aslc\n'.replace(/\n/g, '\r\n')
    );
    fs.writeFileSync(
      path.join(dir, 'Pkg/AcpiTables/Dsdt.asl'),
      'DefinitionBlock (\n  "Dsdt.aml",\n  "DSDT",\n  2,\n  "TEST ", "Tbl  ", 0x1\n)\n{\n  Scope (\\_SB)\n  {\n    Device (PC00)\n    {\n      Method (_STA, 0)\n    }\n  }\n}\n'.replace(/\n/g, '\r\n')
    );
    fs.writeFileSync(
      path.join(dir, 'Pkg/AcpiTables/Facs.aslc'),
      '#include <IndustryStandard/Acpi.h>\n\nEFI_ACPI_1_0_FIRMWARE_ACPI_CONTROL_STRUCTURE FACS = { 0x0 };\n'
    );
    fs.writeFileSync(path.join(dir, 'Pkg/ResetVec.nasm.inc'), '%define FIXED_VECTOR 0x10\n');

    cg = await CodeGraph.init(dir, { index: false });
    await cg.indexAll();
  });

  afterAll(() => {
    cg?.destroy();
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  });

  it('indexes .asl as asl with a DefinitionBlock module node', () => {
    const aslFile = cg.queries.getNodesByFile('Pkg/AcpiTables/Dsdt.asl').find((n) => n.kind === 'file');
    expect(aslFile).toBeDefined();
    expect(aslFile!.language).toBe('asl');
    const block = cg.queries.getNodesByName('DSDT').find((n) => n.kind === 'module' && n.language === 'asl');
    expect(block).toBeDefined();
    const dev = cg.queries.getNodesByName('PC00').find((n) => n.kind === 'constant' && n.language === 'asl');
    expect(dev).toBeDefined();
  });

  it('indexes .aslc as C (it is C)', () => {
    const aslcFile = cg.queries.getNodesByFile('Pkg/AcpiTables/Facs.aslc').find((n) => n.kind === 'file');
    expect(aslcFile).toBeDefined();
    expect(aslcFile!.language).toBe('c');
  });

  it('links INF [Sources] to both asl and aslc files', () => {
    const module = cg.queries.getNodesByName('AcpiTables').find((n) => n.kind === 'module');
    const aslFile = cg.queries.getNodesByFile('Pkg/AcpiTables/Dsdt.asl').find((n) => n.kind === 'file');
    const aslcFile = cg.queries.getNodesByFile('Pkg/AcpiTables/Facs.aslc').find((n) => n.kind === 'file');
    expect(module).toBeDefined();
    expect(aslFile).toBeDefined();
    expect(aslcFile).toBeDefined();
    if (module && aslFile && aslcFile) {
      const edges = cg.queries.getOutgoingEdges(module.id);
      expect(edges.some((e) => e.kind === 'imports' && e.target === aslFile.id)).toBe(true);
      expect(edges.some((e) => e.kind === 'imports' && e.target === aslcFile.id)).toBe(true);
    }
  });

  it('indexes .nasm.inc as assembly', () => {
    const inc = cg.queries.getNodesByFile('Pkg/ResetVec.nasm.inc').find((n) => n.kind === 'file');
    expect(inc).toBeDefined();
    expect(inc!.language).toBe('assembly');
  });
});

describe('EDK2 round-8: generality across any EDK2 tree', () => {
  let dir: string;
  let cg: CodeGraph;

  beforeAll(async () => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'edk2-r8-'));
    // Uppercase .DEC extension + uppercase section headers — legal EDK2
    // spelling; resolver detect() and DEC parsing must not care.
    fs.mkdirSync(path.join(dir, 'MdePkg'), { recursive: true });
    fs.writeFileSync(
      path.join(dir, 'MdePkg/MdePkg.DEC'),
      '[DEFINES]\n  PACKAGE_NAME = MdePkg\n\n[PCDSFIXEDATBUILD]\n  gEfiMdePkgTokenSpaceGuid.PcdDebugPropertyMask|0x0f|UINT8|0x0d\n'.replace(/\n/g, '\r\n')
    );
    // -I-relative include target under the default Include/ layout
    fs.mkdirSync(path.join(dir, 'MdePkg/Include/Register/RiscV64'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'MdePkg/Include/Register/RiscV64/RiscVImpl.h'), '#pragma once\ntypedef struct { UINT64 Value; } RISCV_IMPL;\n');
    // bare .inc NASM macro fragment (must be assembly, not php)
    fs.mkdirSync(path.join(dir, 'MdePkg/Include'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'MdePkg/Include/CommonMacros.inc'), '%define FIXED_VECTOR 0x10\n');
    // RISC-V .S including the header -I-style (BaseLib/RiscV64 pattern)
    fs.mkdirSync(path.join(dir, 'MdePkg/Library/BaseLib/RiscV64'), { recursive: true });
    fs.writeFileSync(
      path.join(dir, 'MdePkg/Library/BaseLib/RiscV64/RiscVMmu.S'),
      '#include "Register/RiscV64/RiscVImpl.h"\n\n.text\n.globl RiscVMmu\nRiscVMmu:\n  ret\n'.replace(/\n/g, '\r\n')
    );
    fs.writeFileSync(
      path.join(dir, 'MdePkg/Library/BaseLib/RiscV64/RiscVMmu.inf'),
      '[Defines]\n  BASE_NAME = RiscVMmu\n  MODULE_TYPE = BASE\n\n[Sources]\n  RiscVMmu.S\n'.replace(/\n/g, '\r\n')
    );
    // Same-package priority: two DECs declare gVendorSharedGuid; the
    // referencing INF lives in VendorPkg and must link to VendorPkg's DEC.
    fs.mkdirSync(path.join(dir, 'VendorPkg/Drv'), { recursive: true });
    fs.writeFileSync(
      path.join(dir, 'VendorPkg/VendorPkg.dec'),
      '[Defines]\n  PACKAGE_NAME = VendorPkg\n\n[Guids]\n  gVendorSharedGuid = { 0x11111111 }\n'.replace(/\n/g, '\r\n')
    );
    fs.writeFileSync(
      path.join(dir, 'MdePkg/OtherPkg.dec'),
      '[Defines]\n  PACKAGE_NAME = OtherPkg\n\n[Guids]\n  gVendorSharedGuid = { 0x22222222 }\n'.replace(/\n/g, '\r\n')
    );
    // Duplicate GUID constants prefer the referencing package
    fs.writeFileSync(
      path.join(dir, 'VendorPkg/Drv/Drv.inf'),
      '[Defines]\n  BASE_NAME = Drv\n  MODULE_TYPE = DXE_DRIVER\n\n[Packages]\n  MdePkg/MdePkg.dec\n  VendorPkg/VendorPkg.dec\n\n[Guids]\n  gVendorSharedGuid\n'.replace(/\n/g, '\r\n')
    );
    // !include written relative to the including file's dir (build tools try
    // the file dir first, then the workspace root)
    fs.writeFileSync(
      path.join(dir, 'VendorPkg/SharedDefines.inc'),
      'DEFINE LOCAL_FLAG = 1\n'
    );
    fs.writeFileSync(
      path.join(dir, 'VendorPkg/IncDrv.inf'),
      '[Defines]\n  BASE_NAME = IncDrv\n  MODULE_TYPE = DXE_DRIVER\n  !include SharedDefines.inc\n'.replace(/\n/g, '\r\n')
    );

    cg = await CodeGraph.init(dir, { index: false });
    await cg.indexAll();
  });

  afterAll(() => {
    cg?.destroy();
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  });

  it('resolver detects an EDK2 tree with an uppercase .DEC', () => {
    const decModule = cg.queries.getNodesByName('MdePkg').find((n) => n.kind === 'module' && n.language === 'edk2');
    expect(decModule).toBeDefined();
    // PCD declared in the uppercase DEC resolved from C would need a C file;
    // the DEC constant itself proves DEC parsing worked.
    const pcd = cg.queries.getNodesByName('PcdDebugPropertyMask').find((n) => n.kind === 'constant' && n.language === 'edk2');
    expect(pcd).toBeDefined();
  });

  it('-I-relative assembly include resolves through the Include/ layout', () => {
    const asm = cg.queries.getNodesByFile('MdePkg/Library/BaseLib/RiscV64/RiscVMmu.S').find((n) => n.kind === 'file');
    const header = cg.queries.getNodesByFile('MdePkg/Include/Register/RiscV64/RiscVImpl.h').find((n) => n.kind === 'file');
    expect(asm).toBeDefined();
    expect(header).toBeDefined();
    if (asm && header) {
      const edges = cg.queries.getOutgoingEdges(asm.id);
      expect(edges.some((e) => e.kind === 'imports' && e.target === header.id)).toBe(true);
    }
  });

  it('bare .inc NASM fragment is indexed as assembly', () => {
    const inc = cg.queries.getNodesByFile('MdePkg/Include/CommonMacros.inc').find((n) => n.kind === 'file');
    expect(inc).toBeDefined();
    expect(inc!.language).toBe('assembly');
  });

  it('duplicate GUID constants prefer the referencing package', () => {
    const infModule = cg.queries.getNodesByName('Drv').find((n) => n.kind === 'module');
    const vendorConst = cg.queries
      .getNodesByName('gVendorSharedGuid')
      .find((n) => n.kind === 'constant' && n.filePath.startsWith('VendorPkg/'));
    expect(infModule).toBeDefined();
    expect(vendorConst).toBeDefined();
    if (infModule && vendorConst) {
      const edges = cg.queries.getOutgoingEdges(infModule.id);
      expect(edges.some((e) => e.kind === 'references' && e.target === vendorConst.id)).toBe(true);
    }
  });

  it('INF !include relative to the including dir resolves (dir-joined fallback)', () => {
    const infModule = cg.queries.getNodesByName('IncDrv').find((n) => n.kind === 'module');
    const incFile = cg.queries.getNodesByFile('VendorPkg/SharedDefines.inc').find((n) => n.kind === 'file');
    expect(infModule).toBeDefined();
    expect(incFile).toBeDefined();
    if (infModule && incFile) {
      const edges = cg.queries.getOutgoingEdges(infModule.id);
      expect(edges.some((e) => e.kind === 'imports' && e.target === incFile.id)).toBe(true);
    }
  });
});

describe('EDK2 round-9: reviewer findings — widened synthesis, .include, clean non-EDK2', () => {
  let dir: string;
  let cg: CodeGraph;

  beforeAll(async () => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'edk2-r9-'));
    fs.mkdirSync(path.join(dir, 'ArmVirtPkg/Library/Flash'), { recursive: true });
    fs.mkdirSync(path.join(dir, 'ArmPkg'), { recursive: true });
    fs.mkdirSync(path.join(dir, 'MdePkg/Include'), { recursive: true });
    fs.mkdirSync(path.join(dir, 'MdePkg/Library/BaseLib/RiscV64'), { recursive: true });
    fs.mkdirSync(path.join(dir, 'MdePkg/Library/BaseLib/RiscV64/RiscVasm.inc'), { recursive: true });
    fs.rmSync(path.join(dir, 'MdePkg/Library/BaseLib/RiscV64/RiscVasm.inc'), { recursive: true });
    fs.mkdirSync(path.join(dir, 'MdePkg/Library/BaseLib/RiscV64'), { recursive: true });
    // DEC with non-Pcd-prefixed PCD + version-suffixed GUID + no-Guid-suffix protocol
    fs.writeFileSync(
      path.join(dir, 'ArmPkg/ArmPkg.dec'),
      '[Defines]\n  PACKAGE_NAME = ArmPkg\n\n[PcdsFixedAtBuild]\n  gArmTokenSpaceGuid.PL011UartClkInHz|1|UINT32|0x1\n\n[Protocols]\n  gEfiMmEndOfPeiProtocol = { 0x8b9e4c91 }\n\n[Guids]\n  gEfiNetworkInterfaceIdentifierProtocolGuid_31 = { 0x1234 }\n'.replace(/\n/g, '\r\n')
    );
    // C using all three shapes
    fs.writeFileSync(
      path.join(dir, 'ArmVirtPkg/Library/Flash/Flash.c'),
      '#include <Uefi.h>\n\nUINTN GetClock (VOID) { return FixedPcdGet32 (PL011UartClkInHz); }\nEFI_STATUS F (VOID) { extern EFI_GUID gEfiMmEndOfPeiProtocol; extern EFI_GUID gEfiNetworkInterfaceIdentifierProtocolGuid_31; return 0; }\n'
    );
    // GAS .include in RISC-V .S + the fragment it pulls
    fs.writeFileSync(path.join(dir, 'MdePkg/Library/BaseLib/RiscV64/RiscVasm.inc'), '%define RV64 1\n');
    fs.writeFileSync(
      path.join(dir, 'MdePkg/Library/BaseLib/RiscV64/RiscVCacheMgmt.S'),
      '.include "RiscVasm.inc"\n\n.text\n.globl RiscVCacheMgmt\nRiscVCacheMgmt:\n  ret\n'
    );
    fs.writeFileSync(
      path.join(dir, 'MdePkg/Library/BaseLib/RiscV64/RiscVCacheMgmt.inf'),
      '[Defines]\n  BASE_NAME = RiscVCacheMgmt\n  MODULE_TYPE = BASE\n\n[Sources]\n  RiscVCacheMgmt.S\n'
    );
    // Block-commented include must NOT mint an edge
    fs.writeFileSync(
      path.join(dir, 'MdePkg/Library/BaseLib/RiscV64/RiscVMmu.S'),
      '/* #include "Ghost.inc" */\n\n.text\n.globl RiscVMmu\nRiscVMmu:\n  ret\n'
    );
    // Windows-driver INF in a NON-EDK2 project (no .dec anywhere) stays clean
    fs.mkdirSync(path.join(dir, 'winsys/Driver'), { recursive: true });
    fs.writeFileSync(
      path.join(dir, 'winsys/Driver/Driver.inf'),
      '[Version]\n  Signature = "$WINDOWS NT$"\n  Provider = Test\n\n[Manufacturer]\n  %Provider% = Devices\n'.replace(/\n/g, '\r\n')
    );

    cg = await CodeGraph.init(dir, { index: false });
    await cg.indexAll();
  });

  afterAll(() => {
    cg?.destroy();
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  });

  it('resolves FixedPcdGet32 (PL011UartClkInHz) to the DEC PCD constant', () => {
    const pcd = cg.queries.getNodesByName('PL011UartClkInHz').find((n) => n.kind === 'constant');
    const cFile = cg.queries.getNodesByFile('ArmVirtPkg/Library/Flash/Flash.c').find((n) => n.kind === 'file');
    expect(pcd).toBeDefined();
    expect(cFile).toBeDefined();
    if (pcd && cFile) {
      const edges = cg.queries.getOutgoingEdges(cFile.id);
      expect(edges.some((e) => e.kind === 'references' && e.target === pcd.id)).toBe(true);
    }
  });

  it('resolves gEfiMmEndOfPeiProtocol and Guid_31 C usage to DEC constants', () => {
    const cFile = cg.queries.getNodesByFile('ArmVirtPkg/Library/Flash/Flash.c').find((n) => n.kind === 'file');
    const proto = cg.queries.getNodesByName('gEfiMmEndOfPeiProtocol').find((n) => n.kind === 'constant');
    const guid31 = cg.queries.getNodesByName('gEfiNetworkInterfaceIdentifierProtocolGuid_31').find((n) => n.kind === 'constant');
    expect(proto).toBeDefined();
    expect(guid31).toBeDefined();
    if (cFile && proto && guid31) {
      const edges = cg.queries.getOutgoingEdges(cFile.id);
      expect(edges.some((e) => e.kind === 'references' && e.target === proto.id)).toBe(true);
      expect(edges.some((e) => e.kind === 'references' && e.target === guid31.id)).toBe(true);
    }
  });

  it('links GAS .include to the fragment and ignores block-commented includes', () => {
    const asm = cg.queries.getNodesByFile('MdePkg/Library/BaseLib/RiscV64/RiscVCacheMgmt.S').find((n) => n.kind === 'file');
    const inc = cg.queries.getNodesByFile('MdePkg/Library/BaseLib/RiscV64/RiscVasm.inc').find((n) => n.kind === 'file');
    const ghost = cg.queries.getNodesByFile('MdePkg/Library/BaseLib/RiscV64/Ghost.inc');
    expect(asm).toBeDefined();
    expect(inc).toBeDefined();
    expect(ghost).toHaveLength(0);
    if (asm && inc) {
      const edges = cg.queries.getOutgoingEdges(asm.id);
      expect(edges.some((e) => e.kind === 'imports' && e.target === inc.id)).toBe(true);
    }
    const mmu = cg.queries.getNodesByFile('MdePkg/Library/BaseLib/RiscV64/RiscVMmu.S').find((n) => n.kind === 'file');
    if (mmu) {
      const edges = cg.queries.getOutgoingEdges(mmu.id);
      expect(edges.some((e) => e.kind === 'imports')).toBe(false);
    }
  });

  it('non-EDK2 Windows INF stays a file node only (no module, no refs)', () => {
    const file = cg.queries.getNodesByFile('winsys/Driver/Driver.inf').find((n) => n.kind === 'file');
    expect(file).toBeDefined();
    const modules = cg.queries.getNodesByFile('winsys/Driver/Driver.inf').filter((n) => n.kind === 'module');
    expect(modules).toHaveLength(0);
    const edges = file ? cg.queries.getOutgoingEdges(file.id) : [];
    expect(edges.filter((e) => e.kind === 'imports' || e.kind === 'references')).toHaveLength(0);
  });
});
