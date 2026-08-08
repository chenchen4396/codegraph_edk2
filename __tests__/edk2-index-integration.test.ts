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
