import { describe, it, expect, beforeAll } from 'vitest';
import { extractFromSource } from '../src/extraction/tree-sitter';
import { initGrammars, loadAllGrammars, detectLanguage } from '../src/extraction/grammars';
import { blankEdk2Constructs } from '../src/extraction/languages/c-cpp';

beforeAll(async () => {
  await initGrammars();
  await loadAllGrammars();
});

const EDK2_SIGNATURE = `#include <Uefi.h>

EFI_STATUS EFIAPI UefiMain(IN UINTN a, OUT VOID *b OPTIONAL) {
  return 0;
}
`;

describe('EDK2 C-dialect blanking — blankEdk2Constructs', () => {
  it('whitespace-replaces EFIAPI/IN/OUT/OPTIONAL, offset- and newline-preserving', () => {
    const out = blankEdk2Constructs(EDK2_SIGNATURE);
    expect(out.length).toBe(EDK2_SIGNATURE.length);
    expect(out.split('\n').length).toBe(EDK2_SIGNATURE.split('\n').length);
    expect(out).not.toMatch(/\bEFIAPI\b/);
    expect(out).not.toMatch(/\bOPTIONAL\b/);
  });

  it('is a no-op for content with none of the qualifiers', () => {
    const plain = 'int add(int in, int out) { return in >> out; }\n';
    expect(blankEdk2Constructs(plain)).toBe(plain);
  });
});

describe('EDK2 C-dialect blanking — extraction end-to-end', () => {
  it('parses an EDK2 .c so EFIAPI/IN/OUT/OPTIONAL do not break the function name', () => {
    const src = `#include <Uefi.h>
EFI_STATUS EFIAPI UefiMain(IN UINTN Argc, IN CHAR16 **Argv) {
  UINT32 v = PcdGet32(PcdDebugPropertyMask);
  VOID *p = FeaturePcdGetPtr(PcdPlatformBootTimeout);
  if (v > 0) { extern void gEfiArpProtocolGuid_SEEN; }
  return EFI_SUCCESS;
}`;
    const result = extractFromSource('test/UefiMain.c', src, 'c');
    const fn = result.nodes.find((n) => n.kind === 'function' && n.name === 'UefiMain');
    // EFIAPI was between return-type and name; with the blank, tree-sitter
    // parses the real function (name is `UefiMain`, not `EFIAPI`).
    expect(fn).toBeDefined();
  });

  it('non-EDK2 C with words IN/OUT in code is unchanged (no blank without EDK2 markers)', () => {
    // The blank only runs when looksLikeEdk2Source is true. A file without
    // <Uefi.h>/EFIAPI/EFI_STATUS won't go through the blank pass at all, so a
    // shift expression `in >> out` parses to its real function shape.
    const src = 'int shift(int in, int out) { return in >> (out); }\n';
    const result = extractFromSource('test/shift.c', src, 'c');
    const fn = result.nodes.find((n) => n.kind === 'function' && n.name === 'shift');
    expect(fn).toBeDefined();
  });
});
describe('EDK2 C blanking — Round 3 audit fixes', () => {
  it('keeps a lone ALL-CAPS return type above a function header (EFI_STATUS on its own line)', async () => {
    // EDK2 style: return type alone on a line, function name on the next,
    // previous line is a closing brace (blankLoneMacroLines guard).
    const src = `#include <Uefi.h>

EFI_STATUS
OtherFunction (VOID)
{
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
CpuDxeInitialize (IN EFI_HANDLE ImageHandle, IN EFI_SYSTEM_TABLE *SystemTable)
{
  return EFI_SUCCESS;
}
`;
    const result = await extractFromSource('ArmPkg/Drivers/CpuDxe/CpuDxe.c', src, 'c');
    const fns = result.nodes.filter((n) => n.kind === 'function');
    const names = fns.map((f) => f.name);
    expect(names).toContain('OtherFunction');
    expect(names).toContain('CpuDxeInitialize');
  });

  it('classifies a .h with C++ keywords only inside doc comments as C', () => {
    const src = `/** @file
  Describes the virtual memory layout — \`virtual\` and \`namespace\` appear
  in this doc comment only.
**/
#ifndef _UEFI_SPEC_H_
#define _UEFI_SPEC_H_

typedef struct _EFI_BOOT_SERVICES {
  UINTN  Signature;
} EFI_BOOT_SERVICES;

#endif
`;
    expect(detectLanguage('MdePkg/Include/Uefi/UefiSpec.h', src)).toBe('c');
  });
});
