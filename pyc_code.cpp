#include "pyc_code.h"
#include "pyc_module.h"
#include "data.h"
#include "plusaes.hpp"

/* == Marshal structure for Code object ==
                1.0     1.3     1.5     2.1     2.3     3.0     3.8     3.11
argcount                short   short   short   long    long    long    long
posonlyargc                                                     long    long
kwonlyargc                                              long    long    long
nlocals                 short   short   short   long    long    long
stacksize                       short   short   long    long    long    long
flags                   short   short   short   long    long    long    long
code            Obj     Obj     Obj     Obj     Obj     Obj     Obj     Obj
consts          Obj     Obj     Obj     Obj     Obj     Obj     Obj     Obj
names           Obj     Obj     Obj     Obj     Obj     Obj     Obj     Obj
varnames                Obj     Obj     Obj     Obj     Obj     Obj
freevars                                Obj     Obj     Obj     Obj
cellvars                                Obj     Obj     Obj     Obj
locals+names                                                            Obj
locals+kinds                                                            Obj
filename        Obj     Obj     Obj     Obj     Obj     Obj     Obj     Obj
name            Obj     Obj     Obj     Obj     Obj     Obj     Obj     Obj
qualname                                                                Obj
firstline                       short   short   long    long    long    long
lntable                         Obj     Obj     Obj     Obj     Obj     Obj
exceptiontable                                                          Obj
*/

void PycCode::load(PycData* stream, PycModule* mod)
{
    if (mod->verCompare(1, 3) >= 0 && mod->verCompare(2, 3) < 0)
        m_argCount = stream->get16();
    else if (mod->verCompare(2, 3) >= 0)
        m_argCount = stream->get32();

    if (mod->verCompare(3, 8) >= 0)
        m_posOnlyArgCount = stream->get32();
    else
        m_posOnlyArgCount = 0;

    if (mod->majorVer() >= 3)
        m_kwOnlyArgCount = stream->get32();
    else
        m_kwOnlyArgCount = 0;

    if (mod->verCompare(1, 3) >= 0 && mod->verCompare(2, 3) < 0)
        m_numLocals = stream->get16();
    else if (mod->verCompare(2, 3) >= 0 && mod->verCompare(3, 11) < 0)
        m_numLocals = stream->get32();
    else
        m_numLocals = 0;

    if (mod->verCompare(1, 5) >= 0 && mod->verCompare(2, 3) < 0)
        m_stackSize = stream->get16();
    else if (mod->verCompare(2, 3) >= 0)
        m_stackSize = stream->get32();
    else
        m_stackSize = 0;

    if (mod->verCompare(1, 3) >= 0 && mod->verCompare(2, 3) < 0)
        m_flags = stream->get16();
    else if (mod->verCompare(2, 3) >= 0)
        m_flags = stream->get32();
    else
        m_flags = 0;

    bool pyarmor_co_obfuscated_flag = m_flags & 0x20000000;

    if (mod->verCompare(3, 8) < 0) {
        // Remap flags to new values introduced in 3.8
        // Pyarmor CO_OBFUSCATED flag always locates at 0x20000000
        if (m_flags & 0xD0000000)
            fprintf(stderr, "Remapping flags (%08X) may not be correct\n", m_flags);
        m_flags = (m_flags & 0x1FFF) | ((m_flags & 0xFFFE000) << 4) | (m_flags & 0x20000000);
    }

    m_code = LoadObject(stream, mod).cast<PycString>();
    m_consts = LoadObject(stream, mod).cast<PycSequence>();
    m_names = LoadObject(stream, mod).cast<PycSequence>();

    if (mod->verCompare(1, 3) >= 0)
        m_localNames = LoadObject(stream, mod).cast<PycSequence>();
    else
        m_localNames = new PycTuple;

    if (mod->verCompare(3, 11) >= 0)
        m_localKinds = LoadObject(stream, mod).cast<PycString>();
    else
        m_localKinds = new PycString;

    if (mod->verCompare(2, 1) >= 0 && mod->verCompare(3, 11) < 0)
        m_freeVars = LoadObject(stream, mod).cast<PycSequence>();
    else
        m_freeVars = new PycTuple;

    if (mod->verCompare(2, 1) >= 0 && mod->verCompare(3, 11) < 0)
        m_cellVars = LoadObject(stream, mod).cast<PycSequence>();
    else
        m_cellVars = new PycTuple;

    m_fileName = LoadObject(stream, mod).cast<PycString>();
    m_name = LoadObject(stream, mod).cast<PycString>();

    if (mod->verCompare(3, 11) >= 0)
        m_qualName = LoadObject(stream, mod).cast<PycString>();
    else
        m_qualName = new PycString;

    if (mod->verCompare(1, 5) >= 0 && mod->verCompare(2, 3) < 0)
        m_firstLine = stream->get16();
    else if (mod->verCompare(2, 3) >= 0)
        m_firstLine = stream->get32();

    if (mod->verCompare(1, 5) >= 0)
        m_lnTable = LoadObject(stream, mod).cast<PycString>();
    else
        m_lnTable = new PycString;

    if (mod->verCompare(3, 11) >= 0)
        m_exceptTable = LoadObject(stream, mod).cast<PycString>();
    else
        m_exceptTable = new PycString;

    // Pyarmor extra fields

    if (!pyarmor_co_obfuscated_flag)
        return;

    unsigned char extra_data[256] = {0};
    unsigned char extra_length = stream->getByte();
    stream->getBuffer(extra_length, extra_data);

    unsigned char pyarmor_fn_count = extra_data[0] & 3;
    unsigned char pyarmor_co_descriptor_count = (extra_data[0] >> 2) & 3;
    if (extra_data[0] & 0xF0)
    {
        fprintf(stderr, "Unsupported Pyarmor CO extra flag (%02X)\n", extra_data[0]);
        fprintf(stderr, "Please open an issue at https://github.com/Lil-House/Pyarmor-Static-Unpack-1shot/issues to request support and help to make this tool better.\n");
    }
    if (pyarmor_co_descriptor_count > 1)
    {
        fprintf(stderr, "Do not support multiple Pyarmor CO descriptors (%d in total)\n", pyarmor_co_descriptor_count);
        fprintf(stderr, "Please open an issue at https://github.com/Lil-House/Pyarmor-Static-Unpack-1shot/issues to request support and help to make this tool better.\n");
    }

    unsigned char *extra_ptr = extra_data + 4;
    for (unsigned char i = 0; i < pyarmor_fn_count; i++)
    {
        unsigned char item_length = (*extra_ptr >> 6) + 2;
        // Ignore the details
        extra_ptr += item_length;
    }
    for (unsigned char i = 0; i < pyarmor_co_descriptor_count; i++)
    {
        unsigned char item_length = (*extra_ptr >> 6) + 2;
        unsigned char *item_end = extra_ptr + item_length;
        // Ignore low 6 bits
        extra_ptr++;
        unsigned long consts_index = 0;
        while (extra_ptr < item_end)
        {
            consts_index = (consts_index << 8) | *extra_ptr;
            extra_ptr++;
        }

        pyarmorDecryptCoCode(consts_index, mod);
    }
}

void PycCode::pyarmorDecryptCoCode(unsigned long consts_index, PycModule *mod)
{
    PycRef<PycString> descriptor = getConst(consts_index).cast<PycString>();
    const std::string &descriptor_str = descriptor->strValue();
    if (descriptor_str.length() < 20)
    {
        fprintf(stderr, "Pyarmor CO descriptor is too short\n");
        return;
    }

    const PyarmorCoDescriptor *desc = (const PyarmorCoDescriptor *)(descriptor_str.data() + 8);
    bool copy_prologue = desc->flags & 0x8;
    bool xor_aes_nonce = desc->flags & 0x4;
    bool short_code = desc->flags & 0x2;

    unsigned int nonce_index = short_code
        ? desc->short_nonce_index
        : desc->short_nonce_index + desc->decrypt_begin_index + desc->decrypt_length;
    unsigned char nonce[16] = {0};
    memcpy(nonce, m_code->value() + nonce_index, 12);
    nonce[15] = 2;
    if (xor_aes_nonce)
    {
        if (!mod->pyarmor_co_code_aes_nonce_xor_enabled)
        {
            fprintf(stderr, "FATAL: Pyarmor CO code AES nonce XOR is not enabled but used\n");
        }
        else
        {
            unsigned char *xor_key = mod->pyarmor_co_code_aes_nonce_xor_key;
            for (int i = 0; i < 12; i++)
                nonce[i] ^= xor_key[i];
        }
    }

    std::string &code_bytes = (std::string &)m_code->strValue();

    plusaes::crypt_ctr(
        (unsigned char *)&code_bytes[desc->decrypt_begin_index],
        desc->decrypt_length,
        mod->pyarmor_aes_key,
        16,
        &nonce);

    if (copy_prologue)
    {
        memcpy(
            &code_bytes[0],
            &code_bytes[desc->decrypt_length],
            desc->decrypt_begin_index);
        // Assume tail of code is not used there
        memset(
            &code_bytes[desc->decrypt_length],
            9, // NOP
            desc->decrypt_begin_index);
    }

    // When running, the first 8 bytes are set to &PyCodeObject
    std::string new_str = "<COAddr>" + descriptor_str.substr(8);
    descriptor->setValue(new_str);
}

PycRef<PycString> PycCode::getCellVar(PycModule* mod, int idx) const
{
    if (mod->verCompare(3, 11) >= 0)
        return getLocal(idx);

    return (idx >= m_cellVars->size())
        ? m_freeVars->get(idx - m_cellVars->size()).cast<PycString>()
        : m_cellVars->get(idx).cast<PycString>();
}
