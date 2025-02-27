#include "pyc_module.h"
#include "data.h"
#include <stdexcept>

void PycModule::setVersion(unsigned int magic)
{
    // Default for versions that don't support unicode selection
    m_unicode = false;

    switch (magic) {
    case MAGIC_1_0:
        m_maj = 1;
        m_min = 0;
        break;
    case MAGIC_1_1:
        m_maj = 1;
        m_min = 1;
        break;
    case MAGIC_1_3:
        m_maj = 1;
        m_min = 3;
        break;
    case MAGIC_1_4:
        m_maj = 1;
        m_min = 4;
        break;
    case MAGIC_1_5:
        m_maj = 1;
        m_min = 5;
        break;

    /* Starting with 1.6, Python adds +1 for unicode mode (-U) */
    case MAGIC_1_6+1:
        m_unicode = true;
        /* Fall through */
    case MAGIC_1_6:
        m_maj = 1;
        m_min = 6;
        break;
    case MAGIC_2_0+1:
        m_unicode = true;
        /* Fall through */
    case MAGIC_2_0:
        m_maj = 2;
        m_min = 0;
        break;
    case MAGIC_2_1+1:
        m_unicode = true;
        /* Fall through */
    case MAGIC_2_1:
        m_maj = 2;
        m_min = 1;
        break;
    case MAGIC_2_2+1:
        m_unicode = true;
        /* Fall through */
    case MAGIC_2_2:
        m_maj = 2;
        m_min = 2;
        break;
    case MAGIC_2_3+1:
        m_unicode = true;
        /* Fall through */
    case MAGIC_2_3:
        m_maj = 2;
        m_min = 3;
        break;
    case MAGIC_2_4+1:
        m_unicode = true;
        /* Fall through */
    case MAGIC_2_4:
        m_maj = 2;
        m_min = 4;
        break;
    case MAGIC_2_5+1:
        m_unicode = true;
        /* Fall through */
    case MAGIC_2_5:
        m_maj = 2;
        m_min = 5;
        break;
    case MAGIC_2_6+1:
        m_unicode = true;
        /* Fall through */
    case MAGIC_2_6:
        m_maj = 2;
        m_min = 6;
        break;
    case MAGIC_2_7+1:
        m_unicode = true;
        /* Fall through */
    case MAGIC_2_7:
        m_maj = 2;
        m_min = 7;
        break;

    /* 3.0 and above are always unicode */
    case MAGIC_3_0+1:
        m_maj = 3;
        m_min = 0;
        m_unicode = true;
        break;
    case MAGIC_3_1+1:
        m_maj = 3;
        m_min = 1;
        m_unicode = true;
        break;

    /* 3.2 stops using the unicode increment */
    case MAGIC_3_2:
        m_maj = 3;
        m_min = 2;
        m_unicode = true;
        break;

    case MAGIC_3_3:
        m_maj = 3;
        m_min = 3;
        m_unicode = true;
        break;

    case MAGIC_3_4:
        m_maj = 3;
        m_min = 4;
        m_unicode = true;
        break;

    case MAGIC_3_5:
        /* fall through */

    case MAGIC_3_5_3:
        m_maj = 3;
        m_min = 5;
        m_unicode = true;
        break;

    case MAGIC_3_6:
        m_maj = 3;
        m_min = 6;
        m_unicode = true;
        break;

    case MAGIC_3_7:
        m_maj = 3;
        m_min = 7;
        m_unicode = true;
        break;

    case MAGIC_3_8:
        m_maj = 3;
        m_min = 8;
        m_unicode = true;
        break;

    case MAGIC_3_9:
        m_maj = 3;
        m_min = 9;
        m_unicode = true;
        break;

    case MAGIC_3_10:
        m_maj = 3;
        m_min = 10;
        m_unicode = true;
        break;

    case MAGIC_3_11:
        m_maj = 3;
        m_min = 11;
        m_unicode = true;
        break;

    case MAGIC_3_12:
        m_maj = 3;
        m_min = 12;
        m_unicode = true;
        break;

    case MAGIC_3_13:
        m_maj = 3;
        m_min = 13;
        m_unicode = true;
        break;

    /* Bad Magic detected */
    default:
        m_maj = -1;
        m_min = -1;
    }
}

bool PycModule::isSupportedVersion(int major, int minor)
{
    switch (major) {
    case 1:
        return (minor >= 0 && minor <= 6);
    case 2:
        return (minor >= 0 && minor <= 7);
    case 3:
        return (minor >= 0 && minor <= 12);
    default:
        return false;
    }
}

void PycModule::loadFromFile(const char* filename)
{
    PycFile in(filename);
    if (!in.isOpen()) {
        fprintf(stderr, "Error opening file %s\n", filename);
        return;
    }
    setVersion(in.get32());
    if (!isValid()) {
        fputs("Bad MAGIC!\n", stderr);
        return;
    }

    int flags = 0;
    if (verCompare(3, 7) >= 0)
        flags = in.get32();

    if (flags & 0x1) {
        // Optional checksum added in Python 3.7
        in.get32();
        in.get32();
    } else {
        in.get32(); // Timestamp -- who cares?

        if (verCompare(3, 3) >= 0)
            in.get32(); // Size parameter added in Python 3.3
    }

    m_code = LoadObject(&in, this).cast<PycCode>();
}

void PycModule::loadFromMarshalledFile(const char* filename, int major, int minor)
{
    PycFile in (filename);
    if (!in.isOpen()) {
        fprintf(stderr, "Error opening file %s\n", filename);
        return;
    }
    if (!isSupportedVersion(major, minor)) {
        fprintf(stderr, "Unsupported version %d.%d\n", major, minor);
        return;
    }
    m_maj = major;
    m_min = minor;
    m_unicode = (major >= 3);
    m_code = LoadObject(&in, this).cast<PycCode>();
}

void PycModule::loadFromOneshotSequenceFile(const char *filename)
{
    PycFile in(filename);
    if (!in.isOpen())
    {
        fprintf(stderr, "Error opening file %s\n", filename);
        return;
    }

    bool oneshot_seq_header = true;
    while (oneshot_seq_header)
    {
        int indicator = in.getByte();
        switch (indicator)
        {
        case 0xA1:
            in.getBuffer(16, this->pyarmor_aes_key);
            break;
        case 0xA2:
            in.getBuffer(12, this->pyarmor_mix_str_aes_nonce);
            break;
        case 0xF0:
            break;
        case 0xFF:
            oneshot_seq_header = false;
            break;
        default:
            fprintf(stderr, "Unknown 1-shot sequence indicator %02X\n", indicator);
            break;
        }
    }

    // Write only. Some fields unknown to us or not needed for decryption are discarded.
    char discard_buffer[64];

    char pyarmor_header[64];
    in.getBuffer(64, pyarmor_header);
    this->m_maj = pyarmor_header[9];
    this->m_min = pyarmor_header[10];
    this->m_unicode = (m_maj >= 3);

    unsigned int remain_header_length = *(unsigned int *)(pyarmor_header + 28) - 64;
    while (remain_header_length)
    {
        unsigned int discard_length = (remain_header_length > 64) ? 64 : remain_header_length;
        in.getBuffer(discard_length, discard_buffer);
        remain_header_length -= discard_length;
    }

    // For 1-shot sequence, the following part has been decrypted once.
    unsigned int code_object_offset = in.get32();
    unsigned int co_code_aes_nonce_xor_key_procedure_length = in.get32();
    this->pyarmor_co_code_aes_nonce_xor_enabled = (co_code_aes_nonce_xor_key_procedure_length > 0);
    unsigned int remain_second_part_length = code_object_offset - 8;
    while (remain_second_part_length)
    {
        unsigned int discard_length = (remain_second_part_length > 64) ? 64 : remain_second_part_length;
        in.getBuffer(discard_length, discard_buffer);
        remain_second_part_length -= discard_length;
    }

    if (this->pyarmor_co_code_aes_nonce_xor_enabled)
    {
        // TODO: Implement the decryption procedure.
    }

    m_code = LoadObject(&in, this).cast<PycCode>();
}

PycRef<PycString> PycModule::getIntern(int ref) const
{
    if (ref < 0 || (size_t)ref >= m_interns.size())
        throw std::out_of_range("Intern index out of range");
    return m_interns[(size_t)ref];
}

PycRef<PycObject> PycModule::getRef(int ref) const
{
    if (ref < 0 || (size_t)ref >= m_refs.size())
        throw std::out_of_range("Ref index out of range");
    return m_refs[(size_t)ref];
}
