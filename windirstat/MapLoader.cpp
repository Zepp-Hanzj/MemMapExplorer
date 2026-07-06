// WinDirStat - Directory Statistics
// Copyright © WinDirStat Team
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 2 of the License, or
// at your option any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

#include "pch.h"
#include "MapLoader.h"

namespace
{
std::unordered_map<const CItem*, MapItemDetails> g_mapItemDetails;
std::unordered_map<const CItem*, std::wstring> g_mapItemSections;

constexpr wchar_t MEMORY_CONFIG_HEADER[] = L"Memory Configuration";
constexpr wchar_t MAP_HEADER[] = L"Linker script and memory map";
constexpr wchar_t ARLINK_MAP_HEADER[] = L"Memory Map of the image";
constexpr wchar_t ARLINK_SYMBOL_TABLE_HEADER[] = L"Image Symbol Table";

constexpr std::uint8_t ELFCLASS32 = 1;
constexpr std::uint8_t ELFCLASS64 = 2;
constexpr std::uint8_t ELFDATA2LSB = 1;
constexpr std::uint32_t PT_LOAD = 1;
constexpr std::uint32_t SHT_SYMTAB = 2;
constexpr std::uint32_t SHT_DYNSYM = 11;
constexpr std::uint16_t SHN_UNDEF = 0;
constexpr std::uint8_t STT_NOTYPE = 0;
constexpr std::uint8_t STT_OBJECT = 1;
constexpr std::uint8_t STT_FUNC = 2;
constexpr std::uint8_t STB_LOCAL = 0;
constexpr std::uint8_t STB_GLOBAL = 1;
constexpr std::uint8_t STB_WEAK = 2;
constexpr std::uint64_t DW_LENGTH_DWARF64 = 0xffffffffull;
constexpr std::uint8_t DW_LNS_copy = 1;
constexpr std::uint8_t DW_LNS_advance_pc = 2;
constexpr std::uint8_t DW_LNS_advance_line = 3;
constexpr std::uint8_t DW_LNS_set_file = 4;
constexpr std::uint8_t DW_LNS_set_column = 5;
constexpr std::uint8_t DW_LNS_negate_stmt = 6;
constexpr std::uint8_t DW_LNS_set_basic_block = 7;
constexpr std::uint8_t DW_LNS_const_add_pc = 8;
constexpr std::uint8_t DW_LNS_fixed_advance_pc = 9;
constexpr std::uint8_t DW_LNS_set_prologue_end = 10;
constexpr std::uint8_t DW_LNS_set_epilogue_begin = 11;
constexpr std::uint8_t DW_LNS_set_isa = 12;
constexpr std::uint8_t DW_LNE_end_sequence = 1;
constexpr std::uint8_t DW_LNE_set_address = 2;
constexpr std::uint8_t DW_LNE_define_file = 3;
constexpr std::uint8_t DW_LNE_set_discriminator = 4;
constexpr std::uint16_t DW_LNCT_path = 0x1;
constexpr std::uint16_t DW_LNCT_directory_index = 0x2;
constexpr std::uint16_t DW_FORM_addr = 0x01;
constexpr std::uint16_t DW_FORM_block2 = 0x03;
constexpr std::uint16_t DW_FORM_block4 = 0x04;
constexpr std::uint16_t DW_FORM_data2 = 0x05;
constexpr std::uint16_t DW_FORM_data4 = 0x06;
constexpr std::uint16_t DW_FORM_data8 = 0x07;
constexpr std::uint16_t DW_FORM_string = 0x08;
constexpr std::uint16_t DW_FORM_block = 0x09;
constexpr std::uint16_t DW_FORM_block1 = 0x0a;
constexpr std::uint16_t DW_FORM_data1 = 0x0b;
constexpr std::uint16_t DW_FORM_flag = 0x0c;
constexpr std::uint16_t DW_FORM_sdata = 0x0d;
constexpr std::uint16_t DW_FORM_strp = 0x0e;
constexpr std::uint16_t DW_FORM_udata = 0x0f;
constexpr std::uint16_t DW_FORM_sec_offset = 0x17;
constexpr std::uint16_t DW_FORM_exprloc = 0x18;
constexpr std::uint16_t DW_FORM_flag_present = 0x19;
constexpr std::uint16_t DW_FORM_line_strp = 0x1f;

const std::wregex kMemoryRegionRegex(
    LR"(^([^\s]+)\s+0x([0-9A-Fa-f]+)\s+0x([0-9A-Fa-f]+)\s+([^\s]+)$)",
    std::regex_constants::optimize);
const std::wregex kTopSectionRegex(
    LR"(^([^\s]+)\s+0x([0-9A-Fa-f]+)\s+0x([0-9A-Fa-f]+)(?:\s+load address 0x([0-9A-Fa-f]+))?\s*$)",
    std::regex_constants::optimize);
const std::wregex kEntryRegex(
    LR"(^\s+([^\s]+)\s+0x([0-9A-Fa-f]+)\s+0x([0-9A-Fa-f]+)(?:\s+(.+))?\s*$)",
    std::regex_constants::optimize);
const std::wregex kEntryNameOnlyRegex(
    LR"(^\s+([^\s]+)\s*$)",
    std::regex_constants::optimize);
const std::wregex kEntryContinuationRegex(
    LR"(^\s+0x([0-9A-Fa-f]+)\s+0x([0-9A-Fa-f]+)(?:\s+(.+))?\s*$)",
    std::regex_constants::optimize);
const std::wregex kArchiveRegex(
    LR"(^(.+?\.a)\(([^)]+)\)$)",
    std::regex_constants::optimize);
const std::wregex kObjectRegex(
    LR"(^(.+?\.o)$)",
    std::regex_constants::optimize);

// ARM armlink MAP format regexes
const std::wregex kArmlinkLoadRegionRegex(
    LR"(^\s+Load Region\s+(\S+)\s+\(Base:\s+0x([0-9A-Fa-f]+),\s+Size:\s+0x([0-9A-Fa-f]+),)",
    std::regex_constants::optimize);
const std::wregex kArmlinkExecRegionRegex(
    LR"(^\s+Execution Region\s+(\S+)\s+\(Exec base:\s+0x([0-9A-Fa-f]+),\s+Load base:\s+0x[0-9A-Fa-f]+,\s+Size:\s+0x([0-9A-Fa-f]+),)",
    std::regex_constants::optimize);
const std::wregex kArmlinkSectionPrefixRegex(
    LR"(^\s+(0x[0-9A-Fa-f]+)\s+(0x[0-9A-Fa-f]+)\s+(0x[0-9A-Fa-f]+)\s+(Code|Data|Zero)\s+(RO|RW|ZI)\s+(\d+)\s+(\*?)\s*(.*)$)",
    std::regex_constants::optimize);
const std::wregex kArmlinkPadRegex(
    LR"(^\s+(0x[0-9A-Fa-f]+)\s+(0x[0-9A-Fa-f]+)\s+(0x[0-9A-Fa-f]+)\s+PAD\s*$)",
    std::regex_constants::optimize);
const std::wregex kArmlinkLibObjectRegex(
    LR"(^(.+\.l)\((.+)\)$)",
    std::regex_constants::optimize);

constexpr std::wstring_view kIgnoredSectionPrefixes[] = {
    L".debug", L".comment", L".symtab", L".strtab", L".shstrtab", L".riscv.attributes"
};
constexpr std::wstring_view kFallbackFlashPrefixes[] = {
    L".init", L".text", L".rodata", L".ctors", L".dtors", L".fini", L".eh_frame", L".gcc_except_table", L".data"
};

struct MemoryRegion
{
    std::wstring name;
    ULONGLONG origin = 0;
    ULONGLONG length = 0;
    std::wstring attrs;

    [[nodiscard]] ULONGLONG End() const noexcept { return origin + length; }
    [[nodiscard]] bool Contains(const ULONGLONG address) const noexcept { return origin <= address && address < End(); }
};

struct Contribution
{
    std::wstring subsection;
    ULONGLONG address = 0;
    ULONGLONG size = 0;
    std::wstring sourcePath;
    std::wstring library;
    std::wstring object;

    [[nodiscard]] ULONGLONG End() const noexcept { return address + size; }
};

struct Symbol;
struct ElfSection;

struct ProgramHeader
{
    std::uint32_t type = 0;
    ULONGLONG offset = 0;
    ULONGLONG virtualAddress = 0;
    ULONGLONG physicalAddress = 0;
    ULONGLONG fileSize = 0;
    ULONGLONG memorySize = 0;
};

struct DebugLineEntry
{
    ULONGLONG address = 0;
    std::wstring file;
    std::uint32_t line = 0;
};

struct DwarfLineFileEntry
{
    std::wstring path;
    ULONGLONG directoryIndex = 0;
};

struct SymbolDebugInfo
{
    std::optional<ULONGLONG> fileOffset;
    std::optional<ULONGLONG> physicalAddress;
    std::wstring sourceFile;
    std::optional<std::uint32_t> sourceLine;
};

struct ParsedElfData
{
    std::vector<ElfSection> sections;
    std::vector<ProgramHeader> programHeaders;
    std::vector<Symbol> symbols;
    std::vector<DebugLineEntry> debugLines;
};

struct Symbol
{
    std::wstring name;
    ULONGLONG address = 0;
    ULONGLONG size = 0;
    std::uint8_t type = 0;
    std::uint8_t bind = 0;
    std::uint16_t sectionIndex = 0;
    std::wstring sectionName;

    [[nodiscard]] ULONGLONG End() const noexcept { return address + size; }
};

struct OutputSection
{
    std::wstring name;
    ULONGLONG address = 0;
    ULONGLONG size = 0;
    std::optional<ULONGLONG> loadAddress;
    std::vector<Contribution> contributions;
};

struct MapParseResult
{
    std::vector<MemoryRegion> selectedRegions;
    std::vector<OutputSection> sections;
};

struct ElfSection
{
    std::uint32_t index = 0;
    std::uint32_t type = 0;
    ULONGLONG offset = 0;
    ULONGLONG size = 0;
    ULONGLONG address = 0;
    std::uint32_t link = 0;
    ULONGLONG entrySize = 0;
    std::wstring name;
};

struct ObjectBucket
{
    std::wstring library;
    std::wstring object;
    std::wstring sourcePath;
    ULONGLONG value = 0;
    std::vector<const Contribution*> contributions;
    std::vector<Symbol> symbols;
    std::unordered_map<const Contribution*, std::vector<std::pair<ULONGLONG, ULONGLONG>>> coverage;
    std::unordered_set<std::wstring, string_hash, std::equal_to<>> symbolKeys;
};

[[nodiscard]] ULONGLONG OverlapSize(const ULONGLONG leftBegin, const ULONGLONG leftEnd,
    const ULONGLONG rightBegin, const ULONGLONG rightEnd)
{
    const ULONGLONG begin = std::max(leftBegin, rightBegin);
    const ULONGLONG end = std::min(leftEnd, rightEnd);
    return end > begin ? end - begin : 0;
}

[[nodiscard]] bool StartsWithInsensitive(const std::wstring_view value, const std::wstring_view prefix)
{
    return value.size() >= prefix.size() && _wcsnicmp(value.data(), prefix.data(), prefix.size()) == 0;
}

[[nodiscard]] ULONGLONG ParseHex(const std::wstring& value)
{
    return wcstoull(value.c_str(), nullptr, 16);
}

[[nodiscard]] std::vector<std::wstring> SplitByMultiSpace(const std::wstring& input)
{
    std::vector<std::wstring> result;
    std::wregex separator(LR"(\s{2,})");
    std::wsregex_token_iterator it(input.begin(), input.end(), separator, -1);
    std::wsregex_token_iterator end;
    for (; it != end; ++it)
    {
        std::wstring part = it->str();
        if (!part.empty()) result.push_back(std::move(part));
    }
    return result;
}

[[nodiscard]] std::vector<std::wstring> ReadAllLines(const std::wstring& path)
{
    const std::filesystem::path filePath(path);
    std::ifstream input(filePath);
    std::vector<std::wstring> lines;
    std::string line;
    while (std::getline(input, line))
    {
        if (!line.empty() && line.back() == '\r')
        {
            line.pop_back();
        }
        lines.push_back(Localization::ConvertToWideString(line));
    }
    return lines;
}

[[nodiscard]] std::vector<std::uint8_t> ReadAllBytes(const std::wstring& path)
{
    std::ifstream input(std::filesystem::path(path), std::ios::binary);
    if (!input.is_open())
    {
        return {};
    }
    input.seekg(0, std::ios::end);
    const auto size = static_cast<std::size_t>(input.tellg());
    input.seekg(0, std::ios::beg);
    std::vector<std::uint8_t> bytes(size);
    if (size > 0)
    {
        input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(size));
    }
    return bytes;
}

[[nodiscard]] std::uint16_t ReadU16(const std::vector<std::uint8_t>& bytes, const std::size_t offset)
{
    return offset + 1 < bytes.size() ?
        static_cast<std::uint16_t>(bytes[offset]) |
        (static_cast<std::uint16_t>(bytes[offset + 1]) << 8) : 0;
}

[[nodiscard]] std::uint32_t ReadU32(const std::vector<std::uint8_t>& bytes, const std::size_t offset)
{
    return offset + 3 < bytes.size() ?
        static_cast<std::uint32_t>(bytes[offset]) |
        (static_cast<std::uint32_t>(bytes[offset + 1]) << 8) |
        (static_cast<std::uint32_t>(bytes[offset + 2]) << 16) |
        (static_cast<std::uint32_t>(bytes[offset + 3]) << 24) : 0;
}

[[nodiscard]] std::uint64_t ReadU64(const std::vector<std::uint8_t>& bytes, const std::size_t offset)
{
    return offset + 7 < bytes.size() ?
        static_cast<std::uint64_t>(ReadU32(bytes, offset)) |
        (static_cast<std::uint64_t>(ReadU32(bytes, offset + 4)) << 32) : 0;
}

[[nodiscard]] std::uint8_t ReadU8(const std::vector<std::uint8_t>& bytes, const std::size_t offset)
{
    return offset < bytes.size() ? bytes[offset] : 0;
}

[[nodiscard]] std::int8_t ReadS8(const std::vector<std::uint8_t>& bytes, const std::size_t offset)
{
    return static_cast<std::int8_t>(ReadU8(bytes, offset));
}

[[nodiscard]] std::wstring ReadUtf8Z(const std::vector<std::uint8_t>& bytes, const std::size_t offset)
{
    if (offset >= bytes.size())
    {
        return {};
    }
    std::size_t end = offset;
    while (end < bytes.size() && bytes[end] != 0)
    {
        end += 1;
    }
    return Localization::ConvertToWideString(
        std::string_view(reinterpret_cast<const char*>(bytes.data() + offset), end - offset));
}

[[nodiscard]] bool ReadULEB128(const std::vector<std::uint8_t>& bytes, std::size_t& offset,
    const std::size_t limit, ULONGLONG& value)
{
    value = 0;
    unsigned int shift = 0;
    while (offset < limit && shift < 64)
    {
        const auto byte = bytes[offset++];
        value |= static_cast<ULONGLONG>(byte & 0x7fu) << shift;
        if ((byte & 0x80u) == 0)
        {
            return true;
        }
        shift += 7;
    }
    return false;
}

[[nodiscard]] bool ReadSLEB128(const std::vector<std::uint8_t>& bytes, std::size_t& offset,
    const std::size_t limit, LONGLONG& value)
{
    value = 0;
    unsigned int shift = 0;
    std::uint8_t byte = 0;
    while (offset < limit && shift < 64)
    {
        byte = bytes[offset++];
        value |= static_cast<LONGLONG>(byte & 0x7fu) << shift;
        shift += 7;
        if ((byte & 0x80u) == 0)
        {
            if (shift < 64 && (byte & 0x40u) != 0)
            {
                value |= -((1ll) << shift);
            }
            return true;
        }
    }
    return false;
}

[[nodiscard]] bool ReadCStringAt(const std::vector<std::uint8_t>& bytes, std::size_t& offset,
    const std::size_t limit, std::wstring& value)
{
    if (offset >= limit)
    {
        return false;
    }

    std::size_t end = offset;
    while (end < limit && bytes[end] != 0)
    {
        ++end;
    }
    if (end >= limit)
    {
        return false;
    }

    value = Localization::ConvertToWideString(
        std::string_view(reinterpret_cast<const char*>(bytes.data() + offset), end - offset));
    offset = end + 1;
    return true;
}

[[nodiscard]] bool ReadInitialLength(const std::vector<std::uint8_t>& bytes, std::size_t& offset,
    const std::size_t limit, ULONGLONG& length, bool& dwarf64)
{
    if (offset + 4 > limit)
    {
        return false;
    }

    const auto raw = ReadU32(bytes, offset);
    offset += 4;
    if (raw == DW_LENGTH_DWARF64)
    {
        if (offset + 8 > limit)
        {
            return false;
        }
        length = ReadU64(bytes, offset);
        offset += 8;
        dwarf64 = true;
        return true;
    }

    length = raw;
    dwarf64 = false;
    return true;
}

[[nodiscard]] bool ReadSizedUnsigned(const std::vector<std::uint8_t>& bytes, std::size_t& offset,
    const std::size_t limit, const std::size_t size, ULONGLONG& value)
{
    if (offset + size > limit)
    {
        return false;
    }

    switch (size)
    {
    case 1: value = ReadU8(bytes, offset); break;
    case 2: value = ReadU16(bytes, offset); break;
    case 4: value = ReadU32(bytes, offset); break;
    case 8: value = ReadU64(bytes, offset); break;
    default: return false;
    }

    offset += size;
    return true;
}

[[nodiscard]] const ElfSection* FindSectionByName(const std::vector<ElfSection>& sections, const std::wstring_view name)
{
    const auto it = std::ranges::find_if(sections, [name](const ElfSection& section)
    {
        return section.name == name;
    });
    return it != sections.end() ? &*it : nullptr;
}

[[nodiscard]] bool ResolveDwarfString(const std::vector<std::uint8_t>& bytes, std::size_t& offset,
    const std::size_t limit, const std::uint16_t form, const std::size_t offsetSize,
    const ElfSection* debugStr, const ElfSection* debugLineStr, std::wstring& value)
{
    switch (form)
    {
    case DW_FORM_string:
        return ReadCStringAt(bytes, offset, limit, value);

    case DW_FORM_strp:
    case DW_FORM_line_strp:
    {
        ULONGLONG stringOffset = 0;
        if (!ReadSizedUnsigned(bytes, offset, limit, offsetSize, stringOffset))
        {
            return false;
        }

        const auto* section = form == DW_FORM_line_strp ? debugLineStr : debugStr;
        if (section == nullptr || section->offset + stringOffset >= bytes.size())
        {
            value.clear();
            return true;
        }

        value = ReadUtf8Z(bytes, static_cast<std::size_t>(section->offset + stringOffset));
        return true;
    }

    default:
        return false;
    }
}

[[nodiscard]] bool ResolveDwarfUnsigned(const std::vector<std::uint8_t>& bytes, std::size_t& offset,
    const std::size_t limit, const std::uint16_t form, const std::size_t offsetSize,
    const std::size_t addressSize, ULONGLONG& value)
{
    switch (form)
    {
    case DW_FORM_data1: return ReadSizedUnsigned(bytes, offset, limit, 1, value);
    case DW_FORM_data2: return ReadSizedUnsigned(bytes, offset, limit, 2, value);
    case DW_FORM_data4: return ReadSizedUnsigned(bytes, offset, limit, 4, value);
    case DW_FORM_data8: return ReadSizedUnsigned(bytes, offset, limit, 8, value);
    case DW_FORM_udata: return ReadULEB128(bytes, offset, limit, value);
    case DW_FORM_sec_offset: return ReadSizedUnsigned(bytes, offset, limit, offsetSize, value);
    case DW_FORM_addr: return ReadSizedUnsigned(bytes, offset, limit, addressSize, value);
    case DW_FORM_flag:
    {
        value = ReadU8(bytes, offset);
        if (offset >= limit)
        {
            return false;
        }
        ++offset;
        return true;
    }
    case DW_FORM_flag_present:
        value = 1;
        return true;
    default:
        return false;
    }
}

[[nodiscard]] bool SkipDwarfForm(const std::vector<std::uint8_t>& bytes, std::size_t& offset,
    const std::size_t limit, const std::uint16_t form, const std::size_t offsetSize,
    const std::size_t addressSize, const ElfSection* debugStr, const ElfSection* debugLineStr)
{
    std::wstring stringValue;
    ULONGLONG unsignedValue = 0;
    LONGLONG signedValue = 0;

    switch (form)
    {
    case DW_FORM_string:
    case DW_FORM_strp:
    case DW_FORM_line_strp:
        return ResolveDwarfString(bytes, offset, limit, form, offsetSize, debugStr, debugLineStr, stringValue);

    case DW_FORM_addr:
    case DW_FORM_data1:
    case DW_FORM_data2:
    case DW_FORM_data4:
    case DW_FORM_data8:
    case DW_FORM_udata:
    case DW_FORM_sec_offset:
    case DW_FORM_flag:
    case DW_FORM_flag_present:
        return ResolveDwarfUnsigned(bytes, offset, limit, form, offsetSize, addressSize, unsignedValue);

    case DW_FORM_sdata:
        return ReadSLEB128(bytes, offset, limit, signedValue);

    case DW_FORM_block1:
        return ReadSizedUnsigned(bytes, offset, limit, 1, unsignedValue) && offset + unsignedValue <= limit ? (offset += static_cast<std::size_t>(unsignedValue), true) : false;
    case DW_FORM_block2:
        return ReadSizedUnsigned(bytes, offset, limit, 2, unsignedValue) && offset + unsignedValue <= limit ? (offset += static_cast<std::size_t>(unsignedValue), true) : false;
    case DW_FORM_block4:
        return ReadSizedUnsigned(bytes, offset, limit, 4, unsignedValue) && offset + unsignedValue <= limit ? (offset += static_cast<std::size_t>(unsignedValue), true) : false;
    case DW_FORM_block:
    case DW_FORM_exprloc:
        return ReadULEB128(bytes, offset, limit, unsignedValue) && offset + unsignedValue <= limit ? (offset += static_cast<std::size_t>(unsignedValue), true) : false;

    default:
        return false;
    }
}

[[nodiscard]] std::wstring CombineDwarfPath(const std::wstring& directory, const std::wstring& file)
{
    if (file.empty())
    {
        return {};
    }
    if (directory.empty() || std::filesystem::path(file).is_absolute())
    {
        return file;
    }
    return (std::filesystem::path(directory) / file).wstring();
}

[[nodiscard]] std::vector<MemoryRegion> ParseMemoryRegions(const std::vector<std::wstring>& lines)
{
    const auto header = std::ranges::find(lines, std::wstring(MEMORY_CONFIG_HEADER));
    if (header == lines.end())
    {
        return {};
    }

    std::vector<MemoryRegion> regions;
    for (auto it = header + 2; it != lines.end(); ++it)
    {
        if (it->empty())
        {
            continue;
        }
        if (*it == MAP_HEADER)
        {
            break;
        }

        std::wsmatch match;
        if (!std::regex_match(*it, match, kMemoryRegionRegex))
        {
            continue;
        }

        regions.push_back({
            .name = match[1].str(),
            .origin = ParseHex(match[2].str()),
            .length = ParseHex(match[3].str()),
            .attrs = match[4].str(),
        });
    }
    return regions;
}

[[nodiscard]] const MemoryRegion* FindRegion(const ULONGLONG address, const std::vector<MemoryRegion>& regions)
{
    for (const auto& region : regions)
    {
        if (region.Contains(address))
        {
            return &region;
        }
    }
    return nullptr;
}

[[nodiscard]] std::wstring SymbolBindLabel(const std::uint8_t bind)
{
    switch (bind)
    {
    case STB_LOCAL:
        return L"LOCAL";
    case STB_GLOBAL:
        return L"GLOBAL";
    case STB_WEAK:
        return L"WEAK";
    default:
        return std::format(L"BIND({})", bind);
    }
}

[[nodiscard]] std::wstring FormatHexValue(const ULONGLONG value)
{
    return std::format(L"0x{:X}", value);
}

void AddDetailField(MapItemDetails& details, const std::wstring& label, const std::wstring& value)
{
    if (!value.empty())
    {
        details.fields.push_back({ .label = label, .value = value });
    }
}

void AddDetailField(MapItemDetails& details, const std::wstring& label, const std::optional<ULONGLONG>& value)
{
    if (value.has_value())
    {
        AddDetailField(details, label, FormatHexValue(*value));
    }
}

[[nodiscard]] std::vector<MemoryRegion> DetectFlashRegions(const std::vector<MemoryRegion>& regions)
{
    std::vector<MemoryRegion> named;
    for (const auto& region : regions)
    {
        std::wstring lower = region.name;
        std::ranges::transform(lower, lower.begin(), [](const wchar_t value)
        {
            return static_cast<wchar_t>(towlower(value));
        });
        if (lower.find(L"flash") != std::wstring::npos || lower.find(L"rom") != std::wstring::npos)
        {
            named.push_back(region);
        }
    }
    if (!named.empty())
    {
        return named;
    }

    std::vector<MemoryRegion> executable;
    for (const auto& region : regions)
    {
        if (region.attrs.find(L'x') != std::wstring::npos && region.attrs.find(L'w') == std::wstring::npos)
        {
            executable.push_back(region);
        }
    }
    return executable;
}

[[nodiscard]] std::vector<MemoryRegion> FilterRegionsByName(const std::vector<MemoryRegion>& regions,
    const std::optional<std::wstring>& selectedRegion)
{
    if (!selectedRegion.has_value() || selectedRegion->empty())
    {
        return regions;
    }

    std::vector<MemoryRegion> filtered;
    for (const auto& region : regions)
    {
        if (_wcsicmp(region.name.c_str(), selectedRegion->c_str()) == 0)
        {
            filtered.push_back(region);
        }
    }
    return filtered;
}

[[nodiscard]] std::vector<MemoryRegion> GetCandidateRegions(const std::vector<MemoryRegion>& regions,
    const std::optional<std::wstring>& selectedRegion)
{
    if (selectedRegion.has_value() && !selectedRegion->empty())
    {
        return FilterRegionsByName(regions, selectedRegion);
    }

    return DetectFlashRegions(regions);
}

[[nodiscard]] bool IsRegionSection(const OutputSection& section, const std::vector<MemoryRegion>& selectedRegions)
{
    if (section.size == 0)
    {
        return false;
    }

    for (const auto prefix : kIgnoredSectionPrefixes)
    {
        if (section.name.starts_with(prefix))
        {
            return false;
        }
    }

    if (section.loadAddress.has_value() && FindRegion(*section.loadAddress, selectedRegions) != nullptr)
    {
        return true;
    }
    if (FindRegion(section.address, selectedRegions) != nullptr)
    {
        return true;
    }
    if (selectedRegions.empty())
    {
        for (const auto prefix : kFallbackFlashPrefixes)
        {
            if (section.name.starts_with(prefix))
            {
                return true;
            }
        }
    }
    return false;
}

[[nodiscard]] std::optional<Contribution> ParseSource(const std::wstring& subsection, const std::wstring& rest)
{
    if (subsection == L"*fill*")
    {
        return Contribution{
            .subsection = subsection,
            .sourcePath = L"[linker fill]",
            .library = L"[linker fill]",
            .object = L"alignment",
        };
    }
    if (rest.empty())
    {
        return std::nullopt;
    }
    if (StartsWithInsensitive(rest, L"LOADADDR") || StartsWithInsensitive(rest, L"ADDR") ||
        StartsWithInsensitive(rest, L"SIZEOF") || StartsWithInsensitive(rest, L"LONG") ||
        StartsWithInsensitive(rest, L"PROVIDE") || StartsWithInsensitive(rest, L"ASSERT"))
    {
        return std::nullopt;
    }

    std::wsmatch match;
    if (std::regex_match(rest, match, kArchiveRegex))
    {
        const auto archivePath = std::filesystem::path(match[1].str());
        return Contribution{
            .subsection = subsection,
            .sourcePath = rest,
            .library = archivePath.filename().wstring(),
            .object = match[2].str(),
        };
    }
    if (std::regex_match(rest, match, kObjectRegex))
    {
        const auto objectPath = std::filesystem::path(match[1].str());
        return Contribution{
            .subsection = subsection,
            .sourcePath = rest,
            .library = L"[objects]",
            .object = objectPath.filename().wstring(),
        };
    }
    return std::nullopt;
}

[[nodiscard]] const Contribution* FindBestContributionForSymbol(const Symbol& symbol,
    const std::vector<const Contribution*>& contributionRecords,
    const std::vector<ULONGLONG>& contributionStarts)
{
    const Contribution* best = nullptr;
    ULONGLONG bestOverlap = 0;

    const auto symbolEnd = symbol.End();
    const auto upper = std::upper_bound(contributionStarts.begin(), contributionStarts.end(), symbol.address);
    std::size_t beginIndex = 0;
    if (upper != contributionStarts.begin())
    {
        beginIndex = static_cast<std::size_t>(std::distance(contributionStarts.begin(), upper) - 1);
    }

    for (std::size_t index = beginIndex; index < contributionRecords.size(); ++index)
    {
        const Contribution* candidate = contributionRecords[index];
        if (candidate->address > symbolEnd)
        {
            break;
        }

        const ULONGLONG overlap = OverlapSize(symbol.address, symbolEnd, candidate->address, candidate->End());
        if (overlap > bestOverlap)
        {
            best = candidate;
            bestOverlap = overlap;
        }

        if (bestOverlap == symbol.size && symbol.size != 0)
        {
            return best;
        }
    }

    if (best != nullptr)
    {
        return best;
    }

    if (upper != contributionStarts.begin())
    {
        const auto index = static_cast<std::size_t>(std::distance(contributionStarts.begin(), upper) - 1);
        const Contribution* candidate = contributionRecords[index];
        if (candidate->address <= symbol.address && symbol.address < candidate->End())
        {
            return candidate;
        }
    }

    return nullptr;
}

[[nodiscard]] const MemoryRegion* FindSelectedRegion(const OutputSection& section,
    const std::vector<MemoryRegion>& selectedRegions)
{
    if (section.loadAddress.has_value())
    {
        if (const auto* region = FindRegion(*section.loadAddress, selectedRegions); region != nullptr)
        {
            return region;
        }
    }
    return FindRegion(section.address, selectedRegions);
}

[[nodiscard]] std::vector<MemoryRegion> ParseArmlinkMemoryRegions(const std::vector<std::wstring>& lines)
{
    std::vector<MemoryRegion> regions;
    const auto header = std::ranges::find(lines, std::wstring(ARLINK_MAP_HEADER));
    if (header == lines.end()) return regions;

    for (auto it = header + 1; it != lines.end(); ++it)
    {
        std::wsmatch match;
        if (std::regex_match(*it, match, kArmlinkLoadRegionRegex))
        {
            regions.push_back({
                .name = match[1].str(),
                .origin = ParseHex(match[2].str()),
                .length = ParseHex(match[3].str()),
                .attrs = L"LR",
            });
        }
        else if (std::regex_match(*it, match, kArmlinkExecRegionRegex))
        {
            regions.push_back({
                .name = match[1].str(),
                .origin = ParseHex(match[2].str()),
                .length = ParseHex(match[3].str()),
                .attrs = L"ER",
            });
        }
        else if (!regions.empty() && !it->empty() && (*it)[0] != L' ')
        {
            break;
        }
    }
    return regions;
}

[[nodiscard]] MapParseResult ParseArmlinkMapFile(const std::vector<std::wstring>& lines, const std::optional<std::wstring>& selectedRegion)
{
    const auto regions = ParseArmlinkMemoryRegions(lines);
    const auto selectedRegions = GetCandidateRegions(regions, selectedRegion);

    const auto header = std::ranges::find(lines, std::wstring(ARLINK_MAP_HEADER));
    if (header == lines.end())
    {
        return { .selectedRegions = selectedRegions };
    }

    std::vector<OutputSection> sections;

    for (auto it = header + 1; it != lines.end(); ++it)
    {
        if (it->empty()) continue;

        if (!it->empty() && (*it)[0] != L' ') break;

        std::wsmatch match;
        if (std::regex_match(*it, match, kArmlinkExecRegionRegex))
        {
            continue;
        }

        if (std::regex_match(*it, match, kArmlinkPadRegex)) continue;

        if (std::regex_match(*it, match, kArmlinkSectionPrefixRegex))
        {
            const ULONGLONG execAddr = ParseHex(match[1].str());
            const ULONGLONG loadAddr = ParseHex(match[2].str());
            const ULONGLONG size = ParseHex(match[3].str());
            if (size == 0) continue;

            const std::wstring rest = match[8].str();
            const auto parts = SplitByMultiSpace(rest);
            if (parts.size() < 2) continue;

            const std::wstring sectionName = parts[0];
            const std::wstring objectName = parts[1];

            OutputSection section{
                .name = sectionName,
                .address = execAddr,
                .size = size,
            };
            if (loadAddr != execAddr)
            {
                section.loadAddress = loadAddr;
            }

            if (!selectedRegions.empty() && FindRegion(execAddr, selectedRegions) == nullptr &&
                (!section.loadAddress.has_value() || FindRegion(*section.loadAddress, selectedRegions) == nullptr))
            {
                continue;
            }

            std::wstring library = L"[objects]";
            std::wstring object = objectName;

            std::wsmatch libMatch;
            if (std::regex_match(objectName, libMatch, kArmlinkLibObjectRegex))
            {
                library = libMatch[1].str();
                object = libMatch[2].str();
            }

            Contribution contrib{
                .subsection = sectionName,
                .address = execAddr,
                .size = size,
                .library = library,
                .object = object,
            };
            section.contributions.push_back(std::move(contrib));
            sections.push_back(std::move(section));
        }
    }

    return { .selectedRegions = selectedRegions, .sections = std::move(sections) };
}

[[nodiscard]] MapParseResult ParseMapFile(const std::wstring& mapPath, const std::optional<std::wstring>& selectedRegion)
{
    const auto lines = ReadAllLines(mapPath);

    const auto armlinkHeader = std::ranges::find(lines, std::wstring(ARLINK_MAP_HEADER));
    if (armlinkHeader != lines.end())
    {
        return ParseArmlinkMapFile(lines, selectedRegion);
    }

    const auto regions = ParseMemoryRegions(lines);
    const auto selectedRegions = GetCandidateRegions(regions, selectedRegion);

    const auto header = std::ranges::find(lines, std::wstring(MAP_HEADER));
    if (header == lines.end())
    {
        return { .selectedRegions = selectedRegions };
    }

    std::vector<OutputSection> sections;
    OutputSection* current = nullptr;
    std::optional<std::wstring> pendingSubsection;
    for (auto it = header + 1; it != lines.end(); ++it)
    {
        if (it->empty())
        {
            continue;
        }

        std::wsmatch topMatch;
        if (std::regex_match(*it, topMatch, kTopSectionRegex))
        {
            pendingSubsection.reset();

            OutputSection candidate{
                .name = topMatch[1].str(),
                .address = ParseHex(topMatch[2].str()),
                .size = ParseHex(topMatch[3].str()),
            };
            if (topMatch[4].matched)
            {
                candidate.loadAddress = ParseHex(topMatch[4].str());
            }

            if (IsRegionSection(candidate, selectedRegions))
            {
                sections.push_back(std::move(candidate));
                current = &sections.back();
            }
            else
            {
                current = nullptr;
            }
            continue;
        }

        if (current == nullptr)
        {
            continue;
        }

        std::wsmatch nameOnlyMatch;
        if (std::regex_match(*it, nameOnlyMatch, kEntryNameOnlyRegex))
        {
            const auto subsection = nameOnlyMatch[1].str();
            if (subsection.starts_with(L"."))
            {
                pendingSubsection = std::move(subsection);
                continue;
            }
        }

        std::wsmatch entryMatch;
        if (std::regex_match(*it, entryMatch, kEntryRegex))
        {
            const ULONGLONG size = ParseHex(entryMatch[3].str());
            if (size == 0)
            {
                pendingSubsection.reset();
                continue;
            }

            const std::wstring rest = entryMatch[4].matched ? entryMatch[4].str() : std::wstring();
            auto contribution = ParseSource(entryMatch[1].str(), rest);
            if (!contribution.has_value())
            {
                pendingSubsection.reset();
                continue;
            }

            contribution->address = ParseHex(entryMatch[2].str());
            contribution->size = size;
            current->contributions.push_back(std::move(*contribution));
            pendingSubsection.reset();
            continue;
        }

        std::wsmatch continuationMatch;
        if (pendingSubsection.has_value() && std::regex_match(*it, continuationMatch, kEntryContinuationRegex))
        {
            const ULONGLONG size = ParseHex(continuationMatch[2].str());
            if (size == 0)
            {
                pendingSubsection.reset();
                continue;
            }

            const std::wstring rest = continuationMatch[3].matched ? continuationMatch[3].str() : std::wstring();
            auto contribution = ParseSource(*pendingSubsection, rest);
            if (!contribution.has_value())
            {
                pendingSubsection.reset();
                continue;
            }

            contribution->address = ParseHex(continuationMatch[1].str());
            contribution->size = size;
            current->contributions.push_back(std::move(*contribution));
            pendingSubsection.reset();
            continue;
        }

        pendingSubsection.reset();
    }

    return {
        .selectedRegions = selectedRegions,
        .sections = std::move(sections),
    };
}

[[nodiscard]] bool IsInterestingSymbolType(const std::uint8_t type)
{
    return type == STT_NOTYPE || type == STT_OBJECT || type == STT_FUNC;
}

[[nodiscard]] std::vector<ElfSection> ParseElfSections(const std::vector<std::uint8_t>& bytes, const std::uint8_t elfClass)
{
    const std::uint64_t sectionOffset = elfClass == ELFCLASS32 ? ReadU32(bytes, 32) : ReadU64(bytes, 40);
    const std::uint16_t sectionEntrySize = elfClass == ELFCLASS32 ? ReadU16(bytes, 46) : ReadU16(bytes, 58);
    const std::uint16_t sectionCount = elfClass == ELFCLASS32 ? ReadU16(bytes, 48) : ReadU16(bytes, 60);
    const std::uint16_t sectionNameIndex = elfClass == ELFCLASS32 ? ReadU16(bytes, 50) : ReadU16(bytes, 62);

    if (sectionOffset == 0 || sectionEntrySize == 0 || sectionCount == 0)
    {
        return {};
    }

    std::vector<ElfSection> sections;
    sections.reserve(sectionCount);
    for (std::uint16_t index = 0; index < sectionCount; ++index)
    {
        const std::size_t base = static_cast<std::size_t>(sectionOffset + static_cast<std::uint64_t>(index) * sectionEntrySize);
        if (base + sectionEntrySize > bytes.size())
        {
            return {};
        }

        const auto nameOffset = ReadU32(bytes, base + 0);
        const auto type = ReadU32(bytes, base + 4);
        const ULONGLONG address = elfClass == ELFCLASS32 ? ReadU32(bytes, base + 12) : ReadU64(bytes, base + 16);
        const ULONGLONG offset = elfClass == ELFCLASS32 ? ReadU32(bytes, base + 16) : ReadU64(bytes, base + 24);
        const ULONGLONG size = elfClass == ELFCLASS32 ? ReadU32(bytes, base + 20) : ReadU64(bytes, base + 32);
        const auto link = elfClass == ELFCLASS32 ? ReadU32(bytes, base + 24) : ReadU32(bytes, base + 40);
        const ULONGLONG entrySize = elfClass == ELFCLASS32 ? ReadU32(bytes, base + 36) : ReadU64(bytes, base + 56);

        sections.push_back({
            .index = index,
            .type = type,
            .offset = offset,
            .size = size,
            .address = address,
            .link = link,
            .entrySize = entrySize,
        });
        sections.back().name = std::to_wstring(nameOffset);
    }

    if (sectionNameIndex >= sections.size())
    {
        return {};
    }

    const auto& stringSection = sections[sectionNameIndex];
    if (stringSection.offset + stringSection.size > bytes.size())
    {
        return {};
    }

    for (auto& section : sections)
    {
        const auto nameOffset = wcstoul(section.name.c_str(), nullptr, 10);
        section.name = ReadUtf8Z(bytes, static_cast<std::size_t>(stringSection.offset + nameOffset));
    }

    return sections;
}

[[nodiscard]] std::vector<ProgramHeader> ParseProgramHeaders(const std::vector<std::uint8_t>& bytes, const std::uint8_t elfClass)
{
    const std::uint64_t programOffset = elfClass == ELFCLASS32 ? ReadU32(bytes, 28) : ReadU64(bytes, 32);
    const std::uint16_t programEntrySize = elfClass == ELFCLASS32 ? ReadU16(bytes, 42) : ReadU16(bytes, 54);
    const std::uint16_t programCount = elfClass == ELFCLASS32 ? ReadU16(bytes, 44) : ReadU16(bytes, 56);

    if (programOffset == 0 || programEntrySize == 0 || programCount == 0)
    {
        return {};
    }

    std::vector<ProgramHeader> headers;
    headers.reserve(programCount);
    for (std::uint16_t index = 0; index < programCount; ++index)
    {
        const std::size_t base = static_cast<std::size_t>(programOffset + static_cast<std::uint64_t>(index) * programEntrySize);
        if (base + programEntrySize > bytes.size())
        {
            return {};
        }

        ProgramHeader header;
        if (elfClass == ELFCLASS32)
        {
            header.type = ReadU32(bytes, base + 0);
            header.offset = ReadU32(bytes, base + 4);
            header.virtualAddress = ReadU32(bytes, base + 8);
            header.physicalAddress = ReadU32(bytes, base + 12);
            header.fileSize = ReadU32(bytes, base + 16);
            header.memorySize = ReadU32(bytes, base + 20);
        }
        else
        {
            header.type = ReadU32(bytes, base + 0);
            header.offset = ReadU64(bytes, base + 8);
            header.virtualAddress = ReadU64(bytes, base + 16);
            header.physicalAddress = ReadU64(bytes, base + 24);
            header.fileSize = ReadU64(bytes, base + 32);
            header.memorySize = ReadU64(bytes, base + 40);
        }
        headers.push_back(header);
    }

    return headers;
}

[[nodiscard]] std::vector<DebugLineEntry> ParseDebugLines(const std::vector<std::uint8_t>& bytes,
    const std::vector<ElfSection>& sections, const std::size_t defaultAddressSize)
{
    const auto* section = FindSectionByName(sections, L".debug_line");
    if (section == nullptr || section->offset + section->size > bytes.size())
    {
        return {};
    }

    const auto* debugStr = FindSectionByName(sections, L".debug_str");
    const auto* debugLineStr = FindSectionByName(sections, L".debug_line_str");

    std::vector<DebugLineEntry> entries;

    std::size_t offset = static_cast<std::size_t>(section->offset);
    const std::size_t limit = static_cast<std::size_t>(section->offset + section->size);
    while (offset < limit)
    {
        std::size_t unitOffset = offset;
        ULONGLONG unitLength = 0;
        bool dwarf64 = false;
        if (!ReadInitialLength(bytes, unitOffset, limit, unitLength, dwarf64))
        {
            break;
        }

        const std::size_t unitEnd = unitOffset + static_cast<std::size_t>(unitLength);
        if (unitEnd > limit)
        {
            break;
        }

        std::size_t cursor = unitOffset;
        const auto version = ReadU16(bytes, cursor);
        cursor += 2;

        const std::size_t offsetSize = dwarf64 ? 8 : 4;
        ULONGLONG headerLength = 0;
        if (!ReadSizedUnsigned(bytes, cursor, unitEnd, offsetSize, headerLength) || cursor + headerLength > unitEnd)
        {
            break;
        }

        const std::size_t headerEnd = cursor + static_cast<std::size_t>(headerLength);
        std::size_t addressSize = defaultAddressSize;
        if (version >= 5)
        {
            addressSize = ReadU8(bytes, cursor++);
            ++cursor; // segment_selector_size
        }

        const auto minimumInstructionLength = ReadU8(bytes, cursor++);
        const auto maximumOperationsPerInstruction = version >= 4 ? ReadU8(bytes, cursor++) : 1;
        (void)maximumOperationsPerInstruction;
        const bool defaultIsStmt = ReadU8(bytes, cursor++) != 0;
        const auto lineBase = ReadS8(bytes, cursor++);
        const auto lineRange = ReadU8(bytes, cursor++);
        const auto opcodeBase = ReadU8(bytes, cursor++);
        if (opcodeBase == 0 || lineRange == 0)
        {
            offset = unitEnd;
            continue;
        }

        std::vector<std::uint8_t> standardOpcodeLengths(opcodeBase, 0);
        for (std::size_t i = 1; i < opcodeBase; ++i)
        {
            standardOpcodeLengths[i] = ReadU8(bytes, cursor++);
        }

        std::vector<std::wstring> includeDirectories(1);
        std::vector<DwarfLineFileEntry> files(1);

        if (version >= 5)
        {
            const auto directoryEntryFormatCount = ReadU8(bytes, cursor++);
            std::vector<std::pair<std::uint16_t, std::uint16_t>> directoryFormats;
            directoryFormats.reserve(directoryEntryFormatCount);
            for (std::uint8_t i = 0; i < directoryEntryFormatCount; ++i)
            {
                ULONGLONG contentType = 0;
                ULONGLONG form = 0;
                if (!ReadULEB128(bytes, cursor, headerEnd, contentType) || !ReadULEB128(bytes, cursor, headerEnd, form))
                {
                    cursor = headerEnd;
                    break;
                }
                directoryFormats.emplace_back(static_cast<std::uint16_t>(contentType), static_cast<std::uint16_t>(form));
            }

            ULONGLONG directoryCount = 0;
            if (!ReadULEB128(bytes, cursor, headerEnd, directoryCount))
            {
                cursor = headerEnd;
            }
            for (ULONGLONG i = 0; i < directoryCount && cursor < headerEnd; ++i)
            {
                std::wstring directory;
                for (const auto& [contentType, form] : directoryFormats)
                {
                    if (contentType == DW_LNCT_path)
                    {
                        if (!ResolveDwarfString(bytes, cursor, headerEnd, form, offsetSize, debugStr, debugLineStr, directory))
                        {
                            cursor = headerEnd;
                            break;
                        }
                    }
                    else if (!SkipDwarfForm(bytes, cursor, headerEnd, form, offsetSize, 0, debugStr, debugLineStr))
                    {
                        cursor = headerEnd;
                        break;
                    }
                }
                includeDirectories.push_back(directory);
            }

            const auto fileEntryFormatCount = ReadU8(bytes, cursor++);
            std::vector<std::pair<std::uint16_t, std::uint16_t>> fileFormats;
            fileFormats.reserve(fileEntryFormatCount);
            for (std::uint8_t i = 0; i < fileEntryFormatCount; ++i)
            {
                ULONGLONG contentType = 0;
                ULONGLONG form = 0;
                if (!ReadULEB128(bytes, cursor, headerEnd, contentType) || !ReadULEB128(bytes, cursor, headerEnd, form))
                {
                    cursor = headerEnd;
                    break;
                }
                fileFormats.emplace_back(static_cast<std::uint16_t>(contentType), static_cast<std::uint16_t>(form));
            }

            ULONGLONG fileCount = 0;
            if (!ReadULEB128(bytes, cursor, headerEnd, fileCount))
            {
                cursor = headerEnd;
            }
            for (ULONGLONG i = 0; i < fileCount && cursor < headerEnd; ++i)
            {
                DwarfLineFileEntry entry;
                for (const auto& [contentType, form] : fileFormats)
                {
                    if (contentType == DW_LNCT_path)
                    {
                        if (!ResolveDwarfString(bytes, cursor, headerEnd, form, offsetSize, debugStr, debugLineStr, entry.path))
                        {
                            cursor = headerEnd;
                            break;
                        }
                    }
                    else if (contentType == DW_LNCT_directory_index)
                    {
                        if (!ResolveDwarfUnsigned(bytes, cursor, headerEnd, form, offsetSize, 0, entry.directoryIndex))
                        {
                            cursor = headerEnd;
                            break;
                        }
                    }
                    else if (!SkipDwarfForm(bytes, cursor, headerEnd, form, offsetSize, 0, debugStr, debugLineStr))
                    {
                        cursor = headerEnd;
                        break;
                    }
                }
                files.push_back(std::move(entry));
            }
        }
        else
        {
            while (cursor < headerEnd)
            {
                std::wstring directory;
                if (!ReadCStringAt(bytes, cursor, headerEnd, directory))
                {
                    cursor = headerEnd;
                    break;
                }
                if (directory.empty())
                {
                    break;
                }
                includeDirectories.push_back(std::move(directory));
            }

            while (cursor < headerEnd)
            {
                DwarfLineFileEntry entry;
                if (!ReadCStringAt(bytes, cursor, headerEnd, entry.path))
                {
                    cursor = headerEnd;
                    break;
                }
                if (entry.path.empty())
                {
                    break;
                }

                ULONGLONG ignored = 0;
                if (!ReadULEB128(bytes, cursor, headerEnd, entry.directoryIndex) ||
                    !ReadULEB128(bytes, cursor, headerEnd, ignored) ||
                    !ReadULEB128(bytes, cursor, headerEnd, ignored))
                {
                    cursor = headerEnd;
                    break;
                }
                files.push_back(std::move(entry));
            }
        }

        struct LineState
        {
            ULONGLONG address = 0;
            ULONGLONG opIndex = 0;
            std::uint32_t file = 1;
            std::uint32_t line = 1;
            std::uint32_t column = 0;
            bool isStmt = false;
            bool basicBlock = false;
            bool endSequence = false;
            bool prologueEnd = false;
            bool epilogueBegin = false;
            ULONGLONG isa = 0;
            ULONGLONG discriminator = 0;
        } state{};
        state.isStmt = defaultIsStmt;

        auto appendRow = [&]()
        {
            if (state.file == 0 || state.file >= files.size())
            {
                return;
            }

            const auto& fileEntry = files[state.file];
            std::wstring directory;
            if (fileEntry.directoryIndex < includeDirectories.size())
            {
                directory = includeDirectories[static_cast<std::size_t>(fileEntry.directoryIndex)];
            }

            const auto path = CombineDwarfPath(directory, fileEntry.path);
            if (!path.empty())
            {
                entries.push_back({
                    .address = state.address,
                    .file = path,
                    .line = state.line,
                });
            }
        };

        cursor = headerEnd;
        while (cursor < unitEnd)
        {
            const auto opcode = ReadU8(bytes, cursor++);
            if (opcode == 0)
            {
                ULONGLONG instructionLength = 0;
                if (!ReadULEB128(bytes, cursor, unitEnd, instructionLength) || cursor + instructionLength > unitEnd)
                {
                    cursor = unitEnd;
                    break;
                }

                const std::size_t instructionEnd = cursor + static_cast<std::size_t>(instructionLength);
                const auto extendedOpcode = ReadU8(bytes, cursor++);
                switch (extendedOpcode)
                {
                case DW_LNE_end_sequence:
                    state.endSequence = true;
                    appendRow();
                    state = {};
                    state.isStmt = defaultIsStmt;
                    break;

                case DW_LNE_set_address:
                {
                    ULONGLONG address = 0;
                    if (ReadSizedUnsigned(bytes, cursor, instructionEnd, addressSize, address))
                    {
                        state.address = address;
                        state.opIndex = 0;
                    }
                    break;
                }

                case DW_LNE_define_file:
                {
                    if (version >= 5)
                    {
                        cursor = instructionEnd;
                        break;
                    }

                    DwarfLineFileEntry entry;
                    ULONGLONG ignored = 0;
                    if (ReadCStringAt(bytes, cursor, instructionEnd, entry.path) &&
                        ReadULEB128(bytes, cursor, instructionEnd, entry.directoryIndex) &&
                        ReadULEB128(bytes, cursor, instructionEnd, ignored) &&
                        ReadULEB128(bytes, cursor, instructionEnd, ignored))
                    {
                        files.push_back(std::move(entry));
                    }
                    break;
                }

                case DW_LNE_set_discriminator:
                {
                    ULONGLONG discriminator = 0;
                    if (ReadULEB128(bytes, cursor, instructionEnd, discriminator))
                    {
                        state.discriminator = discriminator;
                    }
                    break;
                }

                default:
                    break;
                }
                cursor = instructionEnd;
                continue;
            }

            if (opcode < opcodeBase)
            {
                switch (opcode)
                {
                case DW_LNS_copy:
                    appendRow();
                    state.basicBlock = false;
                    state.prologueEnd = false;
                    state.epilogueBegin = false;
                    state.discriminator = 0;
                    break;

                case DW_LNS_advance_pc:
                {
                    ULONGLONG operand = 0;
                    if (ReadULEB128(bytes, cursor, unitEnd, operand))
                    {
                        state.address += operand * minimumInstructionLength;
                    }
                    break;
                }

                case DW_LNS_advance_line:
                {
                    LONGLONG operand = 0;
                    if (ReadSLEB128(bytes, cursor, unitEnd, operand))
                    {
                        state.line = static_cast<std::uint32_t>(static_cast<LONGLONG>(state.line) + operand);
                    }
                    break;
                }

                case DW_LNS_set_file:
                {
                    ULONGLONG operand = 0;
                    if (ReadULEB128(bytes, cursor, unitEnd, operand))
                    {
                        state.file = static_cast<std::uint32_t>(operand);
                    }
                    break;
                }

                case DW_LNS_set_column:
                {
                    ULONGLONG operand = 0;
                    if (ReadULEB128(bytes, cursor, unitEnd, operand))
                    {
                        state.column = static_cast<std::uint32_t>(operand);
                    }
                    break;
                }

                case DW_LNS_negate_stmt:
                    state.isStmt = !state.isStmt;
                    break;

                case DW_LNS_set_basic_block:
                    state.basicBlock = true;
                    break;

                case DW_LNS_const_add_pc:
                {
                    const auto adjustedOpcode = 255u - opcodeBase;
                    state.address += (adjustedOpcode / lineRange) * minimumInstructionLength;
                    break;
                }

                case DW_LNS_fixed_advance_pc:
                {
                    ULONGLONG operand = 0;
                    if (ReadSizedUnsigned(bytes, cursor, unitEnd, 2, operand))
                    {
                        state.address += operand;
                        state.opIndex = 0;
                    }
                    break;
                }

                case DW_LNS_set_prologue_end:
                    state.prologueEnd = true;
                    break;

                case DW_LNS_set_epilogue_begin:
                    state.epilogueBegin = true;
                    break;

                case DW_LNS_set_isa:
                {
                    ULONGLONG operand = 0;
                    if (ReadULEB128(bytes, cursor, unitEnd, operand))
                    {
                        state.isa = operand;
                    }
                    break;
                }

                default:
                    for (std::uint8_t i = 0; i < standardOpcodeLengths[opcode]; ++i)
                    {
                        ULONGLONG ignored = 0;
                        if (!ReadULEB128(bytes, cursor, unitEnd, ignored))
                        {
                            cursor = unitEnd;
                            break;
                        }
                    }
                    break;
                }
            }
            else
            {
                const auto adjustedOpcode = static_cast<unsigned int>(opcode - opcodeBase);
                state.address += (adjustedOpcode / lineRange) * minimumInstructionLength;
                state.line = static_cast<std::uint32_t>(static_cast<int>(state.line) + lineBase + static_cast<int>(adjustedOpcode % lineRange));
                appendRow();
                state.basicBlock = false;
                state.prologueEnd = false;
                state.epilogueBegin = false;
                state.discriminator = 0;
            }
        }

        offset = unitEnd;
    }

    std::ranges::sort(entries, [](const DebugLineEntry& left, const DebugLineEntry& right)
    {
        return left.address < right.address;
    });
    return entries;
}

[[nodiscard]] ParsedElfData ParseElfData(const std::optional<std::wstring>& elfPath)
{
    if (!elfPath.has_value() || !std::filesystem::exists(std::filesystem::path(*elfPath)))
    {
        return {};
    }

    const auto bytes = ReadAllBytes(*elfPath);
    if (bytes.size() < 64 || bytes[0] != 0x7f || bytes[1] != 'E' || bytes[2] != 'L' || bytes[3] != 'F')
    {
        return {};
    }

    const auto elfClass = bytes[4];
    const auto elfData = bytes[5];
    if ((elfClass != ELFCLASS32 && elfClass != ELFCLASS64) || elfData != ELFDATA2LSB)
    {
        return {};
    }

    ParsedElfData result;
    const std::size_t addressSize = elfClass == ELFCLASS32 ? 4 : 8;
    result.sections = ParseElfSections(bytes, elfClass);
    if (result.sections.empty())
    {
        return {};
    }

    result.programHeaders = ParseProgramHeaders(bytes, elfClass);
    result.debugLines = ParseDebugLines(bytes, result.sections, addressSize);

    for (const auto& symbolSection : result.sections)
    {
        if (symbolSection.type != SHT_SYMTAB && symbolSection.type != SHT_DYNSYM)
        {
            continue;
        }
        if (symbolSection.link >= result.sections.size())
        {
            continue;
        }

        const auto& stringSection = result.sections[symbolSection.link];
        if (symbolSection.offset + symbolSection.size > bytes.size() ||
            stringSection.offset + stringSection.size > bytes.size())
        {
            continue;
        }

        const auto entrySize = symbolSection.entrySize != 0 ? symbolSection.entrySize : (elfClass == ELFCLASS32 ? 16 : 24);
        if (entrySize == 0)
        {
            continue;
        }

        const auto count = symbolSection.size / entrySize;
        for (ULONGLONG index = 0; index < count; ++index)
        {
            const std::size_t base = static_cast<std::size_t>(symbolSection.offset + index * entrySize);
            if (base + entrySize > bytes.size())
            {
                break;
            }

            std::uint32_t nameOffset = 0;
            ULONGLONG value = 0;
            ULONGLONG size = 0;
            std::uint8_t info = 0;
            std::uint16_t sectionIndex = 0;

            if (elfClass == ELFCLASS32)
            {
                nameOffset = ReadU32(bytes, base + 0);
                value = ReadU32(bytes, base + 4);
                size = ReadU32(bytes, base + 8);
                info = bytes[base + 12];
                sectionIndex = ReadU16(bytes, base + 14);
            }
            else
            {
                nameOffset = ReadU32(bytes, base + 0);
                info = bytes[base + 4];
                sectionIndex = ReadU16(bytes, base + 6);
                value = ReadU64(bytes, base + 8);
                size = ReadU64(bytes, base + 16);
            }

            const auto type = static_cast<std::uint8_t>(info & 0x0f);
            const auto bind = static_cast<std::uint8_t>(info >> 4);
            if (!IsInterestingSymbolType(type) || size == 0 || sectionIndex == SHN_UNDEF || sectionIndex >= result.sections.size())
            {
                continue;
            }

            const auto& sectionName = result.sections[sectionIndex].name;
            if (sectionName.empty())
            {
                continue;
            }

            std::wstring name = ReadUtf8Z(bytes, static_cast<std::size_t>(stringSection.offset + nameOffset));
            if (name.empty())
            {
                name = L"[anonymous]";
            }

            result.symbols.push_back({
                .name = std::move(name),
                .address = value,
                .size = size,
                .type = type,
                .bind = bind,
                .sectionIndex = sectionIndex,
                .sectionName = sectionName,
            });
        }
    }

    return result;
}

[[nodiscard]] std::vector<Symbol> ParseElfSymbols(const std::optional<std::wstring>& elfPath)
{
    return ParseElfData(elfPath).symbols;
}

[[nodiscard]] std::wstring SymbolTypeLabel(const std::uint8_t type)
{
    switch (type)
    {
    case STT_FUNC:
        return L"FUNC";
    case STT_OBJECT:
        return L"OBJECT";
    case STT_NOTYPE:
        return L"NOTYPE";
    default:
        return L"SYMBOL";
    }
}

[[nodiscard]] std::wstring SymbolTypeExtension(const std::uint8_t type)
{
    switch (type)
    {
    case STT_FUNC:
        return L".func";
    case STT_OBJECT:
        return L".obj";
    case STT_NOTYPE:
        return L".sym";
    default:
        return L".bin";
    }
}

[[nodiscard]] std::wstring SanitizeLeafStem(std::wstring stem)
{
    for (auto& ch : stem)
    {
        if (ch == L'\\' || ch == L'/' || ch == L'|' || ch == L'\r' || ch == L'\n' || ch == L'\t')
        {
            ch = L'_';
        }
    }
    if (stem.empty())
    {
        return L"[unnamed]";
    }
    return stem;
}

[[nodiscard]] std::wstring MakeLeafName(std::wstring stem, const std::wstring& extension)
{
    stem = SanitizeLeafStem(std::move(stem));
    return stem + extension;
}

[[nodiscard]] std::wstring MakeSymbolLeafName(const Symbol& symbol)
{
    return MakeLeafName(
        std::format(L"{} [{}]", symbol.name, SymbolTypeLabel(symbol.type)),
        SymbolTypeExtension(symbol.type));
}

[[nodiscard]] std::wstring MakeContributionLeafName(const Contribution& contribution)
{
    return MakeLeafName(
        std::format(L"{} @ 0x{:X}", contribution.subsection, contribution.address),
        L".contrib");
}

[[nodiscard]] std::wstring MakeResidualLeafName(const std::wstring& label, const ULONGLONG address)
{
    return MakeLeafName(
        std::format(L"{} [residual] @ 0x{:X}", label, address),
        L".residual");
}

[[nodiscard]] std::wstring MakeSectionResidualLeafName(const std::wstring& label)
{
    return MakeLeafName(std::format(L"{} [residual]", label), L".residual");
}

[[nodiscard]] std::optional<ULONGLONG> VirtualAddressToFileOffset(const ULONGLONG address,
    const std::vector<ProgramHeader>& headers)
{
    for (const auto& header : headers)
    {
        if (header.type != PT_LOAD)
        {
            continue;
        }

        const ULONGLONG end = header.virtualAddress + header.fileSize;
        if (header.virtualAddress <= address && address < end)
        {
            return header.offset + (address - header.virtualAddress);
        }
    }
    return std::nullopt;
}

[[nodiscard]] std::optional<ULONGLONG> VirtualAddressToPhysicalAddress(const ULONGLONG address,
    const std::vector<ProgramHeader>& headers)
{
    for (const auto& header : headers)
    {
        if (header.type != PT_LOAD)
        {
            continue;
        }

        const ULONGLONG end = header.virtualAddress + header.memorySize;
        if (header.virtualAddress <= address && address < end)
        {
            return header.physicalAddress + (address - header.virtualAddress);
        }
    }
    return std::nullopt;
}

[[nodiscard]] SymbolDebugInfo GetSymbolDebugInfo(const Symbol& symbol, const ParsedElfData& elfData)
{
    SymbolDebugInfo info;
    info.fileOffset = VirtualAddressToFileOffset(symbol.address, elfData.programHeaders);
    info.physicalAddress = VirtualAddressToPhysicalAddress(symbol.address, elfData.programHeaders);

    if (!elfData.debugLines.empty())
    {
        const auto it = std::ranges::upper_bound(elfData.debugLines, symbol.address, {}, &DebugLineEntry::address);
        if (it != elfData.debugLines.begin())
        {
            const auto& line = *std::prev(it);
            if (line.address <= symbol.address)
            {
                info.sourceFile = line.file;
                info.sourceLine = line.line;
            }
        }
    }

    return info;
}

void RegisterDetails(CItem* item, MapItemDetails details)
{
    if (item != nullptr)
    {
        g_mapItemDetails[item] = std::move(details);
    }
}

[[nodiscard]] std::wstring FormatSizeLabel(const ULONGLONG bytes)
{
    constexpr double KiB = 1024.0;
    constexpr double MiB = 1024.0 * 1024.0;
    constexpr double GiB = 1024.0 * 1024.0 * 1024.0;

    if (bytes >= static_cast<ULONGLONG>(GiB))
    {
        return std::format(L"{:.2f} GiB", static_cast<double>(bytes) / GiB);
    }
    if (bytes >= static_cast<ULONGLONG>(MiB))
    {
        return std::format(L"{:.2f} MiB", static_cast<double>(bytes) / MiB);
    }
    if (bytes >= static_cast<ULONGLONG>(KiB))
    {
        return std::format(L"{:.2f} KiB", static_cast<double>(bytes) / KiB);
    }
    return std::format(L"{} B", bytes);
}

[[nodiscard]] std::wstring MakeRegionNodeName(const std::wstring& regionName, const ULONGLONG usedBytes,
    const ULONGLONG totalBytes)
{
    if (totalBytes == 0)
    {
        return std::format(L"{} ({})", regionName, FormatSizeLabel(usedBytes));
    }

    const double percent = static_cast<double>(usedBytes) * 100.0 / static_cast<double>(totalBytes);
    return std::format(L"{} ({} / {}, {:.2f}%)",
        regionName,
        FormatSizeLabel(usedBytes),
        FormatSizeLabel(totalBytes),
        percent);
}

[[nodiscard]] std::vector<std::pair<ULONGLONG, ULONGLONG>> MergeIntervals(
    std::vector<std::pair<ULONGLONG, ULONGLONG>> intervals)
{
    if (intervals.empty())
    {
        return intervals;
    }

    std::ranges::sort(intervals);
    std::vector<std::pair<ULONGLONG, ULONGLONG>> merged;
    merged.push_back(intervals.front());
    for (std::size_t index = 1; index < intervals.size(); ++index)
    {
        auto& tail = merged.back();
        if (intervals[index].first > tail.second)
        {
            merged.push_back(intervals[index]);
        }
        else
        {
            tail.second = std::max(tail.second, intervals[index].second);
        }
    }
    return merged;
}

[[nodiscard]] ULONGLONG CoveredBytes(const std::vector<std::pair<ULONGLONG, ULONGLONG>>& intervals)
{
    ULONGLONG total = 0;
    for (const auto& [left, right] : intervals)
    {
        total += right - left;
    }
    return total;
}

[[nodiscard]] CItem* CreateDirectoryChild(CItem* parent, const std::wstring& name)
{
    auto* child = new CItem(IT_DIRECTORY, name);
    child->SetAttributes(FILE_ATTRIBUTE_DIRECTORY);
    child->SetFlag(ITF_RESERVED);
    parent->UpwardAddFolders(1);
    parent->AddChild(child);
    return child;
}

[[nodiscard]] CItem* CreateLeafChild(CItem* parent, const std::wstring& name, const ULONGLONG size, const ULONGLONG address = 0)
{
    auto* child = new CItem(IT_FILE, name);
    child->SetAttributes(FILE_ATTRIBUTE_NORMAL);
    child->SetFlag(ITF_RESERVED);
    child->SetIndex(address);
    child->SetSizePhysical(size);
    child->SetSizeLogical(size);
    child->ExtensionDataAdd();
    parent->UpwardAddFiles(1);
    parent->AddChild(child);
    child->SetDone();
    return child;
}

void FinalizeTree(CItem* item)
{
    if (item == nullptr || item->IsLeaf())
    {
        return;
    }
    for (auto* child : item->GetChildren())
    {
        FinalizeTree(child);
    }
    item->SetDone();
}
}

std::vector<MapRegionInfo> GetMapRegions(const std::wstring& mapPath)
{
    const auto lines = ReadAllLines(mapPath);

    const auto armlinkHeader = std::ranges::find(lines, std::wstring(ARLINK_MAP_HEADER));
    const auto regions = armlinkHeader != lines.end()
        ? ParseArmlinkMemoryRegions(lines)
        : ParseMemoryRegions(lines);

    std::vector<MapRegionInfo> result;
    for (const auto& region : regions)
    {
        result.push_back({
            .name = region.name,
            .origin = region.origin,
            .length = region.length,
            .attrs = region.attrs,
        });
    }
    return result;
}

void ClearMapItemDetails()
{
    g_mapItemDetails.clear();
}

const MapItemDetails* GetMapItemDetails(const CItem* item)
{
    if (const auto it = g_mapItemDetails.find(item); it != g_mapItemDetails.end())
    {
        return &it->second;
    }
    return nullptr;
}

std::wstring GetMapItemSectionName(const CItem* item)
{
    if (item == nullptr)
    {
        return {};
    }

    if (const auto it = g_mapItemSections.find(item); it != g_mapItemSections.end())
    {
        return it->second;
    }

    return {};
}

void RemoveMapItemDetails(const CItem* root)
{
    if (root == nullptr)
    {
        return;
    }

    std::vector<const CItem*> stack{ root };
    while (!stack.empty())
    {
        const auto* current = stack.back();
        stack.pop_back();
        g_mapItemDetails.erase(current);
        g_mapItemSections.erase(current);

        if (current->IsLeaf())
        {
            continue;
        }

        for (const auto* child : current->GetChildren())
        {
            stack.push_back(child);
        }
    }
}

CItem* LoadMapResults(const std::wstring& mapPath,
    const std::optional<std::wstring>& elfPath,
    const std::optional<std::wstring>& selectedRegion,
    const std::function<void(const wchar_t*)>& progressCallback)
{
    auto reportProgress = [&](const wchar_t* msg)
    {
        if (progressCallback) progressCallback(msg);
    };

    reportProgress(L"Loading map file...");
    ClearMapItemDetails();

    const auto parsed = ParseMapFile(mapPath, selectedRegion);
    if (parsed.sections.empty())
    {
        return nullptr;
    }

    const auto& sections = parsed.sections;
    const auto& selectedRegions = parsed.selectedRegions;

    reportProgress(L"Loading ELF data...");
    const auto elfData = ParseElfData(elfPath);
    const auto& symbols = elfData.symbols;
    std::unordered_map<std::wstring, std::vector<Symbol>, string_hash, std::equal_to<>> symbolsBySection;
    for (const auto& symbol : symbols)
    {
        symbolsBySection[symbol.sectionName].push_back(symbol);
    }

    reportProgress(L"Building tree structure...");
    const auto rootName = std::filesystem::path(mapPath).filename().wstring();
    auto* root = new CItem(IT_DIRECTORY | ITF_ROOTITEM, rootName);
    root->SetAttributes(FILE_ATTRIBUTE_DIRECTORY);
    root->SetFlag(ITF_RESERVED);
    RegisterDetails(root, {
        .title = rootName,
        .fields = {
            { L"Source MAP", mapPath },
            { L"Source ELF", elfPath.value_or(L"[none]") },
            { L"Selected region", selectedRegion.value_or(L"[auto]") },
        },
    });

    struct RegionBucket
    {
        const MemoryRegion* region = nullptr;
        std::vector<const OutputSection*> sections;
    };

    std::vector<RegionBucket> regionBuckets;
    regionBuckets.reserve(selectedRegions.empty() ? 1 : selectedRegions.size());
    if (selectedRegions.empty())
    {
        RegionBucket synthetic;
        for (const auto& section : sections)
        {
            synthetic.sections.push_back(&section);
        }
        regionBuckets.push_back(std::move(synthetic));
    }
    else
    {
        std::unordered_map<std::wstring, std::size_t, string_hash, std::equal_to<>> regionIndex;
        for (const auto& region : selectedRegions)
        {
            regionIndex.emplace(region.name, regionBuckets.size());
            regionBuckets.push_back({ .region = &region });
        }

        for (const auto& section : sections)
        {
            if (const auto* region = FindSelectedRegion(section, selectedRegions); region != nullptr)
            {
                regionBuckets[regionIndex.at(region->name)].sections.push_back(&section);
            }
        }
    }

    auto buildSectionNode = [&](CItem* regionNode, const OutputSection& section)
    {
        auto* sectionNode = CreateDirectoryChild(regionNode, section.name);
        g_mapItemSections[sectionNode] = section.name;
        MapItemDetails sectionDetails{ .title = section.name };
        AddDetailField(sectionDetails, L"Section", section.name);
        AddDetailField(sectionDetails, L"Logical address", FormatHexValue(section.address));
        AddDetailField(sectionDetails, L"Load address", section.loadAddress.has_value() ? FormatHexValue(*section.loadAddress) : L"[none]");
        AddDetailField(sectionDetails, L"Size", std::format(L"{} ({})", section.size, FormatSizeLabel(section.size)));
        RegisterDetails(sectionNode, std::move(sectionDetails));

        std::unordered_map<std::wstring, ObjectBucket, string_hash, std::equal_to<>> buckets;
        std::vector<const Contribution*> contributionRecords;
        std::vector<ULONGLONG> contributionStarts;
        ULONGLONG accounted = 0;

        auto sortedContributions = section.contributions;
        std::ranges::sort(sortedContributions, [](const Contribution& left, const Contribution& right)
        {
            if (left.address != right.address) return left.address < right.address;
            if (left.size != right.size) return left.size < right.size;
            return left.object < right.object;
        });

        for (const auto& contribution : sortedContributions)
        {
            accounted += contribution.size;
            const auto bucketKey = contribution.library + L"\n" + contribution.object;
            auto& bucket = buckets[bucketKey];
            bucket.library = contribution.library;
            bucket.object = contribution.object;
            bucket.sourcePath = contribution.sourcePath;
            bucket.value += contribution.size;
            bucket.contributions.push_back(&contribution);
            contributionStarts.push_back(contribution.address);
            contributionRecords.push_back(&contribution);
        }

        auto sectionSymbols = std::move(symbolsBySection[section.name]);
        std::ranges::sort(sectionSymbols, [](const Symbol& left, const Symbol& right)
        {
            if (left.address != right.address) return left.address < right.address;
            if (left.size != right.size) return left.size > right.size;
            return left.name < right.name;
        });

        for (const auto& symbol : sectionSymbols)
        {
            ObjectBucket* targetBucket = nullptr;
            const Contribution* matchedContribution = nullptr;

            matchedContribution = FindBestContributionForSymbol(symbol, contributionRecords, contributionStarts);
            if (matchedContribution != nullptr)
            {
                const auto bucketKey = matchedContribution->library + L"\n" + matchedContribution->object;
                targetBucket = &buckets[bucketKey];
            }

            if (targetBucket == nullptr)
            {
                auto& bucket = buckets[L"[unattributed]\n[symbols]"];
                bucket.library = L"[unattributed]";
                bucket.object = L"[symbols]";
                bucket.sourcePath = L"[unattributed]";
                targetBucket = &bucket;
            }

            const auto dedupeKey = std::format(L"{:X}:{:X}", symbol.address, symbol.size);
            if (!targetBucket->symbolKeys.insert(dedupeKey).second)
            {
                continue;
            }

            targetBucket->symbols.push_back(symbol);
            if (matchedContribution != nullptr)
            {
                targetBucket->coverage[matchedContribution].push_back({
                    symbol.address,
                    std::min(symbol.End(), matchedContribution->End())
                });
            }
        }

        std::unordered_map<std::wstring, std::vector<ObjectBucket*>, string_hash, std::equal_to<>> objectsByLibrary;
        std::unordered_map<std::wstring, ULONGLONG, string_hash, std::equal_to<>> librarySizes;
        for (auto& [key, bucket] : buckets)
        {
            if (bucket.value == 0)
            {
                for (const auto* contribution : bucket.contributions)
                {
                    bucket.value += contribution->size;
                }
                for (const auto& symbol : bucket.symbols)
                {
                    bucket.value += symbol.size;
                }
            }
            objectsByLibrary[bucket.library].push_back(&bucket);
            librarySizes[bucket.library] += bucket.value;
        }

        std::vector<std::pair<std::wstring, ULONGLONG>> libraries;
        libraries.reserve(objectsByLibrary.size());
        for (const auto& [library, size] : librarySizes)
        {
            libraries.emplace_back(library, size);
        }
        std::ranges::sort(libraries, [](const auto& left, const auto& right)
        {
            if (left.second != right.second) return left.second > right.second;
            return left.first < right.first;
        });

        for (const auto& [libraryName, ignoredSize] : libraries)
        {
            (void)ignoredSize;
            auto* libraryNode = CreateDirectoryChild(sectionNode, libraryName);
            g_mapItemSections[libraryNode] = section.name;
            auto objectBuckets = objectsByLibrary[libraryName];
            std::ranges::sort(objectBuckets, [](const ObjectBucket* left, const ObjectBucket* right)
            {
                if (left->value != right->value) return left->value > right->value;
                return left->object < right->object;
            });

            for (const auto* bucket : objectBuckets)
            {
                auto* objectNode = CreateDirectoryChild(libraryNode, bucket->object);
                g_mapItemSections[objectNode] = section.name;
                MapItemDetails objectDetails{ .title = bucket->object };
                AddDetailField(objectDetails, L"Library", bucket->library);
                AddDetailField(objectDetails, L"Object", bucket->object);
                AddDetailField(objectDetails, L"Source", bucket->sourcePath);
                AddDetailField(objectDetails, L"Aggregated size", std::format(L"{} ({})", bucket->value, FormatSizeLabel(bucket->value)));
                RegisterDetails(objectNode, std::move(objectDetails));

                if (!bucket->symbols.empty())
                {
                    auto symbolsForObject = bucket->symbols;
                    std::ranges::sort(symbolsForObject, [](const Symbol& left, const Symbol& right)
                    {
                        if (left.size != right.size) return left.size > right.size;
                        if (left.address != right.address) return left.address < right.address;
                        return left.name < right.name;
                    });
                    for (const auto& symbol : symbolsForObject)
                    {
                        auto* symbolNode = CreateLeafChild(objectNode, MakeSymbolLeafName(symbol), symbol.size, symbol.address);
                        g_mapItemSections[symbolNode] = section.name;
                        const auto debugInfo = GetSymbolDebugInfo(symbol, elfData);
                        MapItemDetails symbolDetails{ .title = symbol.name };
                        AddDetailField(symbolDetails, L"Name", symbol.name);
                        AddDetailField(symbolDetails, L"Kind", SymbolTypeLabel(symbol.type));
                        AddDetailField(symbolDetails, L"Binding", SymbolBindLabel(symbol.bind));
                        AddDetailField(symbolDetails, L"Section", symbol.sectionName);
                        AddDetailField(symbolDetails, L"Logical address", FormatHexValue(symbol.address));
                        AddDetailField(symbolDetails, L"Logical end", FormatHexValue(symbol.End()));
                        AddDetailField(symbolDetails, L"Size", std::format(L"{} ({})", symbol.size, FormatSizeLabel(symbol.size)));
                        AddDetailField(symbolDetails, L"File offset", debugInfo.fileOffset);
                        AddDetailField(symbolDetails, L"Physical address", debugInfo.physicalAddress);
                        AddDetailField(symbolDetails, L"Source file", debugInfo.sourceFile);
                        if (debugInfo.sourceLine.has_value())
                        {
                            AddDetailField(symbolDetails, L"Source line", std::to_wstring(*debugInfo.sourceLine));
                        }
                        RegisterDetails(symbolNode, std::move(symbolDetails));
                    }
                }

                bool addedContributionLeaf = false;
                for (const auto* contribution : bucket->contributions)
                {
                    const auto merged = MergeIntervals(bucket->coverage.contains(contribution) ? bucket->coverage.at(contribution)
                                                                                             : std::vector<std::pair<ULONGLONG, ULONGLONG>>{});
                    const ULONGLONG covered = CoveredBytes(merged);
                    const ULONGLONG remainder = contribution->size > covered ? contribution->size - covered : 0;

                    if (bucket->symbols.empty())
                    {
                        const auto label = MakeContributionLeafName(*contribution);
                        auto* leafNode = CreateLeafChild(objectNode, label, contribution->size, contribution->address);
                        g_mapItemSections[leafNode] = section.name;
                        addedContributionLeaf = true;
                    }
                    else if (remainder > 0)
                    {
                        const auto label = MakeResidualLeafName(contribution->subsection, contribution->address);
                        auto* leafNode = CreateLeafChild(objectNode, label, remainder, contribution->address);
                        g_mapItemSections[leafNode] = section.name;
                    }
                }

                if (!addedContributionLeaf && bucket->symbols.empty() && bucket->contributions.empty() && bucket->value > 0)
                {
                    auto* leafNode = CreateLeafChild(objectNode, L"[object payload].payload", bucket->value);
                    g_mapItemSections[leafNode] = section.name;
                }
            }
        }

        if (accounted < section.size)
        {
            CItem* libraryNode = nullptr;
            const auto existing = std::ranges::find_if(sectionNode->GetChildren(), [](const CItem* item)
            {
                return item->GetNameView() == L"[unattributed]";
            });
            if (existing != sectionNode->GetChildren().end())
            {
                libraryNode = *existing;
            }
            else
            {
                libraryNode = CreateDirectoryChild(sectionNode, L"[unattributed]");
            }

            auto* objectNode = CreateDirectoryChild(libraryNode, L"[section payload]");
            g_mapItemSections[objectNode] = section.name;
            const std::wstring leafName = MakeSectionResidualLeafName(section.name);
            auto* leafNode = CreateLeafChild(objectNode, leafName, section.size - accounted, section.address + accounted);
            g_mapItemSections[leafNode] = section.name;
        }
    };

    for (const auto& regionBucket : regionBuckets)
    {
        ULONGLONG usedBytes = 0;
        for (const auto* section : regionBucket.sections)
        {
            usedBytes += section->size;
        }

        const std::wstring baseRegionName = regionBucket.region != nullptr ? regionBucket.region->name : L"[flash]";
        const ULONGLONG totalBytes = regionBucket.region != nullptr ? regionBucket.region->length : usedBytes;
        auto* regionNode = CreateDirectoryChild(root, MakeRegionNodeName(baseRegionName, usedBytes, totalBytes));
        MapItemDetails regionDetails{ .title = baseRegionName };
        AddDetailField(regionDetails, L"Region", baseRegionName);
        if (regionBucket.region != nullptr)
        {
            AddDetailField(regionDetails, L"Origin", FormatHexValue(regionBucket.region->origin));
            AddDetailField(regionDetails, L"Length", std::format(L"{} ({})", regionBucket.region->length, FormatSizeLabel(regionBucket.region->length)));
            AddDetailField(regionDetails, L"Attributes", regionBucket.region->attrs);
        }
        AddDetailField(regionDetails, L"Used", std::format(L"{} ({})", usedBytes, FormatSizeLabel(usedBytes)));
        RegisterDetails(regionNode, std::move(regionDetails));

        for (const auto* section : regionBucket.sections)
        {
            buildSectionNode(regionNode, *section);
        }

        if (regionBucket.region != nullptr && usedBytes < regionBucket.region->length)
        {
            (void)CreateLeafChild(regionNode, L"[unused flash].unused", regionBucket.region->length - usedBytes);
        }
    }

    reportProgress(L"Finalizing...");
    FinalizeTree(root);
    return root;
}
