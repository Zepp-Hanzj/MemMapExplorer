#include "pch.h"
#include "ItemAddress.h"
#include "FileAddressControl.h"

CItemAddress::CItemAddress(CItem* item, const ULONGLONG address, const ULONGLONG size, const ULONGLONG gap, std::wstring section)
    : m_item(item), m_address(address), m_size(size), m_gap(gap), m_section(std::move(section))
{
}

CItemAddress::~CItemAddress()
{
    for (const auto* child : m_children)
    {
        delete child;
    }
}

void CItemAddress::AddAddressChild(CItemAddress* child)
{
    child->SetParent(this);
    std::scoped_lock guard(m_protect);
    m_children.push_back(child);

    if (IsVisible() && IsExpanded())
    {
        CFileAddressControl::Get()->OnChildAdded(this, child);
    }
}

bool CItemAddress::DrawSubItem(const int subitem, CDC* pdc, const CRect rc, const UINT state, int* width, int* focusLeft)
{
    if (subitem != COL_ITEMADDR_NAME) return false;
    return CTreeListItem::DrawSubItem(COL_NAME, pdc, rc, state, width, focusLeft);
}

std::wstring CItemAddress::GetText(const int subitem) const
{
    if (GetParent() == nullptr) return subitem == COL_ITEMADDR_NAME ? Localization::Lookup(IDS_HEX_ADDRESS_VIEW) : std::wstring{};
    if (m_item == nullptr) return {};

    switch (subitem)
    {
    case COL_ITEMADDR_NAME: return m_item->GetPath();
    case COL_ITEMADDR_ADDRESS: return std::format(L"0x{:08X}", m_address);
    case COL_ITEMADDR_SIZE: return FormatBytes(m_size);
    case COL_ITEMADDR_SECTION: return m_section;
    case COL_ITEMADDR_GAP: return m_gap > 0 ? std::format(L"+0x{:X} ({})", m_gap, FormatBytes(m_gap)) : L"";
    default: return {};
    }
}

int CItemAddress::CompareSibling(const CTreeListItem* tlib, const int subitem) const
{
    if (GetParent() == nullptr) return 0;
    if (m_item == nullptr) return 0;

    const auto* other = static_cast<const CItemAddress*>(tlib);

    switch (subitem)
    {
    case COL_ITEMADDR_NAME: return _wcsicmp(m_item->GetPath().c_str(), other->m_item->GetPath().c_str());
    case COL_ITEMADDR_ADDRESS: return m_address < other->m_address ? -1 : m_address > other->m_address ? 1 : 0;
    case COL_ITEMADDR_SIZE: return m_size < other->m_size ? -1 : m_size > other->m_size ? 1 : 0;
    case COL_ITEMADDR_SECTION: return _wcsicmp(m_section.c_str(), other->m_section.c_str());
    case COL_ITEMADDR_GAP: return m_gap < other->m_gap ? -1 : m_gap > other->m_gap ? 1 : 0;
    default: return 0;
    }
}

HICON CItemAddress::GetIcon()
{
    if (m_item == nullptr) return nullptr;
    return CTreeListItem::GetIcon();
}
