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

#pragma once

#include "pch.h"

struct MapRegionInfo
{
    std::wstring name;
    ULONGLONG origin = 0;
    ULONGLONG length = 0;
    std::wstring attrs;
};

struct MapItemDetailField
{
    std::wstring label;
    std::wstring value;
};

struct MapItemDetails
{
    std::wstring title;
    std::vector<MapItemDetailField> fields;
};

std::vector<MapRegionInfo> GetMapRegions(const std::wstring& mapPath);
CItem* LoadMapResults(const std::wstring& mapPath,
    const std::optional<std::wstring>& elfPath = std::nullopt,
    const std::optional<std::wstring>& selectedRegion = std::nullopt,
    const std::function<void(const wchar_t*)>& progressCallback = {});
void ClearMapItemDetails();
const MapItemDetails* GetMapItemDetails(const CItem* item);
void RemoveMapItemDetails(const CItem* root);
std::wstring GetMapItemSectionName(const CItem* item);
