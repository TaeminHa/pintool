/* BEGIN_LEGAL 

Copyright (c) 2023 Intel Corporation

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
  
END_LEGAL */
/// @file xed-chip-enum.h

// This file was automatically generated.
// Do not edit this file.

#if !defined(XED_CHIP_ENUM_H)
# define XED_CHIP_ENUM_H
#include "xed-common-hdrs.h"
#define XED_CHIP_INVALID_DEFINED 1
#define XED_CHIP_I86_DEFINED 1
#define XED_CHIP_I86FP_DEFINED 1
#define XED_CHIP_I186_DEFINED 1
#define XED_CHIP_I186FP_DEFINED 1
#define XED_CHIP_I286REAL_DEFINED 1
#define XED_CHIP_I286_DEFINED 1
#define XED_CHIP_I2186FP_DEFINED 1
#define XED_CHIP_I386REAL_DEFINED 1
#define XED_CHIP_I386_DEFINED 1
#define XED_CHIP_I386FP_DEFINED 1
#define XED_CHIP_I486REAL_DEFINED 1
#define XED_CHIP_I486_DEFINED 1
#define XED_CHIP_PENTIUMREAL_DEFINED 1
#define XED_CHIP_PENTIUM_DEFINED 1
#define XED_CHIP_QUARK_DEFINED 1
#define XED_CHIP_PENTIUMMMXREAL_DEFINED 1
#define XED_CHIP_PENTIUMMMX_DEFINED 1
#define XED_CHIP_ALLREAL_DEFINED 1
#define XED_CHIP_PENTIUMPRO_DEFINED 1
#define XED_CHIP_PENTIUM2_DEFINED 1
#define XED_CHIP_PENTIUM3_DEFINED 1
#define XED_CHIP_PENTIUM4_DEFINED 1
#define XED_CHIP_P4PRESCOTT_DEFINED 1
#define XED_CHIP_P4PRESCOTT_NOLAHF_DEFINED 1
#define XED_CHIP_P4PRESCOTT_VTX_DEFINED 1
#define XED_CHIP_MEROM_DEFINED 1
#define XED_CHIP_PENRYN_DEFINED 1
#define XED_CHIP_PENRYN_E_DEFINED 1
#define XED_CHIP_NEHALEM_DEFINED 1
#define XED_CHIP_WESTMERE_DEFINED 1
#define XED_CHIP_BONNELL_DEFINED 1
#define XED_CHIP_SALTWELL_DEFINED 1
#define XED_CHIP_SILVERMONT_DEFINED 1
#define XED_CHIP_VIA_DEFINED 1
#define XED_CHIP_AMD_K10_DEFINED 1
#define XED_CHIP_AMD_BULLDOZER_DEFINED 1
#define XED_CHIP_AMD_PILEDRIVER_DEFINED 1
#define XED_CHIP_AMD_ZEN_DEFINED 1
#define XED_CHIP_AMD_ZENPLUS_DEFINED 1
#define XED_CHIP_AMD_ZEN2_DEFINED 1
#define XED_CHIP_AMD_FUTURE_DEFINED 1
#define XED_CHIP_GOLDMONT_DEFINED 1
#define XED_CHIP_GOLDMONT_PLUS_DEFINED 1
#define XED_CHIP_TREMONT_DEFINED 1
#define XED_CHIP_SNOW_RIDGE_DEFINED 1
#define XED_CHIP_LAKEFIELD_DEFINED 1
#define XED_CHIP_SANDYBRIDGE_DEFINED 1
#define XED_CHIP_IVYBRIDGE_DEFINED 1
#define XED_CHIP_HASWELL_DEFINED 1
#define XED_CHIP_BROADWELL_DEFINED 1
#define XED_CHIP_SKYLAKE_DEFINED 1
#define XED_CHIP_COMET_LAKE_DEFINED 1
#define XED_CHIP_SKYLAKE_SERVER_DEFINED 1
#define XED_CHIP_CASCADE_LAKE_DEFINED 1
#define XED_CHIP_COOPER_LAKE_DEFINED 1
#define XED_CHIP_KNL_DEFINED 1
#define XED_CHIP_KNM_DEFINED 1
#define XED_CHIP_CANNONLAKE_DEFINED 1
#define XED_CHIP_ICE_LAKE_DEFINED 1
#define XED_CHIP_ICE_LAKE_SERVER_DEFINED 1
#define XED_CHIP_TIGER_LAKE_DEFINED 1
#define XED_CHIP_ALDER_LAKE_DEFINED 1
#define XED_CHIP_SAPPHIRE_RAPIDS_DEFINED 1
#define XED_CHIP_GRANITE_RAPIDS_DEFINED 1
#define XED_CHIP_SIERRA_FOREST_DEFINED 1
#define XED_CHIP_GRAND_RIDGE_DEFINED 1
#define XED_CHIP_ARROW_LAKE_DEFINED 1
#define XED_CHIP_LUNAR_LAKE_DEFINED 1
#define XED_CHIP_FUTURE_DEFINED 1
#define XED_CHIP_ALL_DEFINED 1
#define XED_CHIP_LAST_DEFINED 1
typedef enum {
  XED_CHIP_INVALID,
  XED_CHIP_I86,
  XED_CHIP_I86FP,
  XED_CHIP_I186,
  XED_CHIP_I186FP,
  XED_CHIP_I286REAL,
  XED_CHIP_I286,
  XED_CHIP_I2186FP,
  XED_CHIP_I386REAL,
  XED_CHIP_I386,
  XED_CHIP_I386FP,
  XED_CHIP_I486REAL,
  XED_CHIP_I486,
  XED_CHIP_PENTIUMREAL,
  XED_CHIP_PENTIUM,
  XED_CHIP_QUARK,
  XED_CHIP_PENTIUMMMXREAL,
  XED_CHIP_PENTIUMMMX,
  XED_CHIP_ALLREAL,
  XED_CHIP_PENTIUMPRO,
  XED_CHIP_PENTIUM2,
  XED_CHIP_PENTIUM3,
  XED_CHIP_PENTIUM4,
  XED_CHIP_P4PRESCOTT,
  XED_CHIP_P4PRESCOTT_NOLAHF,
  XED_CHIP_P4PRESCOTT_VTX,
  XED_CHIP_MEROM,
  XED_CHIP_PENRYN,
  XED_CHIP_PENRYN_E,
  XED_CHIP_NEHALEM,
  XED_CHIP_WESTMERE,
  XED_CHIP_BONNELL,
  XED_CHIP_SALTWELL,
  XED_CHIP_SILVERMONT,
  XED_CHIP_VIA,
  XED_CHIP_AMD_K10,
  XED_CHIP_AMD_BULLDOZER,
  XED_CHIP_AMD_PILEDRIVER,
  XED_CHIP_AMD_ZEN,
  XED_CHIP_AMD_ZENPLUS,
  XED_CHIP_AMD_ZEN2,
  XED_CHIP_AMD_FUTURE,
  XED_CHIP_GOLDMONT,
  XED_CHIP_GOLDMONT_PLUS,
  XED_CHIP_TREMONT,
  XED_CHIP_SNOW_RIDGE,
  XED_CHIP_LAKEFIELD,
  XED_CHIP_SANDYBRIDGE,
  XED_CHIP_IVYBRIDGE,
  XED_CHIP_HASWELL,
  XED_CHIP_BROADWELL,
  XED_CHIP_SKYLAKE,
  XED_CHIP_COMET_LAKE,
  XED_CHIP_SKYLAKE_SERVER,
  XED_CHIP_CASCADE_LAKE,
  XED_CHIP_COOPER_LAKE,
  XED_CHIP_KNL,
  XED_CHIP_KNM,
  XED_CHIP_CANNONLAKE,
  XED_CHIP_ICE_LAKE,
  XED_CHIP_ICE_LAKE_SERVER,
  XED_CHIP_TIGER_LAKE,
  XED_CHIP_ALDER_LAKE,
  XED_CHIP_SAPPHIRE_RAPIDS,
  XED_CHIP_GRANITE_RAPIDS,
  XED_CHIP_SIERRA_FOREST,
  XED_CHIP_GRAND_RIDGE,
  XED_CHIP_ARROW_LAKE,
  XED_CHIP_LUNAR_LAKE,
  XED_CHIP_FUTURE,
  XED_CHIP_ALL,
  XED_CHIP_LAST
} xed_chip_enum_t;

/// This converts strings to #xed_chip_enum_t types.
/// @param s A C-string.
/// @return #xed_chip_enum_t
/// @ingroup ENUM
XED_DLL_EXPORT xed_chip_enum_t str2xed_chip_enum_t(const char* s);
/// This converts strings to #xed_chip_enum_t types.
/// @param p An enumeration element of type xed_chip_enum_t.
/// @return string
/// @ingroup ENUM
XED_DLL_EXPORT const char* xed_chip_enum_t2str(const xed_chip_enum_t p);

/// Returns the last element of the enumeration
/// @return xed_chip_enum_t The last element of the enumeration.
/// @ingroup ENUM
XED_DLL_EXPORT xed_chip_enum_t xed_chip_enum_t_last(void);
#endif
