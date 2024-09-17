# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

file(READ ${JSON_SOURCE_PATH} hex_content HEX)
string(REGEX MATCHALL "([A-Za-z0-9][A-Za-z0-9])" bytes "${hex_content}")

file(WRITE ${HEADER_PATH} "#include <string_view>\n")
file(APPEND ${HEADER_PATH} "namespace json_tests{\n")
get_filename_component(json_source_basename ${JSON_SOURCE_PATH} NAME_WE)
file(APPEND ${HEADER_PATH} "inline constexpr char detail_${json_source_basename}_bytes[]{\n")

set(i 0)
foreach(byte ${bytes})
  math(EXPR i "${i} + 1")
  math(EXPR remainder "${i} % 8")
  if(remainder EQUAL 0)
    file(APPEND ${HEADER_PATH} "0x${byte},\n")
  else()
    file(APPEND ${HEADER_PATH} "0x${byte}, ")
  endif()
endforeach()

file(APPEND ${HEADER_PATH} "\n};\n")
file(APPEND ${HEADER_PATH} "inline constexpr std::string_view ${json_source_basename}{std::begin(detail_${json_source_basename}_bytes), std::end(detail_${json_source_basename}_bytes)};")
file(APPEND ${HEADER_PATH} "\n}")
