
####### Expanded from @PACKAGE_INIT@ by configure_package_config_file() #######
####### Any changes to this file will be overwritten by the next CMake run ####
####### The input file was Config.cmake.in                            ########

get_filename_component(PACKAGE_PREFIX_DIR "${CMAKE_CURRENT_LIST_DIR}/../../../" ABSOLUTE)

####################################################################################

set(ENABLE_BITPOLYMUL     OFF)
set(ENABLE_SIMPLESTOT     OFF)
set(ENABLE_SIMPLESTOT_ASM OFF)
set(ENABLE_MR             OFF)
set(ENABLE_MR_KYBER       OFF)
set(ENABLE_NP             OFF)
set(ENABLE_KOS            OFF)
set(ENABLE_IKNP           OFF)
set(ENABLE_SILENTOT       OFF)
set(ENABLE_DELTA_KOS      OFF)
set(ENABLE_DELTA_IKNP     OFF)
set(ENABLE_OOS            OFF)
set(ENABLE_KKRT           OFF)
set(ENABLE_RR             OFF)
set(ENABLE_AKN            OFF)
set(ENABLE_SILENT_VOLE    )

find_package(cryptoTools REQUIRED HINTS "${CMAKE_CURRENT_LIST_DIR}/.." ${CMAKE_CURRENT_LIST_DIR})

include("${CMAKE_CURRENT_LIST_DIR}/libOTeDepHelper.cmake")


include("${CMAKE_CURRENT_LIST_DIR}/libOTeTargets.cmake")
