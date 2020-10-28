cmake_minimum_required(VERSION 3.13)

set(PACKAGE_VERSION   1.0.0)

####################
# options
####################
include(cmake/CfdCommonOption.cmake)
include(cmake/ConvertSrclistFunction.cmake)
include(cmake/CfdWallyOption.cmake)
include(cmake/CfdCommonSetting.cmake)

# cfd option
option(CFD_SHARED "force shared build (ON or OFF. default:OFF)" OFF)
option(ENABLE_CAPI  "enable c-api (ON or OFF. default:ON)" ON)
option(ENABLE_JSONAPI  "enable json-api (ON or OFF. default:ON)" ON)


####################
# subdirectories
####################
project(cfd_all_test CXX)
if(NOT CFD_SINGLE_BUILD)
add_subdirectory(external)
endif()
