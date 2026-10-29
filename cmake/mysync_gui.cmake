# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 META.vn
# Author: Nguyễn Đức Sơn
#
# Dựng `mysync-gui` (wxWidgets 3.2.x, liên kết tĩnh). Được include từ CMakeLists.txt khi MYSYNC_BUILD_GUI=ON.
# Thứ tự: (1) find_package(wxWidgets) nếu hệ thống đã có bản 3.2+ (ưu tiên: Linux có libwxgtk3.2-dev, MSYS2 có
# mingw-w64-*-wxwidgets3.2); (2) dự phòng FetchContent tarball chính thức v3.2.9 có ghim SHA-256.
# Ép dùng bản tải về: -DMYSYNC_WX_FETCH=ON.  Cấm tải: -DMYSYNC_WX_FETCH=OFF (khi đó phải có sẵn wx).
set(MYSYNC_WX_VERSION "3.2.9")
set(MYSYNC_WX_URL "https://github.com/wxWidgets/wxWidgets/releases/download/v${MYSYNC_WX_VERSION}/wxWidgets-${MYSYNC_WX_VERSION}.tar.bz2")
set(MYSYNC_WX_SHA256 "fb90f9538bffd6a02edbf80037a0c14c2baf9f509feac8f76ab2a5e4321f112b")
set(MYSYNC_WX_FETCH "AUTO" CACHE STRING "AUTO|ON|OFF: tải wxWidgets khi không tìm thấy bản hệ thống")
set_property(CACHE MYSYNC_WX_FETCH PROPERTY STRINGS AUTO ON OFF)

set(_wx_found FALSE)
if(NOT MYSYNC_WX_FETCH STREQUAL "ON")
  find_package(wxWidgets 3.2 COMPONENTS adv core base QUIET)
  if(wxWidgets_FOUND)
    set(_wx_found TRUE)
    message(STATUS "mysync-gui: dùng wxWidgets hệ thống (${wxWidgets_VERSION_STRING})")
  endif()
endif()

if(_wx_found)
  include(${wxWidgets_USE_FILE})
  set(MYSYNC_WX_LIBS ${wxWidgets_LIBRARIES})
else()
  if(MYSYNC_WX_FETCH STREQUAL "OFF")
    message(FATAL_ERROR "mysync-gui: không tìm thấy wxWidgets 3.2 và MYSYNC_WX_FETCH=OFF")
  endif()
  message(STATUS "mysync-gui: không có wxWidgets hệ thống, tải v${MYSYNC_WX_VERSION} (SHA-256 ghim)")
  include(FetchContent)
  # wx dùng biến <LIB>_SRC (CORE_SRC, BASE_SRC...) và con cháu thừa kế biến của cha: xoá biến cùng tên của MySync,
  # nếu không wxcore sẽ biên dịch cả src/*.cpp của MySync.
  unset(CORE_SRC)
  unset(TEST_SRC)
  # Chỉ giữ core+base (+adv cho wxTaskBarIcon). Tắt mọi thứ còn lại để rút ngắn thời gian dựng.
  set(wxBUILD_SHARED OFF CACHE BOOL "" FORCE)
  set(wxBUILD_SAMPLES OFF CACHE STRING "" FORCE)
  set(wxBUILD_TESTS OFF CACHE STRING "" FORCE)
  set(wxBUILD_DEMOS OFF CACHE BOOL "" FORCE)
  set(wxBUILD_BENCHMARKS OFF CACHE BOOL "" FORCE)
  set(wxBUILD_INSTALL OFF CACHE BOOL "" FORCE)
  set(wxBUILD_PRECOMP ON CACHE STRING "" FORCE)
  set(wxUSE_DPI_AWARE_MANIFEST "none" CACHE STRING "" FORCE) # manifest riêng của mysync-gui
  foreach(_o HTML RICHTEXT AUI PROPGRID RIBBON STC XRC WEBVIEW MEDIACTRL OPENGL XML WEBREQUEST DEBUGREPORT SOUND WXHTML_HELP HELP)
    set(wxUSE_${_o} OFF CACHE BOOL "" FORCE)
  endforeach()
  if(CMAKE_VERSION VERSION_GREATER_EQUAL 3.24)
    FetchContent_Declare(wxWidgets URL ${MYSYNC_WX_URL} URL_HASH SHA256=${MYSYNC_WX_SHA256}
                         DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
  else()
    FetchContent_Declare(wxWidgets URL ${MYSYNC_WX_URL} URL_HASH SHA256=${MYSYNC_WX_SHA256})
  endif()
  FetchContent_MakeAvailable(wxWidgets)
  set(MYSYNC_WX_LIBS wx::adv wx::core wx::base)
endif()

file(GLOB GUI_APP_SRC CONFIGURE_DEPENDS gui/*.cpp)
list(FILTER GUI_APP_SRC EXCLUDE REGEX "_model\.cpp$")
set(GUI_EXTRA)
if(WIN32)
  list(APPEND GUI_EXTRA gui/mysync-gui.rc)
endif()
add_executable(mysync-gui WIN32 ${GUI_APP_SRC} ${GUI_EXTRA})
target_link_libraries(mysync-gui PRIVATE mysync_gui_model mysync_core ${MYSYNC_WX_LIBS})
target_include_directories(mysync-gui PRIVATE gui)
if(MINGW)
  target_link_options(mysync-gui PRIVATE -static -mwindows)
endif()
if(UNIX AND NOT APPLE)
  target_link_options(mysync-gui PRIVATE -static-libstdc++ -static-libgcc)
endif()

if(UNIX AND NOT APPLE)
  # ui_common.cpp đọc gtk-enable-animations (giảm chuyển động) nên cần đường include GTK3 trực tiếp.
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(GTK3 REQUIRED IMPORTED_TARGET gtk+-3.0)
  target_link_libraries(mysync-gui PRIVATE PkgConfig::GTK3)
endif()
