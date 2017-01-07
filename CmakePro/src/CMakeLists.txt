
#SET(Protobuf_INCLUDE_DIR ${PROJECT_SOURCE_DIR}/Protobuf)
# 添加头文件的查找目录
INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/include)
## 生成各种目标(target)文件: 可执行文件、动态库、静态库
# 指定可执行文件的输出目录，输出到bin下面
SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)
SET(LIBRARY_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/lib)
#指定protobuf
include_directories(${PROJECT_SOURCE_DIR}/protobuf)
link_directories(${PROJECT_SOURCE_DIR}/Protobuf/Lib)

#sqlite3
include_directories(${PROJECT_SOURCE_DIR}/Sqlite/source)
link_directories(${PROJECT_SOURCE_DIR}/Sqlite/Lib)



MESSAGE(STSTUS "###################################")

MESSAGE(STATUS "operation system is ${CMAKE_SYSTEM}")

IF (CMAKE_SYSTEM_NAME MATCHES "Linux")
	MESSAGE(STATUS "current platform: Linux ")
ELSEIF (CMAKE_SYSTEM_NAME MATCHES "Windows")
	MESSAGE(STATUS "current platform: Windows")
	ADD_EXECUTABLE(
	PasswordLibrary 
	Main.cpp 
	DataInfoProto.pb.cc 
	${PROJECT_SOURCE_DIR}/src/Windows/Chrome.cpp 	
	${PROJECT_SOURCE_DIR}/src/Windows/InternetExplorer.cpp 
	${PROJECT_SOURCE_DIR}/src/Windows/WifiPassword.cpp 
	)
	target_link_libraries(
    PasswordLibrary
	libprotobuf.lib
	Sqlite3.lib
	)
ELSEIF (CMAKE_SYSTEM_NAME MATCHES "FreeBSD")
	MESSAGE(STATUS "current platform: FreeBSD")
ELSE ()
	MESSAGE(STATUS "other platform: ${CMAKE_SYSTEM_NAME}")
ENDIF (CMAKE_SYSTEM_NAME MATCHES "Linux")

MESSAGE(STSTUS "###################################")

#ADD_LIBRARY(Chrome_so SHARED Chrome.cpp)
#ADD_LIBRARY(Chrome_a STATIC Chrome.cpp)

# 设置输库出名为 PasswordLibrary => libPasswordLibrary.a
#SET_TARGET_PROPERTIES(PasswordLibrary_a PROPERTIES OUTPUT_NAME "PasswordLibrary")
