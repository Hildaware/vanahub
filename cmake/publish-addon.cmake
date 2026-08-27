if(NOT DEFINED SOURCE_DIR OR NOT IS_DIRECTORY "${SOURCE_DIR}")
    message(FATAL_ERROR "SOURCE_DIR must name the addon source directory")
endif()
if(NOT DEFINED DEST_DIR OR DEST_DIR STREQUAL "")
    message(FATAL_ERROR "DEST_DIR must name the addon output directory")
endif()

file(MAKE_DIRECTORY "${DEST_DIR}")
file(GLOB output_entries RELATIVE "${DEST_DIR}" "${DEST_DIR}/*" "${DEST_DIR}/.*")
foreach(entry IN LISTS output_entries)
    if(NOT entry STREQUAL "." AND
       NOT entry STREQUAL ".." AND
       NOT entry STREQUAL ".stfolder" AND
       NOT entry STREQUAL ".stignore")
        file(REMOVE_RECURSE "${DEST_DIR}/${entry}")
    endif()
endforeach()

file(COPY "${SOURCE_DIR}/" DESTINATION "${DEST_DIR}")
