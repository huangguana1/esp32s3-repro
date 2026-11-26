# webserver.c is built as part of the main component (see main/CMakeLists.txt)
# to avoid an IDF 5.x circular dependency. This empty component keeps the
# original directory layout intact.
idf_component_register()
