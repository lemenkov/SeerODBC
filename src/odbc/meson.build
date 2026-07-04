# SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
#
# SPDX-License-Identifier: Apache-2.0

# The ODBC shim. Compiled only when sql.h was found (see top-level meson.build).
#
# Remaining planned files from docs/ARCHITECTURE.md (convert.c, catalog.c,
# descriptor.c) get added as those functions are implemented.
odbc_sources = files(
  'handles.c',
  'connect.c',
  'attrs.c',
  'exec.c',
  'results.c',
  'catalog.c',
  'diag.c',
  'info.c',
  'unicode.c',
)

# Pure, connection-free logic (SQL preprocessing + the type-conversion matrix),
# in a static library so the offline unit tests can link it directly. Folded
# into the shim below; these symbols stay internal (the version script exports
# only SQL*).
odbc_pure = static_library('seerodbcpure',
  files('sqlprep.c', 'convert.c'),
  include_directories : include_directories('.'),
  dependencies : [common_dep],
)
odbc_pure_dep = declare_dependency(
  link_with : odbc_pure,
  include_directories : include_directories('.'),
  dependencies : [common_dep],
)

odbc_map = meson.current_source_dir() / 'seerodbc.map'

# libodbcinst provides SQLGetPrivateProfileString (DSN lookup in odbc.ini).
odbcinst_dep = cc.find_library('odbcinst', required : true)

# Export only the SQL* symbols (version script). This keeps the protocol
# core and OpenSSL symbols out of the host process's dynamic symbol table -
# the same "don't pollute the host process" reasoning that ruled out GLib.
seerodbc_lib = shared_library('seerodbc',
  odbc_sources,
  include_directories : include_directories('.'),
  dependencies : [seertns_dep, common_dep, odbcinst_dep, odbc_pure_dep],
  # -Bsymbolic: a *W wrapper that calls an ANSI SQL* function must reach OUR
  # definition, not the Driver Manager's identically-named global symbol (which
  # would get our internal handle and reject it). Bind intra-library references
  # to our own definitions. The version script still controls what is exported.
  link_args : ['-Wl,--version-script=' + odbc_map, '-Wl,-Bsymbolic'],
  link_depends : odbc_map,
  install : true,
)
