# SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
#
# SPDX-License-Identifier: Apache-2.0

tns_sources = files(
  'ano.c',
  'auth.c',
  'json.c',
  'lob.c',
  'marshal.c',
  'msg.c',
  'oson.c',
  'packet.c',
  'pipeline.c',
  'placeholders.c',
  'reader.c',
  'schema.c',
  'session.c',
  'stmt.c',
  'transport.c',
  'ttc.c',
  'types.c',
  'writer.c',
)

tns_inc = include_directories('.')

# pthreads: pthread_once (once.h) and the SIGPIPE mask around TLS writes
# (transport.c). Windows needs neither - once.h uses kernel32's one-time init,
# and there is no SIGPIPE - so the DLL ships without a pthreads runtime.
threads_dep = host_machine.system() == 'windows' ? [] : dependency('threads')

# The replay corpus's recorder (#396): test builds only. It makes the client's
# random values a fixed stream when SEER_WIRE_RECORD is set, so a shipped
# driver must never have it; without the option wire.h's hooks are the plain
# calls they stand for and wire.c isn't built.
tns_c_args = []
if get_option('wire_corpus')
  if host_machine.system() == 'windows'
    error('wire_corpus is for recording on Linux / macOS test builds')
  endif
  warning('wire_corpus is on: this build is for recording the replay corpus, not for use')
  tns_sources += files('wire.c')
  tns_c_args += '-DSEER_WIRE_CORPUS=1'
endif

libseertns = static_library('seertns',
  tns_sources,
  include_directories : [tns_inc, core_inc],
  dependencies : [openssl_dep, common_dep, threads_dep],
  c_args : tns_c_args,
)

# Public dependency: the include dir carries the public API (include/seer/),
# the internal tns_inc carries reader.h etc. for in-tree consumers (tests).
seertns_dep = declare_dependency(
  link_with : libseertns,
  include_directories : [tns_inc, core_inc],
  dependencies : [openssl_dep, common_dep, threads_dep],
)
