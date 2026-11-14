/* test_core: Advanced Queuing (AQ) through the core API.
 *
 * Sets up queues with DBMS_AQADM and round-trips messages through them: RAW
 * enqueue and dequeue, correlation and browse, array (bulk) enqueue and
 * dequeue, multi-consumer, object and JSON payloads. Where DBMS_AQADM isn't
 * available to the test account, the checks are skipped with that reason.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core.h"

static void exec_sql(SeerConn *c, const char *sql)
{
  SeerStmt *s = NULL;
  if (seer_stmt_prepare(c, sql, &s) != SEER_OK)
    return;
  seer_stmt_execute(s);
  seer_stmt_close(s);
}

/* Row count of the queue table, or -1 if it doesn't exist (setup unavailable). */
static long qt_count(SeerConn *c)
{
  SeerStmt *s = NULL;
  long n = -1;
  if (seer_stmt_prepare(c, "SELECT COUNT(*) FROM SEER_QT", &s) == SEER_OK &&
      seer_stmt_execute(s) == SEER_OK && seer_stmt_fetch(s) == SEER_OK) {
    const char *v = NULL;
    int isnull = 0;
    seer_stmt_get_string(s, 0, &v, &isnull);
    n = v ? atol(v) : -1;
  }
  seer_stmt_close(s);
  return n;
}

/* The checks, in the order they run. */
static const char *const AQ_CHECKS[] = {
    "AQ RAW enqueue",      "AQ RAW dequeue",    "AQ options (correlation + browse)",
    "AQ array round-trip", "AQ multi-consumer", "AQ object payload",
    "AQ JSON payload",
};

void core_aq(void)
{
  int gated = 0;
  for (size_t i = 0; i < sizeof AQ_CHECKS / sizeof AQ_CHECKS[0]; i++)
    gated |= gated_as("AQ", AQ_CHECKS[i]);
  if (gated)
    return;
  SeerConn *c = core_connect();
  if (c == NULL) {
    fail("AQ RAW enqueue", "connect failed");
    return;
  }

  const char *name = "AQ RAW enqueue";

  /* tear down any leftover, then set up a RAW queue */
  exec_sql(c, "BEGIN DBMS_AQADM.STOP_QUEUE('SEER_Q'); EXCEPTION WHEN OTHERS THEN NULL; END;");
  exec_sql(c, "BEGIN DBMS_AQADM.DROP_QUEUE('SEER_Q'); EXCEPTION WHEN OTHERS THEN NULL; END;");
  exec_sql(c,
           "BEGIN DBMS_AQADM.DROP_QUEUE_TABLE('SEER_QT'); EXCEPTION WHEN OTHERS THEN NULL; END;");
  exec_sql(c, "BEGIN DBMS_AQADM.CREATE_QUEUE_TABLE(queue_table=>'SEER_QT', "
              "queue_payload_type=>'RAW'); END;");
  exec_sql(c, "BEGIN DBMS_AQADM.CREATE_QUEUE(queue_name=>'SEER_Q', queue_table=>'SEER_QT'); END;");
  exec_sql(c, "BEGIN DBMS_AQADM.START_QUEUE('SEER_Q'); END;");
  seer_commit(c);

  if (qt_count(c) < 0) {
    for (size_t i = 0; i < sizeof AQ_CHECKS / sizeof AQ_CHECKS[0]; i++)
      skip(AQ_CHECKS[i], "DBMS_AQADM isn't available to the test account");
    goto done;
  }

  const char *msg = "hello-aq";
  uint8_t msgid[16] = {0};
  SeerStatus st = seer_aq_enq_raw(c, "SEER_Q", (const uint8_t *)msg, strlen(msg), msgid);
  seer_commit(c);

  int nz = 0;
  for (int i = 0; i < 16; i++)
    nz |= msgid[i];
  if (st == SEER_OK && nz && qt_count(c) == 1)
    pass(name);
  else
    fail(name, st != SEER_OK ? (seer_last_error(c) ? seer_last_error(c) : "enqueue")
                             : "message not in queue / zero msgid");

  /* dequeue: the payload round-trips, the queue drains, and a second dequeue
   * reports no message (SEER_ENODATA). */
  const char *dname = "AQ RAW dequeue";
  uint8_t *pay = NULL;
  size_t paylen = 0;
  SeerStatus dst = seer_aq_deq_raw(c, "SEER_Q", 0, &pay, &paylen, NULL);
  seer_commit(c);
  int payload_ok =
      (dst == SEER_OK && paylen == strlen(msg) && pay != NULL && memcmp(pay, msg, paylen) == 0);
  free(pay);
  uint8_t *p2 = NULL;
  size_t pl2 = 0;
  SeerStatus dst2 = seer_aq_deq_raw(c, "SEER_Q", 0, &p2, &pl2, NULL);
  free(p2);
  if (payload_ok && qt_count(c) == 0 && dst2 == SEER_ENODATA)
    pass(dname);
  else
    fail(dname, dst != SEER_OK ? (seer_last_error(c) ? seer_last_error(c) : "dequeue")
                               : "payload mismatch / not drained / empty not ENODATA");

  /* options: enqueue two correlated messages; dequeue "beta" out of order via
   * the correlation filter; BROWSE "alpha" (peek) then REMOVE it (proving the
   * browse left it in place). */
  const char *oname = "AQ options (correlation + browse)";
  SeerAqEnqOptions ea = {.correlation = "alpha"};
  seer_aq_enq_raw_opt(c, "SEER_Q", (const uint8_t *)"A", 1, &ea, NULL);
  ea.correlation = "beta";
  seer_aq_enq_raw_opt(c, "SEER_Q", (const uint8_t *)"B", 1, &ea, NULL);
  seer_commit(c);

  uint8_t *bp = NULL;
  size_t bl = 0;
  SeerAqDeqOptions byb = {.correlation = "beta"};
  SeerStatus r1 = seer_aq_deq_raw_opt(c, "SEER_Q", &byb, &bp, &bl, NULL);
  int filt_ok = (r1 == SEER_OK && bl == 1 && bp && bp[0] == 'B');
  free(bp);
  bp = NULL;
  bl = 0;
  seer_commit(c);

  SeerAqDeqOptions bra = {.browse = 1, .correlation = "alpha"};
  SeerStatus r2 = seer_aq_deq_raw_opt(c, "SEER_Q", &bra, &bp, &bl, NULL);
  int brow_ok = (r2 == SEER_OK && bl == 1 && bp && bp[0] == 'A');
  free(bp);
  bp = NULL;
  bl = 0;
  seer_commit(c);

  SeerAqDeqOptions rma = {.correlation = "alpha"};
  SeerStatus r3 = seer_aq_deq_raw_opt(c, "SEER_Q", &rma, &bp, &bl, NULL);
  int rem_ok = (r3 == SEER_OK && bl == 1 && bp && bp[0] == 'A'); /* browse left it */
  free(bp);
  seer_commit(c);

  if (filt_ok && brow_ok && rem_ok)
    pass(oname);
  else
    fail(oname, "correlation filter / browse / remove-after-browse failed");

  /* array (bulk) round-trip: enqueue three RAW messages in one call, then
   * dequeue them all back in one call. */
  const char *aname = "AQ array round-trip";
  const char *am[3] = {"bulk-1", "bulk-2", "bulk-3"};
  const uint8_t *apl[3] = {(const uint8_t *)am[0], (const uint8_t *)am[1], (const uint8_t *)am[2]};
  size_t aln[3] = {6, 6, 6};
  uint8_t amids[48] = {0};
  SeerStatus ae = seer_aq_enq_raw_array(c, "SEER_Q", 3, apl, aln, amids);
  seer_commit(c);
  int anz = 0;
  for (int i = 0; i < 48; i++)
    anz |= amids[i];

  uint8_t *apay[5] = {0};
  size_t apn[5] = {0};
  int agot = -1;
  SeerStatus adq = seer_aq_deq_raw_array(c, "SEER_Q", 5, 0, apay, apn, &agot);
  seer_commit(c);
  int adrain[3] = {0, 0, 0};
  for (int i = 0; i < agot; i++) {
    for (int j = 0; j < 3; j++)
      if (apn[i] == 6 && apay[i] && memcmp(apay[i], am[j], 6) == 0)
        adrain[j] = 1;
    free(apay[i]);
  }
  if (ae == SEER_OK && anz && adq == SEER_OK && agot == 3 && adrain[0] && adrain[1] && adrain[2])
    pass(aname);
  else
    fail(aname, ae != SEER_OK ? (seer_last_error(c) ? seer_last_error(c) : "array enqueue")
                              : "bulk dequeue count / content mismatch");

  /* multi-consumer: a queue with two named subscribers; enqueue once, then each
   * consumer dequeues its own copy by name (SeerAqDeqOptions.consumer). */
  const char *mname = "AQ multi-consumer";
  exec_sql(c, "BEGIN DBMS_AQADM.STOP_QUEUE('SEER_MQ'); EXCEPTION WHEN OTHERS THEN NULL; END;");
  exec_sql(c, "BEGIN DBMS_AQADM.DROP_QUEUE('SEER_MQ'); EXCEPTION WHEN OTHERS THEN NULL; END;");
  exec_sql(c,
           "BEGIN DBMS_AQADM.DROP_QUEUE_TABLE('SEER_MQT'); EXCEPTION WHEN OTHERS THEN NULL; END;");
  exec_sql(
      c, "BEGIN DBMS_AQADM.CREATE_QUEUE_TABLE(queue_table=>'SEER_MQT', queue_payload_type=>'RAW', "
         "multiple_consumers=>TRUE); END;");
  exec_sql(c,
           "BEGIN DBMS_AQADM.CREATE_QUEUE(queue_name=>'SEER_MQ', queue_table=>'SEER_MQT'); END;");
  exec_sql(c, "BEGIN DBMS_AQADM.START_QUEUE('SEER_MQ'); END;");
  exec_sql(c,
           "BEGIN DBMS_AQADM.ADD_SUBSCRIBER('SEER_MQ', sys.aq$_agent('SUB1', NULL, NULL)); END;");
  exec_sql(c,
           "BEGIN DBMS_AQADM.ADD_SUBSCRIBER('SEER_MQ', sys.aq$_agent('SUB2', NULL, NULL)); END;");
  seer_commit(c);

  SeerStatus me = seer_aq_enq_raw(c, "SEER_MQ", (const uint8_t *)"mc", 2, NULL);
  seer_commit(c);
  int mc_ok = (me == SEER_OK);
  const char *subs[2] = {"SUB1", "SUB2"};
  for (int s = 0; s < 2; s++) {
    SeerAqDeqOptions mo = {.consumer = subs[s]};
    uint8_t *mp = NULL;
    size_t ml = 0;
    SeerStatus md = seer_aq_deq_raw_opt(c, "SEER_MQ", &mo, &mp, &ml, NULL);
    if (!(md == SEER_OK && ml == 2 && mp && memcmp(mp, "mc", 2) == 0))
      mc_ok = 0;
    free(mp);
    seer_commit(c);
  }
  if (mc_ok)
    pass(mname);
  else
    fail(mname, seer_last_error(c) ? seer_last_error(c) : "enqueue / consumer dequeue");
  exec_sql(c, "BEGIN DBMS_AQADM.STOP_QUEUE('SEER_MQ'); DBMS_AQADM.DROP_QUEUE('SEER_MQ'); "
              "DBMS_AQADM.DROP_QUEUE_TABLE('SEER_MQT'); EXCEPTION WHEN OTHERS THEN NULL; END;");

  /* object payload: enqueue a SQL object value, dequeue it back as text. */
  const char *cname = "AQ object payload";
  char schema[128] = "";
  SeerStmt *us = NULL;
  if (seer_stmt_prepare(c, "SELECT USER FROM dual", &us) == SEER_OK &&
      seer_stmt_execute(us) == SEER_OK && seer_stmt_fetch(us) == SEER_OK) {
    const char *u = NULL;
    int isnull = 0;
    seer_stmt_get_string(us, 0, &u, &isnull);
    if (u)
      snprintf(schema, sizeof schema, "%s", u);
  }
  seer_stmt_close(us);

  exec_sql(c, "BEGIN DBMS_AQADM.STOP_QUEUE('SEER_OQ'); EXCEPTION WHEN OTHERS THEN NULL; END;");
  exec_sql(c, "BEGIN DBMS_AQADM.DROP_QUEUE('SEER_OQ'); EXCEPTION WHEN OTHERS THEN NULL; END;");
  exec_sql(c,
           "BEGIN DBMS_AQADM.DROP_QUEUE_TABLE('SEER_OQT'); EXCEPTION WHEN OTHERS THEN NULL; END;");
  exec_sql(c, "DROP TYPE seer_aqo FORCE");
  exec_sql(c, "CREATE TYPE seer_aqo AS OBJECT (id NUMBER, nm VARCHAR2(20))");
  exec_sql(c, "BEGIN DBMS_AQADM.CREATE_QUEUE_TABLE(queue_table=>'SEER_OQT', "
              "queue_payload_type=>'SEER_AQO'); END;");
  exec_sql(c,
           "BEGIN DBMS_AQADM.CREATE_QUEUE(queue_name=>'SEER_OQ', queue_table=>'SEER_OQT'); END;");
  exec_sql(c, "BEGIN DBMS_AQADM.START_QUEUE('SEER_OQ'); END;");
  seer_commit(c);

  const char *ov[] = {"42", "hello"};
  uint8_t om[16] = {0};
  SeerStatus oe = seer_aq_enq_object(c, "SEER_OQ", schema, "SEER_AQO", ov, 2, om);
  seer_commit(c);
  char *otext = NULL;
  SeerStatus od = seer_aq_deq_object(c, "SEER_OQ", schema, "SEER_AQO", 0, &otext, NULL);
  int obj_ok =
      (oe == SEER_OK && od == SEER_OK && otext && strstr(otext, "42") && strstr(otext, "hello"));
  free(otext);
  seer_commit(c);
  if (obj_ok)
    pass(cname);
  else
    fail(cname, seer_last_error(c) ? seer_last_error(c) : "object enqueue/dequeue");
  exec_sql(c, "BEGIN DBMS_AQADM.STOP_QUEUE('SEER_OQ'); DBMS_AQADM.DROP_QUEUE('SEER_OQ'); "
              "DBMS_AQADM.DROP_QUEUE_TABLE('SEER_OQT'); EXCEPTION WHEN OTHERS THEN NULL; END;");
  exec_sql(c, "DROP TYPE seer_aqo FORCE");

  /* JSON payload (native binary JSON): enqueue a document, dequeue it back. The
   * queue table needs an ASSM tablespace (USERS) for the JSON type. */
  if (!gated_as("AQ JSON payload", "AQ JSON payload")) {
    const char *jname = "AQ JSON payload";
    exec_sql(c, "BEGIN DBMS_AQADM.STOP_QUEUE('SEER_JQ'); EXCEPTION WHEN OTHERS THEN NULL; END;");
    exec_sql(c, "BEGIN DBMS_AQADM.DROP_QUEUE('SEER_JQ'); EXCEPTION WHEN OTHERS THEN NULL; END;");
    exec_sql(
        c, "BEGIN DBMS_AQADM.DROP_QUEUE_TABLE('SEER_JQT'); EXCEPTION WHEN OTHERS THEN NULL; END;");
    exec_sql(c, "BEGIN DBMS_AQADM.CREATE_QUEUE_TABLE(queue_table=>'SEER_JQT', "
                "queue_payload_type=>'JSON', storage_clause=>'TABLESPACE USERS'); END;");
    exec_sql(c,
             "BEGIN DBMS_AQADM.CREATE_QUEUE(queue_name=>'SEER_JQ', queue_table=>'SEER_JQT'); END;");
    exec_sql(c, "BEGIN DBMS_AQADM.START_QUEUE('SEER_JQ'); END;");
    seer_commit(c);

    long jc = -1;
    SeerStmt *js = NULL;
    if (seer_stmt_prepare(c, "SELECT COUNT(*) FROM SEER_JQT", &js) == SEER_OK &&
        seer_stmt_execute(js) == SEER_OK && seer_stmt_fetch(js) == SEER_OK) {
      const char *v = NULL;
      int isnull = 0;
      seer_stmt_get_string(js, 0, &v, &isnull);
      jc = v ? atol(v) : -1;
    }
    seer_stmt_close(js);

    if (jc < 0) {
      skip(jname, "no ASSM tablespace USERS for the JSON queue table");
    } else {
      const char *doc = "{\"id\":42,\"nm\":\"hi\"}";
      uint8_t jm[16] = {0};
      SeerStatus je = seer_aq_enq_json(c, "SEER_JQ", doc, jm);
      {
        seer_commit(c);
        char *jt = NULL;
        SeerStatus jd = seer_aq_deq_json(c, "SEER_JQ", 0, &jt, NULL);
        int ok = (je == SEER_OK && jd == SEER_OK && jt && strstr(jt, "\"id\":42") &&
                  strstr(jt, "\"nm\":\"hi\""));
        free(jt);
        seer_commit(c);
        if (ok)
          pass(jname);
        else
          fail(jname, seer_last_error(c) ? seer_last_error(c) : "json enqueue/dequeue");
      }
    }
    exec_sql(c, "BEGIN DBMS_AQADM.STOP_QUEUE('SEER_JQ'); DBMS_AQADM.DROP_QUEUE('SEER_JQ'); "
                "DBMS_AQADM.DROP_QUEUE_TABLE('SEER_JQT'); EXCEPTION WHEN OTHERS THEN NULL; END;");
  }

done:
  exec_sql(c, "BEGIN DBMS_AQADM.STOP_QUEUE('SEER_Q'); DBMS_AQADM.DROP_QUEUE('SEER_Q'); "
              "DBMS_AQADM.DROP_QUEUE_TABLE('SEER_QT'); EXCEPTION WHEN OTHERS THEN NULL; END;");
  seer_disconnect(c);
}
