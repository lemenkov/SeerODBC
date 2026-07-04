/* Live test for SQL OBJECT (ADT) and collection (VARRAY/nested table) parameter
 * binding against the core API.
 *
 * Self-gating: exits 77 (skip) unless SEER_TEST_HOST/SERVICE/USER are set. Binds
 * an object and a VARRAY, inserts each, and reads them back through the decode
 * path. Object/collection binds are 12c+; older servers skip.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "seer/seertns.h"

static int pass_n, fail_n, skip_n;
static void pass(const char *n) { printf("  PASS %s\n", n); pass_n++; }
static void fail(const char *n, const char *w) { printf("  FAIL %s: %s\n", n, w); fail_n++; }
static void skip(const char *n, const char *w) { printf("  SKIP %s: %s\n", n, w); skip_n++; }

static SeerConn *connect_one(void)
{
    const char *port = getenv("SEER_TEST_PORT");
    SeerConnParams p = {
        .host = getenv("SEER_TEST_HOST"),
        .port = (uint16_t)(port ? atoi(port) : 1521),
        .service_name = getenv("SEER_TEST_SERVICE"),
        .username = getenv("SEER_TEST_USER"),
        .password = getenv("SEER_TEST_PASS"),
    };
    SeerConn *c = NULL;
    return seer_connect(&p, &c) == SEER_OK ? c : NULL;
}

static void run(SeerConn *c, const char *sql)
{
    SeerStmt *s = NULL;
    if (seer_stmt_prepare(c, sql, &s) != SEER_OK) return;
    seer_stmt_execute(s);
    seer_stmt_close(s);
}

/* SELECT a single rendered value; returns 1 if it contains both needles. */
static int readback_has(SeerConn *c, const char *sql, const char *a, const char *b)
{
    SeerStmt *s = NULL;
    int ok = 0;
    if (seer_stmt_prepare(c, sql, &s) == SEER_OK && seer_stmt_execute(s) == SEER_OK
        && seer_stmt_fetch(s) == SEER_OK) {
        const char *v = NULL; int isnull = 0;
        if (seer_stmt_get_string(s, 0, &v, &isnull) == SEER_OK && v != NULL)
            ok = (strstr(v, a) != NULL && strstr(v, b) != NULL);
    }
    seer_stmt_close(s);
    return ok;
}

int main(void)
{
    if (!getenv("SEER_TEST_HOST") || !getenv("SEER_TEST_SERVICE") || !getenv("SEER_TEST_USER")) {
        fprintf(stderr, "objbind_test: set SEER_TEST_HOST/SERVICE/USER[/PORT/PASS] - skipping\n");
        return 77;
    }
    SeerConn *c = connect_one();
    if (!c) { fprintf(stderr, "objbind_test: connect failed\n"); return 1; }

    char schema[64];
    snprintf(schema, sizeof schema, "%s", getenv("SEER_TEST_USER"));
    for (char *p = schema; *p; p++) *p = (char)toupper((unsigned char)*p);

    /* --- SQL OBJECT bind --- */
    run(c, "DROP TABLE seerob_t");
    run(c, "DROP TYPE seerob_o");
    run(c, "CREATE TYPE seerob_o AS OBJECT (n NUMBER, s VARCHAR2(20))");
    run(c, "CREATE TABLE seerob_t (o seerob_o)");
    {
        const char *name = "SQL OBJECT bind";
        const char *attrs[2] = { "42", "hello" };
        SeerStmt *ins = NULL;
        seer_stmt_prepare(c, "INSERT INTO seerob_t VALUES (:1)", &ins);
        SeerStatus st = seer_stmt_bind_object(ins, 1, schema, "SEEROB_O", attrs, 2);
        if (st == SEER_ENOTIMPL) {
            skip(name, "object bind requires a 12c+ server");
        } else if (st != SEER_OK || seer_stmt_execute(ins) != SEER_OK) {
            fail(name, seer_last_error(c) ? seer_last_error(c) : "bind/insert");
        } else {
            seer_stmt_close(ins); ins = NULL;
            seer_commit(c);
            if (readback_has(c, "SELECT o FROM seerob_t", "42", "hello")) pass(name);
            else fail(name, "read-back");
        }
        seer_stmt_close(ins);
    }
    run(c, "DROP TABLE seerob_t");
    run(c, "DROP TYPE seerob_o");

    /* --- collection (VARRAY) bind --- */
    run(c, "DROP TABLE seerva_t");
    run(c, "DROP TYPE seerva_o");
    run(c, "CREATE TYPE seerva_o AS VARRAY(5) OF NUMBER");
    run(c, "CREATE TABLE seerva_t (v seerva_o)");
    {
        const char *name = "VARRAY bind";
        const char *elems[3] = { "10", "20", "30" };
        SeerStmt *ins = NULL;
        seer_stmt_prepare(c, "INSERT INTO seerva_t VALUES (:1)", &ins);
        SeerStatus st = seer_stmt_bind_collection(ins, 1, schema, "SEERVA_O", elems, 3);
        if (st == SEER_ENOTIMPL) {
            skip(name, "collection bind requires a 12c+ server");
        } else if (st != SEER_OK || seer_stmt_execute(ins) != SEER_OK) {
            fail(name, seer_last_error(c) ? seer_last_error(c) : "bind/insert");
        } else {
            seer_stmt_close(ins); ins = NULL;
            seer_commit(c);
            if (readback_has(c, "SELECT v FROM seerva_t", "10", "30")) pass(name);
            else fail(name, "read-back");
        }
        seer_stmt_close(ins);
    }
    run(c, "DROP TABLE seerva_t");
    run(c, "DROP TYPE seerva_o");

    /* --- nested object bind (an attribute that is itself an ADT, flattened) --- */
    run(c, "DROP TABLE seerpe_t");
    run(c, "DROP TYPE seerpe_o");
    run(c, "DROP TYPE seerad_o");
    run(c, "CREATE TYPE seerad_o AS OBJECT (street VARCHAR2(20), zip NUMBER)");
    run(c, "CREATE TYPE seerpe_o AS OBJECT (nm VARCHAR2(20), age NUMBER, home seerad_o)");
    run(c, "CREATE TABLE seerpe_t (p seerpe_o)");
    {
        const char *name = "nested object bind";
        const char *vals[4] = { "Bob", "30", "Main St", "12345" };   /* flattened leaves */
        SeerStmt *ins = NULL;
        seer_stmt_prepare(c, "INSERT INTO seerpe_t VALUES (:1)", &ins);
        SeerStatus st = seer_stmt_bind_object(ins, 1, schema, "SEERPE_O", vals, 4);
        if (st == SEER_ENOTIMPL) {
            skip(name, "object bind requires a 12c+ server");
        } else if (st != SEER_OK || seer_stmt_execute(ins) != SEER_OK) {
            fail(name, seer_last_error(c) ? seer_last_error(c) : "bind/insert");
        } else {
            seer_stmt_close(ins); ins = NULL;
            seer_commit(c);
            if (readback_has(c, "SELECT p FROM seerpe_t", "Main St", "12345")) pass(name);
            else fail(name, "read-back");
        }
        seer_stmt_close(ins);
    }
    run(c, "DROP TABLE seerpe_t");
    run(c, "DROP TYPE seerpe_o");
    run(c, "DROP TYPE seerad_o");

    /* --- typed attributes: decimal NUMBER + DATE --- */
    run(c, "DROP TABLE seerty_t");
    run(c, "DROP TYPE seerty_o");
    run(c, "CREATE TYPE seerty_o AS OBJECT (amt NUMBER, born DATE)");
    run(c, "CREATE TABLE seerty_t (o seerty_o)");
    {
        const char *name = "object bind (decimal+DATE)";
        const char *vals[2] = { "-1234.567", "1999-12-31 23:59:58" };
        SeerStmt *ins = NULL;
        seer_stmt_prepare(c, "INSERT INTO seerty_t VALUES (:1)", &ins);
        SeerStatus st = seer_stmt_bind_object(ins, 1, schema, "SEERTY_O", vals, 2);
        if (st == SEER_ENOTIMPL) {
            skip(name, "object bind requires a 12c+ server");
        } else if (st != SEER_OK || seer_stmt_execute(ins) != SEER_OK) {
            fail(name, seer_last_error(c) ? seer_last_error(c) : "bind/insert");
        } else {
            seer_stmt_close(ins); ins = NULL;
            seer_commit(c);
            if (readback_has(c, "SELECT o FROM seerty_t", "-1234.567", "1999-12-31"))
                pass(name);
            else
                fail(name, "read-back");
        }
        seer_stmt_close(ins);
    }
    run(c, "DROP TABLE seerty_t");
    run(c, "DROP TYPE seerty_o");

    /* --- PL/SQL associative-array (index-by table) binds --- */
    run(c, "CREATE OR REPLACE PACKAGE seeraa AS\n"
           "  TYPE num_tab IS TABLE OF NUMBER INDEX BY BINARY_INTEGER;\n"
           "  TYPE str_tab IS TABLE OF VARCHAR2(40) INDEX BY BINARY_INTEGER;\n"
           "  PROCEDURE sum_arr(a IN num_tab, total OUT NUMBER);\n"
           "  PROCEDURE cat_arr(a IN str_tab, result OUT VARCHAR2);\n"
           "  PROCEDURE out_nums(a OUT num_tab);\n"
           "END;");
    run(c, "CREATE OR REPLACE PACKAGE BODY seeraa AS\n"
           "  PROCEDURE sum_arr(a IN num_tab, total OUT NUMBER) IS BEGIN\n"
           "    total := 0; FOR i IN 1..a.COUNT LOOP total := total + a(i); END LOOP; END;\n"
           "  PROCEDURE cat_arr(a IN str_tab, result OUT VARCHAR2) IS BEGIN\n"
           "    result := NULL; FOR i IN 1..a.COUNT LOOP result := result || a(i); END LOOP; END;\n"
           "  PROCEDURE out_nums(a OUT num_tab) IS BEGIN a(1):=10; a(2):=20; a(3):=30; END;\n"
           "END;");
    {
        const char *name = "assoc-array bind (NUMBER)";
        SeerStmt *s = NULL;
        int64_t nums[3] = { 10, 20, 30 };
        seer_stmt_prepare(c, "BEGIN seeraa.sum_arr(:1, :2); END;", &s);
        SeerStatus b = seer_stmt_bind_int64_array(s, 1, nums, 3);
        if (b == SEER_ENOTIMPL) {
            skip(name, "assoc-array bind requires a 12c+ server");
        } else if (b != SEER_OK || seer_stmt_bind_out(s, 2, 2, 22) != SEER_OK
                   || seer_stmt_execute(s) != SEER_OK) {
            fail(name, seer_last_error(c) ? seer_last_error(c) : "bind/exec");
        } else {
            const void *d = NULL; size_t dl = 0; int isn = 0, isb = 0;
            seer_stmt_out_data(s, 2, &d, &dl, &isn, &isb);
            if (d != NULL && dl == 2 && memcmp(d, "60", 2) == 0) pass(name);
            else { char m[64]; snprintf(m, sizeof m, "total='%.*s'", (int)dl, (const char*)d); fail(name, m); }
        }
        seer_stmt_close(s);
    }
    {
        const char *name = "assoc-array bind (VARCHAR)";
        SeerStmt *s = NULL;
        const char *strs[2] = { "foo", "bar" };
        seer_stmt_prepare(c, "BEGIN seeraa.cat_arr(:1, :2); END;", &s);
        SeerStatus b = seer_stmt_bind_text_array(s, 1, strs, 2, 40);
        if (b == SEER_ENOTIMPL) {
            skip(name, "assoc-array bind requires a 12c+ server");
        } else if (b != SEER_OK || seer_stmt_bind_out(s, 2, 1, 100) != SEER_OK
                   || seer_stmt_execute(s) != SEER_OK) {
            fail(name, seer_last_error(c) ? seer_last_error(c) : "bind/exec");
        } else {
            const void *d = NULL; size_t dl = 0; int isn = 0, isb = 0;
            seer_stmt_out_data(s, 2, &d, &dl, &isn, &isb);
            if (d != NULL && dl == 6 && memcmp(d, "foobar", 6) == 0) pass(name);
            else { char m[64]; snprintf(m, sizeof m, "result='%.*s'", (int)dl, (const char*)d); fail(name, m); }
        }
        seer_stmt_close(s);
    }
    {
        const char *name = "OUT assoc-array (NUMBER)";
        SeerStmt *s = NULL;
        seer_stmt_prepare(c, "BEGIN seeraa.out_nums(:1); END;", &s);
        SeerStatus b = seer_stmt_bind_out_array(s, 1, 2 /*NUMBER*/, 0, 10);
        if (b == SEER_ENOTIMPL) {
            skip(name, "assoc-array bind requires a 12c+ server");
        } else if (b != SEER_OK || seer_stmt_execute(s) != SEER_OK) {
            fail(name, seer_last_error(c) ? seer_last_error(c) : "bind/exec");
        } else {
            int ok = (seer_stmt_out_array_len(s, 1) == 3);
            const char *want[3] = { "10", "20", "30" };
            for (int i = 0; ok && i < 3; i++) {
                const char *d = NULL; size_t l = 0; int isn = 0;
                if (seer_stmt_out_array_get(s, 1, i, &d, &l, &isn) != SEER_OK
                    || d == NULL || strcmp(d, want[i]) != 0)
                    ok = 0;
            }
            if (ok) pass(name);
            else fail(name, "wrong count / elements");
        }
        seer_stmt_close(s);
    }
    run(c, "DROP PACKAGE seeraa");

    {
        const char *name = "native JSON bind";
        run(c, "DROP TABLE seerjb");
        run(c, "CREATE TABLE seerjb (doc JSON) TABLESPACE USERS");
        SeerStmt *s = NULL;
        seer_stmt_prepare(c, "INSERT INTO seerjb VALUES (:1)", &s);
        SeerStatus b = seer_stmt_bind_json(s, 1, "{\"name\":\"alice\",\"n\":30}");
        SeerStatus e = (b == SEER_OK) ? seer_stmt_execute(s) : b;
        seer_stmt_close(s);
        seer_commit(c);
        const char *er = seer_last_error(c);
        if (b == SEER_ENOTIMPL) {
            skip(name, "native JSON bind requires a 21c+ server");
        } else if (e != SEER_OK) {
            /* JSON column type / ASSM tablespace may be unavailable -> skip */
            if (er && (strstr(er, "ORA-00902") || strstr(er, "ORA-43853")
                       || strstr(er, "ORA-00942")))
                skip(name, "JSON column type / ASSM tablespace not available");
            else
                fail(name, er ? er : "bind/exec");
        } else if (readback_has(c, "SELECT doc FROM seerjb", "alice", "30")) {
            pass(name);
        } else {
            fail(name, "readback mismatch");
        }
        run(c, "DROP TABLE seerjb");
    }

    {
        const char *name = "native VECTOR bind (f32/f64/i8)";
        run(c, "DROP TABLE seervb");
        run(c, "CREATE TABLE seervb (a VECTOR(3,FLOAT32), b VECTOR(3,FLOAT64), "
               "c VECTOR(3,INT8)) TABLESPACE USERS");
        SeerStmt *s = NULL;
        float  f32[3] = { 1.5f, -2.25f, 3.0f };
        double f64[3] = { 1.5, -2.25, 3.0 };
        int8_t i8[3]  = { 1, -2, 3 };
        seer_stmt_prepare(c, "INSERT INTO seervb VALUES (:1, :2, :3)", &s);
        SeerStatus b1 = seer_stmt_bind_vector_f32(s, 1, f32, 3);
        SeerStatus b2 = seer_stmt_bind_vector_f64(s, 2, f64, 3);
        SeerStatus b3 = seer_stmt_bind_vector_i8(s, 3, i8, 3);
        SeerStatus e = (b1 == SEER_OK && b2 == SEER_OK && b3 == SEER_OK)
                           ? seer_stmt_execute(s) : b1;
        seer_stmt_close(s);
        seer_commit(c);
        const char *er = seer_last_error(c);
        if (b1 == SEER_ENOTIMPL) {
            skip(name, "native VECTOR bind requires a 23ai server");
        } else if (e != SEER_OK) {
            if (er && (strstr(er, "ORA-00907") || strstr(er, "ORA-00902")
                       || strstr(er, "ORA-00942") || strstr(er, "ORA-43853")))
                skip(name, "VECTOR column type not available here");
            else
                fail(name, er ? er : "bind/exec");
        } else if (readback_has(c, "SELECT a FROM seervb", "1.5", "-2.25")
                   && readback_has(c, "SELECT b FROM seervb", "1.5", "-2.25")
                   && readback_has(c, "SELECT c FROM seervb", "1", "-2")) {
            pass(name);
        } else {
            fail(name, "readback mismatch");
        }
        run(c, "DROP TABLE seervb");
    }

    {
        const char *name = "native VECTOR bind (binary/sparse)";
        run(c, "DROP TABLE seervbin");
        run(c, "DROP TABLE seervsp");
        run(c, "DROP TABLE seervspd");
        run(c, "DROP TABLE seervspi");
        run(c, "CREATE TABLE seervbin (v VECTOR(16, BINARY)) TABLESPACE USERS");
        run(c, "CREATE TABLE seervsp (v VECTOR(10, FLOAT32, SPARSE)) TABLESPACE USERS");
        run(c, "CREATE TABLE seervspd (v VECTOR(10, FLOAT64, SPARSE)) TABLESPACE USERS");
        run(c, "CREATE TABLE seervspi (v VECTOR(10, INT8, SPARSE)) TABLESPACE USERS");
        uint8_t bits[2] = { 0xA5, 0x3C };
        SeerStmt *s = NULL;
        seer_stmt_prepare(c, "INSERT INTO seervbin VALUES (:1)", &s);
        SeerStatus bb = seer_stmt_bind_vector_binary(s, 1, bits, 2);
        SeerStatus eb = (bb == SEER_OK) ? seer_stmt_execute(s) : bb;
        seer_stmt_close(s); s = NULL;
        uint32_t idx[2] = { 2, 7 };
        float    val[2] = { 1.5f, -2.25f };
        seer_stmt_prepare(c, "INSERT INTO seervsp VALUES (:1)", &s);
        SeerStatus bs = seer_stmt_bind_vector_sparse_f32(s, 1, 10, 2, idx, val);
        SeerStatus es = (bs == SEER_OK) ? seer_stmt_execute(s) : bs;
        seer_stmt_close(s); s = NULL;
        double  vald[2] = { 1.5, -2.25 };
        seer_stmt_prepare(c, "INSERT INTO seervspd VALUES (:1)", &s);
        SeerStatus bsd = seer_stmt_bind_vector_sparse_f64(s, 1, 10, 2, idx, vald);
        SeerStatus esd = (bsd == SEER_OK) ? seer_stmt_execute(s) : bsd;
        seer_stmt_close(s); s = NULL;
        int8_t  vali[2] = { 5, -3 };
        seer_stmt_prepare(c, "INSERT INTO seervspi VALUES (:1)", &s);
        SeerStatus bsi = seer_stmt_bind_vector_sparse_i8(s, 1, 10, 2, idx, vali);
        SeerStatus esi = (bsi == SEER_OK) ? seer_stmt_execute(s) : bsi;
        seer_stmt_close(s);
        seer_commit(c);
        const char *er = seer_last_error(c);
        if (bb == SEER_ENOTIMPL) {
            skip(name, "native VECTOR bind requires a 23ai server");
        } else if (eb != SEER_OK || es != SEER_OK || esd != SEER_OK || esi != SEER_OK) {
            if (er && (strstr(er, "ORA-00907") || strstr(er, "ORA-00902")
                       || strstr(er, "ORA-00942") || strstr(er, "ORA-43853")))
                skip(name, "VECTOR BINARY/SPARSE not available here");
            else
                fail(name, er ? er : "bind/exec");
        } else if (readback_has(c, "SELECT v FROM seervbin", "165", "60")
                   && readback_has(c, "SELECT v FROM seervsp", "[2, 7]", "1.5")
                   && readback_has(c, "SELECT v FROM seervspd", "[2, 7]", "-2.25")
                   && readback_has(c, "SELECT v FROM seervspi", "[2, 7]", "-3")) {
            pass(name);
        } else {
            fail(name, "readback mismatch");
        }
        run(c, "DROP TABLE seervbin");
        run(c, "DROP TABLE seervsp");
        run(c, "DROP TABLE seervspd");
        run(c, "DROP TABLE seervspi");
    }

    {
        const char *name = "XMLType bind";
        run(c, "DROP TABLE seer_xb");
        run(c, "CREATE TABLE seer_xb (x XMLTYPE)");
        SeerStmt *s = NULL;
        seer_stmt_prepare(c, "INSERT INTO seer_xb VALUES (:1)", &s);
        SeerStatus b = seer_stmt_bind_xmltype(s, 1, "<a><b>hi</b></a>");
        SeerStatus e = (b == SEER_OK) ? seer_stmt_execute(s) : b;
        seer_stmt_close(s);
        seer_commit(c);
        const char *er = seer_last_error(c);
        if (e != SEER_OK) {
            if (er && (strstr(er, "ORA-00942") || strstr(er, "ORA-43853")
                       || strstr(er, "ORA-01031")))
                skip(name, "XMLType column not available here");
            else
                fail(name, er ? er : "bind/exec");
        } else if (readback_has(c, "SELECT t.x.getStringVal() FROM seer_xb t", "<a>", "hi")) {
            /* getStringVal() returns the XML as text, so the check works even where
             * XMLType is legacy CLOB-stored (11g) and not decoded inline on fetch. */
            pass(name);
        } else {
            fail(name, "readback mismatch");
        }
        run(c, "DROP TABLE seer_xb");
    }

    seer_disconnect(c);
    printf("SUMMARY pass=%d fail=%d skip=%d\n", pass_n, fail_n, skip_n);
    return fail_n > 0 ? 1 : 0;
}
