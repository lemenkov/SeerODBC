/*
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "types.h"

#include <stdio.h>
#include <string.h>

/* Reverse the order-preserving transform (§11.7): if the sign bit is set the
 * value was positive (clear it), else it was negative (flip all bits). The
 * result is the big-endian IEEE-754 bit pattern. */
static void unbias_ieee(const uint8_t *in, size_t n, uint8_t *out)
{
    if (in[0] & 0x80) {
        out[0] = in[0] & 0x7F;
        for (size_t i = 1; i < n; i++)
            out[i] = in[i];
    } else {
        for (size_t i = 0; i < n; i++)
            out[i] = (uint8_t)(in[i] ^ 0xFF);
    }
}

SeerStatus seer_decode_number(const uint8_t *data, size_t len, char *out, size_t outsz)
{
    if (out == NULL || outsz < 2)
        return SEER_EPARAM;

    if (len == 0) {
        out[0] = '\0';
        return SEER_EPARAM;          /* NULL should be handled by the caller */
    }
    if (len == 1) {
        snprintf(out, outsz, "%s", data[0] == 0x80 ? "0" : "-1E126");
        return SEER_OK;
    }

    uint8_t expb = data[0];
    int      positive = (expb & 0x80) != 0;
    int      exponent = positive ? ((expb & 0x7f) - 65)
                                 : (((~expb) & 0x7f) - 65);

    const uint8_t *m = data + 1;
    size_t mlen = len - 1;
    if (!positive && mlen > 0 && m[mlen - 1] == 0x66)
        mlen--;                      /* strip the negative terminator */

    /* Each mantissa byte is a base-100 digit pair. NUMBER carries at most ~20
     * mantissa bytes => ~40 digits; allow generous headroom for placement. */
    char digits[64];
    size_t dn = 0;
    for (size_t i = 0; i < mlen && dn + 2 < sizeof digits; i++) {
        int p = positive ? (m[i] - 1) : (101 - m[i]);
        if (p < 0)  p = 0;
        if (p > 99) p = 99;
        digits[dn++] = (char)('0' + p / 10);
        digits[dn++] = (char)('0' + p % 10);
    }
    digits[dn] = '\0';

    int intdig = (exponent + 1) * 2;     /* number of integer-part digits */

    char intpart[160];
    char fracpart[160];
    size_t ip = 0, fp = 0;

    if (intdig >= (int)dn) {
        for (size_t i = 0; i < dn; i++) intpart[ip++] = digits[i];
        for (int i = 0; i < intdig - (int)dn && ip < sizeof intpart - 1; i++)
            intpart[ip++] = '0';
    } else if (intdig <= 0) {
        intpart[ip++] = '0';
        for (int i = 0; i < -intdig && fp < sizeof fracpart - 1; i++)
            fracpart[fp++] = '0';
        for (size_t i = 0; i < dn && fp < sizeof fracpart - 1; i++)
            fracpart[fp++] = digits[i];
    } else {
        for (int i = 0; i < intdig; i++) intpart[ip++] = digits[i];
        for (size_t i = (size_t)intdig; i < dn && fp < sizeof fracpart - 1; i++)
            fracpart[fp++] = digits[i];
    }
    intpart[ip]  = '\0';
    fracpart[fp] = '\0';

    /* Strip leading integer zeros (keep one) and trailing fraction zeros. */
    char *istart = intpart;
    while (istart[0] == '0' && istart[1] != '\0')
        istart++;
    while (fp > 0 && fracpart[fp - 1] == '0')
        fracpart[--fp] = '\0';

    if (fracpart[0] != '\0')
        snprintf(out, outsz, "%s%s.%s", positive ? "" : "-", istart, fracpart);
    else
        snprintf(out, outsz, "%s%s", positive ? "" : "-", istart);
    return SEER_OK;
}

SeerStatus seer_decode_bfloat(const uint8_t *data, size_t len, char *out, size_t outsz)
{
    if (out == NULL || outsz < 16)
        return SEER_EPARAM;
    if (len < 4) {
        out[0] = '\0';
        return SEER_EPROTO;
    }
    uint8_t raw[4];
    unbias_ieee(data, 4, raw);
    uint32_t bits = ((uint32_t)raw[0] << 24) | ((uint32_t)raw[1] << 16) |
                    ((uint32_t)raw[2] << 8)  |  (uint32_t)raw[3];
    float f;
    memcpy(&f, &bits, sizeof f);
    snprintf(out, outsz, "%.9g", (double)f);
    return SEER_OK;
}

SeerStatus seer_decode_bdouble(const uint8_t *data, size_t len, char *out, size_t outsz)
{
    if (out == NULL || outsz < 32)
        return SEER_EPARAM;
    if (len < 8) {
        out[0] = '\0';
        return SEER_EPROTO;
    }
    uint8_t raw[8];
    unbias_ieee(data, 8, raw);
    uint64_t bits = 0;
    for (int i = 0; i < 8; i++)
        bits = (bits << 8) | raw[i];
    double d;
    memcpy(&d, &bits, sizeof d);
    snprintf(out, outsz, "%.17g", d);
    return SEER_OK;
}

void seer_encode_bdouble(double v, uint8_t out[8])
{
    uint64_t bits;
    memcpy(&bits, &v, sizeof bits);
    for (int i = 0; i < 8; i++)              /* big-endian IEEE-754 */
        out[i] = (uint8_t)(bits >> (56 - 8 * i));
    if (out[0] & 0x80)                       /* order-preserving (§11.7) */
        for (int i = 0; i < 8; i++)
            out[i] = (uint8_t)(out[i] ^ 0xFF);
    else
        out[0] = (uint8_t)(out[0] ^ 0x80);
}

void seer_encode_bfloat(float v, uint8_t out[4])
{
    uint32_t bits;
    memcpy(&bits, &v, sizeof bits);
    for (int i = 0; i < 4; i++)              /* big-endian IEEE-754 */
        out[i] = (uint8_t)(bits >> (24 - 8 * i));
    if (out[0] & 0x80)                       /* order-preserving (§11.7) */
        for (int i = 0; i < 4; i++)
            out[i] = (uint8_t)(out[i] ^ 0xFF);
    else
        out[0] = (uint8_t)(out[0] ^ 0x80);
}

size_t seer_encode_number_int(int64_t v, uint8_t *out)
{
    if (v == 0) {
        out[0] = 0x80;
        return 1;
    }

    int      neg = v < 0;
    uint64_t m   = neg ? (~(uint64_t)v + 1) : (uint64_t)v;   /* |v|, INT64_MIN-safe */

    /* Base-100 digits, least-significant first. */
    uint8_t dig[20];
    int     nd = 0;
    while (m > 0 && nd < (int)sizeof dig) {
        dig[nd++] = (uint8_t)(m % 100);
        m /= 100;
    }

    int e = nd - 1;                       /* exponent (leading digit weight) */
    int lo = 0;                           /* drop trailing (low) zero digits */
    while (lo < nd && dig[lo] == 0)
        lo++;

    uint8_t expb = (uint8_t)(0x80 | (65 + e));
    if (neg)
        expb = (uint8_t)~expb;

    size_t oi = 0;
    out[oi++] = expb;
    for (int i = nd - 1; i >= lo; i--)
        out[oi++] = neg ? (uint8_t)(101 - dig[i]) : (uint8_t)(dig[i] + 1);
    if (neg)
        out[oi++] = 0x66;                 /* negative terminator */
    return oi;
}

size_t seer_encode_number_str(const char *s, uint8_t *out)
{
    if (s == NULL)
        return 0;
    while (*s == ' ' || *s == '\t')
        s++;
    int neg = 0;
    if (*s == '+')      s++;
    else if (*s == '-') { neg = 1; s++; }

    /* Collect integer and fraction digit runs. */
    char ipart[128], fpart[128];
    int  ni = 0, nf = 0;
    while (*s >= '0' && *s <= '9') { if (ni < 127) ipart[ni++] = *s; s++; }
    if (*s == '.') {
        s++;
        while (*s >= '0' && *s <= '9') { if (nf < 127) fpart[nf++] = *s; s++; }
    }
    if (*s != '\0' || (ni == 0 && nf == 0))
        return 0;                          /* trailing junk / no digits */

    /* Pad the integer run on the left and the fraction on the right to even
     * lengths so base-100 pairs align at the decimal point. */
    char buf[260];
    int  pos = 0;
    int  ipad = (ni % 2) ? 1 : 0;
    if (ipad) buf[pos++] = '0';
    for (int i = 0; i < ni; i++) buf[pos++] = ipart[i];
    int int_digits = ni + ipad;            /* even */
    for (int i = 0; i < nf; i++) buf[pos++] = fpart[i];
    if (nf % 2) buf[pos++] = '0';
    int ngroups    = pos / 2;
    int int_groups = int_digits / 2;

    uint8_t grp[130];
    for (int g = 0; g < ngroups; g++)
        grp[g] = (uint8_t)((buf[2 * g] - '0') * 10 + (buf[2 * g + 1] - '0'));

    int exp  = int_groups - 1;             /* power of 100 of the leading group */
    int lead = 0;
    while (lead < ngroups && grp[lead] == 0) { lead++; exp--; }   /* drop leading 0 groups */
    int tail = ngroups;
    while (tail > lead && grp[tail - 1] == 0) tail--;            /* drop trailing 0 groups */

    if (lead >= tail) {                    /* the value is zero */
        out[0] = 0x80;
        return 1;
    }
    if (tail - lead > 20)                  /* NUMBER is at most 20 base-100 digits */
        tail = lead + 20;

    uint8_t expb = (uint8_t)(0x80 | (65 + exp));
    if (neg) expb = (uint8_t)~expb;
    size_t oi = 0;
    out[oi++] = expb;
    for (int g = lead; g < tail; g++)
        out[oi++] = neg ? (uint8_t)(101 - grp[g]) : (uint8_t)(grp[g] + 1);
    if (neg)
        out[oi++] = 0x66;                  /* negative terminator */
    return oi;
}

SeerStatus seer_decode_date(const uint8_t *data, size_t len, char *out, size_t outsz)
{
    if (out == NULL || outsz < 20)
        return SEER_EPARAM;
    if (len < 7) {
        out[0] = '\0';
        return SEER_EPROTO;
    }

    int year   = (data[0] - 100) * 100 + (data[1] - 100);
    int month  = data[2];
    int day    = data[3];
    int hour   = data[4] - 1;
    int minute = data[5] - 1;
    int second = data[6] - 1;

    int n = snprintf(out, outsz, "%04d-%02d-%02d %02d:%02d:%02d",
                     year, month, day, hour, minute, second);

    if (len >= 11 && n > 0 && (size_t)n < outsz) {
        uint32_t nanos = ((uint32_t)data[7] << 24) | ((uint32_t)data[8] << 16) |
                         ((uint32_t)data[9] << 8)  |  (uint32_t)data[10];
        if (nanos != 0)
            snprintf(out + n, outsz - (size_t)n, ".%09u", nanos);
    }
    return SEER_OK;
}

/* big-endian ub4 read, debiased by 2**31 to a signed value. */
static int32_t be32_debiased(const uint8_t *p)
{
    uint32_t u = (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
                 (uint32_t)p[2] << 8  | (uint32_t)p[3];
    return (int32_t)(u - 0x80000000u);
}

SeerStatus seer_decode_interval_ym(const uint8_t *data, size_t len, char *out, size_t outsz)
{
    if (out == NULL || outsz < 16)
        return SEER_EPARAM;
    if (len < 5) { out[0] = '\0'; return SEER_EPROTO; }
    int32_t years  = be32_debiased(data);
    int     months = (int)data[4] - 60;        /* months biased by 60 */
    char    sign   = (years < 0 || months < 0) ? '-' : '+';
    long ay = years  < 0 ? -(long)years : years;   /* widen: -INT32_MIN overflows int */
    int  am = months < 0 ? -months : months;
    snprintf(out, outsz, "%c%ld-%02d", sign, ay, am);
    return SEER_OK;
}

SeerStatus seer_decode_interval_ds(const uint8_t *data, size_t len, char *out, size_t outsz)
{
    if (out == NULL || outsz < 32)
        return SEER_EPARAM;
    if (len < 11) { out[0] = '\0'; return SEER_EPROTO; }
    int32_t days  = be32_debiased(data);
    int     hours = (int)data[4] - 60;         /* H/M/S biased by 60 */
    int     mins  = (int)data[5] - 60;
    int     secs  = (int)data[6] - 60;
    int32_t nanos = be32_debiased(data + 7);
    /* The components share one sign for a valid interval; if any is negative the
     * whole interval is, so render the sign once and the magnitudes absolute. */
    char sign = (days < 0 || hours < 0 || mins < 0 || secs < 0 || nanos < 0) ? '-' : '+';
    long ad = days  < 0 ? -(long)days : days;      /* widen: -INT32_MIN overflows int */
    int  ah = hours < 0 ? -hours : hours;
    int  am = mins  < 0 ? -mins  : mins;
    int  as = secs  < 0 ? -secs  : secs;
    long an = nanos < 0 ? -(long)nanos : nanos;
    snprintf(out, outsz, "%c%ld %02d:%02d:%02d.%09ld", sign, ad, ah, am, as, an);
    return SEER_OK;
}
