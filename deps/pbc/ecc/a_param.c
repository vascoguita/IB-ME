#include <stdarg.h>
#include <stdio.h>
#include <stdint.h> // for intptr_t
#include <stdlib.h> //for rand, pbc_malloc, pbc_free
#include <string.h> //for strcmp
#include <gmp.h>
#include "pbc_utils.h"
#include "pbc_field.h"
#include "pbc_fp.h"
#include "pbc_fieldquadratic.h"
#include "pbc_param.h"
#include "pbc_pairing.h"
#include "pbc_curve.h"
#include "pbc_random.h"
#include "pbc_memory.h"
#include "ecc/param.h"
#include "pbc_a_param.h"

typedef struct {
  int exp2;
  int exp1;
  int sign1;
  int sign0;
  mpz_t r; // r = 2^exp2 + sign1 * 2^exp1 + sign0 * 1
  mpz_t q; // we work in E(F_q) (and E(F_q^2))
  mpz_t h; // r * h = q + 1
} *a_param_ptr;

typedef struct {
  field_t Fq, Fq2, Eq;
  int exp2, exp1;
  int sign1;
} *a_pairing_data_ptr;

static void a_clear(void *data) {
  a_param_ptr sp = data;
  mpz_clear(sp->r);
  mpz_clear(sp->q);
  mpz_clear(sp->h);
  pbc_free(data);
}

static void phi_identity(element_ptr out, element_ptr in, pairing_ptr pairing) {
  UNUSED_VAR(pairing);
  element_set(out, in);
}

static void compute_abc_tangent(element_ptr a, element_ptr b, element_ptr c,
    element_ptr Vx, element_ptr Vy, element_ptr e0) {
  //a = -slope_tangent(V.x, V.y);
  //b = 1;
  //c = -(V.y + aV.x);
  //but we multiply by -2*V.y to avoid division so:
  //a = -(3 Vx^2 + cc->a)
  //b = 2 * Vy
  //c = -(2 Vy^2 + a Vx);
  element_square(a, Vx);
  //element_mul_si(a, a, 3);
  element_add(e0, a, a);
  element_add(a, e0, a);
  element_set1(b);
  element_add(a, a, b);
  element_neg(a, a);

  element_double(b, Vy);

  element_mul(e0, b, Vy);
  element_mul(c, a, Vx);
  element_add(c, c, e0);
  element_neg(c, c);
}

static void compute_abc_tangent_proj(element_ptr a, element_ptr b, element_ptr c,
    element_ptr Vx, element_ptr Vy,
    element_ptr z, element_ptr z2, element_ptr e0) {
  //a = -(3x^2 + cca z^4)
  //for this case cca = 1
  //b = 2 y z^3
  //c = -(2 y^2 + x a)
  //a = z^2 a
  element_square(a, z2);
  element_square(b, Vx);
  ////element_mul_si(b, b, 3);
  element_double(e0, b);
  element_add(b, e0, b);
  element_add(a, a, b);
  element_neg(a, a);

  ////element_mul_si(e0, Vy, 2);
  element_double(e0, Vy);
  element_mul(b, e0, z2);
  element_mul(b, b, z);

  element_mul(c, Vx, a);
  element_mul(a, a, z2);
  element_mul(e0, e0, Vy);
  element_add(c, c, e0);
  element_neg(c, c);
}

static void compute_abc_line(element_ptr a, element_ptr b, element_ptr c,
    element_ptr Vx, element_ptr Vy,
    element_ptr V1x, element_ptr V1y,
    element_ptr e0) {
  //a = -(B.y - A.y) / (B.x - A.x);
  //b = 1;
  //c = -(A.y + a * A.x);
  //but we'll multiply by B.x - A.x to avoid division, so
  //a = -(By - Ay)
  //b = Bx - Ax
  //c = -(Ay b + a Ax);
  element_sub(a, Vy, V1y);
  element_sub(b, V1x, Vx);
  element_mul(c, Vx, V1y);
  element_mul(e0, Vy, V1x);
  element_sub(c, c, e0);
}

struct pp_coeff_s {
  element_t a;
  element_t b;
  element_t c;
};
typedef struct pp_coeff_s pp_coeff_t[1];
typedef struct pp_coeff_s *pp_coeff_ptr;

static void pp_coeff_set(pp_coeff_ptr p, element_t a, element_t b, element_t c) {
  element_init(p->a, a->field);
  element_init(p->b, b->field);
  element_init(p->c, c->field);
  element_set(p->a, a);
  element_set(p->b, b);
  element_set(p->c, c);
}

static void a_pairing_pp_init(pairing_pp_t p, element_ptr in1, pairing_t pairing) {
  int i, n;
  a_pairing_data_ptr ainfo = pairing->data;
  p->data = pbc_malloc(sizeof(pp_coeff_t) * (ainfo->exp2 + 1));
  pp_coeff_t *coeff = (pp_coeff_t *) p->data;
  element_t V, V1;
  element_t a, b, c;
  element_t e0;
  element_ptr Vx, Vy;
  element_ptr V1x, V1y;

  #define do_tangent()                        \
    compute_abc_tangent(a, b, c, Vx, Vy, e0); \
    pp_coeff_set(coeff[i], a, b, c);

  #define do_line()                                  \
    compute_abc_line(a, b, c, Vx, Vy, V1x, V1y, e0); \
    pp_coeff_set(coeff[i], a, b, c);

  element_init(V, ainfo->Eq);
  element_init(V1, ainfo->Eq);
  element_set(V, in1);
  Vx = curve_x_coord(V);
  Vy = curve_y_coord(V);
  V1x = curve_x_coord(V1);
  V1y = curve_y_coord(V1);
  element_init(e0, ainfo->Fq);
  element_init(a, ainfo->Fq);
  element_init(b, ainfo->Fq);
  element_init(c, ainfo->Fq);

  n = ainfo->exp1;
  for (i=0; i<n; i++) {
    do_tangent();
    element_double(V, V);
  }

  if (ainfo->sign1 < 0) {
    element_neg(V1, V);
  } else {
    element_set(V1, V);
  }
  n = ainfo->exp2;
  for (; i<n; i++) {
    do_tangent();
    element_double(V, V);
  }

  do_line();

  element_clear(e0);
  element_clear(a);
  element_clear(b);
  element_clear(c);
  element_clear(V);
  element_clear(V1);
  #undef do_tangent
  #undef do_line
}

static void a_pairing_pp_clear(pairing_pp_t p) {
  a_pairing_data_ptr ainfo = p->pairing->data;
  pp_coeff_t *coeff = (pp_coeff_t *) p->data;
  int i, n = ainfo->exp2 + 1;
  for (i=0; i<n; i++) {
    pp_coeff_ptr pp = coeff[i];
    element_clear(pp->a);
    element_clear(pp->b);
    element_clear(pp->c);
  }
  pbc_free(p->data);
}

// Requires cofactor to be odd.
// Overwrites in and temp, out != in.
// Luckily this touchy routine is only used internally.
// TODO: rewrite to allow (out == in)? would simplify a_finalpow()
static void lucas_odd(element_ptr out, element_ptr in, element_ptr temp, mpz_t cofactor) {
  element_ptr in0 = element_x(in);
  element_ptr in1 = element_y(in);
  element_ptr v0 = element_x(out);
  element_ptr v1 = element_y(out);
  element_ptr t0 = element_x(temp);
  element_ptr t1 = element_y(temp);
  int j;

  element_set_si(t0, 2);
  element_double(t1, in0);

  element_set(v0, t0);
  element_set(v1, t1);

  j = mpz_sizeinbase(cofactor, 2) - 1;
  for (;;) {
    if (!j) {
      element_mul(v1, v0, v1);
      element_sub(v1, v1, t1);
      element_square(v0, v0);
      element_sub(v0, v0, t0);
      break;
    }
    if (mpz_tstbit(cofactor, j)) {
      element_mul(v0, v0, v1);
      element_sub(v0, v0, t1);
      element_square(v1, v1);
      element_sub(v1, v1, t0);
    } else {
      element_mul(v1, v0, v1);
      element_sub(v1, v1, t1);
      element_square(v0, v0);
      element_sub(v0, v0, t0);
    }
    j--;
  }

  //assume cofactor = (q + 1) / r is even
  //(r should be odd and q + 1 is always even)
  //thus v0 = V_k, v1 = V_{k+1}
  //and V_{k-1} = P v0 - v1

  //so U_k = (P V_k - 2 V_{k-1}) / (P^2 - 4)
  //     = (2 v1 - P v0) / (P^2 - 4)

  element_mul(in0, v0, t1);
  element_double(v1, v1);
  element_sub(v1, v1, in0);

  element_square(t1, t1);
  element_sub(t1, t1, t0);
  element_sub(t1, t1, t0);
  element_div(v1, v1, t1);

  element_halve(v0, v0);
  element_mul(v1, v1, in1);
}

static inline void a_tateexp(element_ptr out, element_ptr in, element_ptr temp, mpz_t cofactor) {
  element_ptr in1 = element_y(in);
  //simpler but slower:
  //element_pow_mpz(out, f, tateexp);

  //1. Exponentiate by q-1
  //which is equivalent to the following

  element_invert(temp, in);
  element_neg(in1, in1);
  element_mul(in, in, temp);

  //2. Exponentiate by (q+1)/r

  //Instead of:
  //  element_pow_mpz(out, in, cofactor);
  //we use Lucas sequences (see "Compressed Pairings", Scott and Barreto)
  lucas_odd(out, in, temp, cofactor);
}

//computes a Qx + b Qy + c for type A pairing
static inline void a_miller_evalfn(element_ptr out,
    element_ptr a, element_ptr b, element_ptr c,
    element_ptr Qx, element_ptr Qy) {
  //we'll map Q via (x,y) --> (-x, iy)
  //hence Re(a Qx + b Qy + c) = -a Q'x + c and
  //Im(a Qx + b Qy + c) = b Q'y
  element_mul(element_y(out), a, Qx);
  element_sub(element_x(out), c, element_y(out));
  element_mul(element_y(out), b, Qy);
}

static void a_pairing_pp_apply(element_ptr out, element_ptr in2, pairing_pp_t p) {
  //TODO: use proj coords here too to shave off a little time
  element_ptr Qx = curve_x_coord(in2);
  element_ptr Qy = curve_y_coord(in2);
  element_t f, f0;
  int i, n;
  a_pairing_data_ptr ainfo = p->pairing->data;
  pp_coeff_t *coeff = p->data;
  element_init(f, ainfo->Fq2);
  element_init(f0, ainfo->Fq2);

  element_set1(f);
  n = ainfo->exp1;
  for (i=0; i<n; i++) {
    pp_coeff_ptr pp = coeff[i];
    element_square(f, f);
    a_miller_evalfn(f0, pp->a, pp->b, pp->c, Qx, Qy);
    element_mul(f, f, f0);
  }
  if (ainfo->sign1 < 0) {
    element_invert(out, f);
  } else {
    element_set(out, f);
  }
  n = ainfo->exp2;
  for (; i<n; i++) {
    element_square(f, f);
    pp_coeff_ptr pp = coeff[i];
    a_miller_evalfn(f0, pp->a, pp->b, pp->c, Qx, Qy);
    element_mul(f, f, f0);
  }

  element_mul(f, f, out);
  {
    pp_coeff_ptr pp = coeff[i];
    a_miller_evalfn(f0, pp->a, pp->b, pp->c, Qx, Qy);
    element_mul(f, f, f0);
  }

  a_tateexp(out, f, f0, p->pairing->phikonr);

  element_clear(f);
  element_clear(f0);
}

// in1, in2 are from E(F_q), out from F_q^2.
// Pairing via elliptic nets (see Stange).
static void a_pairing_ellnet(element_ptr out, element_ptr in1, element_ptr in2,
    pairing_t pairing) {
  element_ptr x = curve_x_coord(in1);
  element_ptr y = curve_y_coord(in1);

  element_ptr x2 = curve_x_coord(in2);
  element_ptr y2 = curve_y_coord(in2);

  //we map (x2,y2) to (-x2, i y2) before pairing
  //notation: cmi means c_{k-i}, ci means c_{k+i}
  element_t cm3, cm2, cm1, c0, c1, c2, c3, c4;
  element_t dm1, d0, d1;
  element_t A, B, C;

  element_init_same_as(cm3, x);
  element_init_same_as(cm2, x);
  element_init_same_as(cm1, x);
  element_init_same_as(c0, x);
  element_init_same_as(c1, x);
  element_init_same_as(c2, x);
  element_init_same_as(c3, x);
  element_init_same_as(c4, x);
  element_init_same_as(C, x);

  element_init_same_as(dm1, out);
  element_init_same_as(d0, out);
  element_init_same_as(d1, out);
  element_init_same_as(A, x);
  element_init_same_as(B, out);

  // c1 = 2y
  // c0 = 1
  // cm2 = -1
  // cm3 = -2y
  element_double(c1, y);
  element_set1(c0);
  element_neg(cm3, c1);
  element_neg(cm2, c0);

  // a = 1, b = 0 for Y^2 = X^3 + X
  //hence c3 = c_{k+3} = c_4 = 4y(x^6 +  5(x^4 - x^2) - 1)
  //use cm1, C, c2 as temp variables for now
  element_square(cm1, x);
  element_square(C, cm1);
  element_sub(c2, C, cm1);
  element_double(c3, c2);
  element_double(c3, c3);
  element_add(c3, c3, c2);
  element_mul(c2, C, cm1);
  element_add(c3, c3, c2);
  element_add(c3, c3, cm2);
  element_mul(c3, c3, c1);
  element_double(c3, c3);

  // c2 = c_3 = 3x^4 + 6x^2 - 1
  element_double(cm1, cm1);
  element_add(cm1, cm1, C);
  element_double(C, cm1);
  element_add(C, C, cm1);
  element_add(c2, C, cm2);

  // c4 = c_5 = c_2^3 c_4 - c_3^3 = c1^3 c3 - c2^3
  element_square(C, c1);
  element_mul(c4, C, c1);
  element_mul(c4, c4, c3);
  element_square(C, c2);
  element_mul(C, C, c2);
  element_sub(c4, c4, C);

  //compute A, B, d1 (which is d_2 since k = 1)
  //(recall phi takes x2 to -x2, y2 to i y2)
  element_add(A, x, x2);
  element_double(C, x);
  element_sub(C, C, x2);
  element_square(cm1, A);
  element_mul(cm1, C, cm1);
  element_set(element_x(d1), y);
  element_set(element_y(d1), y2);
  element_square(d1, d1);
  element_sub(element_x(d1), element_x(d1), cm1);
  element_neg(B, d1);
  element_invert(B, B);
  element_invert(A, A);
  element_mul(element_x(d1), y, A);
  element_neg(element_x(d1), element_x(d1));
  element_mul(element_y(d1), y2, A);
  element_square(d1, d1);
  element_sub(element_x(d1), C, element_x(d1));
  element_neg(element_y(d1), element_y(d1));

  // cm1 = 0
  // C = (2y)^-1
  element_set0(cm1);
  element_invert(C, c1);

  element_set1(dm1);
  element_set1(d0);

  element_t sm2, sm1;
  element_t s0, s1, s2, s3;
  element_t tm2, tm1;
  element_t t0, t1, t2, t3;
  element_t e0, e1;
  element_t u, v;

  element_init_same_as(sm2, x);
  element_init_same_as(sm1, x);
  element_init_same_as(s0, x);
  element_init_same_as(s1, x);
  element_init_same_as(s2, x);
  element_init_same_as(s3, x);

  element_init_same_as(tm2, x);
  element_init_same_as(tm1, x);
  element_init_same_as(t0, x);
  element_init_same_as(t1, x);
  element_init_same_as(t2, x);
  element_init_same_as(t3, x);

  element_init_same_as(e0, x);
  element_init_same_as(e1, x);

  element_init_same_as(u, d0);
  element_init_same_as(v, d0);

  int m = mpz_sizeinbase(pairing->r, 2) - 2;
  for (;;) {
    element_square(sm2, cm2);
    element_square(sm1, cm1);
    element_square(s0, c0);
    element_square(s1, c1);
    element_square(s2, c2);
    element_square(s3, c3);

    element_mul(tm2, cm3, cm1);
    element_mul(tm1, cm2, c0);
    element_mul(t0, cm1, c1);
    element_mul(t1, c0, c2);
    element_mul(t2, c1, c3);
    element_mul(t3, c2, c4);

    element_square(u, d0);
    element_mul(v, dm1, d1);

    if (mpz_tstbit(pairing->r, m)) {
      //double-and-add
      element_mul(e0, t0, sm2);
      element_mul(e1, tm2, s0);
      element_sub(cm3, e0, e1);
      element_mul(cm3, cm3, C);

      element_mul(e0, t0, sm1);
      element_mul(e1, tm1, s0);
      element_sub(cm2, e0, e1);

      element_mul(e0, t1, sm1);
      element_mul(e1, tm1, s1);
      element_sub(cm1, e0, e1);
      element_mul(cm1, cm1, C);

      element_mul(e0, t1, s0);
      element_mul(e1, t0, s1);
      element_sub(c0, e0, e1);

      element_mul(e0, t2, s0);
      element_mul(e1, t0, s2);
      element_sub(c1, e0, e1);
      element_mul(c1, c1, C);

      element_mul(e0, t2, s1);
      element_mul(e1, t1, s2);
      element_sub(c2, e0, e1);

      element_mul(e0, t3, s1);
      element_mul(e1, t1, s3);
      element_sub(c3, e0, e1);
      element_mul(c3, c3, C);

      element_mul(e0, t3, s2);
      element_mul(e1, t2, s3);
      element_sub(c4, e0, e1);

      element_mul(element_x(out), element_x(u), t0);
      element_mul(element_y(out), element_y(u), t0);
      element_mul(element_x(dm1), element_x(v), s0);
      element_mul(element_y(dm1), element_y(v), s0);
      element_sub(dm1, dm1, out);

      element_mul(element_x(out), element_x(u), t1);
      element_mul(element_y(out), element_y(u), t1);
      element_mul(element_x(d0), element_x(v), s1);
      element_mul(element_y(d0), element_y(v), s1);
      element_sub(d0, d0, out);
      element_mul(element_x(d0), element_x(d0), A);
      element_mul(element_y(d0), element_y(d0), A);

      element_mul(element_x(out), element_x(u), t2);
      element_mul(element_y(out), element_y(u), t2);
      element_mul(element_x(d1), element_x(v), s2);
      element_mul(element_y(d1), element_y(v), s2);
      element_sub(d1, d1, out);
      element_mul(d1, d1, B);
    } else {
      //double
      element_mul(e0, tm1, sm2);
      element_mul(e1, tm2, sm1);
      element_sub(cm3, e0, e1);

      element_mul(e0, t0, sm2);
      element_mul(e1, tm2, s0);
      element_sub(cm2, e0, e1);
      element_mul(cm2, cm2, C);

      element_mul(e0, t0, sm1);
      element_mul(e1, tm1, s0);
      element_sub(cm1, e0, e1);

      element_mul(e0, t1, sm1);
      element_mul(e1, tm1, s1);
      element_sub(c0, e0, e1);
      element_mul(c0, c0, C);

      element_mul(e0, t1, s0);
      element_mul(e1, t0, s1);
      element_sub(c1, e0, e1);

      element_mul(e0, t2, s0);
      element_mul(e1, t0, s2);
      element_sub(c2, e0, e1);
      element_mul(c2, c2, C);

      element_mul(e0, t2, s1);
      element_mul(e1, t1, s2);
      element_sub(c3, e0, e1);

      element_mul(e0, t3, s1);
      element_mul(e1, t1, s3);
      element_sub(c4, e0, e1);
      element_mul(c4, c4, C);

      element_mul(element_x(out), element_x(u), tm1);
      element_mul(element_y(out), element_y(u), tm1);
      element_mul(element_x(dm1), element_x(v), sm1);
      element_mul(element_y(dm1), element_y(v), sm1);
      element_sub(dm1, dm1, out);

      element_mul(element_x(out), element_x(u), t0);
      element_mul(element_y(out), element_y(u), t0);
      element_mul(element_x(d0), element_x(v), s0);
      element_mul(element_y(d0), element_y(v), s0);
      element_sub(d0, d0, out);

      element_mul(element_x(out), element_x(u), t1);
      element_mul(element_y(out), element_y(u), t1);
      element_mul(element_x(d1), element_x(v), s1);
      element_mul(element_y(d1), element_y(v), s1);
      element_sub(d1, d1, out);
      element_mul(element_x(d1), element_x(d1), A);
      element_mul(element_y(d1), element_y(d1), A);
    }
    if (!m) break;
    m--;
  }
  // since c_k lies base field
  // it gets killed by the final powering
  //element_invert(c1, c1);
  //element_mul(element_x(d1), element_x(d1), c1);
  //element_mul(element_y(d1), element_y(d1), c1);

  a_tateexp(out, d1, d0, pairing->phikonr);

  element_clear(dm1);
  element_clear(d0);
  element_clear(d1);

  element_clear(cm3);
  element_clear(cm2);
  element_clear(cm1);
  element_clear(c0);
  element_clear(c1);
  element_clear(c2);
  element_clear(c3);
  element_clear(c4);

  element_clear(sm2);
  element_clear(sm1);
  element_clear(s0);
  element_clear(s1);
  element_clear(s2);
  element_clear(s3);

  element_clear(tm2);
  element_clear(tm1);
  element_clear(t0);
  element_clear(t1);
  element_clear(t2);
  element_clear(t3);

  element_clear(e0);
  element_clear(e1);
  element_clear(A);
  element_clear(B);
  element_clear(C);
  element_clear(u);
  element_clear(v);
}

struct ellnet_pp_st_s {
  element_t sm1, s0, s1, s2;
  element_t tm1, t0, t1, t2;
};
typedef struct ellnet_pp_st_s ellnet_pp_st_t[1];
typedef struct ellnet_pp_st_s *ellnet_pp_st_ptr;

struct ellnet_pp_s {
  element_t x;
  element_t y;
  ellnet_pp_st_t *seq;
};
typedef struct ellnet_pp_s ellnet_pp_t[1];
typedef struct ellnet_pp_s *ellnet_pp_ptr;

static void a_pairing_ellnet_pp_init(pairing_pp_t p, element_ptr in1, pairing_t pairing) {
  element_ptr x = curve_x_coord(in1);
  element_ptr y = curve_y_coord(in1);
  int i, rbits = mpz_sizeinbase(pairing->r, 2);
  ellnet_pp_ptr pp = p->data = pbc_malloc(sizeof(ellnet_pp_t));
  pp->seq = pbc_malloc(sizeof(ellnet_pp_st_t) * rbits);
  element_init_same_as(pp->x, x);
  element_init_same_as(pp->y, y);
  element_set(pp->x, x);
  element_set(pp->y, y);
  for (i=0; i<rbits; i++) {
    ellnet_pp_st_ptr seq = pp->seq[i];
    element_init_same_as(seq->sm1, x);
    element_init_same_as(seq->s0, x);
    element_init_same_as(seq->s1, x);
    element_init_same_as(seq->s2, x);
    element_init_same_as(seq->tm1, x);
    element_init_same_as(seq->t0, x);
    element_init_same_as(seq->t1, x);
    element_init_same_as(seq->t2, x);
  }

  //we map (x2,y2) to (-x2, i y2) before pairing
  //notation: cmi means c_{k-i}, ci means c_{k+i}
  element_t cm3, cm2, cm1, c0, c1, c2, c3, c4;
  element_t C;

  element_init_same_as(cm3, x);
  element_init_same_as(cm2, x);
  element_init_same_as(cm1, x);
  element_init_same_as(c0, x);
  element_init_same_as(c1, x);
  element_init_same_as(c2, x);
  element_init_same_as(c3, x);
  element_init_same_as(c4, x);
  element_init_same_as(C, x);

  // c1 = 2y
  // c0 = 1
  // cm2 = -1
  // cm3 = -2y
  element_double(c1, y);
  element_set1(c0);
  element_neg(cm3, c1);
  element_neg(cm2, c0);

  // a = 1, b = 0 for Y^2 = X^3 + X
  //hence c3 = c_{k+3} = c_4 = 4y(x^6 +  5(x^4 - x^2) - 1)
  //use cm1, C, c2 as temp variables for now
  element_square(cm1, x);
  element_square(C, cm1);
  element_sub(c2, C, cm1);
  element_double(c3, c2);
  element_double(c3, c3);
  element_add(c3, c3, c2);
  element_mul(c2, C, cm1);
  element_add(c3, c3, c2);
  element_add(c3, c3, cm2);
  element_mul(c3, c3, c1);
  element_double(c3, c3);

  // c2 = c_3 = 3x^4 + 6x^2 - 1
  element_double(cm1, cm1);
  element_add(cm1, cm1, C);
  element_double(C, cm1);
  element_add(C, C, cm1);
  element_add(c2, C, cm2);

  // c4 = c_5 = c_2^3 c_4 - c_3^3 = c1^3 c3 - c2^3
  element_square(C, c1);
  element_mul(c4, C, c1);
  element_mul(c4, c4, c3);
  element_square(C, c2);
  element_mul(C, C, c2);
  element_sub(c4, c4, C);

  // cm1 = 0
  // C = (2y)^-1
  element_set0(cm1);
  element_invert(C, c1);

  int k = 0;
  element_t sm2, s3;
  element_t tm2, t3;
  element_ptr sm1, s0, s1, s2;
  element_ptr tm1, t0, t1, t2;
  element_t e0, e1;

  element_init_same_as(sm2, x);
  element_init_same_as(s3, x);

  element_init_same_as(tm2, x);
  element_init_same_as(t3, x);

  element_init_same_as(e0, x);
  element_init_same_as(e1, x);

  int m = rbits - 2;
  for (;;) {
    ellnet_pp_st_ptr seq = pp->seq[k];
    sm1 = seq->sm1;
    s0 = seq->s0;
    s1 = seq->s1;
    s2 = seq->s2;
    tm1 = seq->tm1;
    t0 = seq->t0;
    t1 = seq->t1;
    t2 = seq->t2;

    element_square(sm2, cm2);
    element_square(sm1, cm1);
    element_square(s0, c0);
    element_square(s1, c1);
    element_square(s2, c2);
    element_square(s3, c3);

    element_mul(tm2, cm3, cm1);
    element_mul(tm1, cm2, c0);
    element_mul(t0, cm1, c1);
    element_mul(t1, c0, c2);
    element_mul(t2, c1, c3);
    element_mul(t3, c2, c4);

    if (!m) break;
    k++;

    if (mpz_tstbit(pairing->r, m)) {
      //double-and-add
      element_mul(e0, t0, sm2);
      element_mul(e1, tm2, s0);
      element_sub(cm3, e0, e1);
      element_mul(cm3, cm3, C);

      element_mul(e0, t0, sm1);
      element_mul(e1, tm1, s0);
      element_sub(cm2, e0, e1);

      element_mul(e0, t1, sm1);
      element_mul(e1, tm1, s1);
      element_sub(cm1, e0, e1);
      element_mul(cm1, cm1, C);

      element_mul(e0, t1, s0);
      element_mul(e1, t0, s1);
      element_sub(c0, e0, e1);

      element_mul(e0, t2, s0);
      element_mul(e1, t0, s2);
      element_sub(c1, e0, e1);
      element_mul(c1, c1, C);

      element_mul(e0, t2, s1);
      element_mul(e1, t1, s2);
      element_sub(c2, e0, e1);

      element_mul(e0, t3, s1);
      element_mul(e1, t1, s3);
      element_sub(c3, e0, e1);
      element_mul(c3, c3, C);

      element_mul(e0, t3, s2);
      element_mul(e1, t2, s3);
      element_sub(c4, e0, e1);

    } else {
      //double
      element_mul(e0, tm1, sm2);
      element_mul(e1, tm2, sm1);
      element_sub(cm3, e0, e1);

      element_mul(e0, t0, sm2);
      element_mul(e1, tm2, s0);
      element_sub(cm2, e0, e1);
      element_mul(cm2, cm2, C);

      element_mul(e0, t0, sm1);
      element_mul(e1, tm1, s0);
      element_sub(cm1, e0, e1);

      element_mul(e0, t1, sm1);
      element_mul(e1, tm1, s1);
      element_sub(c0, e0, e1);
      element_mul(c0, c0, C);

      element_mul(e0, t1, s0);
      element_mul(e1, t0, s1);
      element_sub(c1, e0, e1);

      element_mul(e0, t2, s0);
      element_mul(e1, t0, s2);
      element_sub(c2, e0, e1);
      element_mul(c2, c2, C);

      element_mul(e0, t2, s1);
      element_mul(e1, t1, s2);
      element_sub(c3, e0, e1);

      element_mul(e0, t3, s1);
      element_mul(e1, t1, s3);
      element_sub(c4, e0, e1);
      element_mul(c4, c4, C);
    }
    m--;
  }

  element_clear(cm3);
  element_clear(cm2);
  element_clear(cm1);
  element_clear(c0);
  element_clear(c1);
  element_clear(c2);
  element_clear(c3);
  element_clear(c4);

  element_clear(sm2);
  element_clear(s3);

  element_clear(tm2);
  element_clear(t3);

  element_clear(e0);
  element_clear(e1);
  element_clear(C);
}

static void a_pairing_ellnet_pp_clear(pairing_pp_t p) {
  ellnet_pp_ptr pp = p->data;
  int i, rbits = mpz_sizeinbase(p->pairing->r, 2);
  for (i=0; i<rbits; i++) {
    ellnet_pp_st_ptr seq = pp->seq[i];
    element_clear(seq->sm1);
    element_clear(seq->s0);
    element_clear(seq->s1);
    element_clear(seq->s2);
    element_clear(seq->tm1);
    element_clear(seq->t0);
    element_clear(seq->t1);
    element_clear(seq->t2);
  }
  element_clear(pp->x);
  element_clear(pp->y);
  pbc_free(pp->seq);
  pbc_free(p->data);
}

static void a_pairing_ellnet_pp_apply(element_ptr out, element_ptr in2, pairing_pp_t p) {
  element_ptr x2 = curve_x_coord(in2);
  element_ptr y2 = curve_y_coord(in2);
  ellnet_pp_ptr pp = p->data;
  int rbits = mpz_sizeinbase(p->pairing->r, 2);
  int k = 0;
  int m = rbits - 2;
  element_t A, B;
  element_t e0, e1;
  element_t dm1, d0, d1;
  element_t u, v;

  element_init_same_as(A, x2);
  element_init_same_as(B, out);
  element_init_same_as(e0, x2);
  element_init_same_as(e1, x2);
  element_init_same_as(dm1, out);
  element_init_same_as(d0, out);
  element_init_same_as(d1, out);
  element_init_same_as(u, out);
  element_init_same_as(v, out);

  element_add(A, pp->x, x2);
  element_double(e0, pp->x);
  element_sub(e0, e0, x2);
  element_square(e1, A);
  element_mul(e1, e0, e1);
  element_set(element_x(d1), pp->y);
  element_set(element_y(d1), y2);
  element_square(d1, d1);
  element_sub(element_x(d1), element_x(d1), e1);
  element_neg(B, d1);
  element_invert(B, B);
  element_invert(A, A);
  element_mul(element_x(d1), pp->y, A);
  element_neg(element_x(d1), element_x(d1));
  element_mul(element_y(d1), y2, A);
  element_square(d1, d1);
  element_sub(element_x(d1), e0, element_x(d1));
  element_neg(element_y(d1), element_y(d1));

  element_set1(dm1);
  element_set1(d0);
  for (;;) {
    element_ptr sm1, s0, s1, s2;
    element_ptr tm1, t0, t1, t2;
    ellnet_pp_st_ptr seq = pp->seq[k];
    sm1 = seq->sm1;
    s0 = seq->s0;
    s1 = seq->s1;
    s2 = seq->s2;
    tm1 = seq->tm1;
    t0 = seq->t0;
    t1 = seq->t1;
    t2 = seq->t2;
    k++;

    element_square(u, d0);
    element_mul(v, dm1, d1);

    if (mpz_tstbit(p->pairing->r, m)) {
      //double-and-add
      element_mul(element_x(out), element_x(u), t0);
      element_mul(element_y(out), element_y(u), t0);
      element_mul(element_x(dm1), element_x(v), s0);
      element_mul(element_y(dm1), element_y(v), s0);
      element_sub(dm1, dm1, out);

      element_mul(element_x(out), element_x(u), t1);
      element_mul(element_y(out), element_y(u), t1);
      element_mul(element_x(d0), element_x(v), s1);
      element_mul(element_y(d0), element_y(v), s1);
      element_sub(d0, d0, out);
      element_mul(element_x(d0), element_x(d0), A);
      element_mul(element_y(d0), element_y(d0), A);

      element_mul(element_x(out), element_x(u), t2);
      element_mul(element_y(out), element_y(u), t2);
      element_mul(element_x(d1), element_x(v), s2);
      element_mul(element_y(d1), element_y(v), s2);
      element_sub(d1, d1, out);
      element_mul(d1, d1, B);
    } else {
      //double
      element_mul(element_x(out), element_x(u), tm1);
      element_mul(element_y(out), element_y(u), tm1);
      element_mul(element_x(dm1), element_x(v), sm1);
      element_mul(element_y(dm1), element_y(v), sm1);
      element_sub(dm1, dm1, out);

      element_mul(element_x(out), element_x(u), t0);
      element_mul(element_y(out), element_y(u), t0);
      element_mul(element_x(d0), element_x(v), s0);
      element_mul(element_y(d0), element_y(v), s0);
      element_sub(d0, d0, out);

      element_mul(element_x(out), element_x(u), t1);
      element_mul(element_y(out), element_y(u), t1);
      element_mul(element_x(d1), element_x(v), s1);
      element_mul(element_y(d1), element_y(v), s1);
      element_sub(d1, d1, out);
      element_mul(element_x(d1), element_x(d1), A);
      element_mul(element_y(d1), element_y(d1), A);
    }
    if (!m) break;
    m--;
  }
  a_tateexp(out, d1, d0, p->pairing->phikonr);

  element_clear(A);
  element_clear(B);
  element_clear(e0);
  element_clear(e1);
  element_clear(dm1);
  element_clear(d0);
  element_clear(d1);
  element_clear(u);
  element_clear(v);
}

//in1, in2 are from E(F_q), out from F_q^2
static void a_pairing_proj(element_ptr out, element_ptr in1, element_ptr in2,
    pairing_t pairing) {
  a_pairing_data_ptr p = pairing->data;
  element_t V, V1;
  element_t z, z2;
  element_t f, f0, f1;
  element_t a, b, c;
  element_t e0;
  const element_ptr e1 = a, e2 = b, e3 = c;
  int i, n;
  element_ptr Vx, Vy;
  element_ptr V1x, V1y;
  element_ptr Qx = curve_x_coord(in2);
  element_ptr Qy = curve_y_coord(in2);

  //could save a couple of inversions by avoiding
  //this function and rewriting do_line() to handle projective coords
  //convert V from weighted projective (Jacobian) to affine
  //i.e. (X, Y, Z) --> (X/Z^2, Y/Z^3)
  //also sets z to 1
  #define point_to_affine()  \
    element_invert(z, z);    \
    element_square(e0, z);   \
    element_mul(Vx, Vx, e0); \
    element_mul(e0, e0, z);  \
    element_mul(Vy, Vy, e0); \
    element_set1(z);         \
    element_set1(z2);

  #define proj_double()      {     \
    /* e0 = 3x^2 + (cc->a) z^4 */  \
    /* for this case a = 1     */  \
    element_square(e0, Vx);        \
    /*element_mul_si(e0, e0, 3);*/ \
    element_double(e1, e0);        \
    element_add(e0, e1, e0);       \
    element_square(e1, z2);        \
    element_add(e0, e0, e1);       \
                                   \
    /* z_out = 2 y z */            \
    element_mul(z, Vy, z);         \
    /*element_mul_si(z, z, 2);*/   \
    element_double(z, z);          \
    element_square(z2, z);         \
                                   \
    /* e1 = 4 x y^2 */             \
    element_square(e2, Vy);        \
    element_mul(e1, Vx, e2);       \
    /*element_mul_si(e1, e1, 4);*/ \
    element_double(e1, e1);        \
    element_double(e1, e1);        \
                                   \
    /* x_out = e0^2 - 2 e1 */      \
    element_double(e3, e1);        \
    element_square(Vx, e0);        \
    element_sub(Vx, Vx, e3);       \
                                   \
    /* e2 = 8y^4 */                \
    element_square(e2, e2);        \
    /*element_mul_si(e2, e2, 8);*/ \
    element_double(e2, e2);        \
    element_double(e2, e2);        \
    element_double(e2, e2);        \
                                   \
    /*y_out = e0(e1 - x_out) - e2*/\
    element_sub(e1, e1, Vx);       \
    element_mul(e0, e0, e1);       \
    element_sub(Vy, e0, e2);       \
  }

  #define do_tangent()                                    \
    compute_abc_tangent_proj(a, b, c, Vx, Vy, z, z2, e0); \
    a_miller_evalfn(f0, a, b, c, Qx, Qy);                 \
    element_mul(f, f, f0);

  #define do_line()                                  \
    compute_abc_line(a, b, c, Vx, Vy, V1x, V1y, e0); \
    a_miller_evalfn(f0, a, b, c, Qx, Qy);            \
    element_mul(f, f, f0);

  element_init(V, p->Eq);
  element_init(V1, p->Eq);
  element_set(V, in1);

  Vx = curve_x_coord(V);
  Vy = curve_y_coord(V);
  V1x = curve_x_coord(V1);
  V1y = curve_y_coord(V1);

  element_init(f, p->Fq2);
  element_init(f0, p->Fq2);
  element_init(f1, p->Fq2);
  element_set1(f);
  element_init(a, p->Fq);
  element_init(b, p->Fq);
  element_init(c, p->Fq);
  element_init(e0, p->Fq);
  element_init(z, p->Fq);
  element_init(z2, p->Fq);
  element_set1(z);
  element_set1(z2);
  n = p->exp1;
  for (i=0; i<n; i++) {
    //f = f^2 g_V,V(Q)
    //where g_V,V = tangent at V
    element_square(f, f);
    do_tangent();
    proj_double();
  }
  point_to_affine();
  if (p->sign1 < 0) {
    element_neg(V1, V);
    element_invert(f1, f);
  } else {
    element_set(V1, V);
    element_set(f1, f);
  }
  n = p->exp2;
  for (; i<n; i++) {
    element_square(f, f);
    do_tangent();
    proj_double();
  }

  element_mul(f, f, f1);
  point_to_affine();
  do_line();

  a_tateexp(out, f, f0, pairing->phikonr);

  element_clear(f);
  element_clear(f0);
  element_clear(f1);
  element_clear(z);
  element_clear(z2);
  element_clear(V);
  element_clear(V1);
  element_clear(a);
  element_clear(b);
  element_clear(c);
  element_clear(e0);
  #undef point_to_affine
  #undef proj_double
  #undef do_tangent
  #undef do_line
}

//in1, in2 are from E(F_q), out from F_q^2
static void a_pairing_affine(element_ptr out, element_ptr in1, element_ptr in2,
    pairing_t pairing) {
  a_pairing_data_ptr p = pairing->data;
  element_t V, V1;
  element_t f, f0, f1;
  element_t a, b, c;
  element_t e0;
  int i, n;
  element_ptr Qx = curve_x_coord(in2);
  element_ptr Qy = curve_y_coord(in2);
  element_ptr Vx, Vy;
  element_ptr V1x, V1y;

  #define do_tangent()                        \
    compute_abc_tangent(a, b, c, Vx, Vy, e0); \
    a_miller_evalfn(f0, a, b, c, Qx, Qy);     \
    element_mul(f, f, f0);

  #define do_line()                                  \
    compute_abc_line(a, b, c, Vx, Vy, V1x, V1y, e0); \
    a_miller_evalfn(f0, a, b, c, Qx, Qy);            \
    element_mul(f, f, f0);

  element_init(V, p->Eq);
  element_init(V1, p->Eq);
  Vx = curve_x_coord(V);
  Vy = curve_y_coord(V);

  V1x = curve_x_coord(V1);
  V1y = curve_y_coord(V1);

  element_set(V, in1);
  element_init(f, p->Fq2);
  element_init(f0, p->Fq2);
  element_init(f1, p->Fq2);
  element_set1(f);
  element_init(a, p->Fq);
  element_init(b, p->Fq);
  element_init(c, p->Fq);
  element_init(e0, p->Fq);
  n = p->exp1;
  for (i=0; i<n; i++) {
    //f = f^2 g_V,V(Q)
    //where g_V,V = tangent at V
    element_square(f, f);
    do_tangent();
    element_double(V, V);
  }
  if (p->sign1 < 0) {
    element_neg(V1, V);
    element_invert(f1, f);
  } else {
    element_set(V1, V);
    element_set(f1, f);
  }
  n = p->exp2;
  for (; i<n; i++) {
    element_square(f, f);
    do_tangent();
    element_double(V, V);
  }

  element_mul(f, f, f1);
  do_line();

  a_tateexp(out, f, f0, pairing->phikonr);

  element_clear(f);
  element_clear(f0);
  element_clear(f1);
  element_clear(V);
  element_clear(V1);
  element_clear(a);
  element_clear(b);
  element_clear(c);
  element_clear(e0);
  #undef do_tangent
  #undef do_line
}

// On Computing Products of Pairing
//in1, in2 are from E(F_q), out from F_q^2
void a_pairings_affine(element_ptr out, element_t in1[], element_t in2[],
    int n_prod, pairing_t pairing) {
  a_pairing_data_ptr p = pairing->data;
  element_t* V = pbc_malloc(sizeof(element_t)*n_prod);
  element_t* V1 = pbc_malloc(sizeof(element_t)*n_prod);
  element_t f, f0, f1;
  element_t a, b, c;
  element_t e0;
  int i, j, n;
  element_ptr Qx, Qy;
  element_ptr Vx, Vy;
  element_ptr V1x, V1y;

  #define do_tangents()                         \
    for(j=0; j<n_prod; j++){                    \
      Vx = curve_x_coord(V[j]);                 \
      Vy = curve_y_coord(V[j]);                 \
      Qx = curve_x_coord(in2[j]);               \
      Qy = curve_y_coord(in2[j]);               \
                                                \
      compute_abc_tangent(a, b, c, Vx, Vy, e0); \
      a_miller_evalfn(f0, a, b, c, Qx, Qy);     \
      element_mul(f, f, f0);                    \
    }

  #define do_lines()                                   \
    for(j=0;j<n_prod;j++){                             \
      Vx = curve_x_coord(V[j]);                        \
      Vy = curve_y_coord(V[j]);                        \
      V1x = curve_x_coord(V1[j]);                      \
      V1y = curve_y_coord(V1[j]);                      \
      Qx = curve_x_coord(in2[j]);                      \
      Qy = curve_y_coord(in2[j]);                      \
                                                       \
      compute_abc_line(a, b, c, Vx, Vy, V1x, V1y, e0); \
      a_miller_evalfn(f0, a, b, c, Qx, Qy);            \
      element_mul(f, f, f0);                           \
    }

  for(i=0; i<n_prod; i++){
    element_init(V[i],p->Eq);
    element_init(V1[i],p->Eq);
    element_set(V[i],in1[i]);
  }


  element_init(f, p->Fq2);
  element_init(f0, p->Fq2);
  element_init(f1, p->Fq2);
  element_set1(f);
  element_init(a, p->Fq);
  element_init(b, p->Fq);
  element_init(c, p->Fq);
  element_init(e0, p->Fq);
  n = p->exp1;
  for (i=0; i<n; i++) {
    //f = f^2 g_V,V(Q)
    //where g_V,V = tangent at V
    element_square(f, f);
    do_tangents();
    element_multi_double(V, V, n_prod); //V_i = V_i + V_i for all i at one time.
  }
  if (p->sign1 < 0) {
    for(j=0; j<n_prod; j++){
      element_neg(V1[j], V[j]);
    }
    element_invert(f1, f);
  } else {
    for(j=0; j<n_prod; j++){
      element_set(V1[j], V[j]);
    }
    element_set(f1, f);
  }
  n = p->exp2;
  for (; i<n; i++) {
    element_square(f, f);
    do_tangents();
    element_multi_double(V, V, n_prod);
  }

  element_mul(f, f, f1);
  do_lines();

  a_tateexp(out, f, f0, pairing->phikonr);

  element_clear(f);
  element_clear(f0);
  element_clear(f1);
  for(j=0;j<n_prod;j++){
    element_clear(V[j]);
    element_clear(V1[j]);
  }
  pbc_free(V);
  pbc_free(V1);
  element_clear(a);
  element_clear(b);
  element_clear(c);
  element_clear(e0);
  #undef do_tangents
  #undef do_lines
}

static void a_pairing_clear(pairing_t pairing) {
  field_clear(pairing->GT);

  a_pairing_data_ptr p = pairing->data;
  field_clear(p->Eq);
  field_clear(p->Fq);
  field_clear(p->Fq2);
  pbc_free(p);

  mpz_clear(pairing->r);
  mpz_clear(pairing->phikonr);
  field_clear(pairing->Zr);
}

static void a_pairing_option_set(pairing_t pairing, char *key, char *value) {
  if (!strcmp(key, "method")) {
    if (!strcmp(value, "miller")) {
      pairing->map = a_pairing_proj;
      pairing->pp_init = a_pairing_pp_init;
      pairing->pp_clear = a_pairing_pp_clear;
      pairing->pp_apply = a_pairing_pp_apply;
    } else if (!strcmp(value, "miller-affine")) {
      pairing->map = a_pairing_affine;
      pairing->pp_init = a_pairing_pp_init;
      pairing->pp_clear = a_pairing_pp_clear;
      pairing->pp_apply = a_pairing_pp_apply;
    } else if (!strcmp(value, "shipsey-stange")) {
      pairing->map = a_pairing_ellnet;
      pairing->pp_init = a_pairing_ellnet_pp_init;
      pairing->pp_clear = a_pairing_ellnet_pp_clear;
      pairing->pp_apply = a_pairing_ellnet_pp_apply;
    }
  }
}

static void a_finalpow(element_t e) {
  pairing_ptr pairing = e->field->pairing;
  element_t t0, t1;
  element_init_same_as(t0, e->data);
  element_init_same_as(t1, e->data);
  a_tateexp(t0, e->data, t1, pairing->phikonr);
  element_set(e->data, t0);
  element_clear(t0);
  element_clear(t1);
}

static void a_init_pairing(pairing_ptr pairing, void *data) {
  a_param_ptr param = data;
  element_t a, b;
  a_pairing_data_ptr p;

  p = pairing->data = pbc_malloc(sizeof(*p));
  p->exp2 = param->exp2;
  p->exp1 = param->exp1;
  p->sign1 = param->sign1;
  mpz_init(pairing->r);
  mpz_set(pairing->r, param->r);
  field_init_fp(pairing->Zr, pairing->r);
  pairing->map = a_pairing_proj;
  pairing->prod_pairings = a_pairings_affine;

  field_init_fp(p->Fq, param->q);
  element_init(a, p->Fq);
  element_init(b, p->Fq);
  element_set1(a);
  element_set0(b);
  field_init_curve_ab(p->Eq, a, b, pairing->r, param->h);
  element_clear(a);
  element_clear(b);

  field_init_fi(p->Fq2, p->Fq);

  //k=2, hence phi_k(q) = q + 1, phikonr = (q+1)/r
  mpz_init(pairing->phikonr);
  mpz_set(pairing->phikonr, param->h);

  pairing->G1 = p->Eq;
  pairing->G2 = pairing->G1;
  pairing->phi = phi_identity;
  pairing_GT_init(pairing, p->Fq2);
  pairing->finalpow = a_finalpow;

  pairing->clear_func = a_pairing_clear;
  pairing->option_set = a_pairing_option_set;
  pairing->pp_init = a_pairing_pp_init;
  pairing->pp_clear = a_pairing_pp_clear;
  pairing->pp_apply = a_pairing_pp_apply;
}

static void a_param_init(pbc_param_ptr par) {
  static pbc_param_interface_t interface = {{
    a_clear,
    a_init_pairing,
  }};
  par->api = interface;
  a_param_ptr p = par->data = pbc_malloc(sizeof(*p));
  mpz_init(p->r);
  mpz_init(p->q);
  mpz_init(p->h);
}

// Public interface for type A pairings:

int pbc_param_init_a(pbc_param_ptr par, struct symtab_s *tab) {
  a_param_init(par);
  a_param_ptr p = par->data;

  int err = 0;
  err += lookup_mpz(p->q, tab, "q");
  err += lookup_mpz(p->r, tab, "r");
  err += lookup_mpz(p->h, tab, "h");
  err += lookup_int(&p->exp2, tab, "exp2");
  err += lookup_int(&p->exp1, tab, "exp1");
  err += lookup_int(&p->sign1, tab, "sign1");
  err += lookup_int(&p->sign0, tab, "sign0");
  return err;
}