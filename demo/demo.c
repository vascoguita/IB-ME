#include <ibme.h>

#include "demo.h"

int main(){
    //TODO Find adequate parameters
    const char *param_str = "type a\nq 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791\nh 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776\n\nr 730750818665451621361119245571504901405976559617\nexp2 159\nexp1 107\nsign1 1\nsign0 1";
    const char *S = "Vasco";
    const char *R = "Zosia";
    MKP *mkp = NULL;
    EK *ek_S = NULL;
    DK *dk_R = NULL;

    if((mkp = MKP_init(param_str)) == NULL) {
        clear(mkp, ek_S, dk_R);
        return 1;
    }
    setup(&mkp);

    if((ek_S = EK_init(mkp->mpk->pairing)) == NULL) {
        clear(mkp, ek_S, dk_R);
        return 1;
    }
    if(1 == sk_gen(mkp, S, &ek_S)) {
        clear(mkp, ek_S, dk_R);
        return 1;
    }


    dk_R = DK_init(mkp->mpk->pairing);
    if(1 == rk_gen(mkp, R, &dk_R)) {
        clear(mkp, ek_S, dk_R);
        return 1;
    }

    clear(mkp, ek_S, dk_R);
    return 0;
}

void clear(MKP *mkp, EK *ek, DK *dk) {
    DK_clear(dk);
    EK_clear(ek);
    MKP_clear(mkp);
}